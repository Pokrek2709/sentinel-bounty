// Report validation (round 67, Phase 7): check a JSON report FILE
// handed to the operator before trusting it.
//
// The generator renders reports and report-diff compares two of
// them, but until now a malformed or tampered report file was only
// discovered when another command choked on it. `sentinel report
// validate <file.json>` answers the question up front: is this file
// a well-formed report whose findings check out?
//
// Checks, in order:
//   1. Shape: the file must parse as a JSON report object with a
//      non-empty `report_id` string and a `findings` array (bounded
//      at MAX_FINDINGS, duplicate finding_ids refused). A symlinked
//      input is refused. Shape failures are named errors
//      (REPORT_VALIDATE_*) and fail before any verdict is produced.
//   2. Per finding: the strict generator check
//      (src/report/generator.js validateFinding — required fields,
//      severity band, CVSS vector/score agreement) runs first. A
//      finding that fails it is an `error`: a structural defect of
//      the file, because the generator would never have produced
//      it. A finding that passes it gets its rule-based verdict
//      from src/analysis/validator.js validateFinding — `valid`,
//      `false_positive`, or `needs_evidence` — with reasons. Those
//      three are findings, not file defects: they are counted, never
//      errors.
//   3. Report id: the id is recomputed the same way the generator
//      derives it (SHA-256 of { program, sorted finding ids }) and
//      compared with the file's `report_id`. A mismatch is a
//      WARNING, not a failure — the file may come from an older
//      generator version — and is reported as `report_id_matches:
//      false` with a warning line. When `program_name` is missing
//      the id cannot be recomputed at all, which is likewise a
//      warning, not an error.
//
// Exit rule (documented in docs/report-validate-v1.md): exit 0
// when the file parses and every finding validates — that includes
// false_positive and needs_evidence findings, which are counted
// but do not fail the exit code. Only structural errors and band
// mismatches (the `error` findings) fail, with exit 1.
//
// Deliberately NOT done here: no re-scoring beyond the band
// check, no AI verdict, no audit-chain verification (that is
// `audit verify`'s job), and no re-rendering. Validate is
// read-only: it never writes anything.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { readJsonFileBounded, MAX_FINDINGS } = require('../policy/input-limits');
const { validateFinding: validateFindingStrict } = require('./generator');
const { validateFinding: validateFindingVerdict } = require('../analysis/validator');

// Per-finding statuses. `error` is a structural defect (the
// generator would never have produced the finding); the other
// three are rule-based verdicts and never fail the exit code.
const FINDING_STATUSES = ['valid', 'false_positive', 'needs_evidence', 'error'];

function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// The generator's report-id derivation, replicated exactly
// (src/report/generator.js deriveReportId): SHA-256 of the program
// name plus the sorted finding ids, first 12 hex chars. Replicated
// here rather than imported because generator.js does not export
// it; the formula is documented in both places, and the test
// "report_id matches on a generator-produced report" pins the two
// together — if the generator ever changes the formula, that test
// fails loudly instead of silently agreeing.
function deriveExpectedReportId(programName, findings) {
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify({ program: programName, ids: findings.map((f) => f.finding_id).sort() }))
    .digest('hex');
  return `RPT-${digest.slice(0, 12)}`;
}

// Validate the shape of a parsed JSON report file. `label` is the
// file path, carried into the named errors so the operator knows
// which input is at fault. Throws on the first problem found.
function validateReportShape(report, label) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error(`REPORT_VALIDATE_INVALID_REPORT: ${label} is not a JSON report object (expected an object with report_id and a findings array).`);
  }
  if (typeof report.report_id !== 'string' || report.report_id.trim() === '') {
    throw new Error(`REPORT_VALIDATE_INVALID_REPORT: ${label} has no report_id (expected a string).`);
  }
  if (!Array.isArray(report.findings)) {
    throw new Error(`REPORT_VALIDATE_INVALID_REPORT: ${label} has no findings array.`);
  }
  if (report.findings.length > MAX_FINDINGS) {
    throw new Error(`REPORT_VALIDATE_TOO_MANY_FINDINGS: ${label} has ${report.findings.length} findings (maximum ${MAX_FINDINGS}).`);
  }
  const seen = new Set();
  report.findings.forEach((finding, index) => {
    if (!finding || typeof finding !== 'object' || Array.isArray(finding)
      || typeof finding.finding_id !== 'string' || finding.finding_id.trim() === '') {
      throw new Error(`REPORT_VALIDATE_INVALID_FINDING: ${label} finding at index ${index} has no finding_id.`);
    }
    if (seen.has(finding.finding_id)) {
      throw new Error(`REPORT_VALIDATE_DUPLICATE_FINDING_ID: ${label} contains duplicate finding_id "${finding.finding_id}".`);
    }
    seen.add(finding.finding_id);
  });
}

// Read one JSON report file: refuse a symlinked input, read bounded
// (10 MiB, depth 100), then validate the report shape. Any failure
// is a named error; nothing is returned on failure.
async function readReportFileForValidation(filePath) {
  let stat = null;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    throw new Error(`REPORT_VALIDATE_INVALID_REPORT: cannot read ${filePath}: ${error.message}`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`REPORT_VALIDATE_SYMLINK_REFUSED: Refusing to read through a symbolic link: ${filePath}`);
  }
  let parsed;
  try {
    parsed = await readJsonFileBounded(filePath);
  } catch (error) {
    throw new Error(`REPORT_VALIDATE_INVALID_REPORT: cannot read ${filePath}: ${error.message}`);
  }
  validateReportShape(parsed, filePath);
  return parsed;
}

// Validate one finding and classify it. The strict generator check
// runs first: a throw is an `error` with the generator's message
// (which names the finding and the problem). A finding that passes
// it gets its rule-based verdict from the validator. The verdict's
// reasons are carried verbatim; a `valid` verdict's reason is the
// validator's confirmation line.
function validateOneFinding(finding) {
  try {
    validateFindingStrict(finding, 0);
  } catch (error) {
    return { finding_id: finding.finding_id, status: 'error', reasons: [error.message] };
  }
  const rule = validateFindingVerdict(finding);
  return { finding_id: finding.finding_id, status: rule.verdict, reasons: rule.reasons };
}

// Validate a parsed report object (report_id + findings array;
// shape-checked first, so a malformed report throws instead of
// returning a verdict). Returns the validation result:
// {
//   status: 'VALID' | 'INVALID',
//   report_id, report_id_matches, report_id_warning,
//   counts: { findings, valid, false_positive, needs_evidence, errors },
//   findings: [{ finding_id, status, reasons }]  // sorted by finding_id
// }
// Per-finding entries are sorted by finding_id (plain string
// order), so the same finding set in any file order validates to
// byte-identical output. `report_id_matches` is false with a
// warning when the id cannot be recomputed (no program_name) or
// disagrees with the recomputed id — a warning, never a failure.
function validateReport(report) {
  validateReportShape(report, 'report');
  const sortedFindings = [...report.findings].sort((a, b) => compareStrings(a.finding_id, b.finding_id));
  const perFinding = sortedFindings.map((finding) => validateOneFinding(finding));
  const counts = { findings: perFinding.length, valid: 0, false_positive: 0, needs_evidence: 0, errors: 0 };
  for (const entry of perFinding) {
    if (entry.status === 'valid') counts.valid += 1;
    else if (entry.status === 'false_positive') counts.false_positive += 1;
    else if (entry.status === 'needs_evidence') counts.needs_evidence += 1;
    else counts.errors += 1;
  }
  let reportIdMatches = false;
  let reportIdWarning = null;
  if (typeof report.program_name !== 'string' || report.program_name.trim() === '') {
    reportIdWarning = 'cannot verify report_id: program_name is missing or not a string';
  } else {
    const expected = deriveExpectedReportId(report.program_name, report.findings);
    if (expected === report.report_id) {
      reportIdMatches = true;
    } else {
      reportIdWarning = `report_id mismatch: expected ${expected}, found ${report.report_id} (the file may come from an older generator version)`;
    }
  }
  return {
    status: counts.errors === 0 ? 'VALID' : 'INVALID',
    report_id: report.report_id,
    report_id_matches: reportIdMatches,
    report_id_warning: reportIdWarning,
    counts,
    findings: perFinding,
  };
}

// Render the validation result as text (the default): the verdict
// line, the report-id check line, the counts line, then one line
// per finding whose status is not `valid`, with its reasons. When
// every finding is valid the last line says so. Deterministic:
// per-finding lines are in finding_id order.
function renderReportValidationText(result) {
  const lines = [];
  lines.push(`Report Validation — ${result.status}`);
  if (result.report_id_matches) {
    lines.push(`Report ID: ${result.report_id} (verified)`);
  } else {
    lines.push(`Report ID: ${result.report_id} (warning: ${result.report_id_warning})`);
  }
  const counts = result.counts;
  lines.push(`Counts: ${counts.findings} finding${counts.findings === 1 ? '' : 's'}, ${counts.valid} valid, ${counts.false_positive} false_positive, ${counts.needs_evidence} needs_evidence, ${counts.errors} error${counts.errors === 1 ? '' : 's'}`);
  const nonValid = result.findings.filter((entry) => entry.status !== 'valid');
  if (nonValid.length === 0) {
    lines.push('All findings valid.');
  } else {
    nonValid.forEach((entry) => {
      lines.push(`- ${entry.finding_id} [${entry.status}]: ${entry.reasons.join('; ')}`);
    });
  }
  return `${lines.join('\n')}\n`;
}

// Render the validation result as JSON: the result object itself,
// pretty-printed. The key order is fixed (status, report_id,
// report_id_matches, report_id_warning, counts, findings) and
// every list is sorted, so the same report validates to
// byte-identical output.
function renderReportValidationJson(result) {
  return `${JSON.stringify(result, null, 2)}\n`;
}

module.exports = {
  FINDING_STATUSES,
  deriveExpectedReportId,
  validateReportShape,
  readReportFileForValidation,
  validateOneFinding,
  validateReport,
  renderReportValidationText,
  renderReportValidationJson,
};
