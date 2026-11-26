// Report filter (round 71, Phase 7): keep a threshold subset of one
// JSON report — "only High and above, only valid verdicts" —
// without splitting into files.
//
// Split (round 70) groups by one key, but an operator often wants a
// threshold subset in a single report: the Criticals for triage, the
// valid findings for a submission, everything at or above Medium for
// a review meeting. The filter answers that: one valid round-31 JSON
// report carrying only the kept findings, with its own recomputed
// report id, so the subset stands on its own (it passes `report
// validate`).
//
// Predicates (AND-combined, both optional, at least one REQUIRED —
// a filter with no predicate is just a copy, and is refused with
// REPORT_FILTER_NO_PREDICATE):
//   - `--severity <level>`: keep findings at or above this severity
//     (SEVERITY_ORDER: critical > high > medium > low >
//     informational; the level is matched case-insensitively, an
//     unknown level fails with REPORT_FILTER_INVALID_SEVERITY
//     listing the five values).
//   - `--verdict <rule-verdict>`: keep findings whose RULE verdict
//     from round 67's `validateOneFinding` (valid /
//     false_positive / needs_evidence) equals the given value —
//     NOT the stored `validation_status` field. The distinction
//     matters and is worth stating plainly: the schema's
//     `validation_status` enum is a workflow state (detected /
//     needs_review / validated / false_positive / duplicate /
//     rejected — see schemas/finding.schema.json), and it does NOT
//     take the values `valid` or `needs_evidence`. Every
//     generator-produced finding in the fixture set carries
//     `validation_status: "validated"`, so filtering by the stored
//     field would keep either everything or nothing and the
//     filter would be useless. The rule verdict is the triage
//     split the operator actually wants (which findings are
//     confirmed valid, which need evidence, which are false
//     positives), and it is the same path `report validate`
//     (round 67), merge (round 68), anonymize (round 69), and
//     split (round 70) already use. An unknown verdict fails
//     with REPORT_FILTER_INVALID_VERDICT listing the three values.
//     A finding whose rule verdict is `error` fails the filter
//     with REPORT_FILTER_INVALID_FINDING — a structural defect,
//     same as split — it is never silently dropped.
//
// Output: the kept findings are rendered by generateReport itself
// (format 'json', allowMixedTargets: true), so the report_id is
// the generator's own derivation for the kept subset and the
// output passes `report validate` with report_id_matches: true
// by construction. A platform-template report (one finding,
// template set) keeps its template marker, the same passthrough
// split uses. The output carries a `filter` metadata block
// ({ from_report_id, severity, verdict } — keys not given are
// omitted) appended last, so the render's own key order is
// untouched. An empty result is a VALID empty report (total 0),
// not an error — the same rule as JSONL's empty set (round 66):
// generateReport refuses an empty finding set for JSON, so the
// empty report is built here following renderJson's shape
// (report_id from the generator's own derivation for the empty
// set, target_id from the source, program_name, generated_at,
// executive_summary and findings_summary from the generator's own
// helpers (executiveSummary over countBySeverity([]), round 72),
// findings: []), and it passes
// `report validate` with report_id_matches: true. A report with
// no usable generated_at fails with REPORT_FILTER_NO_GENERATED_AT
// (the input's generated_at, else the newest finding created_at
// — generateReport never invents a timestamp from the wall
// clock, and neither does this module).
//
// Inputs are read with readReportFile from report-diff.js (round
// 64): bounded (10 MiB, depth 100), symlinked input refused.
// Shape failures therefore carry REPORT_DIFF_* codes — the
// reader is shared, not re-implemented.
//
// The module never writes anything and never modifies its input
// object. The CLI (bin/sentinel.js runReportFilter) owns the
// --out handling: stdout (pure JSON, pipeable) or safe-write
// (mode 0600), with the one-line summary on stderr. Filter is a
// subset view: it does not re-score, does not change any finding,
// and does not claim the filtered-out findings are invalid.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { generateReport, SEVERITY_ORDER, countBySeverity, executiveSummary } = require('./generator');
const { validateReportShape } = require('./report-diff');
const { validateOneFinding, deriveExpectedReportId, FINDING_STATUSES } = require('./validate');
const { programOf } = require('./merge');

// The rule-verdict values a --verdict predicate may name, in the
// order they are listed in the usage error. FINDING_STATUSES minus
// 'error' (an error finding fails the filter, it is never kept).
const VERDICT_VALUES = FINDING_STATUSES.filter((status) => status !== 'error');

// The generated_at for the filtered report: the input report's own
// generated_at when it is a valid ISO timestamp, else the newest
// finding created_at among the kept findings (or among all source
// findings when the kept set is empty), else a named error — a JSON
// report requires generated_at and the module never invents a
// timestamp from the wall clock (the same rule as round 68's
// pickGeneratedAt and round 70's, reimplemented here because
// neither module exports it).
function pickGeneratedAt(report, findings) {
  const input = typeof report.generated_at === 'string' && Number.isFinite(Date.parse(report.generated_at))
    ? report.generated_at
    : null;
  if (input) return input;
  const created = findings
    .map((finding) => finding.created_at)
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
  if (created.length > 0) {
    return created.sort((x, y) => Date.parse(x) - Date.parse(y)).at(-1);
  }
  throw new Error(
    'REPORT_FILTER_NO_GENERATED_AT: the report carries no generated_at and no finding carries created_at; '
    + 'cannot produce a JSON report (generated_at is required).',
  );
}

// The target_id for the empty report: the source report's own
// target_id when present, else the first target in sorted order
// among the source findings (every generator-produced finding
// carries one), else null. A multi-target source also carries
// target_ids + mixed_targets, the round-49 convention.
function emptyTarget(report, findings) {
  const targetIds = [...new Set(
    findings.map((finding) => String(finding.target_id).trim()).filter((value) => value !== ''),
  )].sort();
  const targetId = typeof report.target_id === 'string' && report.target_id.trim() !== ''
    ? report.target_id.trim()
    : (targetIds[0] || null);
  if (targetIds.length > 1) {
    return { target_id: targetId, target_ids: targetIds, mixed_targets: true };
  }
  return { target_id: targetId };
}

// Build the empty filtered report by hand, following renderJson's
// shape (src/report/generator.js): generateReport refuses an empty
// finding set for JSON, so the empty case cannot go through it.
// The report_id is the generator's own derivation for the empty
// set (deriveExpectedReportId replicates deriveReportId exactly —
// deliberately independent, so validate can check the generator;
// see docs/report-helpers-export-v1.md), and the executive
// summary and findings_summary come from the generator's own
// helpers (executiveSummary over countBySeverity([]), round 72).
function renderEmptyReport(report, programName, generatedAt, filterBlock) {
  const target = emptyTarget(report, report.findings);
  // Round 72: the summary and counts come from the generator's own
  // helpers — they used to be hand-written copies here, so a
  // generator wording change would have silently diverged (round
  // 71 F5). executiveSummary over countBySeverity([]) IS the
  // zero-count summary by construction; the golden test pins the
  // bytes and the anti-divergence test pins the call.
  const zeroCounts = countBySeverity([]);
  const filtered = {
    report_id: deriveExpectedReportId(programName, []),
    target_id: target.target_id,
    program_name: programName,
    generated_at: generatedAt,
    executive_summary: executiveSummary(zeroCounts, programName),
    findings_summary: zeroCounts,
    findings: [],
  };
  if (target.target_ids) {
    filtered.target_ids = target.target_ids;
    filtered.mixed_targets = true;
  }
  if (typeof report.session_id === 'string' && report.session_id.trim() !== '') {
    filtered.session_id = report.session_id;
  }
  filtered.filter = filterBlock;
  return `${JSON.stringify(filtered, null, 2)}\n`;
}

// Filter a parsed JSON report object (report_id + findings array;
// shape-checked first, so a malformed report throws instead of
// returning a partial result). Options: { severity, verdict } —
// at least one required. Returns:
// {
//   report: string,  // the filtered JSON report
//   summary: { total, kept, from_report_id, report_id, severity, verdict }
// }
// `severity`/`verdict` in the summary are the normalized predicate
// values (lowercase), or null when that predicate was not given.
function filterReport(report, options = {}) {
  validateReportShape(report, 'report');
  const rawSeverity = options.severity;
  const rawVerdict = options.verdict;
  const severity = typeof rawSeverity === 'string' && rawSeverity.trim() !== ''
    ? rawSeverity.trim().toLowerCase()
    : null;
  const verdict = typeof rawVerdict === 'string' && rawVerdict.trim() !== ''
    ? rawVerdict.trim().toLowerCase()
    : null;
  if (severity === null && verdict === null) {
    throw new Error(
      'REPORT_FILTER_NO_PREDICATE: filter requires at least one predicate: --severity <level> and/or --verdict <rule-verdict>.',
    );
  }
  if (severity !== null && !SEVERITY_ORDER.includes(severity)) {
    throw new Error(
      `REPORT_FILTER_INVALID_SEVERITY: --severity must be one of ${SEVERITY_ORDER.join(', ')} (got ${JSON.stringify(rawSeverity)}).`,
    );
  }
  if (verdict !== null && !VERDICT_VALUES.includes(verdict)) {
    throw new Error(
      `REPORT_FILTER_INVALID_VERDICT: --verdict must be one of ${VERDICT_VALUES.join(', ')} (got ${JSON.stringify(rawVerdict)}).`,
    );
  }
  // Every finding is checked with round 67's path: the strict
  // generator check first (a throw is a structural defect),
  // then the rule verdict. The verdict is the predicate for
  // --verdict; for --severity it is computed anyway so the
  // strict check cannot be skipped by choosing a predicate.
  const checked = report.findings.map((finding) => {
    const result = validateOneFinding(finding);
    if (result.status === 'error') {
      throw new Error(
        `REPORT_FILTER_INVALID_FINDING: finding ${finding.finding_id} fails the strict check: ${result.reasons.join('; ')}`,
      );
    }
    return { finding, verdict: result.status };
  });
  const severityRank = severity === null ? null : SEVERITY_ORDER.indexOf(severity);
  const kept = checked
    .filter((entry) => {
      if (severityRank !== null && SEVERITY_ORDER.indexOf(entry.finding.severity) > severityRank) return false;
      if (verdict !== null && entry.verdict !== verdict) return false;
      return true;
    })
    .map((entry) => entry.finding);
  const programName = programOf(report);
  const filterBlock = { from_report_id: report.report_id };
  if (severity !== null) filterBlock.severity = severity;
  if (verdict !== null) filterBlock.verdict = verdict;
  const generatedAt = pickGeneratedAt(report, kept.length > 0 ? kept : report.findings);
  let rendered;
  if (kept.length === 0) {
    rendered = renderEmptyReport(report, programName, generatedAt, filterBlock);
  } else {
    const renderOptions = {
      format: 'json',
      programName,
      generatedAt,
      allowMixedTargets: true,
    };
    // A platform-template report (one finding, template set)
    // keeps its template marker; anything else renders generic.
    // A multi-finding kept set with a template set is refused by
    // generateReport itself (a template renders one finding),
    // which is the correct fail-closed behaviour for a
    // hand-edited input.
    if (typeof report.template === 'string' && report.template.trim() !== '' && report.template.trim() !== 'generic') {
      renderOptions.template = report.template.trim();
    }
    const parsed = JSON.parse(generateReport(kept, renderOptions));
    parsed.filter = filterBlock;
    rendered = `${JSON.stringify(parsed, null, 2)}\n`;
  }
  return {
    report: rendered,
    summary: {
      total: report.findings.length,
      kept: kept.length,
      from_report_id: report.report_id,
      report_id: JSON.parse(rendered).report_id,
      severity,
      verdict,
    },
  };
}

module.exports = {
  VERDICT_VALUES,
  filterReport,
};
