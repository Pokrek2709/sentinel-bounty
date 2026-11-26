// Report diff (round 64, Phase 7): compare two JSON reports from two
// runs of the same program and show what changed between them.
//
// An operator re-running detection after a fix previously had to read
// two full reports side by side. The diff answers the only question
// that matters after a re-run: which findings are new, which are
// gone, and which changed — nothing else.
//
// Matching: findings are matched by finding_id only. A finding
// present in the new report but not the old one is `added`; one in
// the old but not the new is `removed`; one present in both is
// `changed` when any compared field differs, otherwise it counts
// toward `unchanged` (count only — unchanged findings are never
// listed, so a no-change re-run diffs to a short "No differences.").
//
// Compared fields, in this fixed order: `severity`, `cvss_score`,
// `verdict`, `asset_id`. `verdict` is the finding's
// `validation_status` field, under the same name the CSV export's
// `verdict` column uses (see src/report/generator.js: the column
// carries validation_status). `merged_from` is deliberately NOT a
// compared field: it is provenance from the semantic dedup pass
// (round 48), not substance — two findings that differ only in
// merged_from are the same finding. Description, steps, evidence,
// references, and every other field are likewise not compared; the
// diff is a triage view, and the full finding lives in the source
// report.
//
// Inputs are JSON report files in the round-31 JSON report format
// (an object with `report_id` and a `findings` array). They are read
// bounded (10 MiB, depth 100 — src/policy/input-limits.js) and a
// symlinked input is refused. The diff does NOT re-validate the
// findings against the finding schema: a diff compares reports, it
// does not re-judge them. Shape errors are named
// (REPORT_DIFF_INVALID_REPORT / REPORT_DIFF_INVALID_FINDING /
// REPORT_DIFF_DUPLICATE_FINDING_ID / REPORT_DIFF_SYMLINK_REFUSED /
// REPORT_DIFF_TOO_MANY_FINDINGS) and fail before any output is
// produced, so a bad input can never leave a half-written file
// behind. A duplicate finding_id inside one report is refused: the
// match would be ambiguous, and a generated report never contains
// one (the pipeline dedupes), so a duplicate can only come from a
// hand-edited file.
//
// Determinism: added / removed / changed are sorted by finding_id
// (plain string order), the changed field list is in the fixed
// field order above, and the diff's own report_id is a hash of the
// two source report ids plus the sorted id lists — so the same two
// report sets in any finding order produce byte-identical output in
// both formats. No --generated-at: like CSV (round 55) and the
// summary (round 61), a diff carries no wall-clock timestamp.
//
// Mixed targets: a diff compares by finding_id regardless of
// target_id, so reports from different targets (or a mixed-target
// report, round 49) diff fine — a changed target_id on a finding
// is not itself a compared field, so a finding that merely moved
// target is unchanged. That is documented, not accidental.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { readJsonFileBounded, MAX_FINDINGS } = require('../policy/input-limits');

// Fields compared between two versions of the same finding, in the
// fixed order they render in a `changed` entry.
const COMPARED_FIELDS = ['severity', 'cvss_score', 'verdict', 'asset_id'];

// A finding reduced to the fields the diff compares, plus its id.
// `verdict` is the finding's validation_status (same mapping as the
// CSV `verdict` column). Missing values normalize to null so that
// "absent" compares equal to "absent" and renders as a single
// placeholder instead of `undefined`.
function summarizeFinding(finding) {
  const score = finding.cvss_score === undefined || finding.cvss_score === null ? null : finding.cvss_score;
  const verdict = typeof finding.validation_status === 'string' && finding.validation_status !== ''
    ? finding.validation_status
    : null;
  const severity = typeof finding.severity === 'string' && finding.severity !== '' ? finding.severity : null;
  const assetId = typeof finding.asset_id === 'string' && finding.asset_id !== '' ? finding.asset_id : null;
  return { finding_id: finding.finding_id, severity, cvss_score: score, verdict, asset_id: assetId };
}

function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// Validate the shape of a parsed JSON report file. `label` is the
// file path, carried into the named errors so the operator knows
// which of the two inputs is at fault.
function validateReportShape(report, label) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error(`REPORT_DIFF_INVALID_REPORT: ${label} is not a JSON report object (expected an object with report_id and a findings array).`);
  }
  if (typeof report.report_id !== 'string' || report.report_id.trim() === '') {
    throw new Error(`REPORT_DIFF_INVALID_REPORT: ${label} has no report_id (expected a string).`);
  }
  if (!Array.isArray(report.findings)) {
    throw new Error(`REPORT_DIFF_INVALID_REPORT: ${label} has no findings array.`);
  }
  if (report.findings.length > MAX_FINDINGS) {
    throw new Error(`REPORT_DIFF_TOO_MANY_FINDINGS: ${label} has ${report.findings.length} findings (maximum ${MAX_FINDINGS}).`);
  }
  const seen = new Set();
  report.findings.forEach((finding, index) => {
    if (!finding || typeof finding !== 'object' || Array.isArray(finding)
      || typeof finding.finding_id !== 'string' || finding.finding_id.trim() === '') {
      throw new Error(`REPORT_DIFF_INVALID_FINDING: ${label} finding at index ${index} has no finding_id.`);
    }
    if (seen.has(finding.finding_id)) {
      throw new Error(`REPORT_DIFF_DUPLICATE_FINDING_ID: ${label} contains duplicate finding_id "${finding.finding_id}".`);
    }
    seen.add(finding.finding_id);
  });
}

// Read one JSON report file: refuse a symlinked input, read bounded
// (10 MiB, depth 100), then validate the report shape. Any failure
// is a named error; nothing is returned on failure.
async function readReportFile(filePath) {
  let stat = null;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    throw new Error(`REPORT_DIFF_INVALID_REPORT: cannot read ${filePath}: ${error.message}`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`REPORT_DIFF_SYMLINK_REFUSED: Refusing to read through a symbolic link: ${filePath}`);
  }
  let parsed;
  try {
    parsed = await readJsonFileBounded(filePath);
  } catch (error) {
    throw new Error(`REPORT_DIFF_INVALID_REPORT: cannot read ${filePath}: ${error.message}`);
  }
  validateReportShape(parsed, filePath);
  return parsed;
}

// The diff's own report id: a hash of the two source report ids
// plus the sorted id lists, so the same pair of report sets always
// yields the same diff id regardless of finding order.
function deriveDiffReportId(oldReportId, newReportId, addedIds, removedIds, changedIds) {
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify({
      old: oldReportId,
      new: newReportId,
      added: [...addedIds].sort(compareStrings),
      removed: [...removedIds].sort(compareStrings),
      changed: [...changedIds].sort(compareStrings),
    }))
    .digest('hex');
  return `RPT-${digest.slice(0, 12)}`;
}

// Compare two validated reports (objects with report_id + findings
// array). Returns the diff object:
// {
//   report_id, old_report_id, new_report_id,
//   added: [summarized finding, ...],      // in new, not in old
//   removed: [summarized finding, ...],    // in old, not in new
//   changed: [{ finding_id, changes: [{ field, old, new }] }],
//   counts: { added, removed, changed, unchanged },
// }
// `added` / `removed` entries are compact summaries (id + the four
// compared fields), not full findings — the full finding lives in
// the source report, and a compact row keeps the diff deterministic
// and readable. `changed` lists exactly which of the four fields
// differ, in the fixed COMPARED_FIELDS order.
function diffReports(oldReport, newReport) {
  validateReportShape(oldReport, 'old report');
  validateReportShape(newReport, 'new report');
  const oldById = new Map(oldReport.findings.map((finding) => [finding.finding_id, summarizeFinding(finding)]));
  const newById = new Map(newReport.findings.map((finding) => [finding.finding_id, summarizeFinding(finding)]));
  const added = [];
  const removed = [];
  const changed = [];
  let unchanged = 0;
  for (const [findingId, newFinding] of [...newById.entries()].sort((a, b) => compareStrings(a[0], b[0]))) {
    const oldFinding = oldById.get(findingId);
    if (!oldFinding) {
      added.push(newFinding);
      continue;
    }
    const changes = [];
    for (const field of COMPARED_FIELDS) {
      if (oldFinding[field] !== newFinding[field]) {
        changes.push({ field, old: oldFinding[field], new: newFinding[field] });
      }
    }
    if (changes.length === 0) {
      unchanged += 1;
    } else {
      changed.push({ finding_id: findingId, changes });
    }
  }
  for (const [findingId, oldFinding] of [...oldById.entries()].sort((a, b) => compareStrings(a[0], b[0]))) {
    if (!newById.has(findingId)) removed.push(oldFinding);
  }
  return {
    report_id: deriveDiffReportId(
      oldReport.report_id,
      newReport.report_id,
      added.map((finding) => finding.finding_id),
      removed.map((finding) => finding.finding_id),
      changed.map((entry) => entry.finding_id),
    ),
    old_report_id: oldReport.report_id,
    new_report_id: newReport.report_id,
    added,
    removed,
    changed,
    counts: { added: added.length, removed: removed.length, changed: changed.length, unchanged },
  };
}

function formatScore(value) {
  return value === null ? 'Not scored' : String(value);
}

function formatChangeValue(field, value) {
  if (value === null) return field === 'cvss_score' ? 'Not scored' : 'none';
  return String(value);
}

function formatDiffRow(finding) {
  return `- ${finding.finding_id} | ${finding.severity === null ? 'none' : finding.severity} | CVSS ${formatScore(finding.cvss_score)} | ${finding.asset_id === null ? 'none' : finding.asset_id} | ${finding.verdict === null ? 'none' : finding.verdict}`;
}

// Render the diff as Markdown (the default format): header lines,
// one section per non-empty category in added / removed / changed
// order, then the unchanged count. An empty diff renders the counts
// line plus "No differences." — it is not an error.
function renderReportDiffMarkdown(diff) {
  const lines = [];
  lines.push(`Report Diff — ${diff.report_id}`);
  lines.push(`Old report: ${diff.old_report_id}`);
  lines.push(`New report: ${diff.new_report_id}`);
  lines.push(`Counts: ${diff.counts.added} added, ${diff.counts.removed} removed, ${diff.counts.changed} changed, ${diff.counts.unchanged} unchanged`);
  lines.push('');
  if (diff.counts.added === 0 && diff.counts.removed === 0 && diff.counts.changed === 0) {
    lines.push('No differences.');
    return `${lines.join('\n')}\n`;
  }
  if (diff.added.length > 0) {
    lines.push(`Added (${diff.added.length}):`);
    diff.added.forEach((finding) => lines.push(formatDiffRow(finding)));
    lines.push('');
  }
  if (diff.removed.length > 0) {
    lines.push(`Removed (${diff.removed.length}):`);
    diff.removed.forEach((finding) => lines.push(formatDiffRow(finding)));
    lines.push('');
  }
  if (diff.changed.length > 0) {
    lines.push(`Changed (${diff.changed.length}):`);
    diff.changed.forEach((entry) => {
      lines.push(`- ${entry.finding_id}:`);
      entry.changes.forEach((change) => {
        lines.push(`  - ${change.field}: ${formatChangeValue(change.field, change.old)} -> ${formatChangeValue(change.field, change.new)}`);
      });
    });
    lines.push('');
  }
  lines.push(`Unchanged: ${diff.counts.unchanged} finding${diff.counts.unchanged === 1 ? '' : 's'}.`);
  return `${lines.join('\n')}\n`;
}

// Render the diff as JSON: the diff object itself, pretty-printed.
// The key order is fixed (report_id, old/new, added, removed,
// changed, counts) and every list is sorted, so the same pair of
// report sets renders byte-identically.
function renderReportDiffJson(diff) {
  return `${JSON.stringify(diff, null, 2)}\n`;
}

module.exports = {
  COMPARED_FIELDS,
  summarizeFinding,
  validateReportShape,
  readReportFile,
  deriveDiffReportId,
  diffReports,
  renderReportDiffMarkdown,
  renderReportDiffJson,
};
