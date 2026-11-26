// Report merge (round 68, Phase 7): combine two JSON reports from
// two runs (or two detectors, or two targets) into one valid
// round-31 JSON report.
//
// An operator running two detectors has two reports and no way to
// combine them except reading both. The merge answers that: one
// report, one finding set, one report id.
//
// Matching: findings are matched by finding_id only. A finding
// present in both inputs with byte-identical content after
// canonicalization (see below) is kept once; a finding present in
// only one input is carried into the union; a finding present in
// both with DIFFERENT content is a conflict and fails the merge
// with REPORT_MERGE_CONFLICTING_FINDING naming the id and the
// first differing field — a merge must never silently pick one
// version of a finding.
//
// Canonicalization: object keys are sorted recursively, so two
// findings that differ only in key order compare identical.
// `merged_from` arrays are sorted as well: merged_from is an id
// set from the semantic dedup pass (round 48), not an ordered
// list, so [A, B] and [B, A] are the same provenance. Every other
// array keeps its order (steps, evidence, references are ordered).
//
// Program: both inputs must agree on program_name (a missing
// program_name normalizes to 'Unnamed Program', the generator's
// own default). A disagreement fails with
// REPORT_MERGE_PROGRAM_MISMATCH: merging reports from different
// programs into one report would misattribute the findings, the
// same fail-closed logic as the mixed-target refusal (round 49).
// Targets are different: the merged report is produced with
// allowMixedTargets, so differing targets are carried as
// target_ids + mixed_targets: true, exactly the round-49
// convention — merging two targets is a stated use case, and the
// merge itself is the opt-in. The session id comes from the
// first finding in grouped order, the generator's own convention.
//
// Report id: the merged report is rendered by generateReport
// itself (format 'json'), so the report_id is the generator's
// own derivation (SHA-256 of program + sorted finding ids) and
// the output is a valid round-31 JSON report by construction —
// including groups, counts, executive summary, and the
// mixed-target fields. The generated_at is the newer of the two
// inputs' generated_at values when either carries one, else the
// newest finding created_at, else the merge fails with
// REPORT_MERGE_NO_GENERATED_AT (a JSON report requires one).
// An empty merged set fails with REPORT_MERGE_EMPTY, and a
// merged set over MAX_FINDINGS fails with
// REPORT_MERGE_TOO_MANY_FINDINGS (the same bound the rest of the
// system assumes).
//
// Validation: each finding is checked with validateOneFinding
// (round 67's path: the strict generator check first, then the
// rule verdict). A finding that fails the strict check is a
// REPORT_MERGE_INVALID_FINDING — a report the current generator
// would never have produced cannot be merged. This also means a
// report from an older generator version whose findings fail the
// current strict check cannot be merged; run `report validate`
// on it first. The merge does NOT re-score, does NOT run
// semantic dedup (near-identical findings with different ids
// stay separate — that is round 48's job), and does NOT run an
// AI verifier.
//
// Inputs are read with readReportFile from report-diff.js (round
// 64): bounded (10 MiB, depth 100), symlinked input refused.
// Shape failures therefore carry REPORT_DIFF_* codes — the reader
// is shared, not re-implemented — and fail before any output is
// produced.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { generateReport } = require('./generator');
const { validateReportShape } = require('./report-diff');
const { validateOneFinding } = require('./validate');
const { MAX_FINDINGS } = require('../policy/input-limits');

// Truncate a value for an error message: findings can carry long
// descriptions, and the message only needs to name the field and
// show enough of each side to tell them apart.
function shortValue(value) {
  if (value === undefined) return '<missing>';
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

// Canonicalize a value for comparison: object keys sorted
// recursively; `merged_from` arrays sorted (an id set, not an
// ordered list); every other array keeps its order.
function canonicalize(value, key) {
  if (Array.isArray(value)) {
    if (key === 'merged_from') {
      return [...value].sort().map((item) => canonicalize(item, null));
    }
    return value.map((item) => canonicalize(item, null));
  }
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      out[k] = canonicalize(value[k], k);
    }
    return out;
  }
  return value;
}

// The canonical string form of a finding: two findings that
// differ only in key order (or merged_from order) stringify
// identically.
function canonicalFindingString(finding) {
  return JSON.stringify(canonicalize(finding, null));
}

// The first top-level field whose canonical values differ,
// keys in sorted order. Returns null when the findings are
// canonically identical. A key present in one finding and
// absent in the other counts as differing.
function firstDifferingField(a, b) {
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  for (const key of keys) {
    const oldValue = JSON.stringify(canonicalize(a[key], key));
    const newValue = JSON.stringify(canonicalize(b[key], key));
    if (oldValue !== newValue) {
      return { field: key, old: shortValue(a[key]), new: shortValue(b[key]) };
    }
  }
  return null;
}

// The program a report belongs to: a missing or blank
// program_name normalizes to 'Unnamed Program', the generator's
// own default, so an old report without the field still merges
// with a report under that name.
function programOf(report) {
  return typeof report.program_name === 'string' && report.program_name.trim() !== ''
    ? report.program_name.trim()
    : 'Unnamed Program';
}

// The generated_at for the merged report: the newer of the two
// inputs' generated_at values when either carries a valid ISO
// timestamp, else the newest finding created_at, else a named
// error — a JSON report requires generated_at and the merge
// never invents a timestamp from the wall clock.
function pickGeneratedAt(a, b, findings) {
  const candidates = [a.generated_at, b.generated_at]
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
  if (candidates.length > 0) {
    return candidates.sort((x, y) => Date.parse(x) - Date.parse(y)).at(-1);
  }
  const created = findings
    .map((finding) => finding.created_at)
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
  if (created.length > 0) {
    return created.sort((x, y) => Date.parse(x) - Date.parse(y)).at(-1);
  }
  throw new Error(
    'REPORT_MERGE_NO_GENERATED_AT: neither report carries generated_at and no finding carries created_at; '
    + 'cannot produce a JSON report (generated_at is required).',
  );
}

// Merge two parsed JSON report objects (report_id + findings
// array; shape-checked first, so a malformed report throws
// instead of returning a partial merge). Returns:
// {
//   report: <the merged JSON report, as a string>,
//   summary: { total, fromA, fromB, shared }
// }
// `shared` counts findings present in both inputs (identical,
// kept once); `total` is the merged finding count. The merged
// report is rendered by generateReport (format 'json'), so its
// report_id, groups, counts, and mixed-target fields are the
// generator's own — the merge never invents a report shape.
function mergeReports(a, b) {
  validateReportShape(a, 'first report');
  validateReportShape(b, 'second report');
  const programA = programOf(a);
  const programB = programOf(b);
  if (programA !== programB) {
    throw new Error(
      `REPORT_MERGE_PROGRAM_MISMATCH: reports disagree on program_name ("${programA}" vs "${programB}"); `
      + 'merging reports from different programs would misattribute the findings.',
    );
  }
  // Every finding is checked with round 67's path: the strict
  // generator check first (a throw is a structural defect), then
  // the rule verdict (counted, never fatal here — the verdict
  // itself is not part of the merge decision).
  for (const [report, label] of [[a, 'first report'], [b, 'second report']]) {
    for (const finding of report.findings) {
      const checked = validateOneFinding(finding);
      if (checked.status === 'error') {
        throw new Error(
          `REPORT_MERGE_INVALID_FINDING: finding ${finding.finding_id} in the ${label} fails the strict check: ${checked.reasons.join('; ')}`,
        );
      }
    }
  }
  const byId = new Map();
  for (const finding of a.findings) {
    byId.set(finding.finding_id, { finding, canonical: canonicalFindingString(finding) });
  }
  let shared = 0;
  for (const finding of b.findings) {
    const existing = byId.get(finding.finding_id);
    if (!existing) {
      byId.set(finding.finding_id, { finding, canonical: canonicalFindingString(finding) });
      continue;
    }
    const canonical = canonicalFindingString(finding);
    if (canonical === existing.canonical) {
      shared += 1;
      continue;
    }
    const differing = firstDifferingField(existing.finding, finding);
    throw new Error(
      `REPORT_MERGE_CONFLICTING_FINDING: finding_id "${finding.finding_id}" differs between the two reports `
      + `in field "${differing.field}" (first report: ${differing.old}; second report: ${differing.new}); `
      + 'a merge must never silently pick one version.',
    );
  }
  const merged = [...byId.values()].map((entry) => entry.finding);
  if (merged.length === 0) {
    throw new Error('REPORT_MERGE_EMPTY: both reports carry no findings; there is nothing to merge.');
  }
  if (merged.length > MAX_FINDINGS) {
    throw new Error(
      `REPORT_MERGE_TOO_MANY_FINDINGS: merged report would carry ${merged.length} findings (maximum ${MAX_FINDINGS}).`,
    );
  }
  const generatedAt = pickGeneratedAt(a, b, merged);
  const report = generateReport(merged, {
    format: 'json',
    programName: programA,
    generatedAt,
    allowMixedTargets: true,
  });
  return {
    report,
    summary: { total: merged.length, fromA: a.findings.length, fromB: b.findings.length, shared },
  };
}

module.exports = {
  canonicalFindingString,
  firstDifferingField,
  programOf,
  mergeReports,
};
