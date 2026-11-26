// Report stats (round 74, Phase 7): a compact triage summary of one
// JSON report file — "how bad is this report?" without reading the
// whole thing.
//
// Every report command so far renders, compares, validates, merges,
// splits, filters, or anonymizes a report. Stats answers the
// question an operator asks first: total findings, counts by
// severity, counts by rule verdict, counts by finding class, the
// CVSS distribution, and the top assets by finding count — plus the
// generator's own executive summary line.
//
// Inputs are read with readReportFile from report-diff.js (round
// 64): bounded (10 MiB, depth 100), symlinked input refused.
// Shape failures therefore carry REPORT_DIFF_* codes — the reader
// is shared, not re-implemented.
//
// Counting reuses the existing helpers, never re-implements them:
// severity counts come from the generator's exported
// `countBySeverity` (round 72), the summary line from the
// generator's exported `executiveSummary` (round 72), and the
// verdict of each finding from round 67's `validateOneFinding`
// (valid / false_positive / needs_evidence — the RULE verdict, NOT
// the stored `validation_status` workflow state; round 70 proved
// grouping by that field is useless, since every
// generator-produced finding carries `validated`). A finding that
// fails the strict generator check inside `validateOneFinding`
// is counted in a fourth verdict bucket, `error`: it is a
// structural defect of the file, but stats never fails on content
// — it is counted, and the exit code stays 0.
//
// Class is the finding's `vulnerability_type` field (the schema's
// name for it), resolved through the validator's evidence-class
// resolution (round 78): `resolveEvidenceClass` maps the type
// string to its canonical class id (equals-or-contains against
// the class's match list, first match in file order wins), so
// 'SQLi', 'Blind SQL Injection', and 'SQL Injection' all count
// as 'sql injection', and 'auth bypass via JWT' counts as
// 'authentication bypass' (file order beats the later JWT
// class). The resolution needs no evidence — it matches the
// type string alone. When no class matches, the class is the
// normalized raw string (trim + lowercase, as before); a
// finding with no usable `vulnerability_type` counts under
// `unknown`. One documented gap: the matcher does not
// normalize hyphens, so 'sql-injection' matches neither 'sql
// injection' nor 'sqli' and stays its own class. Classes are
// ordered by count descending, ties by class name ascending, so
// the output is deterministic for any input order.
//
// CVSS: a finding is `scored` when `cvss_score` is a finite
// number, `unscored` otherwise. Min / max / mean are computed
// over the scored findings only; the mean is rounded to 2
// decimals. With no scored findings all three are null. Stats
// never re-scores: it reads the file's `cvss_score` as-is.
//
// Top assets: the 5 assets with the most findings, ordered by
// count descending, ties by `asset_id` string order. Findings
// with no usable `asset_id` are excluded from this ranking
// (documented — the ranking is not a partition of `total`).
//
// Exit rule: exit 0 whenever the file parses — even an
// all-false-positive report, even a report full of `error`
// findings. Stats is a summary view, not a verdict. Only a
// failure to read or parse the file fails, with a named error.
//
// Deliberately NOT done here: no re-scoring, no verdicting
// beyond the rule verdict, no per-finding listing (that is the
// report itself), no writing — stats is read-only, and a low
// total does not mean the target is clean, only that the report
// is small.
//
// Reconciliation (round 77): the summary line comes from the
// generator's `executiveSummary`, which counts only findings
// with a VALID severity (`countBySeverity(...).total`), while
// `total` counts every finding in the file. On a
// generator-produced file the two agree, but on a hand-edited
// file they can diverge — a finding with an invalid or missing
// severity is counted in `total` and in no severity bucket.
// Stats reconciles the two numbers visibly instead of hiding
// the gap: `invalid_severity` is the count of findings the
// summary does not count (findings.length minus the severity
// counts' total), and it is carried in both renderers — but
// ONLY when it is greater than zero, so generator-produced
// outputs stay byte-identical. Every such finding also lands in
// the `error` verdict bucket (the strict check rejects an
// invalid or missing severity), so nothing is hidden twice
// over; the reconciliation line just names the gap the summary
// and the total would otherwise show.
//
// Error findings (round 79): a finding whose rule verdict is
// `error` failed the generator's strict check, so its DECLARED
// values are not trusted — a hand-edited file can declare any
// severity or CVSS score, and letting those declarations into
// the triage numbers would pollute them (round 74's F5: an
// error finding with a declared Critical severity and a 9.8
// score used to inflate the critical count and the CVSS mean).
// Error findings are therefore counted in `total` and in the
// verdict counts (as before — they are findings, not nothing),
// but they contribute to NO breakdown: no severity bucket, no
// CVSS distribution, no class count, no top-asset count. They
// are named instead by `error_findings`, carried in both
// renderers but ONLY when greater than zero, so
// generator-produced outputs stay byte-identical.
//
// Interaction of the two named gaps (round 79): `invalid_severity`
// counts findings with an invalid or missing severity,
// regardless of verdict; `error_findings` counts findings with
// verdict `error`, regardless of severity validity. Every
// invalid-severity finding is `error` (the strict check rejects
// an invalid or missing severity), so invalid_severity is always
// a subset of error_findings — but error_findings can be larger
// (an error finding with a valid declared severity, e.g. a band
// mismatch). The two numbers are independent facts, not a
// partition: a finding that is both counts toward both. The
// severity buckets sum to total minus error_findings (every
// non-error finding has a valid severity, so none is skipped),
// and the summary's number is findings.length minus
// invalid_severity (the generator's summary counts declared
// valid severity, error findings included — its wording is the
// generator's and is not changed here, so on a hand-edited
// file the summary can name more criticals than the Severity
// line shows; the Error findings line explains why).
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { countBySeverity, executiveSummary } = require('./generator');
const { readReportFile } = require('./report-diff');
const { validateOneFinding } = require('./validate');
const { resolveEvidenceClass } = require('../analysis/validator');
const { programOf } = require('./merge');

// Verdict buckets in the order they render (the three rule
// verdicts first, then `error` — a structural defect, counted
// but never failing the exit code).
const VERDICT_VALUES = ['valid', 'false_positive', 'needs_evidence', 'error'];

// Severity buckets in the order they render (the generator's
// SEVERITY_ORDER).
const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'informational'];

// Top-asset list length.
const TOP_ASSETS = 5;

function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// Round to 2 decimals as a JSON number (4.86 stays 4.86, not
// "4.86").
function round2(value) {
  return Number(value.toFixed(2));
}

// The finding's class: resolved through the validator's
// evidence-class resolution (round 78) — the canonical class id
// for the finding's `vulnerability_type`. The resolution needs
// no evidence (it matches the type string alone, so stats never
// requires evidence to classify); when no class matches, or the
// knowledge file failed to load (the resolver then returns
// null), fall back to the normalized raw string (trim +
// lowercase, as before). Missing or blank counts under
// `unknown`.
function classOf(finding) {
  const raw = finding.vulnerability_type == null ? '' : String(finding.vulnerability_type).trim().toLowerCase();
  if (raw === '') return 'unknown';
  const entry = resolveEvidenceClass(finding.vulnerability_type);
  return entry ? entry.id : raw;
}

// Compute the stats of a parsed report object (report_id +
// findings array; shape-checked first, so a malformed report
// throws instead of returning stats). Returns the stats object:
// {
//   report_id, summary, total,
//   invalid_severity,  // ONLY when > 0: findings with an invalid
//                      // or missing severity — counted in `total`
//                      // and in no severity bucket, and not in
//                      // the summary's number (round 77)
//   error_findings,    // ONLY when > 0: findings with verdict
//                      // `error` — counted in `total` and in the
//                      // verdict counts, but in NO breakdown
//                      // (round 79)
//   by_severity: { critical, high, medium, low, informational },
//   by_verdict: { valid, false_positive, needs_evidence, error },
//   by_class: [{ class, count }]  // count desc, class asc
//   cvss: { scored, unscored, min, max, mean },  // nulls when unscored
//   top_assets: [{ asset_id, count }]  // top 5, count desc, id asc
// }
// Deterministic: every list is sorted, so the same finding set in
// any file order stats to byte-identical output.
function computeReportStats(report) {
  const findings = report.findings;
  // Round 79: the verdict is computed once per finding and kept
  // — an `error` finding's declared values are not trusted, so
  // the breakdowns below run over the non-error findings only.
  // The verdict counts themselves run over ALL findings.
  const verdicts = findings.map((finding) => validateOneFinding(finding).status);
  const errorFindings = verdicts.filter((status) => status === 'error').length;
  const nonError = findings.filter((_, index) => verdicts[index] !== 'error');
  // The summary line and invalid_severity keep their round-77
  // definitions over ALL findings (the generator's summary
  // counts declared valid severity, error findings included —
  // its wording is not changed here).
  const severityCounts = countBySeverity(findings);
  const bySeverity = {};
  const nonErrorSeverity = countBySeverity(nonError);
  for (const severity of SEVERITY_VALUES) bySeverity[severity] = nonErrorSeverity[severity];
  // Round 77: the summary counts only findings with a valid
  // severity (severityCounts.total); `total` counts every
  // finding. The gap is named, not hidden — but the key is
  // present only when the gap exists, so generator-produced
  // outputs stay byte-identical.
  const invalidSeverity = findings.length - severityCounts.total;
  const byVerdict = {};
  for (const verdict of VERDICT_VALUES) byVerdict[verdict] = 0;
  for (const status of verdicts) byVerdict[status] += 1;
  const classCounts = new Map();
  const assetCounts = new Map();
  let scored = 0;
  let unscored = 0;
  let min = null;
  let max = null;
  let sum = 0;
  // Round 79: only non-error findings feed the breakdowns — an
  // error finding's declared severity, CVSS score, class, and
  // asset are untrusted and must not pollute the triage numbers.
  for (const finding of nonError) {
    const cls = classOf(finding);
    classCounts.set(cls, (classCounts.get(cls) || 0) + 1);
    if (typeof finding.asset_id === 'string' && finding.asset_id.trim() !== '') {
      const assetId = finding.asset_id.trim();
      assetCounts.set(assetId, (assetCounts.get(assetId) || 0) + 1);
    }
    if (typeof finding.cvss_score === 'number' && Number.isFinite(finding.cvss_score)) {
      scored += 1;
      sum += finding.cvss_score;
      if (min === null || finding.cvss_score < min) min = finding.cvss_score;
      if (max === null || finding.cvss_score > max) max = finding.cvss_score;
    } else {
      unscored += 1;
    }
  }
  const byClass = [...classCounts.entries()]
    .map(([cls, count]) => ({ class: cls, count }))
    .sort((a, b) => b.count - a.count || compareStrings(a.class, b.class));
  const topAssets = [...assetCounts.entries()]
    .map(([assetId, count]) => ({ asset_id: assetId, count }))
    .sort((a, b) => b.count - a.count || compareStrings(a.asset_id, b.asset_id))
    .slice(0, TOP_ASSETS);
  // Key order is fixed: invalid_severity sits right after total
  // when present (round 77), then error_findings (round 79);
  // both are omitted entirely when zero so generator-produced
  // stats stay byte-identical.
  const stats = {
    report_id: report.report_id,
    summary: executiveSummary(severityCounts, programOf(report)),
    total: findings.length,
  };
  if (invalidSeverity > 0) stats.invalid_severity = invalidSeverity;
  if (errorFindings > 0) stats.error_findings = errorFindings;
  stats.by_severity = bySeverity;
  stats.by_verdict = byVerdict;
  stats.by_class = byClass;
  stats.cvss = {
    scored,
    unscored,
    min,
    max,
    mean: scored === 0 ? null : round2(sum / scored),
  };
  stats.top_assets = topAssets;
  return stats;
}

// Render the stats as text (the default): the header line, the
// executive summary line, then one line per section. Deterministic:
// every list is sorted.
function renderReportStatsText(stats) {
  const lines = [];
  lines.push(`Report Stats — ${stats.report_id}`);
  lines.push(stats.summary);
  // Round 77: when findings exist that the summary does not
  // count (invalid severity), the Total line says so visibly —
  // the parenthetical reconciles the summary's number with the
  // total. When there are none, the line is unchanged, so
  // generator-produced output stays byte-identical.
  if (stats.invalid_severity > 0) {
    const counted = stats.total - stats.invalid_severity;
    lines.push(`Total: ${stats.total} finding${stats.total === 1 ? '' : 's'} (${counted} counted in summary, ${stats.invalid_severity} invalid severity)`);
  } else {
    lines.push(`Total: ${stats.total} finding${stats.total === 1 ? '' : 's'}`);
  }
  // Round 79: error findings are named on their own line — they
  // are counted in `total` and in the verdict counts, but they
  // contribute to no breakdown below (their declared values are
  // untrusted). The line appears only when the count is greater
  // than zero, so generator-produced output stays byte-identical.
  if (stats.error_findings > 0) {
    lines.push(`Error findings: ${stats.error_findings} (not counted in severity, CVSS, class, or top assets)`);
  }
  const severity = stats.by_severity;
  lines.push(`Severity: ${SEVERITY_VALUES.map((value) => `${value} ${severity[value]}`).join(', ')}`);
  const verdict = stats.by_verdict;
  lines.push(`Verdict: ${VERDICT_VALUES.map((value) => `${value} ${verdict[value]}`).join(', ')}`);
  if (stats.by_class.length === 0) {
    lines.push('Class: none');
  } else {
    lines.push(`Class: ${stats.by_class.map((entry) => `${entry.class} ${entry.count}`).join(', ')}`);
  }
  if (stats.cvss.scored === 0) {
    lines.push(`CVSS: 0 scored, ${stats.cvss.unscored} unscored; no scored findings`);
  } else {
    lines.push(`CVSS: ${stats.cvss.scored} scored, ${stats.cvss.unscored} unscored; min ${stats.cvss.min}, max ${stats.cvss.max}, mean ${stats.cvss.mean.toFixed(2)}`);
  }
  if (stats.top_assets.length === 0) {
    lines.push('Top assets: none');
  } else {
    lines.push('Top assets:');
    stats.top_assets.forEach((entry) => lines.push(`- ${entry.asset_id}: ${entry.count}`));
  }
  return `${lines.join('\n')}\n`;
}

// Render the stats as JSON: the stats object itself,
// pretty-printed. The key order is fixed (report_id, summary,
// total, invalid_severity when present, error_findings when
// present, by_severity, by_verdict, by_class, cvss, top_assets)
// and every list is sorted, so the same report stats to
// byte-identical output.
function renderReportStatsJson(stats) {
  return `${JSON.stringify(stats, null, 2)}\n`;
}

module.exports = {
  VERDICT_VALUES,
  SEVERITY_VALUES,
  TOP_ASSETS,
  classOf,
  computeReportStats,
  renderReportStatsText,
  renderReportStatsJson,
  readReportFile,
};
