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
// name for it), normalized the same way the validator normalizes
// it (trim + lowercase); a finding with no usable
// `vulnerability_type` counts under `unknown`. Classes are
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
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { countBySeverity, executiveSummary } = require('./generator');
const { readReportFile } = require('./report-diff');
const { validateOneFinding } = require('./validate');
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

// The finding's class: `vulnerability_type`, normalized the same
// way the validator normalizes it (trim + lowercase). Missing or
// blank counts under `unknown`.
function classOf(finding) {
  const raw = finding.vulnerability_type == null ? '' : String(finding.vulnerability_type).trim().toLowerCase();
  return raw === '' ? 'unknown' : raw;
}

// Compute the stats of a parsed report object (report_id +
// findings array; shape-checked first, so a malformed report
// throws instead of returning stats). Returns the stats object:
// {
//   report_id, summary, total,
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
  const severityCounts = countBySeverity(findings);
  const bySeverity = {};
  for (const severity of SEVERITY_VALUES) bySeverity[severity] = severityCounts[severity];
  const byVerdict = {};
  for (const verdict of VERDICT_VALUES) byVerdict[verdict] = 0;
  const classCounts = new Map();
  const assetCounts = new Map();
  let scored = 0;
  let unscored = 0;
  let min = null;
  let max = null;
  let sum = 0;
  for (const finding of findings) {
    byVerdict[validateOneFinding(finding).status] += 1;
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
  return {
    report_id: report.report_id,
    summary: executiveSummary(severityCounts, programOf(report)),
    total: findings.length,
    by_severity: bySeverity,
    by_verdict: byVerdict,
    by_class: byClass,
    cvss: {
      scored,
      unscored,
      min,
      max,
      mean: scored === 0 ? null : round2(sum / scored),
    },
    top_assets: topAssets,
  };
}

// Render the stats as text (the default): the header line, the
// executive summary line, then one line per section. Deterministic:
// every list is sorted.
function renderReportStatsText(stats) {
  const lines = [];
  lines.push(`Report Stats — ${stats.report_id}`);
  lines.push(stats.summary);
  lines.push(`Total: ${stats.total} finding${stats.total === 1 ? '' : 's'}`);
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
// total, by_severity, by_verdict, by_class, cvss, top_assets)
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
