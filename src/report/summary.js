// Compact summary report format (round 61, Phase 7): a one-page
// executive summary of a validated finding set, in plain text.
//
// Choice of format: plain text, not short Markdown. A summary is
// pasted into chat, email, or a ticket more often than it is
// rendered — plain text needs no renderer, and it keeps the summary
// visually distinct from the full Markdown report so the two are
// never confused. Every value here is a headline number or an id
// already present in the full report; nothing is invented.
//
// Contents (in order): program name + report id, target(s),
// session (only when the findings carry one), total findings with
// counts by severity, counts by verdict, highest severity, the top
// findings table (at most 10 rows, severity then finding_id, with a
// "+N more" line when truncated), the advisory AI-verdict count,
// and a pointer to the full report. No --generated-at: like CSV
// (round 55), a summary carries no report header beyond the counts,
// so it never requires one.
//
// Verdicts: the counts are over the findings' `validation_status`
// values as carried on the findings (e.g. `validated`), ordered by
// count descending then name ascending for determinism. This is NOT
// the validator's rule verdict enum (valid / false_positive /
// needs_evidence, see src/analysis/validator.js) — the generator
// never computes rule verdicts, so a summary cannot count them
// without lying about its source. The doc (docs/report-summary-v1.md)
// states the source field explicitly.
//
// Determinism: the same finding set in any input order produces
// byte-identical output — the caller passes findings already in the
// grouped order (see generateReport), and the top-findings table
// re-sorts by severity then finding_id, a pure function of the set.
// No wall-clock timestamp is ever generated here.
//
// What the summary deliberately omits: descriptions, steps to
// reproduce, proof of concept, evidence, evidence checklists,
// impact, remediation, and references. Those live in the full
// report only; the last line says so. An empty finding set renders
// the header lines with zero counts and "No findings." — it is not
// an error (unlike Markdown/JSON/HTML, which still require at
// least one finding).
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { SEVERITY_ORDER } = require('./generator');

const TOP_FINDINGS_LIMIT = 10;

function countByVerdict(findings) {
  const counts = new Map();
  for (const finding of findings) {
    const verdict = typeof finding.validation_status === 'string' && finding.validation_status !== ''
      ? finding.validation_status
      : 'unknown';
    counts.set(verdict, (counts.get(verdict) || 0) + 1);
  }
  // Deterministic order: count descending, then name ascending
  // (plain string order, never locale-dependent).
  return [...counts.entries()].sort((a, b) => {
    if (b[1] !== a[1]) return b[1] - a[1];
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    return 0;
  });
}

function formatTopFinding(finding, number) {
  const score = finding.cvss_score !== undefined && finding.cvss_score !== null
    ? String(finding.cvss_score)
    : 'Not scored';
  return `${number}. ${finding.finding_id} | ${finding.severity} | CVSS ${score} | ${finding.asset_id} | ${finding.validation_status}`;
}

// Render the summary. `orderedFindings` is the finding set in the
// grouped order (target, asset, severity, finding_id) — the
// top-findings table re-sorts it by severity then finding_id.
// `counts` is the countBySeverity result for the same set.
// `aiVerdictCount` is how many findings carry an advisory
// ai_verdict (formatAiVerdict !== null); the caller counts it.
// `sessionId` may be null (line omitted). `targetIds` is the sorted
// distinct target list; `multiTarget` marks the opt-in rendering.
function renderSummary({ reportId, programName, targetIds, multiTarget, sessionId, counts, orderedFindings, aiVerdictCount }) {
  const lines = [];
  lines.push(`Bug Bounty Report Summary — ${programName}`);
  lines.push(`Report ID: ${reportId}`);
  if (multiTarget) {
    lines.push(`Targets: ${targetIds.join(', ')}`);
  } else if (targetIds.length === 1) {
    lines.push(`Target: ${targetIds[0]}`);
  } else {
    lines.push('Target: not specified');
  }
  if (sessionId) {
    lines.push(`Session: ${sessionId}`);
  }
  const severityParts = SEVERITY_ORDER.map((severity) => `${severity}: ${counts[severity]}`).join(', ');
  lines.push(`Findings: ${counts.total} total (${severityParts})`);
  const verdictCounts = countByVerdict(orderedFindings);
  lines.push(verdictCounts.length === 0
    ? 'Verdicts: none'
    : `Verdicts: ${verdictCounts.map(([verdict, count]) => `${verdict}: ${count}`).join(', ')}`);
  const highest = SEVERITY_ORDER.find((severity) => counts[severity] > 0) || 'none';
  lines.push(`Highest severity: ${highest}`);
  lines.push('');
  if (orderedFindings.length === 0) {
    lines.push('No findings.');
    return `${lines.join('\n')}\n`;
  }
  lines.push('Top findings:');
  const ranked = [...orderedFindings].sort((a, b) => {
    const severityDelta = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDelta !== 0) return severityDelta;
    if (String(a.finding_id) < String(b.finding_id)) return -1;
    if (String(a.finding_id) > String(b.finding_id)) return 1;
    return 0;
  });
  const shown = ranked.slice(0, TOP_FINDINGS_LIMIT);
  shown.forEach((finding, index) => {
    lines.push(formatTopFinding(finding, index + 1));
  });
  const remaining = ranked.length - shown.length;
  if (remaining > 0) {
    lines.push(`... and ${remaining} more finding${remaining === 1 ? '' : 's'} (see the full report).`);
  }
  lines.push('');
  lines.push(`AI verdicts (advisory): ${aiVerdictCount} of ${orderedFindings.length} finding${orderedFindings.length === 1 ? ' carries' : 's carry'} an AI verdict.`);
  lines.push('');
  lines.push('See the full report for descriptions, steps, evidence, and references.');
  return `${lines.join('\n')}\n`;
}

module.exports = { renderSummary, countByVerdict, TOP_FINDINGS_LIMIT };
