// JSONL report format (round 66, Phase 7): one JSON object per
// line, for pipeline consumers that want to stream findings
// without parsing a whole JSON document.
//
// Line 1 is the summary object: { type: 'report-summary',
// report_id, target_id, session_id, total,
// counts_by_severity, counts_by_verdict }. `target_id` is omitted
// when there is no target (the empty set); `session_id` is omitted
// when the findings carry none; `target_ids` + `mixed_targets`
// appear only for opt-in multi-target reports (round 49), with
// `target_id` holding the first target in sorted order — the same
// convention as the JSON format. Lines 2..N are one finding object
// per line, in the same grouped order as the Markdown/JSON formats
// (round 42 grouping: target, then asset, then severity, then
// finding_id), each line the same shape as the JSON format's
// `findings` entries: the finding object plus its
// `evidence_checklist`, and its advisory `ai_verdict` when a
// verifier ran (round 50).
//
// Counts are reused, never re-implemented: `counts` is the
// countBySeverity result for the set (see src/report/generator.js),
// and the verdict counts come from countByVerdict in
// src/report/summary.js (over `validation_status`, count
// descending then name ascending). The verdict source is the same
// as the summary format's — the generator never computes rule
// verdicts, so a JSONL report cannot count them without lying
// about its source; the doc (docs/report-jsonl-v1.md) states the
// source field explicitly.
//
// Determinism: the same finding set in any input order produces
// byte-identical output — the caller passes findings already in
// grouped order (see generateReport), the summary line has fixed
// key order, and every line is JSON.stringify of a fixed-shape
// object. No --generated-at: like CSV and summary (rounds 55/61),
// a JSONL export carries no report header beyond the summary line,
// so it never requires one. An empty finding set renders the
// summary line only (total 0) — it is not an error, the same rule
// as CSV's header-only empty output.
//
// What JSONL deliberately omits: grouping sections, the evidence
// narrative, and any prose. A consumer that needs the grouped
// view or the narrative reads the full Markdown/JSON report;
// the doc links there. Each finding line is self-contained, so a
// consumer can filter lines with grep/jq without reading the
// summary line first.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { evidenceChecklistForClass } = require('../analysis/validator');
const { countByVerdict } = require('./summary');

// Render the JSONL export. `orderedFindings` is the finding set in
// the grouped order (target, asset, severity, finding_id).
// `counts` is the countBySeverity result for the same set.
// `targetId` may be null (empty set: the field is omitted).
// `sessionId` may be null (line field omitted). `targetIds` is the
// sorted distinct target list; `multiTarget` marks the opt-in
// rendering.
function renderJsonl({ reportId, targetId, sessionId, targetIds, multiTarget, counts, orderedFindings }) {
  const verdictCounts = {};
  for (const [verdict, count] of countByVerdict(orderedFindings)) {
    verdictCounts[verdict] = count;
  }
  const summary = {
    type: 'report-summary',
    report_id: reportId,
    total: counts.total,
    counts_by_severity: {
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      informational: counts.informational,
    },
    counts_by_verdict: verdictCounts,
  };
  if (targetId) summary.target_id = targetId;
  if (sessionId) summary.session_id = sessionId;
  if (multiTarget) {
    summary.target_ids = [...targetIds];
    summary.mixed_targets = true;
  }
  const lines = [JSON.stringify(summary)];
  for (const finding of orderedFindings) {
    lines.push(JSON.stringify({
      ...finding,
      evidence_checklist: evidenceChecklistForClass(finding),
    }));
  }
  return `${lines.join('\n')}\n`;
}

module.exports = { renderJsonl };
