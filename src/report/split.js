// Report split (round 70, Phase 7): split one JSON report into one
// JSON report per severity or per verdict.
//
// An operator with one report containing findings of many severities
// has no way to hand the Criticals to one team and the Lows to
// another — they must copy the whole report or hand-edit JSON. The
// split answers that: one valid round-31 JSON report per group,
// each with its own recomputed report id, so each team gets a
// report that stands on its own (it passes `report validate`).
//
// Grouping keys:
//   - `severity`: the finding's `severity` field — the exact values
//     the generator uses (critical / high / medium / low /
//     informational, SEVERITY_ORDER). The strict check guarantees
//     every finding carries one of these, so the groups are
//     exactly that set, in that order.
//   - `verdict`: the RULE verdict from round 67's
//     `validateOneFinding` (valid / false_positive /
//     needs_evidence), NOT the stored `validation_status` field.
//     The distinction matters and is worth stating plainly: the
//     schema's `validation_status` enum is a workflow state
//     (detected / needs_review / validated / false_positive /
//     duplicate / rejected — see schemas/finding.schema.json),
//     and it does NOT take the values `valid` or
//     `needs_evidence`. Every generator-produced finding in the
//     fixture set carries `validation_status: "validated"`, so
//     grouping by the stored field would put every finding in
//     one "validated" group and the split would be useless. The
//     rule verdict is the triage split the operator actually
//     wants (which findings are confirmed valid, which need
//     evidence, which are false positives), and it is the same
//     path `report validate` (round 67), merge (round 68), and
//     anonymize (round 69) already use. A finding whose rule
//     verdict is `error` fails the split with
//     REPORT_SPLIT_INVALID_FINDING — a structural defect, same
//     as merge/anonymize — it is never silently dropped into a
//     group. Group order for verdicts is the FINDING_STATUSES
//     order (valid, false_positive, needs_evidence).
//
// Output: each group's file is a valid round-31 JSON report
// rendered by generateReport itself (format 'json',
// allowMixedTargets: true), so its report_id is the generator's
// own derivation (SHA-256 of program + sorted finding ids for
// THAT subset) and the output passes `report validate` with
// report_id_matches: true by construction. The file is named
// `<report-id>-<group>.json` (group slug lowercased, e.g.
// `RPT-0536be9278ec-critical.json`). Each output carries a
// `split` metadata block ({ from_report_id, group_by, group })
// appended last, so the render's own key order is untouched.
// Empty groups are NOT written. The session id comes from the
// first finding in grouped order and the target handling is the
// generator's own (a group spanning targets renders with
// target_ids + mixed_targets: true, the round-49 convention).
// A platform-template report (one finding, template set) keeps
// its template marker, the same passthrough anonymize uses.
//
// Inputs are read with readReportFile from report-diff.js (round
// 64): bounded (10 MiB, depth 100), symlinked input refused.
// Shape failures therefore carry REPORT_DIFF_* codes — the
// reader is shared, not re-implemented. An empty finding set
// fails with REPORT_SPLIT_EMPTY, and a report with no usable
// generated_at fails with REPORT_SPLIT_NO_GENERATED_AT (the
// input's generated_at, else the newest finding created_at
// within the group — generateReport never invents a timestamp
// from the wall clock, and neither does this module).
//
// The module never writes anything and never modifies its input
// object. The CLI (bin/sentinel.js runReportSplit) owns the
// --out-dir handling: creation (mode 0700), the non-empty guard,
// the inside-skill/state refusal, and the per-file safe writes
// (mode 0600). No network requests, no scanners, no live data.
// Node stdlib only.
'use strict';

const { generateReport, SEVERITY_ORDER, pickGeneratedAt } = require('./generator');
const { validateReportShape } = require('./report-diff');
const { validateOneFinding, FINDING_STATUSES } = require('./validate');
const { programOf } = require('./merge');

// The two grouping keys, in the order they are listed in the
// usage error. The verdict order is the FINDING_STATUSES order
// minus 'error' (an error finding fails the split, it is never
// a group).
const GROUP_BY_VALUES = ['severity', 'verdict'];
const VERDICT_ORDER = FINDING_STATUSES.filter((status) => status !== 'error');

// The generated_at for one group's report comes from the
// generator's shared pickGeneratedAt (round 73): the input
// report's own generated_at when valid, else the newest finding
// created_at within the group. The helper returns null when
// nothing is available; this module throws its OWN named error
// at the call site (a JSON report requires generated_at and the
// module never invents a timestamp from the wall clock).

// Split a parsed JSON report object (report_id + findings array;
// shape-checked first, so a malformed report throws instead of
// returning a partial result). Options: { groupBy } — 'severity'
// or 'verdict'. Returns:
// {
//   files: [{ group, fileName, report, count }],
//   summary: { total, from_report_id, group_by, groups: [{ group, count, fileName }] }
// }
// `files` is in deterministic group order (SEVERITY_ORDER for
// severity, VERDICT_ORDER for verdict); only non-empty groups
// appear. `report` is the group's JSON report as a string.
function splitReport(report, options = {}) {
  validateReportShape(report, 'report');
  const groupBy = options.groupBy;
  if (groupBy !== 'severity' && groupBy !== 'verdict') {
    throw new Error(
      `REPORT_SPLIT_INVALID_GROUP_BY: --by must be "severity" or "verdict" (got ${groupBy === undefined ? 'nothing' : JSON.stringify(groupBy)}).`,
    );
  }
  if (report.findings.length === 0) {
    throw new Error('REPORT_SPLIT_EMPTY: the report carries no findings; there is nothing to split.');
  }
  // Every finding is checked with round 67's path: the strict
  // generator check first (a throw is a structural defect),
  // then the rule verdict. The verdict is the grouping key for
  // --by verdict; for --by severity it is computed anyway so
  // the strict check cannot be skipped by choosing a key.
  const checked = report.findings.map((finding) => {
    const result = validateOneFinding(finding);
    if (result.status === 'error') {
      throw new Error(
        `REPORT_SPLIT_INVALID_FINDING: finding ${finding.finding_id} fails the strict check: ${result.reasons.join('; ')}`,
      );
    }
    return { finding, verdict: result.status };
  });
  const byGroup = new Map();
  for (const entry of checked) {
    const group = groupBy === 'severity' ? entry.finding.severity : entry.verdict;
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group).push(entry.finding);
  }
  const order = groupBy === 'severity' ? SEVERITY_ORDER : VERDICT_ORDER;
  const programName = programOf(report);
  const files = [];
  for (const group of order) {
    const groupFindings = byGroup.get(group);
    if (!groupFindings || groupFindings.length === 0) continue;
    const generatedAt = pickGeneratedAt([report], groupFindings);
    if (generatedAt === null) {
      throw new Error(
        'REPORT_SPLIT_NO_GENERATED_AT: the report carries no generated_at and no finding in this group carries created_at; '
        + 'cannot produce a JSON report (generated_at is required).',
      );
    }
    const renderOptions = {
      format: 'json',
      programName,
      generatedAt,
      allowMixedTargets: true,
    };
    // A platform-template report (one finding, template set)
    // keeps its template marker; anything else renders generic.
    // A multi-finding group with a template set is refused by
    // generateReport itself (a template renders one finding),
    // which is the correct fail-closed behaviour for a
    // hand-edited input.
    if (typeof report.template === 'string' && report.template.trim() !== '' && report.template.trim() !== 'generic') {
      renderOptions.template = report.template.trim();
    }
    const rendered = generateReport(groupFindings, renderOptions);
    const parsed = JSON.parse(rendered);
    parsed.split = {
      from_report_id: report.report_id,
      group_by: groupBy,
      group,
    };
    const fileName = `${parsed.report_id}-${String(group).toLowerCase()}.json`;
    files.push({
      group,
      fileName,
      report: `${JSON.stringify(parsed, null, 2)}\n`,
      count: groupFindings.length,
    });
  }
  return {
    files,
    summary: {
      total: report.findings.length,
      from_report_id: report.report_id,
      group_by: groupBy,
      groups: files.map((file) => ({ group: file.group, count: file.count, fileName: file.fileName })),
    },
  };
}

module.exports = {
  GROUP_BY_VALUES,
  VERDICT_ORDER,
  splitReport,
};
