# Compact summary report format (round 61, Phase 7)

`sentinel report --format summary` renders a validated finding set
as a one-page plain-text executive summary — headline counts plus
the top findings — instead of the full report. It is the generic
template only: platform templates (Immunefi/Code4rena/HackerOne/
Bugcrowd) are Markdown-only, and requesting one with
`--format summary` fails cleanly with a named error instead of
producing a half-templated file (`Template "<name>" renders
Markdown only; summary output uses the generic template.`).

## Why plain text

A summary is pasted into chat, email, or a ticket more often than
it is rendered. Plain text needs no renderer, and it keeps the
summary visually distinct from the full Markdown report so the two
are never confused. The renderer lives in
`src/report/summary.js` (`renderSummary`, `countByVerdict`,
`TOP_FINDINGS_LIMIT`); `src/report/generator.js` dispatches to it
and owns validation, grouping, and the mixed-target rule, so the
summary inherits all of those without re-implementing them.

## Layout

One compact page, in this exact order (field names as rendered):

| Line | Value |
| --- | --- |
| `Bug Bounty Report Summary — <program>` | Program name (default `Unnamed Program`) |
| `Report ID: RPT-<12 hex>` | Deterministic hash of program + sorted finding ids (same derivation as the other formats) |
| `Target: <id>` / `Targets: <a, b>` / `Target: not specified` | Single target, opt-in multi-target list (ascending), or no findings |
| `Session: <id>` | Only when the findings carry a session id (from the first finding in grouped order, the same source JSON uses); omitted otherwise |
| `Findings: N total (critical: a, high: b, medium: c, low: d, informational: e)` | Severity counts, same numbers as the Markdown summary table |
| `Verdicts: <verdict>: <n>, …` / `Verdicts: none` | Counts over the findings' `validation_status` values, ordered by count descending then name ascending; `none` for an empty set |
| `Highest severity: <severity>` / `none` | First severity band with a non-zero count, else `none` |
| `Top findings:` + rows | At most 10 rows, ordered by severity (critical first) then `finding_id`: `N. <finding_id> | <severity> | CVSS <score\|Not scored> | <asset_id> | <validation_status>` |
| `... and N more finding(s) (see the full report).` | Only when more than 10 findings exist |
| `AI verdicts (advisory): X of Y finding(s) carry/carries an AI verdict.` | How many findings carry an advisory `ai_verdict` (0 when no verifier is configured) |
| `See the full report for descriptions, steps, evidence, and references.` | Pointer to the full report |

An empty finding set renders the header lines with zero counts and
`No findings.` (exit 0). Every other format still requires at
least one finding.

No `--generated-at` is needed — like CSV (round 55), a summary
carries no report header beyond the counts — so summary output
never requires one, unlike JSON. The output is identical with and
without `--generated-at` (tested).

## Verdicts: what the counts actually count

The `Verdicts:` line counts the findings' `validation_status`
values as carried on the findings (e.g. `validated`,
`needs_review`). This is NOT the validator's rule verdict enum
(`valid` / `false_positive` / `needs_evidence`, see
`src/analysis/validator.js`) — the generator never computes rule
verdicts, so a summary cannot count them without lying about its
source. The line documents its source field by naming the values
it counts; a consumer that needs the rule verdicts should use the
validator directly.

## Determinism and interaction with the other rules

- The same finding set in any input order produces byte-identical
  output (grouping order is a pure function of the finding set,
  and the top-findings table re-sorts by severity then
  `finding_id`). Verified by test, including a reversed input
  order.
- Mixed-target input without `--allow-mixed-targets` is refused
  with the round-49 named error (`REPORT_MIXED_TARGETS_REFUSED`);
  with the flag, the `Targets:` line names all targets in
  ascending order.
- The report command has no `--json` flag: summary is a text
  format, and JSON output is `--format json`. A stray `--json`
  is refused as `Unknown option: --json`, cleanly, with no file
  written (tested at the CLI).
- Markdown, JSON, HTML, and CSV output are unchanged by this
  round: the same golden SHA-256 hashes pinned in
  `tests/report-html.test.js` and `tests/report-csv.test.js`
  are re-pinned in `tests/report-summary.test.js` (Markdown
  `df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779`,
  JSON
  `82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf`),
  and the CSV output is asserted byte-identical to the round-55
  expected text.
- One deliberate test-expectation change: the unknown-format
  error now lists five formats
  (`expected "markdown", "json", "html", "csv", or "summary"`),
  so the round-55 assertion in `tests/report-csv.test.js` was
  updated to the new message (same change, no behaviour change
  beyond the added format).

## Known limitations

- The summary carries headline numbers only: no descriptions,
  steps to reproduce, proof of concept, evidence, evidence
  checklist, impact, remediation, or references. It is a
  triage/briefing export, not a submission — use Markdown, HTML,
  or a platform template for the full report.
- The top-findings table shows at most 10 rows; the remainder is
  counted, not listed. The full report lists every finding.
- The `Verdicts:` line counts `validation_status`, not the
  validator's rule verdicts (see above).
- The `AI verdicts` line counts findings that carry an advisory
  verdict; it does not summarise what the verdicts say — the
  full report carries the advisory line per finding.
