# Flat CSV report export (round 55, Phase 7)

`sentinel report --format csv` renders the same validated, grouped
findings as the Markdown/JSON reports into one flat row per finding
plus a header row — a machine-readable export for spreadsheets and
triage tooling. It is the generic template only: platform templates
(Immunefi/Code4rena) are Markdown-only, and requesting one with
`--format csv` fails cleanly with a named error instead of producing
a half-templated file (`Template "<name>" renders Markdown only; CSV
output uses the generic template.`).

## Schema

One row per finding, header row first, LF line endings, trailing
newline. Column order is fixed:

| # | Column | Value |
| --- | --- | --- |
| 1 | `finding_id` | The finding's id, verbatim |
| 2 | `target_id` | The finding's target id, verbatim |
| 3 | `asset_id` | The finding's asset id, verbatim |
| 4 | `severity` | `critical` / `high` / `medium` / `low` / `informational` |
| 5 | `cvss_base_score` | Effective base score (declared, or computed from `cvss_vector`); empty when the finding carries no score at all |
| 6 | `cvss_temporal_score` | Declared or vector-derived temporal score; empty when absent |
| 7 | `cvss_environmental_score` | Declared or vector-derived environmental score; empty when absent |
| 8 | `verdict` | The finding's `validation_status` value (e.g. `validated`) |
| 9 | `evidence_checklist` | Compact summary: `present/total` plus the missing items joined with `; ` — `9/9 (complete)` when nothing is missing, `3/10 (missing: proof_of_concept; evidence; …)` otherwise |
| 10 | `merged_from` | Ids the finding was merged from, joined with `; `; empty for a singleton |
| 11 | `ai_verdict` | The advisory AI verdict line (same text as Markdown: `needs_evidence (confidence 0, source: stub) — no AI model configured`); empty when no verifier is configured |

Row order is the same grouped order as the flat JSON `findings`
array: targets ascending, then asset groups ascending, findings
inside a group by severity (critical first) then `finding_id`.
No `generated_at` is needed — a CSV row set carries no report
header beyond the column names — so CSV output never requires
`--generated-at`, unlike JSON.

An empty finding set renders the header row only (exit 0). Every
other format still requires at least one finding. The same
`--format csv` + template combination is refused for an empty set
as for a non-empty one — the refusal is about the format, not the
finding count.

## Escaping (the security rule for this format)

Every field goes through `escapeCsvField`
(`src/report/generator.js`), which implements RFC 4180: a field
containing a double quote, a comma, or a line break (`\n` or `\r`)
is wrapped in double quotes with inner quotes doubled; every other
field is written verbatim. A parse round-trip (tested with a minimal
RFC 4180 parser in `tests/report-csv.test.js`) recovers the exact
original values, including a finding id containing a quote and a
comma and an asset id containing a comma, a quote, and a newline.

Finding content is untrusted, so hostile values are rendered
verbatim as inert text — the file itself never executes anything:
`<script>`, `javascript:`, and formula-looking values (`=cmd`,
`+cmd`, `@cmd`) appear exactly as written. The generator does NOT
silently alter a value to defuse it (no leading-quote or tab
prefix): altering the data would make the export lie about the
finding, and the export's job is to carry the finding faithfully.

**Formula injection is a spreadsheet-consumer risk, not a file
risk.** A spreadsheet that interprets a cell starting with `=`,
`+`, or `@` as a formula can execute it on open — the CSV file
itself contains no formula, only text. Operators should therefore
treat every CSV export as untrusted input: open it with the
spreadsheet's data-import wizard (which lets the cell type be set
to text) or in a text editor, and never double-click-open a CSV
whose findings may carry attacker-controlled strings (asset ids,
finding ids, merged-from ids, AI-verdict reasons).

The precise tests (`tests/report-csv.test.js`): a hostile fixture
(finding id `FND-"X",1`, asset id `app, "quoted"<newline>newline`,
merged-from `=2+5+cmd|calc`) renders quoted per RFC 4180, the
formula string appears verbatim, no `<script` markup exists in the
file, and a parse round-trip recovers all three original values
exactly.

## Determinism and interaction with the other rules

- The same finding set in any input order produces byte-identical
  CSV (grouping order is a pure function of the finding set).
  Verified by test, including a reversed input order.
- Mixed-target input without `--allow-mixed-targets` is refused
  with the round-49 named error (`REPORT_MIXED_TARGETS_REFUSED`);
  with the flag, rows render for all targets in ascending target
  order.
- Markdown and JSON output are unchanged by this round: the same
  golden SHA-256 hashes pinned in `tests/report-html.test.js` are
  re-pinned in `tests/report-csv.test.js` (Markdown
  `df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779`,
  JSON
  `82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf`).

## Known limitations

- The CSV carries one row per finding and no report metadata: no
  report id, no program name, no generated time, no severity
  summary, no description, steps, proof of concept, impact,
  remediation, or references. It is a triage export, not a
  submission — use Markdown, HTML, or a platform template for the
  full report.
- The evidence checklist is a summary, not the full checklist: the
  class label and the per-item required/recommended marks are in
  Markdown/JSON/HTML only.
- The `verdict` column carries `validation_status`, not the
  validator's internal verdict enum — the two agree for validated
  findings, but the column name documents the source field so no
  consumer mistakes it for something else.
- Formula-injection protection is a consumer responsibility (see
  above); the generator deliberately does not rewrite values.
