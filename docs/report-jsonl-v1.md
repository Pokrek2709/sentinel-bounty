# Report — JSONL export (round 66, Phase 7)

`sentinel report --format jsonl` renders a validated finding set
as one JSON object per line: a summary line first, then one
finding per line. It is the streaming counterpart of the flat CSV
export (round 55): a pipeline consumer that wants to process
findings one at a time — `jq`, `grep`, a log shipper, a triage
import — reads lines without parsing a whole JSON document.

## Format

One JSON object per line, compact (`JSON.stringify`, no
indentation), each line terminated by `\n`; the output ends with
a trailing newline.

**Line 1 — the summary object:**

```json
{"type":"report-summary","report_id":"RPT-0536be9278ec","total":3,"counts_by_severity":{"critical":1,"high":0,"medium":1,"low":1,"informational":0},"counts_by_verdict":{"validated":3},"target_id":"TGT-LAB-001","session_id":"SES-REPORT-001"}
```

Fields, in fixed order:

- `type`: always `"report-summary"`.
- `report_id`: the deterministic report id (same function as the
  other formats: a hash of program name + sorted finding ids).
- `total`: number of findings.
- `counts_by_severity`: the `countBySeverity` result for the set
  (`critical`, `high`, `medium`, `low`, `informational`) — the
  same counts the Markdown summary table and the JSON
  `findings_summary` carry. Reused, never re-implemented.
- `counts_by_verdict`: verdict counts over the findings'
  `validation_status` values, count descending then name
  ascending (the `countByVerdict` helper from
  `src/report/summary.js`, shared with the summary format).
  This is the findings' carried status (e.g. `validated`), NOT
  the validator's rule verdict enum (`valid` /
  `false_positive` / `needs_evidence`) — the generator never
  computes rule verdicts, so a JSONL report cannot count them
  without lying about its source.
- `target_id`: the first target in sorted order (the same
  convention as the JSON format). Omitted when there is no
  target (the empty set).
- `session_id`: the session of the first finding in grouped
  order. Omitted when the findings carry none.
- `target_ids` + `mixed_targets: true`: only for opt-in
  multi-target reports (round 49), with `target_id` holding the
  first target in sorted order.

**Lines 2..N — one finding object per line**, in the same
grouped order as the Markdown/JSON formats (round 42 grouping:
target, then asset, then severity, then finding_id). Each line is
the same shape as the JSON format's `findings` entries: the
finding object plus its `evidence_checklist`, and its advisory
`ai_verdict` when a verifier ran (round 50). A consumer can
therefore take a JSONL line and a JSON `findings` entry for the
same finding and compare them field-for-field — the test suite
does exactly that.

## Rules

- **Deterministic.** The same finding set in any input order
  produces byte-identical output: findings arrive in grouped
  order, the summary line has fixed key order, and every line is
  `JSON.stringify` of a fixed-shape object.
- **No `--generated-at`.** Like CSV and summary (rounds 55/61),
  a JSONL export carries no report header beyond the summary
  line, so it never requires one; output is identical with and
  without `--generated-at`.
- **Empty set.** Renders the summary line only (total 0, all
  severity counts 0, empty verdict counts) — not an error, the
  same rule as CSV's header-only empty output. The other
  formats still require at least one finding.
- **Template + jsonl is refused**, like HTML, CSV, and summary:
  platform templates are Markdown-only.
- **`--json` is refused as an unknown option**: jsonl is its own
  format, and JSON output is `--format json`.
- **Mixed targets** follow the round-49 rule: refused by default
  (`REPORT_MIXED_TARGETS_REFUSED`), rendered with
  `--allow-mixed-targets`, with `target_ids` + `mixed_targets`
  on the summary line.
- **`--out`** writes through the safe-write rules (symlink
  refused, mode 0600); without it the export goes to stdout.

## What JSONL deliberately omits

Grouping sections, the evidence narrative, and any prose. A
consumer that needs the grouped view or the narrative reads the
full Markdown/JSON report. Each finding line is self-contained,
so a consumer can filter lines with `grep`/`jq` without reading
the summary line first.

## Tests

`tests/report-jsonl.test.js` (16 tests): the exact summary line
and the pinned full-output sha256 for the shared 3-finding
fixture; finding lines equal to the JSON format's finding entries
field-for-field, in grouped order; summary counts equal to the
Markdown counts; determinism across input orders; `--generated-at`
ignored; empty set (summary line only, report id
`RPT-11ba7f2d7f84`); `ai_verdict` present with the stub verifier
and absent without; template + jsonl refused (non-empty and
empty sets); mixed-target refusal and opt-in rendering; the
`renderJsonl` session-field omission; the updated unknown-format
error (now six formats); Markdown/JSON/HTML/CSV/summary goldens
unchanged. Two deliberate test-expectation changes: the
unknown-format error now lists six formats
(`expected "markdown", "json", "html", "csv", "summary", or
"jsonl"`), so the round-55 assertion in
`tests/report-csv.test.js` and the round-61 assertion in
`tests/report-summary.test.js` were updated to the new message
(same change, no behaviour change beyond the added format).

## Known limitations

- JSONL lines are not grouped into sections: a reader that wants
  the asset grouping must reconstruct it from the `asset_id`
  field on each line, or read the full JSON report's `groups`
  array.
- The summary line's verdict counts are over
  `validation_status`, not over the validator's rule verdicts
  (same limitation as the summary format, round 61).
