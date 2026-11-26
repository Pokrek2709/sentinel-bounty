# Report stats — a compact triage summary (round 74, Phase 7)

`sentinel report stats <report.json> [--json]` prints a compact
triage summary of one JSON report file: total findings, counts by
severity, counts by rule verdict, counts by finding class, the
CVSS distribution, and the top 5 assets by finding count — plus
the generator's executive summary line. It answers the question
an operator asks first — "how bad is this report?" — without
reading the whole thing.

The implementation lives in `src/report/stats.js`
(`computeReportStats`, `renderReportStatsText`,
`renderReportStatsJson`, `classOf`); the CLI handler is
`runReportStats` in `bin/sentinel.js`.

## What is computed

Every field is deterministic: every list is sorted, so the same
finding set in any file order stats to byte-identical output in
both formats.

- `report_id` — the file's own report id, carried verbatim.
- `summary` — the generator's own executive summary line
  (`executiveSummary` over `countBySeverity([])`-style counts,
  round 72), with the program name from `programOf`
  (`program_name`, else `Unnamed Program`).
- `total` — the number of findings in the file's `findings`
  array. Every finding counts, including `error` verdicts.
- `by_severity` — counts per severity from the generator's
  exported `countBySeverity`. A finding with a severity outside
  the schema is counted in `total` but in no severity bucket
  (and is an `error` verdict — see below).
- `by_verdict` — counts per RULE verdict from round 67's
  `validateOneFinding`: `valid`, `false_positive`,
  `needs_evidence`, plus a fourth bucket, `error`, for findings
  that fail the strict generator check inside
  `validateOneFinding`. The verdict is the rule verdict, NOT the
  stored `validation_status` workflow state — round 70 proved
  grouping by that field is useless, since every
  generator-produced finding carries `validated`.
- `by_class` — counts per finding class, where the class is the
  finding's `vulnerability_type` field (the schema's name for
  it), normalized the same way the validator normalizes it
  (trim + lowercase). A finding with a missing or blank
  `vulnerability_type` counts under `unknown`. Ordered by count
  descending, ties by class name ascending.
- `cvss` — `scored` (findings whose `cvss_score` is a finite
  number), `unscored` (all others), and `min` / `max` / `mean`
  over the scored findings only; the mean is rounded to 2
  decimals. With no scored findings all three are null. Stats
  never re-scores: it reads the file's `cvss_score` as-is.
- `top_assets` — the 5 assets with the most findings, ordered
  by count descending, ties by `asset_id` string order.
  Findings with no usable `asset_id` are excluded from this
  ranking (documented — the ranking is not a partition of
  `total`).

## Output

Text (default) is a compact triage block:

```text
Report Stats — RPT-<id>
Program <name>: <total> validated finding(s) — <c> critical, <h> high, <m> medium, <l> low, <i> informational. Highest severity: <top>. All findings in this report were validated against the finding schema before rendering.
Total: <total> findings
Severity: critical <c>, high <h>, medium <m>, low <l>, informational <i>
Verdict: valid <v>, false_positive <f>, needs_evidence <n>, error <e>
Class: <class> <count>, ...
CVSS: <s> scored, <u> unscored; min <min>, max <max>, mean <mean>
Top assets:
- <asset>: <count>
...
```

An empty report renders every count at zero, `Class: none`,
`CVSS: 0 scored, 0 unscored; no scored findings`, and
`Top assets: none` — it is not an error.

`--json` renders the stats object itself, pretty-printed, with
the fixed key order `report_id`, `summary`, `total`,
`by_severity`, `by_verdict`, `by_class`, `cvss`, `top_assets`.

## Exit code and errors

Exit 0 whenever the file parses — even an all-false-positive
report, even a report full of `error` findings. Stats is a
summary view, not a verdict. Only a failure to read or parse
the file fails, with a named error. Inputs are read with
`readReportFile` from round 64's report-diff.js (bounded at
10 MiB, symlinked input refused), so shape failures carry
`REPORT_DIFF_*` codes — the reader is shared, not
re-implemented. Stats is read-only: it never writes anything.

## What stats deliberately does not do

No re-scoring, no verdicting beyond the rule verdict, no
per-finding listing (that is the report itself), and no claim
that a low total means the target is clean — a low total only
means the report is small. The `error` verdict bucket counts
structural defects; it does not fail the command, and it does
not repair them — that is `report validate`'s (round 67) job
to report and the operator's job to fix.
