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
- `invalid_severity` — the count of findings with a severity
  outside the schema (invalid string or missing field): `total`
  minus the sum of the severity buckets. It is exactly the gap
  between the summary's number and `total` (round 77 — this
  closes the divergence documented in round 74's F5, where the
  two numbers sat next to each other with no explanation).
  The field is present only when it is greater than zero, in
  both formats, so generator-produced output stays
  byte-identical. Every such finding also lands in the `error`
  verdict bucket (the strict check rejects an invalid or
  missing severity).
- `error_findings` — the count of findings whose rule verdict
  is `error` (they failed the strict generator check: missing
  required field, invalid severity, severity/CVSS band
  mismatch, or a bad vector/score). They are counted in
  `total` and in the verdict counts, but they contribute to NO
  breakdown: no severity bucket, no CVSS distribution, no
  class count, no top-asset count — their declared values are
  not trusted (round 79 — this closes the pollution
  documented in round 74's F5, where an error finding with a
  declared Critical severity and a 9.8 score inflated the
  critical count and the CVSS mean). The field is present only
  when it is greater than zero, in both formats, so
  generator-produced output stays byte-identical. Interaction
  with `invalid_severity`: the two count different things and
  are independent, not a partition — `invalid_severity` counts
  findings with an invalid or missing severity regardless of
  verdict, `error_findings` counts verdict-`error` findings
  regardless of severity validity. Every invalid-severity
  finding is `error`, so `invalid_severity` is always a subset
  of `error_findings`; `error_findings` can be larger (an error
  finding with a valid declared severity, e.g. a band
  mismatch). A finding that is both counts toward both. The
  severity buckets sum to `total` minus `error_findings`
  (every non-error finding has a valid severity).
- `by_severity` — counts per severity from the generator's
  exported `countBySeverity`, computed over the NON-ERROR
  findings only (round 79). A finding with a severity outside
  the schema is counted in `total` but in no severity bucket
  (and is an `error` verdict — see below); an `error` finding
  with a valid declared severity is likewise in no bucket —
  its declared severity is not trusted.
- `by_verdict` — counts per RULE verdict from round 67's
  `validateOneFinding`: `valid`, `false_positive`,
  `needs_evidence`, plus a fourth bucket, `error`, for findings
  that fail the strict generator check inside
  `validateOneFinding`. The verdict is the rule verdict, NOT the
  stored `validation_status` workflow state — round 70 proved
  grouping by that field is useless, since every
  generator-produced finding carries `validated`.
- `by_class` — counts per finding class, where the class is
  the finding's `vulnerability_type` field (the schema's name
  for it) resolved through the validator's evidence-class
  resolution (`resolveEvidenceClass` in
  `src/analysis/validator.js`, round 78): the type string is
  matched equals-or-contains against each class's match list
  in `knowledge/evidence-checklists.json`, first match in file
  order wins, and the count carries the class's canonical id —
  so `SQLi`, `Blind SQL Injection`, and `SQL Injection` all
  count as `sql injection`, and `auth bypass via JWT` counts as
  `authentication bypass` (the auth-bypass class precedes the
  JWT class in file order). The resolution needs no evidence —
  it matches the type string alone. When no class matches, the
  class is the normalized raw string (trim + lowercase, as
  before); a finding with a missing or blank
  `vulnerability_type` counts under `unknown`. One documented
  gap: the matcher does not normalize hyphens, so
  `sql-injection` matches neither `sql injection` nor `sqli`
  and stays its own class. This closes the raw-string
  limitation from round 74's F5 (two spellings of one class
  were counted separately). Ordered by count descending, ties
  by class name ascending. `error` findings are not counted
  in any class (round 79). One consequence: the `unknown`
  class is unreachable through stats — any finding that would
  map to it (a missing or blank `vulnerability_type`) is an
  `error` finding, because the type is a required schema
  field; `classOf` still returns `unknown` for direct callers.
- `cvss` — `scored` (NON-ERROR findings whose `cvss_score` is
  a finite number), `unscored` (all other non-error findings),
  and `min` / `max` / `mean` over the scored findings only;
  the mean is rounded to 2 decimals. With no scored findings
  all three are null. Stats never re-scores: it reads the
  file's `cvss_score` as-is. `error` findings contribute
  nothing here (round 79) — a declared 9.8 or an out-of-range
  11 on a defective finding must not move the mean.
- `top_assets` — the 5 assets with the most findings, ordered
  by count descending, ties by `asset_id` string order.
  Findings with no usable `asset_id` are excluded from this
  ranking (documented — the ranking is not a partition of
  `total`). `error` findings are not counted in the ranking
  (round 79).

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

When findings with an invalid severity exist, the Total line
reconciles the summary's number with the total visibly:

```text
Total: <total> findings (<counted> counted in summary, <invalid> invalid severity)
```

where `<counted>` is the summary's number (the sum of the
severity buckets) and `<invalid>` is `invalid_severity`. The
two always add up to `<total>` — the reconciliation is
arithmetic, not prose. When there are no invalid-severity
findings the line is the plain form above, so
generator-produced output is byte-identical with or without
the reconciliation.

When `error` findings exist, a line of its own names them,
right after the Total line:

```text
Error findings: <error> (not counted in severity, CVSS, class, or top assets)
```

It appears only when the count is greater than zero, so
generator-produced output is byte-identical with or without
it. Note the summary line above it still counts the errors'
DECLARED severities (the generator's wording — it is not
changed here), so on a hand-edited file the summary can name
more criticals than the Severity line below shows; the Error
findings line is the explanation for that gap.

An empty report renders every count at zero, `Class: none`,
`CVSS: 0 scored, 0 unscored; no scored findings`, and
`Top assets: none` — it is not an error.

`--json` renders the stats object itself, pretty-printed, with
the fixed key order `report_id`, `summary`, `total`,
`invalid_severity` (only when greater than zero),
`error_findings` (only when greater than zero),
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
to report and the operator's job to fix. What the bucket
does change is the breakdowns: an `error` finding's declared
values are excluded from the severity, CVSS, class, and
top-asset counts (round 79), and the exclusion is named by
`error_findings` rather than hidden.
