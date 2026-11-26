# Report filter into a threshold subset (round 71, Phase 7)

`sentinel report filter <report.json> [--severity <level>]
[--verdict <rule-verdict>] [--out <filtered.json>]` keeps a
threshold subset of one JSON report — only High and above, only
valid verdicts, or both AND-combined — as one valid round-31 JSON
report with its own recomputed report id and a `filter` metadata
block, so the subset stands on its own (it passes `report
validate`). Split (round 70) groups by one key into files; the
filter is the single-report answer to the same triage question:
the Criticals for triage, the valid findings for a submission,
everything at or above Medium for a review meeting.

The implementation lives in `src/report/filter.js`
(`filterReport`); the CLI handler is `runReportFilter` in
`bin/sentinel.js`, reached as a subcommand of `report` (the
round-67 intercept pattern: `report filter` is intercepted in
`runReport` before `parseOptions`, which would otherwise
reject `filter` as an unknown option).

## Inputs

The input is one JSON report file in the round-31 JSON report
format (an object with `report_id` and a `findings` array).
It is read with `readReportFile` from `report-diff.js`
(round 64): bounded (10 MiB, depth 100), a symlinked input is
refused. Shape failures therefore carry `REPORT_DIFF_*` codes
— the reader is shared, not re-implemented — and fail before
any output is produced, so a bad input can never leave a
half-written file behind. A duplicate `finding_id` inside the
input is refused by the same reader
(`REPORT_DIFF_DUPLICATE_FINDING_ID`).

## Predicates

Both predicates are optional, but at least one is REQUIRED —
a filter with no predicate is just a copy, and is refused
with `REPORT_FILTER_NO_PREDICATE`. When both are given they
AND together: a finding is kept only when it satisfies both.

- **severity** — keep findings at or above this severity
  (`SEVERITY_ORDER`: critical > high > medium > low >
  informational; `--severity high` keeps critical and high).
  The level is matched case-insensitively (`HIGH` works, and
  the normalized lowercase value is what the `filter` block
  and the summary carry). An unknown level fails with
  `REPORT_FILTER_INVALID_SEVERITY`, naming all five values.
- **verdict** — keep findings whose RULE verdict from round
  67's `validateOneFinding` equals the given value: valid /
  false_positive / needs_evidence. This is NOT the stored
  `validation_status` field, and the distinction is worth
  stating plainly: the schema's `validation_status` enum is
  a workflow state (detected / needs_review / validated /
  false_positive / duplicate / rejected — see
  `schemas/finding.schema.json`), and it does NOT take the
  values `valid` or `needs_evidence`. Every
  generator-produced finding in the fixture set carries
  `validation_status: "validated"`, so filtering by the
  stored field would keep either everything or nothing and
  the filter would be useless — `--verdict validated` is
  refused with `REPORT_FILTER_INVALID_VERDICT`, naming the
  three rule verdicts, not silently treated as a match. The
  rule verdict is the triage split the operator actually
  wants (which findings are confirmed valid, which need
  evidence, which are false positives), and it is the same
  path `report validate` (round 67), merge (round 68),
  anonymize (round 69), and split (round 70) already use.
  A finding whose rule verdict is `error` fails the filter
  with `REPORT_FILTER_INVALID_FINDING` — a structural defect,
  same as split — it is never silently dropped.

**Validation.** Every finding is checked with
`validateOneFinding` (round 67's path: the strict generator
check first, then the rule verdict) before any filtering
happens — for `--severity` alone the verdict is computed
anyway, so the strict check cannot be skipped by choosing a
predicate. A report with no usable `generated_at` fails with
`REPORT_FILTER_NO_GENERATED_AT` (the input's `generated_at`,
else the newest finding `created_at` among the kept
findings — or among all source findings when the kept set is
empty — the filter never invents a timestamp from the wall
clock).

## Output

The kept findings are rendered by `generateReport` itself
(format `'json'`, `allowMixedTargets: true`), so the
`report_id` is the generator's own derivation (SHA-256 of
program + sorted finding ids for THAT subset) and the output
is a valid round-31 JSON report by construction — including
`groups`, `findings_summary`, `executive_summary`, and the
mixed-target fields (a kept set spanning targets renders
with `target_ids` + `mixed_targets: true`, the round-49
convention). The session id comes from the first finding in
grouped order, the generator's own convention. A
platform-template report (one finding, template set) keeps
its template marker, the same passthrough split uses; a
multi-finding kept set with a template set is refused by
`generateReport` itself, which is the correct fail-closed
behaviour for a hand-edited input.

The output carries a `filter` metadata block appended last
(so the render's own key order is untouched), with only the
predicates that were given:

```json
"filter": {
  "from_report_id": "RPT-3aeafa977190",
  "severity": "high",
  "verdict": "needs_evidence"
}
```

**Empty result.** An empty kept set is a VALID empty report
(`total` 0), not an error — the same rule as JSONL's empty
set (round 66). `generateReport` refuses an empty finding
set for JSON, so the empty report is built in `filter.js`
following `renderJson`'s shape: `report_id` from the
generator's own derivation for the empty set, `target_id`
from the source report (else the first target in sorted
order among the source findings, plus `target_ids` +
`mixed_targets: true` when the source spans targets),
`program_name`, `generated_at`, the executive summary in the
generator's own wording for zero counts, a zero
`findings_summary`, `findings: []`, the source `session_id`
when present, and the `filter` block. It passes `report
validate` with `report_id_matches: true`.

**stdout / stderr contract.** The filtered JSON goes to
stdout (pipeable) or `--out` (safe-write, mode 0600). The
one-line summary always goes to stderr, so stdout stays a
clean report:

```text
filtered 2 of 5 findings (severity >= high)
filtered 1 of 5 findings (verdict valid)
filtered 1 of 5 findings (severity >= high, verdict needs_evidence)
```

With `--out`, stdout names the file instead
(`Filtered report written to <path>`), and the summary still
goes to stderr.

**Exit codes.** 0 on success — including an empty result.
1 on any named error (shape, invalid finding, no predicate,
unknown severity/verdict, no generated_at), with the message
on stderr and no file written — the filter is computed fully
in memory first, so a validation failure can never leave a
half-written file behind.

The input file is never modified (read-only: bytes and
mtime unchanged, pinned by a test).

## Deliberately not done

- No re-scoring: scores and severities are carried verbatim
  from the input (the strict check only refuses a finding
  whose own severity disagrees with its own score).
- No filtering by arbitrary predicate: the predicates are
  exactly a severity threshold and a rule verdict. A
  `--where` style filter is a future round if the user asks
  for it.
- No grouping by the stored `validation_status` workflow
  state (see "Predicates" above — that filter would keep
  everything or nothing on generator-produced reports).
- No AI verdict: an `ai_verdict` carried by an input finding
  is preserved verbatim (the generator's spread), but the
  filter never runs a verifier.
- No claim about the filtered-out findings: filter is a
  subset view. A finding dropped by `--severity high` is not
  invalid, and a finding dropped by `--verdict valid` is not
  a false positive — it simply did not match the predicate.
  The only new values in the output are the recomputed
  `report_id`, counts, groups, summary, and the `filter`
  metadata block, all computed by the generator.
