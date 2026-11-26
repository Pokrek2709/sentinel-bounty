# Report merge between two runs (round 68, Phase 7)

`sentinel report merge <a-report.json> <b-report.json>
[--out <merged.json>]` combines two JSON reports from two runs
(or two detectors, or two targets) into one valid round-31 JSON
report. An operator running two detectors previously had two
reports and no way to combine them except reading both.

The implementation lives in `src/report/merge.js`
(`mergeReports`, `canonicalFindingString`,
`firstDifferingField`, `programOf`, `pickGeneratedAt`); the
CLI handler is `runReportMerge` in `bin/sentinel.js`, reached
as a subcommand of `report` (the round-67 intercept pattern:
`report merge` is intercepted in `runReport` before
`parseOptions`, which would otherwise reject `merge` as an
unknown option).

## Inputs

Both inputs are JSON report files in the round-31 JSON report
format (an object with `report_id` and a `findings` array).
They are read with `readReportFile` from `report-diff.js`
(round 64): bounded (10 MiB, depth 100), a symlinked input is
refused. Shape failures therefore carry `REPORT_DIFF_*` codes
— the reader is shared, not re-implemented — and fail before
any output is produced, so a bad input can never leave a
half-written file behind. A duplicate `finding_id` inside one
input is refused by the same reader
(`REPORT_DIFF_DUPLICATE_FINDING_ID`).

## Merge rules

Findings are matched by `finding_id` only:

- **Identical** — present in both inputs with byte-identical
  content after canonicalization (see below): kept once.
- **Disjoint** — present in only one input: carried into the
  union.
- **Conflicting** — present in both with different content:
  the merge fails with `REPORT_MERGE_CONFLICTING_FINDING`,
  naming the `finding_id` and the first differing field (top-
  level keys in sorted order, with both values shown). A merge
  must never silently pick one version of a finding.

**Canonicalization.** Object keys are sorted recursively, so
two findings that differ only in key order compare identical.
`merged_from` arrays are sorted as well: `merged_from` is an
id set from the semantic dedup pass (round 48), not an ordered
list, so `["FND-X", "FND-Y"]` and `["FND-Y", "FND-X"]` are the
same provenance. Every other array keeps its order (steps,
evidence, references are ordered). A finding that carries
`merged_from` in one input but not the other is a conflict,
not an identity: the deduped finding is a different object
(it carries the merged provenance and the unioned evidence),
and the merge cannot know which version is authoritative.

**Program.** Both inputs must agree on `program_name` (a
missing or blank value normalizes to `Unnamed Program`, the
generator's own default). A disagreement fails with
`REPORT_MERGE_PROGRAM_MISMATCH`: merging reports from
different programs into one report would misattribute the
findings — the same fail-closed logic as the mixed-target
refusal (round 49). Targets are different: the merged report
is produced with `allowMixedTargets`, so differing targets
are carried as `target_ids` (sorted) + `mixed_targets: true`,
exactly the round-49 convention — merging two targets is a
stated use case, and the merge itself is the opt-in. The
session id comes from the first finding in grouped order,
the generator's own convention.

**Validation.** Every finding is checked with
`validateOneFinding` (round 67's path: the strict generator
check first, then the rule verdict). A finding that fails the
strict check is a `REPORT_MERGE_INVALID_FINDING` — a report
the current generator would never have produced cannot be
merged. This also means a report from an older generator
version whose findings fail the current strict check cannot
be merged; run `report validate` on it first. The verdict
itself (`valid` / `false_positive` / `needs_evidence`) is not
part of the merge decision: a `false_positive` finding merges
like any other — the merge combines reports, it does not
re-judge them.

**Empty and oversized.** A merged set of zero findings fails
with `REPORT_MERGE_EMPTY` (the generator cannot render an
empty JSON report). A merged set over `MAX_FINDINGS`
(10,000) fails with `REPORT_MERGE_TOO_MANY_FINDINGS` — the
same bound the rest of the system assumes.

**Generated time.** The merged report's `generated_at` is the
newer of the two inputs' `generated_at` values when either
carries a valid ISO timestamp, else the newest finding
`created_at`, else the merge fails with
`REPORT_MERGE_NO_GENERATED_AT`. A JSON report requires
`generated_at` and the merge never invents a timestamp from
the wall clock.

## Output

The merged report is rendered by `generateReport` itself
(format `'json'`), so its `report_id` is the generator's own
derivation (SHA-256 of program + sorted finding ids), and the
output is a valid round-31 JSON report by construction —
including `groups`, `findings_summary`, `executive_summary`,
and the mixed-target fields. The merged report for a given
finding set is byte-identical to a direct render of the same
set (pinned by a test).

**stdout / stderr contract.** The merged JSON goes to stdout
(pipeable) or to `--out` (safe-write, mode 0600, parent
directories created; with `--out` stdout carries only
`Merged report written to <path>`). The one-line merge
summary always goes to stderr, so stdout stays a clean
report:

```text
merged <N> findings from <a> + <b> (<shared> shared, 0 conflicts)
```

`<N>` is the merged finding count; `<a>` / `<b>` are the
input finding counts; `<shared>` counts findings present in
both inputs (identical, kept once). `0 conflicts` states the
conflict check ran and found none — any conflict is a fatal
error, so a successful merge always reports 0.

**Exit codes.** 0 on success. 1 on any named error (shape,
program mismatch, invalid finding, conflict, empty, too
many, no generated_at), with the message on stderr and no
output file written.

## Deliberately not done

- No re-scoring: scores and severities are carried verbatim
  from the inputs (the strict check only refuses a finding
  whose own severity disagrees with its own score).
- No dedup of near-identical findings: two findings with
  different ids stay separate even when they describe the
  same weakness — that is semantic dedup's job (round 48),
  not the merge's.
- No AI verdict: an `ai_verdict` carried by an input finding
  is preserved verbatim (the generator's spread), but the
  merge never runs a verifier.
- No re-rendering of the inputs: the merge never changes a
  finding's content; the only new values in the output are
  the merged `report_id`, `generated_at`, counts, groups,
  and summary, all computed by the generator.
