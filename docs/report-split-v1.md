# Report split into per-group reports (round 70, Phase 7)

`sentinel report split <report.json> --by severity|verdict
--out-dir <dir> [--force]` splits one JSON report into one
valid round-31 JSON report per group — one file per non-empty
severity (or rule verdict) in `--out-dir`, each with its own
recomputed report id and a `split` metadata block, so each team
gets a report that stands on its own (it passes `report
validate`). An operator with one report containing findings of
many severities previously had to copy the whole report or
hand-edit JSON to hand the Criticals to one team and the Lows
to another.

The implementation lives in `src/report/split.js`
(`splitReport`); the CLI handler is `runReportSplit` in
`bin/sentinel.js`, reached as a subcommand of `report` (the
round-67 intercept pattern: `report split` is intercepted in
`runReport` before `parseOptions`, which would otherwise
reject `split` as an unknown option). The `--out-dir`
preparation (`prepareSplitOutDir`) and the inside-skill/state
guard (`pathOutsideSkillAndState`) live in `bin/sentinel.js`
next to the handler.

## Inputs

The input is one JSON report file in the round-31 JSON report
format (an object with `report_id` and a `findings` array).
It is read with `readReportFile` from `report-diff.js`
(round 64): bounded (10 MiB, depth 100), a symlinked input is
refused. Shape failures therefore carry `REPORT_DIFF_*` codes
— the reader is shared, not re-implemented — and fail before
any output is produced, so a bad input can never create the
output directory or leave a half-written file behind. A
duplicate `finding_id` inside the input is refused by the
same reader (`REPORT_DIFF_DUPLICATE_FINDING_ID`).

## Grouping keys

`--by` is required and takes exactly two values (anything
else fails with `REPORT_SPLIT_INVALID_GROUP_BY`, naming both
allowed values):

- **severity** — the finding's `severity` field: critical /
  high / medium / low / informational, in that order
  (`SEVERITY_ORDER`). The strict check guarantees every
  finding carries one of these, so the groups are exactly
  that set.
- **verdict** — the RULE verdict from round 67's
  `validateOneFinding`: valid / false_positive /
  needs_evidence, in that order. This is NOT the stored
  `validation_status` field, and the distinction is worth
  stating plainly: the schema's `validation_status` enum is
  a workflow state (detected / needs_review / validated /
  false_positive / duplicate / rejected — see
  `schemas/finding.schema.json`), and it does NOT take the
  values `valid` or `needs_evidence`. Every
  generator-produced finding in the fixture set carries
  `validation_status: "validated"`, so grouping by the
  stored field would put every finding in one "validated"
  group and the split would be useless. The rule verdict is
  the triage split the operator actually wants (which
  findings are confirmed valid, which need evidence, which
  are false positives), and it is the same path `report
  validate` (round 67), merge (round 68), and anonymize
  (round 69) already use. A finding whose rule verdict is
  `error` fails the split with `REPORT_SPLIT_INVALID_FINDING`
  — a structural defect, same as merge/anonymize — it is
  never silently dropped into a group.

**Validation.** Every finding is checked with
`validateOneFinding` (round 67's path: the strict generator
check first, then the rule verdict) before any grouping
happens — for `--by severity` the verdict is computed anyway,
so the strict check cannot be skipped by choosing a key. An
empty finding set fails with `REPORT_SPLIT_EMPTY`. A report
with no usable `generated_at` fails with
`REPORT_SPLIT_NO_GENERATED_AT` (the input's `generated_at`,
else the newest finding `created_at` within the group — the
split never invents a timestamp from the wall clock).

**Generated time.** Each group's `generated_at` is the input
report's own `generated_at` when it is a valid ISO timestamp,
else the newest finding `created_at` within that group. Two
groups can therefore carry different `generated_at` values
when the input has none and the groups' newest findings
differ — that is the generator's own fallback, applied per
group.

## Output

Each group's file is rendered by `generateReport` itself
(format `'json'`, `allowMixedTargets: true`), so its
`report_id` is the generator's own derivation (SHA-256 of
program + sorted finding ids for THAT subset) and the output
is a valid round-31 JSON report by construction — including
`groups`, `findings_summary`, `executive_summary`, and the
mixed-target fields (a group spanning targets renders with
`target_ids` + `mixed_targets: true`, the round-49
convention). The session id comes from the first finding in
grouped order, the generator's own convention. A
platform-template report (one finding, template set) keeps
its template marker, the same passthrough anonymize uses; a
multi-finding group with a template set is refused by
`generateReport` itself, which is the correct fail-closed
behaviour for a hand-edited input.

The file is named `<report-id>-<group>.json` (group slug
lowercased, e.g. `RPT-0536be9278ec-critical.json`), where
`<report-id>` is that group's own recomputed report id.
Each output carries a `split` metadata block appended last
(so the render's own key order is untouched):

```json
"split": {
  "from_report_id": "RPT-3aeafa977190",
  "group_by": "severity",
  "group": "critical"
}
```

Empty groups are NOT written: a report with no `false_positive`
findings produces no `*-false_positive.json` file.

**stdout / stderr contract.** stdout carries only the written
file paths, one per line (pipeable), in deterministic group
order. The per-group summary lines go to stderr:

```text
critical: 1 finding -> /tmp/out/RPT-f4341c7c301c-critical.json
medium: 1 finding -> /tmp/out/RPT-dfe972674eb8-medium.json
low: 1 finding -> /tmp/out/RPT-e70c87e276a9-low.json
```

**Exit codes.** 0 on success. 1 on any named error (shape,
invalid finding, unknown `--by`, empty, no generated_at,
out-dir guard), with the message on stderr and no files
written — the split is computed fully in memory first, so a
validation failure can never create the directory or leave a
half-written file behind. (A write failure mid-way — disk
full, permissions — can leave earlier files behind; that is
the same as every other command that writes more than one
file.)

## The --out-dir guard

`--out-dir` is required. The handler refuses it when it lies
inside the skill directory or the state directory
(`REPORT_SPLIT_OUT_DIR_FORBIDDEN`): a stray write inside the
skill could corrupt the installed skill, and one inside the
state dir could corrupt kill-switch/audit state. The guard
reuses the `path.relative` inside-check from
`pathOutsideSkill` in `bin/sentinel.js` (the same technique,
applied to both roots as `pathOutsideSkillAndState`); like
that helper it is a lexical check on the resolved path — a
symlinked parent directory is the operator's own path (the
safe-write philosophy, see `src/policy/safe-write.js`), so
it is not chased here.

The directory is created when missing (mode 0700, parents
included). An existing non-empty directory is refused
unless `--force` is passed
(`REPORT_SPLIT_OUT_DIR_NOT_EMPTY`); `--force` only
overwrites the files this split writes — other files already
in the directory are left alone. An existing path that is
not a directory is refused
(`REPORT_SPLIT_OUT_DIR_NOT_A_DIRECTORY`). Each written file
goes through `writeFileRefusingSymlink` (mode 0600), so a
planted symlink at a target file path is refused.

The input file is never modified (read-only: bytes and
mtime unchanged, pinned by a test).

## Deliberately not done

- No re-scoring: scores and severities are carried verbatim
  from the input (the strict check only refuses a finding
  whose own severity disagrees with its own score).
- No filtering by arbitrary predicate: the split keys are
  exactly severity and verdict. A `--where` style filter is
  a future round if the user asks for it.
- No grouping by the stored `validation_status` workflow
  state (see "Grouping keys" above — that split would be
  useless on generator-produced reports).
- No AI verdict: an `ai_verdict` carried by an input finding
  is preserved verbatim (the generator's spread), but the
  split never runs a verifier.
- No re-rendering of the input: the split never changes a
  finding's content; the only new values in the outputs are
  the per-group `report_id`, `generated_at`, counts, groups,
  summary, and the `split` metadata block, all computed by
  the generator.
