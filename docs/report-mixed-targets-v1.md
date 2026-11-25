# Mixed-target reports v1 (round 49, 2026-11-26)

## Decision

A report covering findings from more than one distinct `target_id`
is **refused by default** (`REPORT_MIXED_TARGETS_REFUSED`) and
renders only when the operator opts in explicitly with
`--allow-mixed-targets` (generator option `allowMixedTargets`).
This closes the open policy question from
[report-grouping-v1](report-grouping-v1.md) (split, tag, or refuse)
with "refuse by default, tag + group with opt-in".

Why refuse by default: the pre-round-49 generator rendered mixed
input silently and put only the first finding's `target_id` into
JSON `target_id`, dropping every other target without a trace — a
report that names one target while containing another target's
findings misattributes them. A mixed-target report is only ever
produced by an operator who asked for it by name.

## Behavior

- **Default refusal.** After validation, the generator collects the
  distinct trimmed `target_id`s (sorted ascending). More than one
  distinct target and no opt-in → throw
  `REPORT_MIXED_TARGETS_REFUSED`, naming the target count and every
  target, and telling the operator the opt-in flag. Nothing is
  written: `generateReport` produces output in memory only, and the
  CLI writes the output file only after generation succeeds, so a
  refused report can never leave a half-written file behind. The
  check runs after validation, so a missing `target_id` still fails
  first as a missing required field. It runs before the template
  branch, so a template request over mixed input is refused as
  mixed-target (a template request over a same-target pair still
  fails as a template: one finding per report).
- **Opt-in grouping.** With the flag, the report groups by target
  first, then by asset within each target (reusing
  `groupFindingsByAsset` from round 42). Order is deterministic:
  `target_id` ascending (plain string order, never locale), then
  `asset_id` ascending, then severity (critical first), then
  `finding_id`. The finding number stays global across targets.
  The same findings in any input order produce byte-identical
  output in all three formats.
- **Header.** The report states the full target list in its header
  in every format: Markdown adds `This report covers multiple
  targets: <t1>, <t2>.` after the executive summary, then a
  `## Target: <id>` section per target with the asset sections as
  `### Asset:` subsections; HTML adds the same sentence as a
  paragraph and `<h2>Target:` headings with `<h3>Asset:`
  subsections; JSON adds `target_ids` (sorted array),
  `mixed_targets: true`, and `target_id` per group.
- **JSON `target_id`.** `schemas/report.schema.json` still requires
  `target_id` (string). In a multi-target report it holds the first
  target in sorted order — the same value the single-target path
  carries — and the schema documents that; `target_ids` is the
  authoritative list. A consumer that reads only `target_id` sees a
  real target, and `mixed_targets: true` next to it says the report
  is not a single-target report.
- **Platform templates.** Immunefi and Code4rena render one finding
  per report, so they can never be mixed-target: a template request
  over mixed input is refused by the mixed-target check before the
  template branch is reached. Template JSON keeps its flat shape
  (no `groups`, no `target_ids`).
- **Single-target output is unchanged.** When there is exactly one
  target, no target heading or line is added in any format: the
  golden hashes in `tests/report-html.test.js` (Markdown
  `df1c6adc…`, JSON `82e08ebb…`, captured round 44) still pass, and
  single-target JSON carries no `target_ids` / `mixed_targets` /
  per-group `target_id`.

## What is NOT implemented

- No splitting into one report per target (the operator who wants
  separate reports generates one per target).
- No fuzzy or semantic cross-target matching: grouping is by exact
  `target_id` string (trimmed). Two spellings of the same target
  are two targets.
- No cross-target dedup: the exact-key and semantic dedup passes
  run before grouping and already merge duplicates; the mixed-target
  grouping never merges findings across targets.
- No `session_id` handling for mixed input: `session_id` still
  comes from the first finding in grouped order, as in the
  single-target path.

## Implementation

- `src/report/generator.js` — `groupFindingsByTarget(findings)`
  (exported): `[{ target_id, groups }]` with targets sorted
  ascending and asset groups in round-42 order; a missing, empty,
  whitespace-only, or non-string `target_id` maps to the
  `"unassigned"` target (defensive for direct callers —
  `generateReport` never sees it, because validation rejects a
  missing `target_id` first). `generateReport` computes the distinct
  sorted target ids, throws `REPORT_MIXED_TARGETS_REFUSED` unless
  `options.allowMixedTargets === true`, and passes
  `targetGroups` / `multiTarget` / `targetIds` to the renderers.
  `renderMarkdown` / `renderHtml` / `renderJson` branch on
  `multiTarget` and render exactly the pre-round-49 output when it
  is false.
- `bin/sentinel.js` — `--allow-mixed-targets` is a boolean flag
  (same pattern as drill `--recover`): stripped before
  `parseOptions`, passed as `allowMixedTargets` to
  `generateReport`. Usage lines updated.
- `schemas/report.schema.json` — `target_ids` (array of strings)
  and `mixed_targets` (boolean) properties; `target_id` per group
  (multi-target reports only); `groups` description updated.
- Tests: `tests/report-mixed-targets.test.js` (11 tests:
  `groupFindingsByTarget` order and unassigned bucket, default
  refusal naming both targets and the flag, opt-in Markdown / JSON /
  HTML grouping and headers, single-target golden hashes unchanged,
  determinism across input orderings in all three formats, template
  + mixed input refused as mixed-target, template + same-target
  pair refused as a template, CLI refusal with no output file, CLI
  opt-in rendering target sections). Fixture:
  `tests/fixtures/mixed-target-findings.json` (confirmed-full on
  `local-lab` + potential-full retargeted to `local-lab-2`).

## Remaining policy note

The opt-in exists for operators who consciously want a cross-target
report; the default stays single-target. Whether mixed-target
reports should ever be the default, or whether the skill should
split mixed input into one report per target automatically, remains
a user decision — this round deliberately does not change the
default.
