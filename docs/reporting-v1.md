# Reporting Engine v1

Phase 7 of Sentinel Bounty. Renders **validated** finding objects
(conforming to `schemas/finding.schema.json`) into a bug-bounty report.
Markdown by default, JSON with `--format json`.

## What is implemented

- `src/report/generator.js` — `generateReport(findings, options)`,
  `validateFinding(finding, index)`, `severityForScore(score)`,
  `countBySeverity(findings)`. Node stdlib only.
- CLI: `sentinel report --finding <finding.json>` or
  `sentinel report --findings <findings-array.json>`, with
  `[--out <report.md>] [--format markdown|json] [--generated-at <iso>] [--program <name>]`.
  Exactly one of `--finding` / `--findings` is required. `--out` omitted
  prints to stdout. Errors print a clear message and exit non-zero.
- Markdown output: title, generated line, a summary counts table
  (critical / high / medium / low / informational / total), then one
  section per finding with severity, CVSS and CWE line, affected
  component (`asset_id` / `asset_url`), reproduction steps, PoC reference
  and evidence, impact, remediation, and references. Findings render
  grouped by `asset_id` (see [report-grouping-v1](report-grouping-v1.md)):
  groups ordered by asset_id ascending, findings inside a group by
  severity then finding_id, with a global finding number across groups.
  A report covering more than one distinct `target_id` is refused by
  default (`REPORT_MIXED_TARGETS_REFUSED`); with
  `--allow-mixed-targets` it groups by target first, then by asset,
  and states the full target list in its header (see
  [report-mixed-targets-v1](report-mixed-targets-v1.md)).
- JSON output: an object conforming to `schemas/report.schema.json`
  (`report_id`, `target_id`, `program_name`, `generated_at`,
  `executive_summary`, `findings_summary` counts, `findings` array).
  Generic reports additionally carry a `groups` array (one entry per
  asset, with per-group counts and findings); the flat `findings`
  array follows the same grouped order. Platform-template JSON omits
  `groups`. A multi-target report (opted in with
  `--allow-mixed-targets`) additionally carries `target_ids` (sorted
  array), `mixed_targets: true`, and `target_id` per group;
  `target_id` itself holds the first target in sorted order.
  `report_id` is deterministic: `RPT-` plus the first 12 hex characters
  of a SHA-256 over the program name and the sorted finding ids, so the
  same findings under the same program always get the same id.
- Tests: `tests/report-generator.test.js` (determinism, every severity
  band boundary, mismatch and missing-field errors, summary counts, JSON
  shape, CLI end-to-end), `tests/report-grouping.test.js` (group
  order, within-group severity order, unassigned bucket, single-finding
  report, determinism across input orders, verdict stability, JSON
  shape, dedupe-before-grouping, template JSON exclusion), and
  `tests/report-mixed-targets.test.js` (default refusal, opt-in
  grouping and headers in all three formats, single-target golden
  hashes unchanged, determinism, template interaction, CLI refusal
  and opt-in). Fixtures in `tests/fixtures/`:
  `report-critical.json` (critical, full evidence), `report-medium.json`
  (medium, minimal but complete), `report-findings-array.json`
  (critical + medium + low), `report-incomplete.json` (deliberately
  missing `impact` and `remediation`, for the error test).

## Strict severity rule

Severity is derived from `cvss_score` using the bands in
`knowledge/cvss/cvss-calc.json` (`severity_ratings`), loaded at runtime —
critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9,
informational 0.0. Bands are matched on their lower bound: a score must
reach the next band's minimum to move up (3.95 stays low, 8.95 stays
high), which makes every listed boundary score map exactly onto its band.

If a finding carries both `severity` and `cvss_score` and they disagree,
generation **fails** with an error naming the finding, the declared
severity, the score, and the derived severity. This is deliberate: a
report must never carry a wrong severity label, and the generator refuses
to guess which of the two values is right. Fix the finding and re-run.

## Determinism rule

Same input produces byte-identical output. The generator never calls
`new Date()` or any other wall-clock source. `generated_at` comes from,
in order: the `--generated-at` flag (or `options.generatedAt`), the
newest `created_at` among the findings, or — if neither exists — the
report records "Not specified". JSON output additionally requires a
`generated_at` (the report schema mandates it as a date-time string), so
a JSON report without any available timestamp fails with a clear error
instead of inventing one.

## Completeness rule

A finding missing any field required by `schemas/finding.schema.json`
fails with an error naming the missing field(s), and generation stops
before any output is produced. The CLI generates the full report in
memory first and only writes `--out` after generation succeeds, so a
failed run can never leave a half-written report file behind.

## Input bounds and output safety (round 34)

Finding and target input files are bounded before they are read
(`src/policy/input-limits.js`): 10 MiB per file, at most 10,000
findings per `--findings` array, and at most 100 levels of JSON
nesting (checked with an explicit stack, never recursion, so the
check itself cannot overflow). Over-limit input fails with a clear
error and exit 1 instead of being rendered.

Output writes refuse a planted symlink at the exact output path
(`src/policy/safe-write.js`: lstat pre-check plus `O_NOFOLLOW` on
POSIX). The `--out` path itself is operator-chosen, so writing to an
absolute or `..` path is expected CLI behavior — but a symlink at
that path is never followed, so attacker-influenced report content
(a finding's description is untrusted data) cannot be redirected to
the link target. The same guard covers `check-env --output` and the
storage marker written by the environment checker.

Probed and found NOT vulnerable in the same round (regression tests
in `tests/cli-security-self-review.test.js`): prototype pollution via
parsed JSON (no `Object.assign` anywhere; all merges are spreads or
`Map`s; validator/generator/normalizer read named fields only);
argument injection (`spawn` runs with `shell: false` and fixed
allowlisted args; hostile metacharacters arrive literally); malicious
kill-switch state and audit-log lines (unparseable/wrong-shape state
is `KILL_SWITCH_STATE_CORRUPT`, hostile worker entries are dropped,
corrupt audit lines make `audit-health` report `AUDIT_LOG_CORRUPT`).
A symlinked state file is still read through — deliberately not
fixed: planting it already requires state-directory write access, in
which case the attacker could replace the state file outright, so
refusing the link would add no security.

## What is NOT implemented yet

- No live data: the engine renders only finding objects supplied as
  files. It does not fetch, scan, or query any target.
- No PDF output (markdown and JSON only).
- No report signing, submission, or platform upload.
- No multi-program aggregation by default: a report covering more
  than one distinct `target_id` is refused
  (`REPORT_MIXED_TARGETS_REFUSED`) unless the operator opts in with
  `--allow-mixed-targets`, in which case the report groups by target
  first, then by asset, and states the full target list in its
  header — see [report-mixed-targets-v1](report-mixed-targets-v1.md).
  `target_id` / `session_id` in JSON output come from the first
  finding in grouped order; in a multi-target report `target_id` is
  the first target in sorted order and `target_ids` lists all of
  them. There is no automatic splitting into one report per target.

## Platform templates

`sentinel report --finding <finding.json> --template immunefi|code4rena|hackerone|bugcrowd`
renders one finding into the section layout a platform expects (one
finding per report; `--findings` with a template fails cleanly). The
templates are data files in `knowledge/report-templates/`, loaded at
runtime — see [report-templates-v1](report-templates-v1.md).
