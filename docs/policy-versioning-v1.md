# Policy versioning v1 (round 96, Phase 6)

`POLICY_VERSION` in `src/analysis/policies.js` names the F6
decision set the code enforces. The version tracks the
**decision set, not the enforcement code**: wiring an
existing decision into a new path, or adding a way to print
the version, does not bump it. A decision changes only by an
explicit user decision — never by a round's own judgment
call — and a decision change is a MAJOR bump with a
migration note.

## The scheme

`POLICY_VERSION` is `MAJOR.MINOR.PATCH`:

- **MAJOR** — a decision changed (a constant's value, or
  the addition/removal of a decision). Requires an explicit
  user decision naming the new rule, and a migration note in
  this doc: what changed, what reports produced under the old
  version still mean, and what an operator must do (usually
  nothing — old reports remain valid records of what was
  generated under the old version).
- **MINOR** — enforcement surface added without changing any
  decision: a decision wired into a new path, a new command
  that prints the policy, a new stderr note. The version
  does NOT bump for these — the decision set is unchanged —
  but they are recorded in the CHANGELOG and the round
  report, so the enforcement history is auditable.
- **PATCH** — documentation or test clarifications with no
  behavior change.

## Current version: 1.0.0

The v1 decision set, approved by the user on 2026-11-28
(~01:03 WIB, "Semua yang di daftar") and recorded in
`docs/policies-f6-v1.md`:

1. Semantic dedup stays `conservative`.
2. Rule-verdict false positives are `exclude-from-reports`
   (opt back in with `--include-false-positives`).
3. The AI verdict is advisory-only (`AI_VERDICT_OVERRIDE =
   false`).
4. Detection never auto-runs (`DETECTION_AUTO_RUN = false`).
5. Detectors stay synchronous (`DETECTOR_ASYNC = false`).

Round 96 added enforcement without changing any decision,
so the version stays 1.0.0: `enforceReportPolicies` wires
false-positive exclusion (first) and the conservative
semantic dedup pass (second, never across rule verdicts)
into `sentinel report` generation from raw findings, the
evidence-entry canonicalization learned the structured
evidence shape so the dedup rule applies to the AST
detector's findings too, and `sentinel policy` prints the
active version. None of that is a version bump — the
decisions are the same five.

## How the operator knows which version is active

- `sentinel policy` prints the version and the five
  decisions (text, or `--json` for the same summary as
  JSON). It is read-only and changes nothing.
- Every policy-enforced report run names the version on
  stderr: `Excluded N false_positive finding(s) from the
  report (policy F6 v1.0.0; ...)` and `Merged N duplicate
  finding(s) (policy F6 v1.0.0, conservative semantic
  dedup).` Stdout stays a clean report.
- `POLICY_VERSION` is a constant in
  `src/analysis/policies.js`, next to the five decision
  constants; `tests/policies-f6.test.js` pins the constants
  and `tests/policies-f6-enforcement.test.js` pins the
  version and the enforcement order.

## Migrating v1 to a future v2

When a user decision changes a decision, the round that
implements it must:

1. Bump `POLICY_VERSION` to `2.0.0` (MAJOR — the decision
   set changed).
2. Update the decision constant(s) in
   `src/analysis/policies.js` and the rationale in
   `docs/policies-f6-v1.md` (or its successor doc).
3. Add a migration note to this doc: the old rule, the new
   rule, what reports generated under v1 still mean, and
   whether an operator must do anything (the default
   answer is nothing — a stored report is a record of what
   was generated under the version that generated it, and
   `report validate` does not re-apply policy).
4. Update the tests that pin the old decision
   (`tests/policies-f6.test.js` and
   `tests/policies-f6-enforcement.test.js`) and the
   `sentinel policy` output, and record the change in the
   CHANGELOG.

What never happens silently: no flag, environment variable,
or config file can change a decision (there is none — a
code search for the decision names finds only the
constants, their tests, and their docs); no round may bump
the version without the user decision behind it; and no
decision change is ever smuggled in as an enforcement
fix — if a fix needs a decision to change, that is a
blocker to report, not a judgment call to make.

## Compatibility rules

- A report generated under v1 remains valid under v2's
  `report validate`: validation checks structure and the
  strict generator rules, not policy.
- `merged_from` on a merged finding is provenance, not
  substance: a `merged_from`-only difference is unchanged
  in `report-diff`.
- False-positive exclusion applies only at generation from
  raw findings (`sentinel report --finding/--findings`);
  stored reports keep whatever they already carry, and
  report transformations (merge, split, filter, render,
  anonymize) do not re-apply policy.
- `sentinel detect` output stays raw by design: detect is
  a finding source, and policy enforcement happens at
  report generation.
