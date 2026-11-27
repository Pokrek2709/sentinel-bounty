# F6 policies v1 (round 90, Phase 6)

Three open policy questions from rounds 48, 50, and 67 —
plus the two detection-mode questions left open by the
detector rounds — decided by the user on 2026-11-28
(~01:03 WIB, "Semua yang di daftar") and implemented as
EXECUTABLE policy in `src/analysis/policies.js`, not prose.
Each decision below names what would change it: a future
explicit user decision — never a round's own judgment call.

## 1. Semantic dedup stays conservative — forever, until the user says otherwise

`semanticDedupeFindings` (`src/analysis/validator.js`,
round 48) merges only when ALL four hold: same normalized
`vulnerability_type`, same `asset_id`, same CVSS base
vector AND severity (or same severity with no vector on
either side), and at least one shared evidence entry. No
text-similarity merging of titles, descriptions, or steps;
no looser matching of any kind.

Rationale: dedup trades recall (fewer duplicate reports)
against the risk of hiding a genuinely distinct finding.
The conservative rule can only merge findings that already
agree on type, asset, score, and at least one piece of
shared evidence — the merge drops no information a
triage analyst needs, because the merged finding carries
the evidence union, the steps union, and `merged_from`.
Any loosening (same type + asset + vector without shared
evidence, or a similarity threshold) would need a new
user decision, because it changes what a report can hide.

Enforcement: the pass itself IS the conservative
implementation — there is no looser mode to enable.
`SEMANTIC_DEDUP_MODE = 'conservative'` in
`src/analysis/policies.js` is the pin tying this doc to
the code, and `tests/policies-f6.test.js` asserts the
constant and the non-merge cases (same type + asset +
vector WITHOUT shared evidence does not merge; different
severity does not merge).

## 2. False positives are excluded from generated reports — by default

A finding whose RULE verdict (round 67's
`validateOneFinding`: the strict generator check first,
then the rule verdict) is `false_positive` is excluded
from a report generated from raw findings
(`sentinel report --finding <finding.json>` /
`--findings <findings-array.json>`), unless the operator
passes `--include-false-positives`.

Rationale: a report is a claim that its findings are
worth a program's time. A finding the rule itself labels
false_positive has already been triaged out by the
pipeline's own evidence rules — shipping it in a report
is noise at best and a credibility loss at worst. The
finding is not deleted: it stays in the finding store,
`report validate` still counts it, and the operator can
always re-include it with the flag (for example to show a
program what was triaged out).

Scope, stated precisely because it matters:

- The exclusion applies ONLY at generation from raw
  findings (the `runReport` CLI path). `generateReport`
  itself is untouched.
- Report transformations (merge, split, filter, render,
  anonymize) keep whatever a stored report already
  carries — a stored report is a record of what was
  generated, and `report filter --verdict false_positive`
  exists precisely to select those findings.
- A finding that FAILS the strict check (status `error`)
  is never excluded: `generateReport` throws on it, as
  before. Exclusion must never mask a structural defect.
- If every finding is excluded, the command fails closed
  with `REPORT_ALL_FINDINGS_FALSE_POSITIVE` instead of
  rendering an empty report — the operator asked for a
  report, not a blank page.
- When findings are excluded, the count goes to stderr
  (`Excluded N false_positive finding(s) from the report
  (policy F6; use --include-false-positives to keep
  them).`), so stdout stays a clean report.

Enforcement: `excludeFalsePositives` in
`src/analysis/policies.js`, wired into `runReport` in
`bin/sentinel.js`; `FALSE_POSITIVE_REPORTING =
'exclude-from-reports'`. Tests: unit tests on the helper
(keeps valid / needs_evidence / error findings, excludes
false_positive) and CLI tests (excluded by default with
the stderr note, kept with the flag, all-excluded fails
with the named error).

## 3. The AI verdict NEVER overrides the rule verdict

The AI verdict stays advisory only, exactly as round 50
built it: `validateFinding` computes the rule verdict
first, then runs the verifier and adds `aiVerdict` +
`aiVerdictSource` to the result; `generateReport`
attaches `ai_verdict` after validation, so a verifier
can never change a verdict, a score, or the
mixed-target check. There is no downgrade-only override
and no upgrade: an AI model is not deterministic or
auditable the way the rule is, so it cannot change what
the report claims.

Rationale: the rule verdict is reproducible from the
finding alone — any reviewer can re-run it and get the
same answer. An AI verdict depends on a model, a prompt,
and a version; letting it change the verdict would make
the report's claims unreproducible and unauditable. The
AI verdict's job is to flag disagreement for a human to
look at, and the renderers already label it advisory in
every format.

Enforcement: `AI_VERDICT_OVERRIDE = false` in
`src/analysis/policies.js`; the wiring in
`src/analysis/validator.js` and
`src/report/generator.js` is unchanged (there is nothing
to change — the override never existed). Tests:
`tests/policies-f6.test.js` asserts the constant and pins
both disagreement directions (a `false_positive` AI
verdict on a valid finding, and a `valid` AI verdict on
an unevidenced finding, both leave the rule verdict
unchanged).

What would change it: a future user decision naming the
override rule (for example "only downgrade valid to
needs_evidence, never upgrade") plus the code to enforce
exactly that rule. A model choice is a separate open
decision (no model is plugged in today).

## 4. Detection never auto-runs

A detector runs only when the operator invokes
`sentinel detect` with an explicit `--detector`. No
watcher, no hook, no scheduled scan, no implicit trigger
from another command. `DETECTION_AUTO_RUN = false`.

Rationale: detection over operator-supplied text is safe
precisely because the operator chooses the text and the
moment. Auto-running it over anything the tool happens
to see would turn a deliberate action into ambient
surveillance of the operator's own files — and would
need its own scope, budget, and approval story first.

## 5. Detectors stay synchronous

A detector is a synchronous function
`detector(input, defaults) -> { findings, skipped,
errors }`, and a detector that returns a Promise is
refused (`DETECTOR_INVALID_RESULT`, enforced by
`validateDetectorResult` in `src/detection/detector.js`
since round 51). An async model call belongs to an
adapter that pre-computes findings before the run.
`DETECTOR_ASYNC = false`.

Rationale: the pipeline is synchronous and deterministic
— the same input always produces the same output in the
same process. Async detectors would make detection
order-, timing-, and network-dependent, and would need
timeouts, cancellation, and a different audit story.
That is a future architecture decision, not a flag.

## What this round does not decide

- No model is chosen for the AI verifier (still open).
- No detector is added or removed here (see
  `docs/detection-policy-v1.md` for the detector-set
  decision).
- No public-target execution is authorized (see
  `docs/public-http-adapter-v1.md` — the adapter exists
  behind the activation gate; nothing invokes it yet).
