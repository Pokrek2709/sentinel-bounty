# Finding Validation v1

`src/analysis/validator.js` is a pure, deterministic classifier over local
finding records. It implements the Phase 6 validation rules over fixtures
only: it reads the fields on a finding and returns a verdict. It makes no
model call, no network request, and no live verification of any kind.

The finding record is `schemas/finding.schema.json`. No second schema was
created. The severity bands come from
`knowledge/cvss/cvss-calc.json` `severity_ratings` (critical 9.0–10.0, high
7.0–8.9, medium 4.0–6.9, low 0.1–3.9, informational 0.0); the module
requires that JSON file directly so the bands stay the single source of
truth.

## API

```js
const { validateFinding, dedupeFindings, evidenceChecklist } = require('../src/analysis/validator');
```

All three functions are pure and never throw on malformed input.

## Verdict rules (`validateFinding`)

Returns `{ verdict, reasons }`, where `verdict` is `'valid'`,
`'false_positive'`, or `'needs_evidence'` and `reasons` is an array of
short explicit strings.

Precedence, in order:

1. **Not an object, or missing a required field** → `needs_evidence`,
   one `missing required field: <name>` reason per missing field, in
   schema order. Required fields are the thirteen in
   `schemas/finding.schema.json`: `finding_id`, `session_id`,
   `target_id`, `asset_id`, `title`, `vulnerability_type`, `severity`,
   `confidence`, `validation_status`, `description`,
   `steps_to_reproduce`, `impact`, `remediation`. "Missing" means the
   key is absent, `undefined`, or `null`. An empty string or empty array
   is present-but-empty, not missing; emptiness of the reproducibility
   triad is handled by rule 5 instead. The validator classifies; it
   does not reject input.
2. **confidence `false_positive`** → `false_positive` (reason:
   `confidence field says false_positive`). The analyst's own judgement
   wins over every other rule, including a severity/cvss mismatch — a
   dead finding's label is moot.
3. **confidence `needs_manual_review`** → `needs_evidence` (reason:
   `manual review required`).
4. **Unknown severity** (not one of the five band names: critical,
   high, medium, low, informational) → `needs_evidence` (reason:
   `unknown severity: <value>`). Checked after the confidence
   short-circuits above, so a `false_positive` still wins, and before
   the mismatch/evidence collection below: a non-band severity cannot
   be band-checked at all, and with an unbandable `cvss_score` it
   previously slipped through as `valid` — while the report generator
   rejects it outright.
5. **Severity/cvss mismatch, a present-but-invalid `cvss_score`, and
   missing reproducibility evidence are collected together.** A finding
   can report e.g. `severity/cvss mismatch` and `missing
   proof_of_concept`. The severity is never silently re-labelled. A
   present `cvss_score` that is not a finite number in [0, 10] is
   reported as `invalid cvss_score` on its own; it is not a *mismatch*,
   and a missing `cvss_score` (`undefined` or `null`) stays unchecked
   entirely.
6. **Reproducibility evidence** — a finding is fully evidenced when
   `proof_of_concept` is a non-empty string, `evidence` is a non-empty
   array, and `steps_to_reproduce` is a non-empty array. Each missing
   piece adds its own reason: `missing proof_of_concept`, `missing
   evidence`, `missing steps_to_reproduce`.
7. **confidence `confirmed`** with complete evidence and no mismatch →
   `valid`. Otherwise → `needs_evidence` with the reasons from rules
   5–6.
8. **confidence `potential`** with complete evidence and no mismatch →
   `valid`, with a reason noting it was potential but fully evidenced.
   Otherwise → `needs_evidence` with the reasons from rules 5–6.
9. **Any other confidence value** → `needs_evidence` (reason: `unknown
   confidence: <value>`).

Severity/cvss agreement is checked only when `severity` is one of the
five band names and `cvss_score` is a finite number. The score is
rounded to one decimal place first (CVSS 3.1 scores carry one decimal;
this also absorbs float noise such as `6.9000000001`). After rounding,
every score in [0, 10] falls in exactly one band. A missing or
non-numeric `cvss_score` is not a mismatch — `cvss_score` is optional
in the schema — but a present score that is not a finite number in
[0, 10] is reported as `invalid cvss_score` (rule 5 above), so it can
no longer slip through as `valid`.

## Deduplication (`dedupeFindings`)

Groups findings by root-cause key:

```text
vulnerability_type + '|' + asset_id + '|' + normalized first steps_to_reproduce line
```

Normalization of the first step trims, collapses runs of whitespace to
one space, and lowercases, so the same step written with different
spacing or casing still dedupes. The vulnerability type is a free-form
string in the schema (not an enum), so it is normalized the same way
(trim + lowercase). The `asset_id` is an identifier and stays exact
(case-sensitive): the same flaw on `lab-asset-01` vs `Lab-Asset-01`
does not dedupe. An empty or missing steps array uses
the literal key part `(no-steps)`. Missing `vulnerability_type` or
`asset_id` contributes an empty key part.

Returns `{ groups: [{ key, findings: [...] }], duplicates }`, where
`duplicates` is the count of findings beyond the first per group.
Groups appear in first-seen order; findings within a group keep input
order. A non-array input returns `{ groups: [], duplicates: 0 }`.

This is exact-key dedup only. It does not detect the same root cause
expressed in different words, different steps, or a different asset.

## Evidence checklist (`evidenceChecklist`)

Returns an array of `{ item, present }` for the seven checklist items,
always in this order, never omitting an item:

| item | present when |
| --- | --- |
| `proof_of_concept` | a non-empty string |
| `evidence` | a non-empty array |
| `steps_to_reproduce` | a non-empty array |
| `impact` | a non-empty string |
| `remediation` | a non-empty string |
| `cwe_id` | a non-empty string |
| `cvss_vector` | a non-empty string |

The item set does not vary by confidence: the same seven items are what
a reviewer checks whatever the finding claims. A malformed finding
reports all seven items as `present: false`.

## Fixtures

`tests/fixtures/` holds local finding fixtures (no live data):

- `confirmed-full.json` — confirmed, fully evidenced, severity/score
  agree (high / 7.5).
- `confirmed-missing-poc.json` — confirmed with evidence and steps but
  no PoC, no `cwe_id`, no `cvss_vector`.
- `potential.json` — potential with steps only.
- `potential-full.json` — potential but fully evidenced.
- `false-positive.json` — confidence `false_positive`.
- `severity-mismatch.json` — severity high with CVSS score 9.8
  (critical band).
- `duplicate-a.json` / `duplicate-b.json` — same root cause (same
  vulnerability type, asset, and first step modulo casing/spacing,
  including the type's own casing), different `finding_id`.

## What is NOT implemented yet

- No AI model call: verdicts come from the fixed rules above, not from
  a model judging the finding.
- No live verification: nothing is re-tested against a target, and no
  PoC is executed. `proof_of_concept` is checked for presence only, not
  for correctness.
- No semantic similarity dedup: dedup is exact root-cause-key matching
  only. Paraphrased steps, a reworded vulnerability type, or the same
  flaw on a different asset will not group together.
- No schema validation: the validator classifies records against the
  required-field list; it does not validate types, enums, or formats
  generally. Two exceptions are pinned by tests: an out-of-enum
  `severity` is flagged as `unknown severity`, and a present-but-invalid
  `cvss_score` is flagged as `invalid cvss_score` (both fail closed to
  `needs_evidence` instead of slipping through as `valid`).
- No persistence: verdicts are returned in memory. Storing a verdict
  back onto a finding record (e.g. `validation_status`) is a later
  phase's job.
