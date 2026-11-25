# Detection stub v1

> **STUB — no real scanner is invoked, and nothing here performs detection
> against any target.** This is Phase 5 scaffolding only: it reshapes
> detector-style output that already exists (local JSON fixtures) into the
> shared finding record, so phases 6–7 have a stable shape to consume.
> There is no network access, no scanner binary, and no target involved.

## The normalized record

`src/detection/normalized-record.js` exports `normalizeRawFinding(raw, defaults)`,
a pure function (Node stdlib only, no I/O) that converts one raw
detector-style output object into a record conforming to
`schemas/finding.schema.json`. It returns a fresh object containing ONLY
fields defined in that schema; unknown keys in the raw input are dropped.

Rules:

- **Strict, never invents data.** A required string field that is missing
  or empty in `raw` throws an `Error` naming the field. `impact` and
  `remediation` are required by the finding schema, so a raw finding
  without them throws instead of being padded with invented text.
- **Severity.** If `raw` has a numeric `cvss_score` and no `severity`, the
  severity is derived from the `severity_ratings` bands in
  `knowledge/cvss/cvss-calc.json` (critical 9.0–10.0, high 7.0–8.9,
  medium 4.0–6.9, low 0.1–3.9, informational 0.0), using inclusive lower
  bounds so one-decimal scores in the gaps between band edges still land
  in exactly one band. If both are present and disagree, it throws an
  `Error` naming the mismatch. If neither is present, it throws
  (severity is required). A provided `severity` outside the schema enum
  also throws.
- **Defaults.** `validation_status` defaults to `'detected'`;
  `confidence` defaults to `'potential'`. `session_id`, `target_id`, and
  `asset_id` come from the `defaults` second argument when absent in
  `raw`, and it throws if still missing. A provided `confidence` /
  `validation_status` outside its schema enum throws.
- **Steps.** `steps_to_reproduce` accepts a string (split on newlines,
  trimmed, empty lines dropped) or an array of strings; anything else
  throws. An empty result after splitting/filtering throws.
- **Optional fields.** `cwe_id`, `cvss_vector`, `proof_of_concept`,
  `evidence`, `references`, `asset_url`, `cvss_score`, and `created_at`
  are copied through only when present (with a type check); they are
  never invented. `discovery_tool` is set from the raw's
  `discovery_tool` / `tool` value when present, and otherwise left absent
  — no fake tool name is ever written.

`severityForScore(score)` is also exported for reuse by other workers.

## The stub detector

`src/detection/stub-detector.js` exports
`runStubDetector(fixturePath, defaults)`. It reads a LOCAL fixture JSON
file shaped like a fake scanner output:

```json
{
  "tool": "stub-scanner-fixture",
  "results": [
    {
      "finding_id": "STUB-001",
      "title": "Reflected cross-site scripting in search parameter",
      "vulnerability_type": "Cross-Site Scripting",
      "description": "The search parameter reflects input without encoding.",
      "steps_to_reproduce": "1. Open the lab search page.\n2. Enter <script>alert(1)</script>.",
      "impact": "An attacker could execute script in a victim's browser session.",
      "remediation": "Encode all reflected output.",
      "cvss_score": 8.2
    }
  ]
}
```

It normalizes each result via `normalizeRawFinding` and returns:

```js
{
  tool: 'stub-scanner-fixture', // fixture tool name
  findings: [ /* normalized finding records */ ],
  skipped: 0,                   // results that failed normalization
  errors: []                    // one message per skipped result
}
```

- A single bad result does NOT abort the run: it is counted in `skipped`
  and its error message is recorded in `errors`.
- The fixture `tool` name is authoritative for the whole file and is
  recorded as `discovery_tool` on every finding it produces.
- A missing/unreadable fixture file, invalid JSON, a missing `tool`, or a
  missing/non-array `results` throws a clear `Error` naming the problem
  (the whole run cannot start without a well-formed fixture).

## Fixtures

- `tests/fixtures/stub-scanner-output.json` — tool
  `stub-scanner-fixture`, 2 valid raw results (one with string steps and
  a derived severity, one with array steps and an explicit matching
  severity) plus 1 deliberately bad result (missing `title`) that must be
  skipped.
- `tests/fixtures/stub-scanner-empty.json` — tool
  `stub-scanner-fixture`, empty `results` array.

Both fixtures are invented lab data. Nothing in them refers to a real
target, and no finding in them is a real vulnerability.

## Tests

`tests/detection-stub.test.js` covers the normalization happy path
(string steps, derived severity, defaults applied), each throw case
(missing required field, severity/CVSS mismatch, neither severity nor
score, bad steps type, unknown keys dropped), the stub detector
end-to-end on the fixture (2 good + 1 bad → 2 findings, skipped 1, error
recorded), the empty fixture, and a missing fixture file.
