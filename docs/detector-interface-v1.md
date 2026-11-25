# Detector interface v1

> **INTERFACE ONLY — no real detector is built here, no scanner is
> invoked, and nothing here performs detection against any target.**
> This is Phase 5 scaffolding: it defines the contract a detector
> must satisfy so a real one can be plugged in later, makes the
> round-31 stub detector the reference implementation of that
> contract, and adds `sentinel detect` to run any conforming
> detector over a local input record. Fixtures only; no network
> access, no scanner binary, no target involved.

## The contract

`src/detection/detector.js` defines the interface. A detector is a
**synchronous** function:

```text
detector(input, defaults) -> { findings, skipped, errors }
```

- **`input`** is a raw detector-input record — the shape
  `normalizeRawFinding()` accepts (a raw finding-shaped object:
  `finding_id`, `title`, `vulnerability_type`, `description`,
  `steps_to_reproduce`, `impact`, `remediation`, `severity` or
  `cvss_score`, plus optional `evidence`, `references`, `cwe_id`,
  `cvss_vector`, `proof_of_concept`, …) — or a **batch** record
  `{ tool, results: [ <raw>, ... ] }` (the shape of the round-31
  stub fixtures).
- **`defaults`** is the `{ session_id, target_id, asset_id }`
  fallback object from `normalizeRawFinding()`. A detector that
  needs those ids takes them from `defaults`, never invents them.
- The return value is an **envelope**: `findings` is an array of
  NORMALIZED finding records (the shape the validator expects);
  `skipped` is a non-negative integer counting raw inputs that
  failed normalization; `errors` is an array of strings naming
  each skipped input's failure.

The function must return its result synchronously: a detector
that returns a Promise is refused as an invalid result
(`DETECTOR_INVALID_RESULT`), because the pipeline is synchronous
and deterministic — an async detector belongs to a future round or
to an adapter that pre-computes findings.

### What a detector MUST NOT do

- Make network requests.
- Write anywhere outside its own return value.
- Invent data. Normalization never invents a field, so a finding
  can only cite evidence present in the input record.

A detector that needs to drop a bad input counts it in `skipped`
with the error recorded, exactly as the stub does; it never aborts
the run over one bad record, and never pads a finding to make it
pass.

### Result validation

`validateDetectorResult(result)` validates the envelope and
returns a normalized copy: every finding is re-normalized through
`normalizeRawFinding()` (which proves it conforms to
`schemas/finding.schema.json` and drops any unknown fields the
detector smuggled in), `skipped` and `errors` are copied. It
throws `DETECTOR_INVALID_RESULT` on any violation: a Promise
return, a non-object, findings that are not an array, a finding
that fails re-normalization (naming its index), a skipped count
that is not a non-negative integer, or errors that are not an
array of strings.

## The stub detector (reference implementation)

`stubDetector(input, defaults)` in `src/detection/detector.js`
is the built-in stub and the reference implementation of the
contract: it normalizes its input and nothing else. A batch
record normalizes each result with the batch `tool` forced as
`discovery_tool` on every finding (the fixture-level tool is
authoritative, as in round 31); any other object is treated as a
single raw record. A non-object input throws
`DETECTOR_INVALID_INPUT`. Bad records are counted in `skipped`,
never thrown.

The shared batch normalizer `runDetectorOnRecords(records, tool,
defaults)` is used by both the stub detector and
`runStubDetector` (round 31), so both paths normalize
identically. `runStubDetector(fixturePath, defaults)` in
`src/detection/stub-detector.js` is unchanged in behavior — it
still reads and parses the fixture file itself (with its exact
round-31 error messages) and returns `{ tool, findings, skipped,
errors }`. See `docs/detection-stub-v1.md`.

## Running a detector without crashing the caller

`runDetector(detector, input, defaults)` runs a detector against
a defensive copy of the input (JSON round-trip for JSON-shaped
input; a shallow copy if that fails), so a buggy or hostile
detector cannot mutate the caller's record, and validates the
result. A detector that throws, or returns an invalid result, is
caught: the returned envelope is `findings: []`, `skipped: 0`,
the failure in `errors`, and the `error` field set — the caller
never crashes because of a detector.

## Loading a custom detector

`getDetector(spec, skillRoot)` resolves a specification:

- `undefined` / `null` → `null` (no detector configured).
- `'stub'` → the built-in stub detector, source `'stub'`.
- a function → the function itself, source `'inline'`.
- a string path → `loadDetector(path, skillRoot)`.
- anything else → throws `DETECTOR_INVALID_DETECTOR`.

`loadDetector(modulePath, skillRoot)` loads a detector module
only from inside the skill directory, with the same safety rules
as the round-50 verifier loader: an absolute path must resolve
inside the skill root; a relative path is resolved under the
skill root; the file itself must not be a symlink, and its
realpath must stay inside the real skill root (so a symlinked
parent directory cannot smuggle in a file from outside); the
module's export must be a function, or an object with a `detect`
function. Refusals, all named:

| Code | Meaning |
| ---- | ------- |
| `DETECTOR_NOT_FOUND` | The path does not exist. |
| `DETECTOR_NOT_A_FILE` | The path exists but is not a file. |
| `DETECTOR_SYMLINK_REFUSED` | The file itself is a symlink, or its realpath escapes the real skill root. |
| `DETECTOR_PATH_OUTSIDE_SKILL` | An absolute path outside the skill root (relative paths resolve under it). |
| `DETECTOR_LOAD_FAILED` | `require()` failed. |
| `DETECTOR_INVALID_MODULE` | The export is not a function and has no `detect` function. |

The returned `{ detector, source }` names the source as the file
basename (or the module's `name` property when it is a
non-empty string). The loader validates the export shape but
cannot sandbox the module's top-level code — that code DOES run
on load — so only load detector modules from authors you trust,
exactly as you would trust any other code in the skill
directory.

## CLI: `sentinel detect`

```text
sentinel detect [--detector stub|<path>] --input <record.json>
  [--session-id <id>] [--target-id <id>] [--asset-id <id>]
  [--out <findings.json>]
```

It runs the named detector over a local input record (read
bounded, like every other JSON input: size + nesting depth) and
prints the findings as JSON to stdout:

```json
{
  "detector": "stub",
  "findings": [ "...normalized finding records..." ],
  "skipped": 1,
  "errors": ["missing or empty required field: title"]
}
```

`--detector` defaults to `stub`. The optional `--session-id` /
`--target-id` / `--asset-id` options supply the `defaults`
fallback for input records that do not carry those ids
themselves; without them, a record missing an id is counted in
`skipped`. With `--out`, the JSON is written with the round-34
safe-write rules (mode `0600`, planted symlinks refused). A bad
detector path fails with a named `DETECTOR_*` error before any
output is written, so `--out` can never leave a half-written
file behind. A detector that throws or returns an invalid result
is recorded in the output envelope (`error` field), never a
crash.

The output findings are normalized finding records, directly
consumable by the validator (`sentinel report` or
`validateFinding`) — the detect → validate → dedupe → report
pipeline is proven end to end by test over the round-31 stub
fixture.

## Open decisions for the user

- **Which real detectors to build**, and under which
  authorization. The interface is ready; no detector exists yet
  beyond the stub, and building one is a scope decision, not an
  implementation detail.
- **Whether a detector should ever run automatically** inside a
  pipeline (detect → validate → report in one command), or stay
  a manual, operator-invoked step. Today it is manual:
  `sentinel detect` produces findings; the operator feeds them to
  `sentinel report` deliberately.
- **Whether detectors may be asynchronous** (a detector that
  calls an external tool or model). The contract is synchronous
  by design; an async detector needs an async pipeline round.
