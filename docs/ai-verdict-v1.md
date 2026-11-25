# AI-verdict interface v1 (round 50, 2026-11-26)

The pluggable interface a model-based finding verifier must satisfy
(`src/analysis/ai-verdict.js`), the built-in stub verifier, and the
safe loader for custom verifier modules. This round does NOT choose a
model and does NOT call one — it defines the contract so a model can
be plugged in later, and wires it in as ADVISORY ONLY.

## The contract

A verifier is a SYNCHRONOUS function:

```js
verifier(finding) -> { verdict, confidence, reasons }
```

- `finding` — a normalized finding record. The verifier receives a
  DEFENSIVE COPY (JSON round-trip for JSON-shaped findings) and
  cannot mutate the finding being reported. A verifier that tries to
  mutate its input is harmless: the copy is discarded after the call
  (tested).
- `verdict` — one of `'valid'`, `'false_positive'`, `'needs_evidence'`.
- `confidence` — a finite number in `[0, 1]`.
- `reasons` — an array of strings (possibly empty).

The function must return its result SYNCHRONOUSLY. A verifier that
returns a Promise is refused as an invalid result
(`AI_VERDICT_INVALID_RESULT: verifier must return a result
synchronously`), because the validator and the report generator are
synchronous and deterministic. An async model call belongs to a
future round (an async validator) or to an adapter that
pre-computes verdicts before the run.

`validateAiVerdictResult(result)` enforces the contract and returns
a normalized copy (the caller's object is never shared). It throws
`AI_VERDICT_INVALID_RESULT` with a detail on any violation: a
Promise return, a non-object, an unknown verdict, a confidence
outside `[0, 1]` or not a finite number, or reasons that are not an
array of strings.

## The stub verifier (the default)

`stubVerifier()` is deterministic and always returns
`{ verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] }`.
It ignores its argument and NEVER claims a finding valid or
false_positive — even for a fully-evidenced confirmed finding
(tested).

The stub is the verifier used when a verifier is requested without
naming a custom module: `--verifier stub`, or the string `'stub'`
in code. When NO verifier is requested at all, no `ai_verdict` is
attached — a report without a verifier is byte-identical to the
pre-round-50 output (the round-44 golden hashes still pass; tested
in `tests/ai-verdict.test.js`).

## Advisory-only precedence

The wiring is:

1. `validateFinding(finding, { verifier })` in
   `src/analysis/validator.js` computes the rule-based verdict
   FIRST, exactly as before (the rule logic lives untouched in
   `validateFindingRule`), then runs the verifier and adds
   `aiVerdict` + `aiVerdictSource` to the returned result. The rule
   verdict NEVER changes because of the AI verdict — a verifier
   that disagrees with the rule verdict is recorded, not obeyed
   (tested both directions: a `false_positive` AI verdict on a
   valid finding, and a `valid` AI verdict on an unevidenced
   finding).
2. `generateReport(findings, { verifier })` in
   `src/report/generator.js` attaches `ai_verdict` +
   `ai_verdict_source` to each validated finding AFTER validation
   (`attachAiVerdict`, which returns a copy and never mutates the
   input), so a verifier can never change a verdict, a score, or
   the mixed-target check. The renderers show the AI verdict
   distinctly, labelled advisory: Markdown
   `- **AI verdict (advisory):** <verdict> (confidence <c>, source: <s>) — <reasons>`,
   HTML `<dt>AI verdict (advisory)</dt>`, JSON `ai_verdict` carried
   by the spread. Platform templates render their own fixed
   sections and do not carry the AI verdict in Markdown — the same
   precedent as the evidence checklist — but their JSON form still
   does, via the spread.
3. The finding schema (`schemas/finding.schema.json`) declares the
   optional `ai_verdict` object (`verdict`, `confidence`,
   `reasons`, optional `error`) and `ai_verdict_source` string.

`validateFinding` keeps its never-throws contract: a verifier
option that is neither a function nor `'stub'` is recorded as a
verifier failure (`aiVerdict` needs_evidence with the error,
`aiVerdictSource` `'invalid'`), never thrown. Path strings are NOT
accepted by `validateFinding` — loading a module from a path is
I/O and belongs to the caller (`getVerifier` / `loadVerifier`).

## The loader (`loadVerifier`)

`getVerifier(spec, skillRoot)` resolves a specification:

- `undefined` / `null` → `null` (no verifier configured).
- `'stub'` → `{ verifier: stubVerifier, source: 'stub' }`.
- a function → `{ verifier: spec, source: 'inline' }`.
- a string path → `loadVerifier(spec, skillRoot)`.
- anything else → throws `AI_VERDICT_INVALID_VERIFIER`.

`loadVerifier(modulePath, skillRoot)` loads a verifier module from
inside the skill directory only:

- An absolute path must resolve inside the skill root; a relative
  path is resolved under the skill root. Anything else is refused
  with `AI_VERDICT_PATH_OUTSIDE_SKILL`.
- The file itself must not be a symlink
  (`AI_VERDICT_SYMLINK_REFUSED`), and its realpath must stay
  inside the real skill root (so a symlinked parent directory
  cannot smuggle in a file from outside).
- A missing file is refused with `AI_VERDICT_NOT_FOUND`; a
  non-file with `AI_VERDICT_NOT_A_FILE`; a require failure with
  `AI_VERDICT_LOAD_FAILED`.
- The module's export must be a function, or an object with a
  `verify` function; anything else is refused with
  `AI_VERDICT_INVALID_MODULE`. The returned source is the file
  basename, or the module's `name` property when it is a non-empty
  string.

Honest limitation: the loader validates the export shape but
cannot sandbox the module's top-level code — `require()` runs it
on load. Only load verifier modules from authors you trust,
exactly as you would trust any other code in the skill directory.
The path and symlink restrictions limit the attack surface to
files the operator deliberately placed inside the skill dir.

## Verifier failure handling

`runVerifier(verifier, finding)` catches everything a verifier can
do wrong. A verifier that throws, or returns an invalid result,
produces `{ verdict: 'needs_evidence', confidence: 0, reasons:
['ai verifier error: <message>'], error: '<message>' }` — the
validator never crashes because of a verifier (tested for both a
throwing verifier and an invalid-shape return). A clean run carries
no `error` field.

## CLI

```
sentinel report --finding <finding.json> [--verifier stub|<path>] [--out <report.md>] ...
sentinel report --findings <findings-array.json> [--verifier stub|<path>] ...
```

`--verifier stub` attaches the stub verdict to every finding.
`--verifier <path>` loads a verifier module from inside the skill
directory (relative paths resolve under the skill root). A verifier
that fails to load throws a named error before any output is
produced, so a bad `--verifier` can never leave a half-written
report behind (tested: exit non-zero, named error on stderr, no
output file).

## Known limitations and open decisions (for the user)

- NO model is plugged in. The interface is ready; choosing the
  model (which model, local vs remote, what credentials it needs)
  is still an open decision.
- The interface is SYNCHRONOUS. A model that must be called over
  HTTP (or any other async transport) cannot be used as a verifier
  today — it needs either a future async-validator round or an
  adapter that pre-computes verdicts before the run.
- The AI verdict is ADVISORY ONLY by design. Whether it should
  ever override the rule-based verdict — and under what policy
  (e.g. only to downgrade `valid` to `needs_evidence`, never to
  upgrade) — is still an open decision.
- A verifier sees one finding at a time and cannot compare
  findings (no cross-finding context); grouping and dedup stay
  rule-based.
