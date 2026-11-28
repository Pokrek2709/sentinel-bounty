# Sanitizer modeling v1 (round 101, Phase 5)

Round 95 documented "no sanitizer modeling" as a known
false-positive source: a `validate()` / allow-list call
did not cleanse taint, so code that validated before
deserializing or executing could still be flagged. Round
101 models sanitizers as an explicit allow-list in the
shared taint engine (`SANITIZERS` in
`src/detection/taint-engine.js`): a call in the list
returns a clean value regardless of argument taint, so a
sink call on the result is not reported. The list is
deliberately narrow, and the exclusions are pinned by
tests just like the entries — a sanitizer that is not
provably cleansing is worse than no sanitizer, because it
silently drops real findings.

## 1. The allow-list

| call | returns | why it cleanses |
|---|---|---|
| `Number(x)` | number | a number cannot carry a string payload into a string sink |
| `parseInt(x)` | number | same — the result is a number (or `NaN`) |
| `parseFloat(x)` | number | same |
| `Boolean(x)` | boolean | a boolean cannot carry a string payload |
| `Number.parseInt(x)` | number | the same function reached as a member of `Number` |
| `Number.parseFloat(x)` | number | same |

Rules of the model:

- The sanitizer's ARGUMENTS are still evaluated first,
  so a sink nested in one is still checked:
  `Number(yaml.load(req.body))` still flags the
  `yaml.load` call.
- The cleanse applies to the RETURN VALUE only. A
  sanitizer does not cleanse a variable it never touched:
  sanitizing `n` leaves `m` tainted.
- A sanitizer inside a wrapper cleanses through the
  wrapper: `clean(x) { return Number(x); }` makes
  `yaml.load(clean(req.body))` clean, because the
  wrapper's computed return taint is clean (see
  `docs/inter-procedural-taint-v1.md` §3).
- A user binding that shadows a sanitizer name disables
  it for that scope: a local
  `function Number(x) { return x; }` is not a sanitizer,
  and `Number(req.body)` stays tainted. The engine
  checks that no binding for the root name exists before
  treating the call as a sanitizer.

## 2. What is NOT a sanitizer (pinned exclusions)

| call | why it does NOT cleanse |
|---|---|
| `encodeURIComponent(x)`, `encodeURI(x)` | encoding preserves attacker-controlled string content — and `encodeURIComponent` leaves `'` unescaped, so shell breakout through a quote survives. The result is still a string carrying the input. |
| `String(x)` | preserves the string content exactly. |
| `JSON.stringify(x)` | preserves the content as a JSON string; as a shell command it is still attacker-controlled text, and as a deserialization input it is still attacker-influenced. |
| `x.trim()`, `x.toUpperCase()`, other string methods | content-preserving transformations; the payload survives. |
| An aliased sanitizer (`const f = Number; f(x)`) | not tracked — the allow-list matches direct calls only. Call the sanitizer directly. |
| Any user `validate()` / allow-list function | unknown to the engine; it cannot know what the function checks. A `validate()` that throws on bad input and returns the value is NOT modeled — the sink on its result is still flagged (confidence `potential`, triaged out of band). |

## 3. Deliberate limits

- The list is a fixed table, not a heuristic: no
  function is treated as a sanitizer because of its name
  pattern, its argument count, or its return type
  annotation (the subset grammar has none).
- Sanitizing is all-or-nothing per call: there is no
  partial cleanse (e.g. "the first argument is
  validated, the second is not" is not modeled — the
  engine judges only the first argument of a sink
  anyway).
- A sanitizer applied to a tainted MEMBER
  (`Number(req.body)`) cleanses the same way as to a
  bare identifier — the check is on the callee name,
  not on the argument shape.
- The list grows only by a round that adds an entry with
  its rationale and its pinning tests (as this round
  does). An entry without a proof that its return value
  cannot carry a string payload does not belong here.
