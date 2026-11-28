# tainted-redos detector v1 — twenty-seventh real detector, twelfth parser-based (round 113)

`sentinel detect --detector tainted-redos` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to regular
expression construction and use, reporting one finding per
distinct sink site. It is the twenty-seventh real detector
(after `tainted-xxe`, round 113) and the twelfth
parser-based one: it reuses the shared taint engine
(`src/detection/taint-engine.js`, extracted in round 101)
as a thin wrapper supplying its sink table and finding
metadata (CWE-1333, severity medium). See
`docs/parser-taint-scope-v1.md` §17 for the scoping (ReDoS
was the second of the two JavaScript classes of round 113,
the return to JavaScript after the Solidity set closed in
round 112).

## Input contract

- The detector takes a raw detector-input record — the shape
  `normalizeRawFinding()` accepts — or a batch
  `{ tool, results: [...] }`. It parses only the record's
  `content` string: text the operator already holds (for
  example source code or a code excerpt captured in the lab)
  and hands to the CLI. It never reads a file itself, never
  makes a request, and never executes the code it scans.
- `source` (optional, non-empty string) labels where the text
  came from and is carried into the description and proof of
  concept.
- `language` (optional) must be JavaScript (`javascript`,
  `js`, `node`, case-insensitive) when present; any other
  value counts the record in `skipped`. When absent, the
  content is attempted as JavaScript.
- `session_id` / `target_id` / `asset_id` come from the
  record, else from `defaults` (the CLI `--session-id` /
  `--target-id` / `--asset-id` options); a record missing an
  id after defaults is counted in `skipped`, never invented.
- A record without a non-empty string `content` is counted in
  `skipped` with its error recorded, never thrown; a bad
  record never aborts a batch. A non-object input throws
  `DETECTOR_INVALID_INPUT`, exactly like the stub detector.
- Batch records follow the stub convention: the batch `tool`,
  when present, is forced as `discovery_tool` on every
  finding; otherwise the finding carries
  `discovery_tool: 'tainted-redos'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — regular-expression use; all CWE-1333,
severity medium):

| sink | notes |
|---|---|
| `RegExp` | bare sink: `RegExp(tainted)` and `new RegExp(tainted)` — the first argument is the pattern |
| `match` | method sink: the first argument is the pattern, whatever the receiver |
| `search` | method sink: the first argument is the pattern |
| `replace` | method sink: the first argument is the pattern |
| `split` | method sink: the first argument is the pattern |

Only these shapes are sinks. `regex.test` / `regex.exec`
are NOT sinks: the danger lives in the receiver pattern,
which the engine cannot analyze for catastrophic
backtracking (there is no regex-complexity analysis —
see the honest limit below). `matchAll` is NOT a sink
(outside the brief's named scope; a string argument to
it throws). A three-part call (`window.RegExp(...)`) is
not resolved. Other regex shapes stay regex-covered by
`dangerous-call` — this parser is JavaScript-only.

**Coercion, stated precisely.** `match` and `search`
coerce a string argument to a regular expression, so a
tainted string pattern is a vector exactly like
`RegExp`. `replace` and `split` match a string argument
LITERALLY (no regex compilation), so only a tainted
RegExp OBJECT passed as the pattern is a vector there —
the engine cannot tell a tainted string from a tainted
RegExp object, so a finding on `replace` / `split` is
`potential` and the operator must check the pattern's
type. This is pinned by tests, not hidden.

**No regex-complexity analysis — the honest limit.**
The engine never inspects pattern text. A tainted
pattern reaching a sink is flagged because the attacker
fully or partly controls the pattern, so any
catastrophic construct (nested quantifiers such as
`(a+)+`, `(a|a)*`, `(a*)*`) can be supplied — but the
detector does NOT prove the pattern contains one. A
tainted pattern that is in fact harmless (for example a
plain literal string used with `match` / `search`, or a
pattern validated elsewhere) is a false positive the
operator must dismiss. Conversely a clean pattern is
never flagged, however catastrophic it looks: the
pattern is developer-controlled, so there is no
attacker vector. Severity is `medium`: the impact is
availability only (CPU exhaustion), never data
disclosure or code execution.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call whose first argument (the pattern) is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const R = RegExp`, `const m = s.match`) with any argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean first argument is NOT
reported: the regex detector already flags that call
site, and the AST detector adds nothing. A sink call
with zero arguments cannot execute attacker data and is
not reported. Only the FIRST argument is assessed: a
tainted second argument (`RegExp` flags, `replace`'s
replacement) is not covered in this round.

Taint propagates through: assignment and declaration,
member access on a tainted base, binary / logical /
conditional expressions, template interpolations, array /
object literals, `await`, unary `-` / `+` / `~`. `!`,
`typeof`, `void`, `delete` cleanse (they produce a boolean
or nothing, not the data). Return values of known
functions are computed: an identity wrapper propagates
taint, a constant-returning wrapper does not, a wrapper
returning a global source propagates it. Return values of
unknown calls are tainted when any argument is tainted
(an over-approximation, chain extended with
`callee(...)`). A sanitizer call (`Number`, `parseInt`,
`parseFloat`, `Boolean`, `Number.parseInt`,
`Number.parseFloat`) returns clean — see
`docs/sanitizer-modeling-v1.md`. Branch joins are OR:
tainted on any path stays tainted.

## What the parser sees that a regex cannot — and what it cannot

- A sink in a comment or a string literal is NOT a sink:
  the tokenizer strips comments and treats string
  contents as single tokens, so prose never becomes a
  finding. This is the sharpest difference from the regex
  detector, which matches call text wherever it appears.
- An aliased call IS a call: `const R = RegExp; R(x)`
  and `const m = s.match; m(x)` resolve the alias to
  its sink. Reassigning the alias to a non-sink value
  clears it (`let R = RegExp; R = 5; R(x)` is not a
  finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function get(u) {
  return RegExp(u); }` called as `get(userInput)`
  flags the sink with the cross-function chain, and the
  fallback still flags the sink when the wrapper is
  never called or called only with clean arguments —
  then with the parameter chain only, and without
  claiming the wrapper is reachable from a tainted
  call. See `docs/inter-procedural-taint-v1.md`.
- `new RegExp(d)` IS the same sink as `RegExp(d)`:
  round 113 sink-checks `new` expressions like calls,
  and fixed the subset parser's `new` target grammar —
  `new RegExp(d)` used to mis-parse as `new
  (RegExp(d))` with empty arguments. `new Foo(d)` for
  any other constructor is still not a finding.

## Known limitations (documented, not hidden)

- **JavaScript only.** A second language needs a second
  parser.
- **Inter-procedural (round 101).** Taint flows from a
  call site into a callee, through return values, IIFEs,
  and function aliases, on the shared engine
  (`src/detection/taint-engine.js`); the chain proves
  the flow. A sink inside a helper never called, or
  called only with clean arguments, is still flagged
  via the parameters-as-sources fallback. Remaining
  limits: methods are not resolved through the call
  graph (analyzed with parameters-as-sources when
  their class is walked), no `this` modeling, and
  when several flows reach one sink site the first
  chain wins (see `docs/inter-procedural-taint-v1.md`).
- **Sanitizer modeling (round 101).** `Number`,
  `parseInt`, `parseFloat`, `Boolean`,
  `Number.parseInt`, `Number.parseFloat` cleanse
  taint — their return values cannot carry a string
  payload. Encoding and content-preserving calls
  (`encodeURIComponent`, `encodeURI`, `String`,
  `JSON.stringify`, string methods) do NOT cleanse;
  a user binding shadowing a sanitizer name disables
  it. An unknown `validate()` is still not modeled,
  so code that allow-lists a pattern before compiling
  it can still be flagged; the finding is
  confidence `potential` for exactly this reason — the
  operator triages it, and the validator's
  `false_positive` verdict exists for exactly that. See
  `docs/sanitizer-modeling-v1.md`.
- **No import mapping.** `RegExp` and the string
  methods are built-ins, not module members — there is
  nothing to resolve through imports. A bare `RegExp`
  call still flags by name alone, whatever binding it
  came from (the direct-sink check runs first — the
  round-105 `request` quirk, same rule). See
  `docs/import-resolution-v1.md`.
- **Judged argument only.** Only the first argument
  (the pattern) is judged — a tainted second argument
  is not judged in this round.
- **`replace` / `split` over-approximation.** See the
  coercion note: a tainted string pattern there is
  matched literally, so only a tainted RegExp object
  is a vector; the finding is `potential` and the
  operator checks the pattern's type.
- **Subset grammar.** Class fields, decorators, and other
  constructs outside the subset (see
  `docs/parser-taint-scope-v1.md` §2.2) fail the parse and
  skip the record rather than being scanned
  approximately. Block scoping is not modeled: bindings
  are function-scoped.
- **No reachability proof.** A sink inside dead code is
  still flagged — the detector parses structure, not
  reachability. Every finding is confidence `potential`
  because the detector cannot prove the call is
  reachable or attacker-controlled; exploitability must
  be verified out of band before reporting.

## Future work (not this round)

- Regex-complexity analysis on literal patterns
  (nested-quantifier detection), so a tainted pattern
  can be graded by shape rather than by control alone.
- `matchAll` and `RegExp.prototype` methods
  (`Symbol.match`, `Symbol.replace`) as further sink
  shapes.
- A timeout-bounded / linear-time engine check as a
  mitigations note in the finding.
- A `get`-as-identifier fix in the subset parser (the
  round-101 keyword limitation).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-redos-` + the first 16 hex chars of SHA-256
  (`tainted-redos:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
