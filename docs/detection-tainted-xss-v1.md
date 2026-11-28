# tainted-xss detector v1 — ninth real detector, fourth parser-based (round 104)

`sentinel detect --detector tainted-xss` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to HTML sinks,
reporting one finding per distinct sink site. It is the
ninth real detector (after `tainted-sql`, round 103) and
the fourth parser-based one: it reuses the shared taint
engine (`src/detection/taint-engine.js`, extracted in round
101). Round 104 is the first round to EXTEND the shared
engine for a new sink shape (round 103 needed no engine
change): XSS sinks are not all calls — `innerHTML` /
`outerHTML` are assignment sinks, and
`insertAdjacentHTML` is a method sink that judges its
second argument. Both shapes are config tables in the
engine (`assignmentSinks`, `methodSinks`) plus a per-sink
`argIndex`; the three earlier AST detectors define
neither table and behave exactly as before. See
`docs/parser-taint-scope-v1.md` §8 for the scoping (XSS
was the next named AST class after tainted SQL).

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
  `discovery_tool: 'tainted-xss'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — HTML sinks; all CWE-79, severity high):

| sink | notes |
|---|---|
| `document.write`, `document.writeln` | fixed-root calls; the first argument is the written markup |
| `insertAdjacentHTML` | method sink (any receiver — the method exists only on DOM elements); judges its SECOND argument (the HTML), because the first is the position constant (`beforebegin`, `afterbegin`, `beforeend`, `afterend`) |
| `innerHTML`, `outerHTML` | assignment sinks (any receiver: `el.innerHTML`, `document.body.innerHTML`, `el['innerHTML']`); judged on the assigned value, including `+=` |

Only these shapes are sinks. `textContent` /
`innerText` are safe by construction and are not sinks.
jQuery `.html()` is NOT a sink in this round (a
no-argument `.html()` is a getter, and the detector does
not model jQuery semantics). A three-part call
(`window.document.write(...)`) is not resolved. Other
languages' XSS APIs stay regex-covered by
`dangerous-call` — this parser is JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`document.write(...)`, `el.insertAdjacentHTML(...)`) whose judged argument is tainted | the taint chain (source + identifier-name steps); the description names the judged argument when it is not the first (`argument 2`) |
| `tainted-assign` | assignment to a sink property (`el.innerHTML = ...`, `el.innerHTML += ...`) whose assigned value is tainted | the taint chain plus the assigned-to target (`el.innerHTML`) and property (`innerHTML`), evidence type `ast-assign` |
| `aliased-call` | sink call reached through an alias (`const w = document.write`, `const { write } = document`, `const f = el.insertAdjacentHTML`) with any argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean judged argument, and an
assignment of a clean value, are NOT reported: the regex
detector already flags those call sites, and the AST
detector adds nothing. A sink call with zero arguments
cannot execute attacker data and is not reported. Only
the JUDGED argument is assessed: for `document.write`
that is the first argument; for `insertAdjacentHTML`
that is the second (the HTML). A tainted argument
outside the judged index is not covered in this round
(see limitations).

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
- An aliased call IS a call: `const w = document.write;
  w(x)` and `const { write } = document; write(x)`
  resolve the alias to its sink. Reassigning the alias to a
  non-sink value clears it (`let w = document.write;
  w = 5; w(x)` is not a finding).
- An assignment IS a sink site: `el.innerHTML = x`
  flags when `x` is tainted, and the regex detector's
  innerHTML rule cannot tell a tainted assignment from a
  constant one. The assignment's receiver is irrelevant —
  only the property name and the assigned value are
  judged.
- A wrapper function IS analyzed through the call
  graph (round 101): `function render(v) {
  el.innerHTML = v; }` called as
  `render(userInput)` flags the sink with the
  cross-function chain (`parameter 'req' of function
  'handle' → req.body → parameter 'v' of function
  'render'`), and the fallback still flags the sink when
  the wrapper is never called or called only with
  clean arguments — then with the parameter chain only,
  and without claiming the wrapper is reachable from a
  tainted call. See `docs/inter-procedural-taint-v1.md`.

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
  so code that validates before assigning can still
  be flagged; the finding is confidence `potential`
  for exactly this reason — the operator triages it,
  and the validator's `false_positive` verdict exists
  for exactly that. See `docs/sanitizer-modeling-v1.md`.
- **Import resolution (round 106).** This detector has no
  import mapping: its sinks are DOM globals, not module
  members, so `require('fs').write(...)` is still not a
  sink. A three-part call (`window.document.write(...)`)
  is still not resolved either. Destructuring of a fixed
  root (`const { write } = document`) was already
  resolved. A destructured method sink
  (`const { insertAdjacentHTML } = el`) is still NOT
  resolved: the destructuring rule keys on the receiver
  name, and `insertAdjacentHTML` has no fixed receiver.
  See `docs/import-resolution-v1.md`.
- **Judged argument only.** `document.write` judges
  its first argument only — a tainted second or later
  argument (`document.write('static', x)`) is not
  judged in this round. `insertAdjacentHTML` judges
  its second argument only — a tainted first argument
  (the position constant) is not judged. `Object.assign`
  into `innerHTML` (`Object.assign(el, {innerHTML: x})`)
  is not a sink in this round (no assignment-expression
  shape). These are future work, not silent gaps.
- **Method sinks match by name alone.** Any receiver's
  `insertAdjacentHTML` is a sink — the method exists
  only on DOM elements, so the name is distinctive
  enough. A non-DOM object with a same-named method
  would be flagged too; the finding is confidence
  `potential` for exactly this reason.
- **Subset grammar.** Class fields, decorators, and other
  constructs outside the subset (see
  `docs/parser-taint-scope-v1.md` §2.2) fail the parse and
  skip the record rather than being scanned
  approximately. Block scoping is not modeled: bindings
  are function-scoped.
- **No reachability proof.** A sink inside dead code is
  still flagged — the detector parses structure, not
  reachability. Every finding is confidence `potential`
  because the detector cannot prove the assignment or
  call is reachable or attacker-controlled;
  exploitability must be verified out of band before
  reporting.

## Future work (not this round)

- Judging further arguments (`document.write`'s second
  and later arguments) as a tainted-arg variant.
- `Object.assign` into a sink property as an assignment
  sink.
- jQuery `.html()` as a sink class (needs jQuery
  semantics: setter vs getter by argument count).
- Destructured method sinks (`const { insertAdjacentHTML }
  = el`).
- A fifth AST class on the same engine (SSTI +
  path traversal + SSRF is the next named candidate in
  `docs/parser-taint-scope-v1.md`).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-xss-` + the first 16 hex chars of SHA-256
  (`tainted-xss:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
