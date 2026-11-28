# tainted-xxe detector v1 — twenty-sixth real detector, eleventh parser-based (round 113)

`sentinel detect --detector tainted-xxe` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to XML parser
sinks, reporting one finding per distinct sink site. It is
the twenty-sixth real detector (after
`solidity-cross-function-reentrancy`, round 112) and the
eleventh parser-based one: it reuses the shared taint
engine (`src/detection/taint-engine.js`, extracted in
round 101) as a thin wrapper supplying its sink table and
finding metadata (CWE-611, severity high). See
`docs/parser-taint-scope-v1.md` §17 for the scoping (XXE
was the first of the two JavaScript classes of round 113,
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
  `discovery_tool: 'tainted-xxe'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — XML parsing; all CWE-611, severity high):

| sink | notes |
|---|---|
| `libxmljs.parseXml` | the first argument is the XML string; flagged ONLY when the second argument is an object literal containing `noent: true` (see the gate below) |
| `libxmljs.parseXmlString` | same gate as `parseXml` |
| `parseFromString` | method sink (xmldom `DOMParser`): the first argument is the XML string, whatever the receiver |
| `parseString` | method sink (xml2js `Parser`): the first argument is the XML string |
| `parseStringPromise` | method sink (xml2js `Parser`): the first argument is the XML string |
| `parser.write` | fixed two-part sink (sax `parser`): the first argument is the XML string |

Only these shapes are sinks. A bare `parseXml(...)` is
deliberately NOT a sink (only the `libxmljs` root is — a
bare `parseXml` could be any library's function). A
three-part call (`app.libxmljs.parseXml(...)`) is not
resolved. `JSON.parse` is NOT a sink (JSON has no
entities). `document.querySelector` is NOT a sink (CSS
selectors, not XML). `xpath.parse` is NOT a sink. Other
XML shapes stay regex-covered by `dangerous-call` — this
parser is JavaScript-only.

**The libxmljs gate.** libxmljs substitutes entities
only when the `noent` option is true; the library
default (no options, or `noent: false`) does not
substitute them, so a plain call is NOT a finding.
Round 113 added a config-driven `dangerousOptions` gate
to the shared engine for exactly this shape: a sink
entry may carry `{ argIndex, props }`, and the finding
fires only when the named argument is an object literal
containing one of the named properties with a strictly
equal literal value. Here that is argument 1 containing
`noent: true` (an identifier key or a string key — both
are literal property names). An options object held in a
variable is NOT inspected (the gate needs a literal),
so it is not a finding — a documented false negative,
not a silent skip.

**xmldom / xml2js caveat.** xmldom expands internal
entities by default and does not fetch external entities
in current versions; xml2js (over sax) likewise expands
internal entities by default. So a finding on those
sinks is a potential entity-expansion / XXE vector that
needs version-specific verification — the finding is
confidence `potential` for exactly this reason, and the
operator triages it. The detector does not claim an
external-entity fetch happens on every version.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call whose first argument (the XML string) is tainted — and, for the libxmljs pair, whose options argument carries the `noent: true` literal | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const p = libxmljs.parseXml`, `const { parseXml } = libxmljs`) with any argument — the libxmljs gate still applies | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean first argument is NOT
reported: the regex detector already flags that call
site, and the AST detector adds nothing. A sink call
with zero arguments cannot execute attacker data and is
not reported. Only the FIRST argument is assessed: a
tainted second argument that is not the options literal
is not covered in this round.

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
- An aliased call IS a call: `const p =
  libxmljs.parseXml; p(d, { noent: true })` and `const {
  parseXml } = libxmljs; parseXml(d, { noent: true })`
  resolve the alias to its sink. Reassigning the
  alias to a non-sink value clears it (`let p =
  libxmljs.parseXml; p = 5; p(d, { noent: true })` is
  not a finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function get(u) {
  return libxmljs.parseXml(u, { noent: true }); }`
  called as `get(userInput)` flags the sink with the
  cross-function chain, and the fallback still flags
  the sink when the wrapper is never called or called
  only with clean arguments — then with the parameter
  chain only, and without claiming the wrapper is
  reachable from a tainted call. See
  `docs/inter-procedural-taint-v1.md`.
- The `noent` gate IS a literal check, not a dataflow
  one: `const opts = { noent: true };
  libxmljs.parseXml(d, opts)` is NOT a finding. The
  engine does not do constant propagation for the
  options object — see the limitations.

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
  so code that strips DOCTYPE declarations before
  parsing can still be flagged; the finding is
  confidence `potential` for exactly this reason — the
  operator triages it, and the validator's
  `false_positive` verdict exists for exactly that. See
  `docs/sanitizer-modeling-v1.md`.
- **Import resolution (round 106).** A sink reached as
  `require('libxmljs').parseXml(...)` now resolves to
  `libxmljs.parseXml`, and so do the ESM forms and
  module aliases. A three-part call
  (`app.libxmljs.parseXml(...)`) is still not resolved.
  Destructuring of a fixed root (`const { parseXml } =
  libxmljs`) was already resolved. See
  `docs/import-resolution-v1.md`.
- **Judged argument only.** Only the first argument
  (the XML string) is judged — and for the libxmljs
  pair, the options literal gates the finding.
- **Variable options are a false negative.** The
  `dangerousOptions` gate inspects only an object
  literal at the call site; an options object held in a
  variable, built by spread, or returned by a helper is
  not a finding even when it carries `noent: true`.
- **xmldom / xml2js version caveat.** See the sinks
  section: external-entity fetching depends on the
  library version; verify out of band.
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

- Constant propagation for the options object, so a
  variable holding `{ noent: true }` is judged too.
- Detecting DOCTYPE stripping / rejection before the
  parse as a sanitizer shape.
- Streaming XML shapes (`sax.createStream`, `parser.write`
  in a stream pipeline) as a combined sink shape.
- Other XML libraries (`fast-xml-parser`, `xml-js`,
  `libxmljs2`) as further sink tables.
- A `get`-as-identifier fix in the subset parser (the
  round-101 keyword limitation).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text. The
  `dangerousOptions` gate inspects a literal option
  value only for a boolean decision; the value never
  appears in a finding.
- `finding_id` is deterministic:
  `tainted-xxe-` + the first 16 hex chars of SHA-256
  (`tainted-xxe:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
