# tainted-ssrf detector v1 — twelfth real detector, seventh parser-based (round 105)

`sentinel detect --detector tainted-ssrf` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to
outbound-request sinks, reporting one finding per distinct
sink site. It is the twelfth real detector (after
`tainted-path-traversal`, round 105) and the seventh
parser-based one: it reuses the shared taint engine
(`src/detection/taint-engine.js`, extracted in round
101) with one small additive fix to alias resolution (see
below) — otherwise a thin wrapper supplying its sink
table and finding metadata (CWE-918, severity high). See
`docs/parser-taint-scope-v1.md` §9 for the scoping (SSRF
was one of the three named AST classes after tainted
XSS).

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
  `discovery_tool: 'tainted-ssrf'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — outbound requests; all CWE-918, severity high):

| sink | notes |
|---|---|
| `fetch` | bare name — the platform fetch API; the first argument is the URL |
| `request` | bare name — the request library's main export; the first argument is the URL |
| `http.get`, `http.request` | the first argument is the URL (or an options object whose properties carry the host) |
| `https.get`, `https.request` | same as `http.*` over TLS |
| `axios.get`, `axios.post`, `axios.put`, `axios.delete`, `axios.request` | the first argument is the URL |

The bare names `fetch` and `request` ARE sinks in this
round: unlike `query` (round 103) or `render` (this
round's SSTI detector), both names are distinctive
globals in JavaScript — `fetch` is the platform fetch
API and `request` is the request library's main export
— so a bare call is a request by construction. A
user-defined function of the same name is flagged too
(documented over-approximation, confidence `potential`
for exactly this reason).

Only these shapes are sinks. `window.fetch` is NOT a
sink in this round (the `window` receiver is not in the
sink list). `XMLHttpRequest.open` is NOT a sink
(client-side XHR, not a server-side request).
`WebSocket` is NOT a sink (a different protocol). A
three-part call (`app.http.get(...)`) is not resolved.
Other shapes stay regex-covered by `dangerous-call` —
this parser is JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`fetch(...)`, `http.get(...)`, `axios.get(...)`) whose first argument (the URL) is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const g = http.get`, `const { request } = http`, `const f = fetch`) with any argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean first argument is NOT
reported: the regex detector already flags that call
site, and the AST detector adds nothing. A sink call
with zero arguments cannot execute attacker data and is
not reported. Only the FIRST argument is assessed: a
tainted second argument (options, body, config) is not
covered in this round. An options object as the first
argument IS judged as a whole — its properties' taint
joins, so `http.get({ hostname: d })` flags when `d` is
tainted.

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
- An aliased call IS a call: `const g = http.get;
  g(x)` and `const { put } = axios; put(x)` resolve the
  alias to its sink. Reassigning the alias to a non-sink
  value clears it (`let f = fetch; f = 5; f(x)` is not
  a finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function get(u) {
  return fetch(u); }` called as `get(userInput)`
  flags the sink with the cross-function chain
  (`parameter 'req' of function 'handle' → req.body →
  parameter 'u' of function 'get'`), and the fallback
  still flags the sink when the wrapper is never called
  or called only with clean arguments — then with the
  parameter chain only, and without claiming the wrapper
  is reachable from a tainted call. See
  `docs/inter-procedural-taint-v1.md`.

## Round-105 engine fix: bare-name sink aliases

Round 105 makes one small additive fix to the shared
engine (`aliasSinkOf` in `src/detection/taint-engine.js`):
a bare-name sink bound to a new name (`const f = fetch`,
`const f = unserialize`) now resolves as an alias of
that sink. Before this fix, only member-expression
aliases resolved (`const q = db.query`), so a bare-name
sink could not be aliased at all — the binding carried
no alias and the call was an unknown call. The fix
checks `config.sinks[node.name]` before falling back to
the binding lookup, so it only affects identifiers that
ARE bare-name sinks (`fetch`, `request`, `unserialize`);
every other identifier resolves exactly as before. The
pre-existing AST detectors are unchanged (their test
files pass unmodified — no test pinned the old
non-resolution). Two quirks stay, pinned by tests:

- **Name collision:** a destructured alias whose name
  collides with a bare sink name (`const { request } =
  http`) is judged as the ALIAS (`http.request`), not
  as the bare sink — the alias check runs before the
  direct-sink check (round 114 overturned the round-105
  rule that judged it as the bare sink), so
  `request("https://example.com")` flags as an
  `aliased-call` finding even with a clean argument,
  like every other aliased call.
- **`get` is a parser keyword:** a bare identifier
  literally named `get` does not parse (round-101
  limitation — `unexpected keyword get`), so a record
  calling `get(...)` directly is skipped, and
  destructuring a member named `get`
  (`const { get } = http`) is unusable in scanned code.
  The other members (`request`, `post`) resolve.

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
  so code that validates a URL before fetching can
  still be flagged; the finding is confidence
  `potential` for exactly this reason — the operator
  triages it, and the validator's `false_positive`
  verdict exists for exactly that. See
  `docs/sanitizer-modeling-v1.md`. Note: this detector
  does NOT model URL allow-list checks — a
  `startsWith('https://api.example.com')` guard is
  not recognized as a sanitizer, so guarded fetches
  can still be flagged; that is future work, not a
  silent gap.
- **Import resolution (round 106).** A sink reached as
  `require('http').get(...)` now resolves to `http.get`,
  and so do the ESM forms and module aliases
  (`require('request')` resolves to bare sink `request`).
  A three-part call (`app.http.get(...)`) is still not
  resolved. Destructuring of a fixed root
  (`const { put } = axios`) was already resolved. The
  bare-sink collision rule changed in round 114: a
  destructured name colliding with a bare sink
  (`request`) is now judged as the alias
  (`http.request`). See `docs/import-resolution-v1.md`.
- **Judged argument only.** Only the first argument
  (the URL) is judged — a tainted second argument
  (options, body, config) is not judged in this
  round.
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

- `window.fetch` as a sink shape (the `window`
  receiver).
- Modeling URL allow-list checks (`startsWith` on an
  allow-listed origin) as sanitizers.
- `XMLHttpRequest` as a sink class (client-side SSRF
  shape — a different threat model, needs its own rule).
- Judging further arguments as a tainted-arg variant.
- A `get`-as-identifier fix in the subset parser (the
  round-101 keyword limitation blocks destructuring
  `http.get` by its plain name).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-ssrf-` + the first 16 hex chars of SHA-256
  (`tainted-ssrf:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
