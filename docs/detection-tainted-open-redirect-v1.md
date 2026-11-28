# tainted-open-redirect detector v1 — fifteenth real detector, tenth parser-based (round 107)

`sentinel detect --detector tainted-open-redirect` parses
the `content` string of an operator-supplied local input
record as JavaScript and tracks taint from sources to
HTTP redirect sinks, reporting one finding per distinct
sink site. It is the fifteenth real detector (after
`tainted-xpath`, round 107) and the tenth parser-based
one: it reuses the shared taint engine
(`src/detection/taint-engine.js`, extracted in round 101)
as a thin wrapper supplying its sink table and finding
metadata (CWE-601, severity high). See
`docs/parser-taint-scope-v1.md` §11 for the scoping (open
redirect was one of the three named AST classes after
tainted SSRF).

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
  `discovery_tool: 'tainted-open-redirect'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — HTTP redirects; all CWE-601, severity high):

| sink | notes |
|---|---|
| `res.redirect` | Express; the first argument is the redirect URL |
| `response.redirect` | the `response` alias for Express `res` |
| `reply.redirect` | Fastify; the first argument is the redirect URL |
| `ctx.redirect` | Koa; the first argument is the redirect URL |

Only these shapes are sinks. A bare `redirect(...)` is
deliberately NOT a sink (the name is too generic). A
three-part call (`app.res.redirect(...)`) is not
resolved. `res.render` is NOT a sink (a view name, not a
redirect URL). A `window.location` assignment is NOT a
sink in this round (an assignment shape, not a redirect
call). Other redirect shapes stay regex-covered by
`dangerous-call` — this parser is JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`res.redirect(...)`, `reply.redirect(...)`, `ctx.redirect(...)`) whose first argument (the URL) is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const r = res.redirect`, `const { redirect } = res`) with any argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean first argument is NOT
reported: the regex detector already flags that call
site, and the AST detector adds nothing. A sink call
with zero arguments cannot execute attacker data and is
not reported. Only the FIRST argument is assessed: the
two-argument form `res.redirect(status, url)` judges
only its first argument (the status, normally a
constant) — a tainted URL in second position is NOT
covered in this round, documented limitation.

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
- An aliased call IS a call: `const r = res.redirect;
  r(x)` and `const { redirect } = res; redirect(x)`
  resolve the alias to its sink. Reassigning the alias
  to a non-sink value clears it (`let r = res.redirect;
  r = 5; r(x)` is not a finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function get(u) {
  return res.redirect(u); }` called as
  `get(userInput)` flags the sink with the cross-function
  chain, and the fallback still flags the sink when the
  wrapper is never called or called only with clean
  arguments — then with the parameter chain only, and
  without claiming the wrapper is reachable from a
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
  and URL allow-list checks (`startsWith` on an
  allow-listed origin) are NOT modeled as sanitizers
  either — a guarded redirect can still be flagged;
  the finding is confidence `potential` for exactly
  this reason — the operator triages it, and the
  validator's `false_positive` verdict exists for
  exactly that. See `docs/sanitizer-modeling-v1.md`.
- **Import resolution (round 106).** This detector
  carries no import table: `res` / `response` /
  `reply` / `ctx` are request-handler parameters, not
  modules — there is nothing to resolve. See
  `docs/import-resolution-v1.md`.
- **Judged argument only.** Only the first argument
  (the URL) is judged — a tainted URL in second
  position of the two-argument form
  `res.redirect(status, url)` is not judged in this
  round. (A tainted first argument of that form — the
  status — would flag, an over-approximation of the
  single-index rule; the form is normally called with
  a constant status.)
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

- Judging the second argument of the two-argument
  `res.redirect(status, url)` form.
- `window.location` assignment as an assignment sink
  (the round-104 mechanism).
- Modeling URL allow-list checks as sanitizers.

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-open-redirect-` + the first 16 hex chars of
  SHA-256
  (`tainted-open-redirect:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
