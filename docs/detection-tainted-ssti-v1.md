# tainted-ssti detector v1 — tenth real detector, fifth parser-based (round 105)

`sentinel detect --detector tainted-ssti` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to
server-side template-engine sinks, reporting one finding
per distinct sink site. It is the tenth real detector
(after `tainted-xss`, round 104) and the fifth
parser-based one: it reuses the shared taint engine
(`src/detection/taint-engine.js`, extracted in round
101) with no engine change — a thin wrapper supplying
its sink table and finding metadata (CWE-1336, severity
high). See `docs/parser-taint-scope-v1.md` §9 for the
scoping (SSTI was one of the three named AST classes
after tainted XSS).

## CWE choice: CWE-1336, not CWE-94

SSTI has two plausible CWEs. CWE-94 ("Improper Control
of Generation of Code", code injection) is the broader
parent: a template engine that evaluates attacker input
does generate code, so CWE-94 fits. CWE-1336 ("Improper
Neutralization of Special Elements Used in a Template
Engine") is the template-engine-specific CWE, created
for exactly this class — a template string that carries
attacker-controlled template syntax. The detector uses
**CWE-1336** because it names the mechanism (template
syntax neutralization) rather than the consequence (code
generation); a finding that cites CWE-94 would be
correct but less precise, and a triager reading
CWE-1336 knows immediately which neutralization failed.
The engine-specific remediation (keep templates
constant, pass data only as the render object) follows
from the same choice.

There is no dedicated evidence class for server-side
template injection in `knowledge/evidence-checklists.json`
yet, so findings use the generic checklist (the
validator falls back to the normalized raw type string
when no class matches). The detector's
`vulnerability_type` is the canonical name
`server-side template injection`.

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
  `discovery_tool: 'tainted-ssti'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — template engines; all CWE-1336, severity high):

| sink | notes |
|---|---|
| `ejs.render`, `ejs.compile` | the first argument is the template string; `compile` returns a render function, but the template string is the injection point |
| `pug.compile`, `pug.render` | the first argument is the template string |
| `nunjucks.renderString` | the first argument is the template string |
| `handlebars.compile` | the first argument is the template string |

Only these shapes are sinks. `ejs.renderFile` /
`pug.renderFile` are NOT sinks (their first argument is
a file path, not a template string — a tainted path there
is path traversal, not SSTI). `nunjucks.render` is NOT a
sink (its first argument is a template NAME, not a
template string). `res.render` is NOT a sink (an Express
view name, not a template string). A bare `render(...)`
is NOT a sink (the name is too generic). A three-part
call (`app.ejs.render(...)`) is not resolved. Other
engines' shapes stay regex-covered by
`dangerous-call` — this parser is JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink is reported

A sink is reported ONLY when it carries information the
regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`ejs.render(...)`, `pug.compile(...)`) whose first argument (the template string) is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const r = ejs.render`, `const { render } = ejs`, `const { compile } = handlebars`) with any argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean first argument is NOT
reported: the regex detector already flags that call
site, and the AST detector adds nothing. A sink call
with zero arguments cannot execute attacker data and is
not reported. Only the FIRST argument is assessed: a
tainted second argument (the data object) is not
covered — data injected into a constant template is a
different shape (the engine escapes data by design),
and judging it would flag every render of user data.
A constant template with a tainted data object
(`ejs.render("Hello <%= name %>", { name: d })`) is
therefore NOT a finding.

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
- An aliased call IS a call: `const r = ejs.render;
  r(x)` and `const { render } = pug; render(x)`
  resolve the alias to its sink. Reassigning the alias to a
  non-sink value clears it (`let r = ejs.render;
  r = 5; r(x)` is not a finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function render(t) {
  return ejs.render(t); }` called as
  `render(userInput)` flags the sink with the
  cross-function chain (`parameter 'req' of function
  'handle' → req.body → parameter 't' of function
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
  so code that validates before rendering can still
  be flagged; the finding is confidence `potential`
  for exactly this reason — the operator triages it,
  and the validator's `false_positive` verdict exists
  for exactly that. See `docs/sanitizer-modeling-v1.md`.
- **No import resolution.** A sink reached as
  `require('ejs').render(...)` is not resolved, and a
  three-part call (`app.ejs.render(...)`) is not
  resolved either. Destructuring of a fixed root
  (`const { render } = ejs`) IS resolved — that is
  not an import. Import resolution is round 106.
- **Judged argument only.** Only the first argument
  (the template string) is judged — a tainted second
  argument (the data object) is not judged in this
  round. `ejs.compile` is judged the same way: its
  template string is the first argument.
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

- Judging the data object as a tainted-arg variant
  (template-data injection into a constant template is a
  different class and needs its own rule, not a reuse of
  this one).
- `ejs.renderFile` / `pug.renderFile` as path-traversal
  sinks (their first argument is a path — the
  path-traversal detector's shape, not this one's).
- More engines (Mustache, Liquid, Marko) as sink
  classes on the same engine.
- A dedicated evidence class for server-side template
  injection in `knowledge/evidence-checklists.json`
  (currently the generic checklist applies).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-ssti-` + the first 16 hex chars of SHA-256
  (`tainted-ssti:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink site per record; at most
  100 findings per record (further matches are dropped
  and the drop is recorded in `errors`, so a truncated
  scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
