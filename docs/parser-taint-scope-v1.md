# Parser/taint scope v1 (round 95, Phase 5)

Round 90 closed the synchronous-regex detector set: five real
detectors, and the classes the regex approach cannot reach were
named but not scoped (SQL/template/LDAP/XPath injection,
path traversal, SSRF, open redirect, XXE, ReDoS — all need
taint or data-flow analysis; key management and password
storage are outside call-site reach). This document scopes
the parser/taint approach that follows: what regex cannot do
and why, what the first parser-based detector proves, and
what is deliberately NOT covered in this round.

## 1. What regex cannot do (and why)

A regex sees text. It cannot see structure, and it cannot
see flow. Four concrete gaps follow from that:

1. **Code versus prose.** A regex matches `yaml.load(` in a
   comment, a string literal, a docstring, or a test fixture
   exactly as it matches a real call. The detector can only
   report "the text is present". Only a parser — which
   distinguishes a call expression from a comment or a
   string — can refuse the prose cases.
2. **Aliased and indirect calls.** `const l = yaml.load;
   l(userInput)` and `const { load } = yaml; load(userInput)`
   never contain the text `yaml.load(`, so no call-site
   regex matches them. Only name resolution — tracking
   which identifier was bound to which sink — finds them.
3. **Taint: input reaching a sink.** `yaml.load("static")`
   and `yaml.load(req.body)` are the same call text with
   opposite risk. A regex cannot tell a literal from data
   that flowed from a source (`req.body`, `process.argv`,
   a function parameter). Only data-flow (taint) analysis
   can, by tracking which values derive from a source.
4. **Calls spread across functions.** A wrapper —
   `function parse(d) { return yaml.load(d); }` called as
   `parse(userInput)` — puts the sink in one function and
   the attacker-controlled value in another. A regex sees
   the sink text but cannot connect the two. That needs a
   call graph (inter-procedural analysis), which is out of
   scope for this round (see §4).

## 2. Approach: a small stdlib-only JavaScript parser plus intra-procedural taint

### 2.1 The parser

`src/detection/js-parser.js` is a hand-written tokenizer
plus recursive-descent parser for a defined subset of
JavaScript (see §2.2). It is a real parser — token stream,
grammar, AST nodes carrying line/column positions — not a
regex wearing an AST name. It is stdlib-only (`node:`
modules only), synchronous, deterministic, and never
executes the code it parses.

Why hand-written instead of an established parser:

- **Acorn was evaluated and not adopted this round.**
  Acorn (MIT, ~100 KB, the parser behind ESLint and
  webpack) is the natural npm choice for a full JavaScript
  grammar. It was rejected for this round for three
  reasons: (a) it is an npm dependency, and the skill
  installs and verifies offline — a dependency would need
  a vendoring story that does not exist yet; (b) every
  module in this skill is stdlib-only today, and the
  prototype's single detector class does not need a full
  grammar; (c) the subset parser is sufficient to prove
  the approach (structure + taint) on one class. Acorn
  remains the documented upgrade path: if the detector
  set grows beyond what the subset grammar covers, or a
  second language is added, adopt Acorn (vendored) instead
  of growing the hand-written grammar. That is a future
  decision, not a blocker for this round.
- **No regex fallback, ever.** If the content does not
  parse under the subset grammar, the detector counts the
  record in `skipped` with a parse error (position
  included) — it never silently falls back to scanning
  text with a regex. A partial or wrong answer presented
  as a parse is worse than no answer.

### 2.2 The subset grammar

The parser covers the constructs the taint analysis
needs, and fails loudly on the rest:

- Program, block statements, function declarations /
  expressions / arrow functions (block and expression
  bodies, `async` / `*` markers skipped), class
  declarations and expressions with method definitions
  (methods are analyzed as functions; fields are not).
- Variable declarations (`const` / `let` / `var`,
  multiple declarators, object destructuring, array
  destructuring), assignment (including compound
  `+=` etc.), `return`, `if` / `else`, `while`,
  `for` / `for...of` / `for...in`, `try` / `catch` /
  `finally`, `throw`, `switch` (cases parsed as
  statements), `break` / `continue`.
- Call expressions (including optional chaining
  `?.(`), member expressions (`.` and `[]`, including
  `?.`), `new`, `await` / `yield`, unary / binary /
  logical / conditional / update expressions.
- Literals: strings (single, double, template with
  interpolations), numbers, booleans, `null`,
  `undefined`, regex literals (tokenized as literals,
  never evaluated); object literals (shorthand and
  computed keys), array literals, spread elements.
- `import` / `export` statements are skipped
  structurally (their bindings are not tracked — a
  sink imported under its own name, e.g.
  `import { load } from 'js-yaml'`, is NOT resolved
  to `yaml.load`; see §4).
- Comments (line and block) are stripped by the
  tokenizer; string contents are single tokens. Sink
  text inside a comment or a string never becomes a
  call node — that is the point.

### 2.3 The taint analysis (intra-procedural)

The analysis runs per function scope over the AST:

- **Sources:** every function parameter is tainted
  (untrusted input by definition); member access rooted
  at `process.argv` is tainted. Nothing else is a
  source in this round.
- **Propagation:** assignment and variable declaration
  (`const x = <tainted>` taints `x`); member access on
  a tainted base (`x.y` is tainted when `x` is);
  binary / logical / conditional expressions (tainted
  when any operand is); template literals (tainted
  when any interpolation is); array / object literals
  (tainted when any element / value is); `await` and
  unary `-` / `+` / `~` (tainted when the operand is).
  `!`, `typeof`, `void`, `delete` cleanse (they produce
  a boolean or nothing, not the data).
- **Not tracked:** return values of unknown calls are
  clean (an under-approximation, documented — it
  trades missed findings for fewer false positives);
  taint does not cross function boundaries (a call
  `parse(userInput)` does not taint `parse`'s
  parameter — the sink inside `parse` is flagged
  because its parameter is a source by rule, not
  because the call site was analyzed).
- **No sanitizer modeling.** A `validate()` /
  allow-list call does not cleanse taint. That is a
  known false-positive source, documented in the
  detector doc; sanitizer modeling is future work
  (§5).

### 2.4 The first detector: `tainted-deserialize`

`src/detection/tainted-deserialize.js` proves the
approach on one class: unsafe deserialization in
JavaScript (CWE-502). Sinks: `yaml.load`,
`YAML.load`, `yaml.loadAll`, `unserialize`
(js-yaml and phpjs-style unserialize). A sink call
is reported only when it carries information the
regex detector cannot:

- a **direct** sink call whose first argument is
  tainted (evidence: the taint chain — source and
  the variable names it flowed through); or
- an **aliased** sink call (`const l = yaml.load`,
  `const { load } = yaml`) with any first argument
  (evidence: the alias binding — the regex detector
  cannot see these calls at all).

A direct sink call with a clean argument is NOT
reported: the regex detector (`dangerous-call`,
round 87) already flags that call site, and the
AST detector adds nothing. `JSON.parse` and
`yaml.safeLoad` are not sinks (safe loaders).

The detector follows the same contract as the five
regex detectors: synchronous function
`detector(input, defaults) -> { findings, skipped,
errors }` over a local content record or batch,
one finding per call site, confidence `potential`,
never executing the code, never carrying a literal
value or source line into a finding (evidence is
the sink name, position, and taint chain of
identifier names only).

## 3. What this round delivers

- This scoping document.
- `src/detection/js-parser.js`: tokenizer +
  recursive-descent subset parser.
- `src/detection/tainted-deserialize.js`: the
  `tainted-deserialize` detector (taint analysis +
  detector envelope), registered in
  `src/detection/detector.js` and in the
  `sentinel detect` CLI help.
- `docs/detection-tainted-deserialize-v1.md`: the
  detector doc.
- Tests: positive cases (tainted direct call,
  tainted `req.body`, aliased call, destructured
  alias, wrapper function, taint through assignment
  / member / template / binary), negative cases
  (literal argument, clean variable, `JSON.parse`,
  `yaml.safeLoad`, sink text in a comment and in a
  string), structural cases (parse error skips the
  record, batch records, envelope rules), and the
  no-secret rule (no literal value appears in any
  finding).

## 4. Deliberate limits of this round

- **JavaScript only.** Python (`pickle` / `marshal` /
  `shelve`) and PHP (`unserialize`) stay regex-covered
  by `dangerous-call`. A second language needs a
  second parser — that is a new round, not a flag.
- **Intra-procedural only.** No call-graph analysis:
  taint does not flow from a call site into a callee,
  and a sink inside a helper is flagged only because
  the helper's parameter is a source by rule.
- **No sanitizer modeling** (§2.3).
- **No import resolution.** A sink imported under its
  own name is not resolved to its module member.
  (`const { load } = yaml` IS resolved — that is
  destructuring of a name already in scope, not an
  import.)
- **Subset grammar.** Class fields, decorators, and
  other constructs outside §2.2 fail the parse and
  skip the record rather than being scanned
  approximately. That is the honest failure mode.
- **One detector class.** The parser and the taint
  engine are built to be reused, but this round
  ships one detector on top of them. A second
  AST-based class (for example tainted command
  execution, or tainted SQL) is a later round that
  reuses this engine — it is not smuggled into
  this one.

## 5. What comes next (not this round)

- A second AST detector class on the same engine
  (tainted command execution is the natural next
  one: the sink list exists in `dangerous-call`,
  the taint engine is the new part).
- Inter-procedural taint (call-graph analysis) for
  wrapper functions and cross-function flow.
- Sanitizer modeling (an allow-list of cleansing
  calls, with tests pinning each one).
- Acorn (vendored) if the grammar outgrows the
  subset, or a second language parser.
- Import resolution (mapping imported names to
  their module members).

## 6. Round-101 addendum (2026-11-28) — what §5's first two items became

The first two §5 items are done, and the engine is now
shared rather than copied per detector. The §4/§5 text
above is kept as written (the round-95 record); this
section is the dated update.

- **Inter-procedural taint: done (round 101).**
  `src/detection/taint-engine.js` is the single shared
  engine both parser detectors run on (the round-95/100
  per-detector copies are gone; all pre-existing tests
  still pass on it). Taint flows from a call site into a
  callee, through return values, IIFEs, and function
  aliases; a helper never called (or called only with
  clean arguments) is still analyzed once with its
  parameters as sources (the round-95 fallback). The
  chain proves the cross-function flow. See
  `docs/inter-procedural-taint-v1.md` for the model,
  the termination guards (recursion set, depth cap 8,
  memoization), and the remaining limits: methods are
  not resolved through the graph, no import resolution,
  no `this` modeling, first-flow-wins chains.
- **Sanitizer modeling: done (round 101).**
  `Number`, `parseInt`, `parseFloat`, `Boolean`,
  `Number.parseInt`, `Number.parseFloat` cleanse taint
  (their return values cannot carry a string payload);
  encoding and content-preserving calls
  (`encodeURIComponent`, `encodeURI`, `String`,
  `JSON.stringify`, string methods) do not. A user
  binding shadowing a sanitizer name disables it.
  See `docs/sanitizer-modeling-v1.md`.
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser; import resolution. The second AST detector
  class (tainted command execution) shipped in round
  100 on the same engine.

## 7. Round-103 addendum (2026-11-28) — the third AST class on the shared engine

The third AST detector class shipped in round 103, and
it is the first one built on the shared engine without
touching it: `tainted-sql` is a thin wrapper over
`createTaintDetector(config)` with only its sink table
and finding metadata (CWE-89, severity high). No engine
change was needed — the round-101 engine already carried
every behavior the new class relies on (inter-procedural
flow, return-value taint, sanitizer modeling, alias
resolution). The inter-procedural test battery now
parameterizes over all three parser-based detectors.

- **Sinks:** ten two-part member calls — `db`, `pool`,
  `connection`, `client`, `conn`, each with `query` and
  `execute`. The receiver list is the tested surface,
  not a pattern: a bare `query(...)` is deliberately
  not a sink (the name is too generic), a three-part
  call (`app.db.query(...)`) is not resolved, and
  `prepare` is not a sink in this round.
- **Parameterized queries are safe by construction:**
  only the first argument (the SQL string) is judged,
  so a constant SQL string with placeholders plus a
  parameter array is never flagged — even when the
  bound parameters are tainted. No special case is
  needed; the rule is the same first-argument rule as
  rounds 95/100.
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser; import resolution (round 106). The next AST
  class is tainted XSS (round 104).

## 8. Round-104 addendum (2026-11-28) — the fourth AST class extends the shared engine

The fourth AST detector class shipped in round 104, and
it is the first one that EXTENDS the shared engine
(round 103 needed no engine change): `tainted-xss` is a
thin wrapper over `createTaintDetector(config)` with its
sink tables and finding metadata (CWE-79, severity
high), but XSS sinks are not all calls, so the engine
gained three config-driven capabilities, all additive —
a detector that defines neither new table behaves
exactly as before (all pre-existing AST tests pass
unchanged):

- **Assignment sinks** (`assignmentSinks`): a property
  whose assignment is a sink, judged on the assigned
  value — `innerHTML` and `outerHTML`, any receiver
  (`el.innerHTML`, `document.body.innerHTML`,
  `el['innerHTML']`, `el.innerHTML += x`). Evidence
  kind `tainted-assign`, type `ast-assign`, carrying
  the assigned-to target and the property.
- **Method sinks** (`methodSinks`): calls matched by
  method name alone, whatever the receiver —
  `insertAdjacentHTML`, which exists only on DOM
  elements, so the name is distinctive enough.
- **Judged-argument index** (`argIndex` on a sink
  entry, default 0): `insertAdjacentHTML` judges its
  second argument — the HTML — because its first is
  the position constant. The round-100 "first argument
  only" pin is generalized, not dropped: one judged
  argument per sink, and a tainted argument outside
  the judged index is still not covered.

The inter-procedural test battery now parameterizes
over all four parser-based detectors.

- **Sinks:** two fixed-root calls (`document.write`,
  `document.writeln`), one method sink
  (`insertAdjacentHTML`, second argument judged), two
  assignment properties (`innerHTML`, `outerHTML`).
  `textContent` / `innerText` are safe by
  construction and are not sinks; jQuery `.html()` is
  not a sink in this round (a no-argument `.html()`
  is a getter; no jQuery modeling).
- **Deliberate exclusions, pinned by tests:** a
  three-part call (`window.document.write(...)`) is
  not resolved; a destructured method sink
  (`const { insertAdjacentHTML } = el`) is not
  resolved (the destructuring rule keys on the
  receiver name); `Object.assign` into `innerHTML`
  is not a sink; `document.write`'s second and later
  arguments are not judged.
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser; import resolution (round 106). The next AST
  class is SSTI + path traversal + SSRF (round 105).

## 9. Round-105 addendum (2026-11-28) — three AST classes on the shared engine

Three AST detector classes shipped in round 105, all
thin wrappers over `createTaintDetector(config)` with
their sink tables and finding metadata, no new sink
shape — round 104's config tables (`sinks`,
`methodSinks`, `assignmentSinks`, per-sink `argIndex`)
already cover everything these three need:

- **SSTI** (`tainted-ssti`, CWE-1336, severity high):
  template-engine sinks `ejs.render` / `ejs.compile`,
  `pug.compile` / `pug.render`,
  `nunjucks.renderString`, `handlebars.compile` —
  first argument (the template string) judged. CWE
  choice: CWE-1336 is the template-engine-specific
  CWE; CWE-94 is the broader code-injection parent
  and is less precise for SSTI (see
  `docs/detection-tainted-ssti-v1.md`). A constant
  template with a tainted data object is NOT flagged
  — only the template string is judged.
- **Path traversal** (`tainted-path-traversal`, CWE-22,
  severity high): `fs` path-taking sinks `readFile` /
  `readFileSync` / `writeFile` / `writeFileSync` /
  `createReadStream` / `createWriteStream` / `readdir` /
  `readdirSync` / `unlink` / `unlinkSync` — first
  argument (the path) judged. `path.join` does not
  sanitize (the joined path stays tainted); path
  containment checks are NOT modeled as sanitizers.
- **SSRF** (`tainted-ssrf`, CWE-918, severity high):
  outbound-request sinks `fetch`, `request`,
  `http.get` / `http.request`, `https.get` /
  `https.request`, `axios.get` / `post` / `put` /
  `delete` / `request` — first argument (the URL)
  judged. The bare names `fetch` and `request` ARE
  sinks (distinctive globals, unlike `query` or
  `render`); an options object as the first argument
  is judged as a whole (its properties' taint joins).

The inter-procedural test battery now parameterizes
over all seven parser-based detectors.

- **Engine fix (additive):** `aliasSinkOf` now resolves
  a bare-name sink bound to a new name (`const f =
  fetch`, `const f = unserialize`) as an alias of that
  sink. Before this fix only member-expression aliases
  resolved, so a bare-name sink could not be aliased
  at all. The fix checks `config.sinks[node.name]`
  before the binding lookup and only affects
  identifiers that ARE bare-name sinks; every other
  identifier resolves exactly as before, and the
  pre-existing AST detectors are unchanged (their test
  files pass unmodified).
- **Deliberate exclusions, pinned by tests:** SSTI —
  `ejs.renderFile` / `pug.renderFile` (a file path, not
  a template string), `nunjucks.render` (a template
  NAME), `res.render` (an Express view name), a bare
  `render(...)`, a three-part call, a tainted data
  object; path traversal — `fs.existsSync` (a check,
  not a sink), `fs.mkdir`, `res.sendFile`,
  `fs.promises.*` (three-part), a bare `readFile(...)`,
  a tainted second argument; SSRF — `window.fetch`,
  `XMLHttpRequest.open` (client-side), `WebSocket`,
  a three-part call, a tainted second argument, and a
  destructured alias whose name collides with a bare
  sink name (`const { request } = http` is judged as
  the bare `request` sink, not as the alias, because
  the direct-sink check runs first). A bare identifier
  literally named `get` does not parse (the round-101
  keyword limitation — `unexpected keyword get`), so a
  record calling `get(...)` directly is skipped and
  destructuring a member named `get` is unusable in
  scanned code.
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser; import resolution (round 106). The next AST
  class is tainted LDAP + XPath + open redirect
  (round 107).

## 10. Round-106 addendum (2026-11-29) — import resolution on the shared engine

The last §5 item is done. A sink reached through an
import now resolves to its canonical sink, for every
parser-based detector at once:

- **Four spellings resolve** — direct require member
  (`require('child_process').exec(d)`), namespace alias
  (`const cp = require('child_process'); cp.exec(d)`),
  destructured require (`const { exec } =
  require('child_process'); exec(d)`), and the ESM
  equivalents (`import { exec }`, `import cp from`,
  `import * as cp from`). Direct calls are judged like
  any direct sink call (finding only when the judged
  argument is tainted); aliased calls follow the alias
  rule (reported with any argument).
- **Import tables are per detector** (`moduleRoots` /
  `moduleBareSinks` in each wrapper's config, pinned by
  tests): `child_process` / `node:child_process`,
  `fs` / `node:fs`, `http` / `node:http`, `https` /
  `node:https`, `axios`, `ejs`, `pug`, `nunjucks`,
  `handlebars`, `js-yaml` → `yaml`; `request` →
  bare sink `request`, `node-fetch` → bare sink
  `fetch`. SQL and XSS carry no table (their sink roots
  are receiver names / DOM globals, not modules). Only
  `js-yaml` maps to `yaml` — the `yaml` package is not
  mapped (its API is `parse`, not `load`).
- **A bare-root identity resolves too** — an identifier
  that IS a sink root binds as that root (`const cp =
  child_process`, `const mydb = db`). This retires the
  round-100/103/104/105 pins that said those aliases
  were unresolved; the affected pin tests were updated
  (the cases moved to `tests/import-resolution.test.js`
  as positives, the comments in the detector test files
  record the move).
- **The parser tracks import bindings** (round 106):
  side-effect, default, namespace, and named imports
  (with `as` aliases) with a string-literal module
  specifier. Anything outside that set falls back to
  the pre-round-106 structural skip, so a record with
  an exotic import still scans. Import bindings are
  hoisted like function declarations. Dynamic import
  (`import('mod')`) is skipped structurally.
- **The round-105 quirk is reconciled, not changed:**
  a destructured name colliding with a bare sink
  (`request`) is judged as the bare sink, because the
  direct-sink check runs first — whether the source is
  a bare identifier or a require call.
- **Engine changes (additive, in
  `src/detection/taint-engine.js`):** bindings carry a
  fourth field (`module`: `{ kind: 'root', root }` or
  `{ kind: 'bare', sink }`); `moduleBindingOf`,
  `requireModuleName`, and `requireMemberName` resolve
  require calls, module-bound identifiers, and
  sink-root identities; `aliasSinkOf` resolves
  import-resolved members; `checkSinkCall` judges the
  canonical sink as a direct call and module-bare
  aliases as aliased calls; `bindImportDeclaration`
  binds ESM specifiers against the import tables.
- **Deliberate exclusions, pinned by tests:** dynamic
  require, a concatenated module name, an unknown
  module, a relative path, re-export (named and star),
  a module-object assignment (`module.exports =
  require(...)`), object-property indirection (the
  deep-alias pin — identifier re-aliasing propagates,
  property indirection does not), a shadowed
  `require`, and `require('pg').query` / `require('yaml').load`
  (no mapping). A bare identifier named `get` still
  does not parse (the round-101 keyword limitation).
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser. The next AST class is tainted LDAP + XPath +
  open redirect (round 107).

## 11. Round-107 addendum (2026-11-29) — three AST classes on the shared engine

Three AST detector classes shipped in round 107, all
thin wrappers over `createTaintDetector(config)` with
their sink tables and finding metadata, no engine change
— round 104's config tables (`sinks`, `methodSinks`,
`assignmentSinks`, per-sink `argIndex`) already cover
everything these three need:

- **LDAP** (`tainted-ldap`, CWE-90, severity high):
  `client.search` — the SECOND argument (the filter /
  options) judged, because ldapjs takes
  `(base, options, callback)` and the filter lives in
  `options` (a string filter, or an object whose
  properties' taint joins). The first argument (the
  search base DN) is NOT judged — a tainted base is DN
  injection, a different shape from the classic filter
  injection. Import tables: `ldapjs` / `ldapts` →
  root `client`.
- **XPath** (`tainted-xpath`, CWE-643, severity high):
  `xpath.select` / `xpath.select1` / `xpath.evaluate`,
  `document.evaluate` — first argument (the
  expression) judged. A bare `select(...)` or
  `evaluate(...)` is deliberately not a sink (both
  names are too generic). Import table: `xpath` →
  root `xpath`.
- **Open redirect** (`tainted-open-redirect`, CWE-601,
  severity high): `res.redirect` / `response.redirect`
  / `reply.redirect` / `ctx.redirect` — first argument
  (the URL) judged. No import table: the receivers are
  request-handler parameters, not modules.

The inter-procedural test battery now parameterizes
over all ten parser-based detectors.

- **Deliberate exclusions, pinned by tests:** LDAP —
  a tainted base DN, a single-argument call (no judged
  argument), `client.bind` / `add` / `modify` / `del`,
  a bare `search(...)`, a three-part call, an unknown
  module, a relative path; XPath — a tainted context
  node (second argument), a bare `select(...)` /
  `evaluate(...)`, `document.querySelector` (CSS, not
  XPath), `xpath.parse` (parses, does not evaluate), a
  three-part call; open redirect — a tainted URL in
  second position of `res.redirect(status, url)`, a
  bare `redirect(...)`, `res.render` (a view name),
  a `window.location` assignment (an assignment shape,
  not a call), a three-part call. LDAP filter escaping
  (RFC 4515) and URL allow-list checks are NOT modeled
  as sanitizers.
- **Still open from §5:** Acorn (vendored) if the
  grammar outgrows the subset, or a second language
  parser. The next step is the second-language parser
  itself: Solidity (round 108, reentrancy).

## 12. Round-108 addendum (2026-11-29) — the second language: Solidity

The second-language parser §5 left open is now built:
a hand-written stdlib-only Solidity subset parser
(`src/detection/sol-parser.js`, see
`docs/solidity-parser-v1.md`) — tokenizer +
recursive-descent, the same shape as the JavaScript
subset parser, covering contracts, state variables,
functions (constructor / receive / fallback), modifiers,
and the statements and expressions reentrancy detection
needs (including call options `{value: ...}`, tuple
declarations, and `msg.sender` / `msg.value` /
`block.timestamp` / `tx.origin`). Unsupported syntax
(assembly, try/catch, struct-constructor arguments)
fails with a named `SolParseError`, never silently
skipped.

The first Solidity detector, `solidity-reentrancy`
(CWE-841, SWC-107), runs a separate segment-based
analysis over that AST — it does NOT reuse the
JavaScript taint engine, which is JavaScript-specific.
Its envelope is its own function following
`createTaintDetector`'s pattern, because that factory's
`scanRecord` parses JavaScript and runs `TaintAnalyzer`.
Shared code is limited to the language-neutral pieces:
`findingIdFor`, the content / finding caps, and
`normalizeRawFinding`. See
`docs/detection-solidity-reentrancy-v1.md`.

- **Deliberate exclusions, pinned by tests:**
  `delegatecall` / `staticcall` are not sinks this
  round; cross-function reentrancy, storage-reference
  aliasing, cross-iteration writes, and `this.` calls
  are not modeled; base contracts from another file are
  not resolved.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset — and, by the
  same logic, `@solidity-parser/parser` (evaluated,
  not adopted this round) if the Solidity detector set
  outgrows the subset grammar. The next step is more
  Solidity classes on the same parser (round 109:
  access control).

## 13. Round-109 addendum (2026-11-29) — two Solidity access-control classes

Two more Solidity classes land on the same subset parser
(round 108's §12 "next step"), both CWE-862 (Missing
Authorization — the absence of a check, not a wrong one;
CWE-284 is the broader parent and stays out of scope
until a detector judges a check that exists):

- `solidity-access-control` (seventeenth real detector,
  second Solidity detector): an external/public function
  that performs a sensitive operation — a state write, a
  fund-moving call (`.call` / `.transfer` / `.send` on any
  receiver), a `selfdestruct`, or a `.delegatecall` — with
  no access control at all (no onlyOwner/role modifier, no
  `require(msg.sender == ...)` check, no if-revert guard),
  one finding per function on the earliest operation. See
  `docs/detection-solidity-access-control-v1.md`.
- `solidity-unprotected-initializer` (eighteenth real
  detector, third Solidity detector): an external/public
  `initialize()` with neither the `initializer` /
  `reinitializer` modifier nor any access control, one
  finding per function. Either protection alone is enough
  to stay silent. See
  `docs/detection-solidity-unprotected-initializer-v1.md`.

The guard rule is shared, not duplicated: `hasAccessControl`
in `src/detection/sol-guards.js` (modifiers allow-list,
require sender-equality / role-call, if-revert on
`msg.sender != ...`), plus `effectiveStateVars` (own +
same-file bases, transitive, cycle-guarded) — the
Solidity-side analogue of the shared JavaScript taint
engine, so the two detectors cannot drift apart on what
counts as a guard. The reentrancy detector keeps its own
copies (it predates this module); do not refactor it.

The parser grows two small additive pieces to support
these detectors: FunctionDefinition nodes now record
`visibility` (`external` / `public` / `internal` /
`private`, null when unqualified — internal by the
language default), and `revert` statements now parse
(`revert NotOwner();`, `revert("reason");`, `revert();`)
as RevertStatement nodes — the if-revert guard the
detectors recognize is now actually parseable (before
this round `revert` was a reserved word with no statement
form, so the guard could never fire through the parser).

- **Deliberate exclusions, pinned by tests:**
  `require(tx.origin == ...)` is NOT a guard (round 110
  territory); `assert`, `nonReentrant`, `whenNotPaused`,
  and `onlyInitializing` are NOT guards; a guard placed
  after the sensitive operation still counts (no
  control-flow / reachability proof); cross-function
  access control is not modeled (round 112); `this.`
  calls are not modeled; a function that is public by
  design (deposit, vote, claim) is still flagged — the
  detector cannot tell intent, and the finding is a
  candidate for manual review.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset — and, by the
  same logic, `@solidity-parser/parser` (evaluated,
  not adopted) if the Solidity detector set outgrows the
  subset grammar. The next step is more Solidity classes
  on the same parser (round 110: rounding, tx.origin,
  weak randomness).

## 14. Round-110 addendum (2026-11-29) — three Solidity classes: rounding, tx.origin, weak randomness

Three more Solidity classes land on the same subset parser
(round 109's §13 "next step"), each with its own CWE —
this round is the first where the Solidity detectors
diverge in CWE, because the flaws are different kinds:

- `solidity-rounding` (nineteenth real detector, fourth
  Solidity detector): a `*` whose operand is directly a
  `/` — division before multiplication, the division
  truncates before the multiplication runs (CWE-682
  Incorrect Calculation, severity medium), one finding
  per multiplication site. Multiply-first-divide-last
  (`x * y / z`) and bare division are clean. See
  `docs/detection-solidity-rounding-v1.md`.
- `solidity-tx-origin` (twentieth real detector, fifth
  Solidity detector): a `==` / `!=` comparison whose
  subtree contains `tx.origin`, in a function or modifier
  body (CWE-862 — the check validates the transaction
  originator, not the immediate caller — not CWE-477,
  because tx.origin is not an obsolete function; CWE-863
  is the closest sibling and is documented as considered),
  one finding per comparison site, outermost only. This
  closes the pin round 109 left behind: the
  access-control detectors deliberately do NOT treat
  `require(tx.origin == ...)` as a guard, so a function
  guarded only by tx.origin is flagged by both detectors
  — complementary, not duplicate. See
  `docs/detection-solidity-tx-origin-v1.md`.
- `solidity-weak-randomness` (twenty-first real detector,
  sixth Solidity detector): block entropy
  (`block.timestamp`, `block.number`, `blockhash(...)`,
  `block.difficulty` / `block.prevrandao`, `block.coinbase`)
  inside a hash call (`keccak256` / `sha256` / `sha3`), as
  a modulo operand, or as a seed-named initializer
  (CWE-338 Use of Cryptographically Weak PRNG, severity
  medium; CWE-337 is the closest sibling and is
  documented as considered), one finding per
  entropy-source site. Block data in a deadline check,
  deadline arithmetic, or a log is clean — the context
  restriction is the whole point. See
  `docs/detection-solidity-weak-randomness-v1.md`.

Shared this round, not duplicated: `renderExpression` in
`src/detection/sol-guards.js` — the evidence renderer all
three detectors use, so a division, a comparison, and a
block-entropy source render the same way (nested binary
children parenthesized, call arguments elided as `(...)`,
so a literal inside an argument never lands in a
finding).

The parser grows one small additive piece to support
these detectors: ContractDefinition nodes now keep their
`modifiers` (ModifierDefinition nodes with name, params,
and body). Before this round modifiers were parsed and
discarded — a contract whose only tx.origin check sat in
a modifier was invisible to every detector. A contract
without modifiers carries an empty array, not an absent
field.

- **Deliberate exclusions, pinned by tests:**
  rounding — division and multiplication in separate
  statements (needs data flow), division inside a call
  argument of a multiplied value, division before
  exponentiation, modifier bodies; tx.origin — tx.origin
  as a plain value (assigned, logged, passed as an
  argument) is clean, while `require(tx.origin !=
  address(0))` IS flagged (a null-check the detector
  cannot tell from an authorization check, false positive
  by design); weak randomness — a seed variable used
  later is not traced (no data flow), `block.gaslimit`
  is not a source, modifier bodies are not scanned.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset — and, by the
  same logic, `@solidity-parser/parser` (evaluated,
  not adopted) if the Solidity detector set outgrows the
  subset grammar. The next step is more Solidity classes
  on the same parser (round 111: oracle dependence,
  signature replay).

## 15. Round-111 addendum (2026-11-29) — two Solidity classes: oracle dependence, signature replay

Two more Solidity classes land on the same subset parser
(round 110's §14 "next step"), each with its own CWE —
the Solidity detectors keep diverging in CWE, because
the flaws are different kinds:

- `solidity-oracle-dependence` (twenty-second real
  detector, seventh Solidity detector): a single-source
  price (`getReserves`, `getAmountsOut` /
  `getAmountsIn`, `latestAnswer` / `latestRoundData`)
  used in arithmetic with no TWAP, median, or staleness
  check in the same function (CWE-829 Inclusion of
  Functionality from Untrusted Control Sphere, severity
  high — not CWE-20, which is too generic to say
  anything about trusting the source), one finding per
  price-call site. The price result is tracked to
  arithmetic name-based (direct, or through a variable
  it was assigned to — plain and tuple declarations,
  plain assignments), not by data flow. A TWAP /
  median call or a staleness check on `updatedAt` in
  the same function is clean; a price used only for
  display, only returned, or only in a comparison is
  clean. See
  `docs/detection-solidity-oracle-dependence-v1.md`.
- `solidity-signature-replay` (twenty-third real
  detector, eighth Solidity detector): a compared
  `ecrecover` authorization whose signed message
  carries no nonce, no deadline, and no EIP-712 domain
  separator (CWE-294 Authentication Bypass by
  Capture-replay, severity high — not CWE-347, because
  the signature IS verified correctly and what is
  missing is the message's uniqueness), one finding per
  ecrecover site, in function and modifier bodies.
  "Compared" means the call sits inside a `==` / `!=`
  comparison directly, or a variable it was assigned to
  appears in one; an uncompared ecrecover authorizes
  nothing and is out of scope. ANY ONE of a nonce, a
  deadline, or an EIP-712 binding in the same body is
  clean — the safe pattern is all three together, but a
  consumed nonce alone already prevents replay. See
  `docs/detection-solidity-signature-replay-v1.md`.

Shared this round, not duplicated: the name-based
assignment tracking both detectors use (a price call's
result, or an ecrecover result, bound to a variable
name and followed into arithmetic / a comparison) —
and the parser fact it exposed: a plain declaration's
initial value lives on the declarator
(`declarations[i].initialValue`, statement-level
`initialValue` null), while a tuple declaration's
lives at statement level. Both detectors read both
shapes; the first test run caught the plain-declaration
shape being missed, and the fix is pinned by the two
"compared through a variable" tests.

- **Deliberate exclusions, pinned by tests:**
  oracle dependence — comparison-only use (the price
  gates a threshold, it is not computed with), a bare
  `price()` / `spotPrice()` call (too ambiguous to name
  as a source), cross-function protection, modifier
  bodies; signature replay — an uncompared ecrecover
  (CWE-347 territory), library wrappers
  (`ECDSA.recover`, `SignatureChecker`), signature
  malleability (CWE-347 territory), a nonce consumed
  in another function.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset — and, by the
  same logic, `@solidity-parser/parser` (evaluated,
  not adopted) if the Solidity detector set outgrows the
  subset grammar. The next step is more Solidity classes
  on the same parser (round 112: unchecked external
  calls, cross-function reentrancy).

## 16. Round-112 addendum (2026-11-29) — two Solidity classes: unchecked call, cross-function reentrancy

The last two Solidity classes on the map before the
round returns to JavaScript (round 113: XXE + ReDoS).
Both run over the same subset parser and share
`walkExpression` / `renderExpression` in
`sol-guards.js`; neither touches the JavaScript taint
engine, and neither grows the parser — no new node
types, no new fields. The parser fact this round
reused is the tuple-declaration shape §15 exposed:
a plain declaration's initial value lives on the
declarator, a tuple declaration's at statement level,
and the unchecked-call detector reads both — binding
only the tuple's FIRST NAMED element, because `.call`
returns `(bool, bytes)` and only the bool says
whether the call worked.

- **Unchecked call (`solidity-unchecked-call`,
  CWE-252):** a low-level call (`.call` /
  `.delegatecall` / `.staticcall` / `.send`) whose
  return value is never checked in the same function
  or modifier body. A check is a direct check
  (require / assert / if / while / do-while / for-test
  / return) or an assigned-then-checked variable —
  name-based, so a variable bound to the call and
  mentioned in a check position anywhere later in the
  same body is clean. `.transfer` is not a sink (it
  reverts on failure); an unchecked ERC20 `transfer`
  is a separate class, pinned out of scope.
- **Cross-function reentrancy
  (`solidity-cross-function-reentrancy`, CWE-841):**
  the first detector that analyzes ACROSS functions:
  function A (external / public) performs an external
  call (`.call` / `.transfer` / `.send`) and then
  READS a state variable, while a different
  external / public function B of the same contract
  WRITES it. One finding per (call site, variable, B)
  triple. Same-file base contracts count (their state
  variables and functions are visible to the derived
  contract). The read rule is position-based — a read
  after the sink's source position, not inside the
  sink's own subtree — so a read inside a branch
  after the call counts (over-approximation, stated
  in the detector doc, unlike round 108's
  segment-based rule). The guard rule is `A guarded
  AND B guarded`: one `nonReentrant` alone is not
  enough, analyzed not assumed, and both one-sided
  cases are pinned as findings. The analysis tracks
  declaration scopes and function parameters, so a
  local or parameter shadowing a state variable is
  not a read of it.

- **Deliberate exclusions, pinned by tests:**
  unchecked call — a checked call of any of the
  forms above, `.transfer`, an unchecked ERC20
  transfer, a call inside a comment or string;
  cross-function reentrancy — a pair guarded on
  both sides, an internal reader or writer, a
  constructor or modifier as the writer, a read
  before the call only, a read inside the call's
  own arguments, a write-after-call in the same
  function (round 108 territory), a writer of a
  different variable, `delegatecall` and `this.`
  calls as sinks, a local / parameter shadowing
  the state variable.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset — and, by
  the same logic, `@solidity-parser/parser`
  (evaluated, not adopted) if the Solidity detector
  set outgrows the subset grammar. The next step is
  back to JavaScript (round 113: XXE + ReDoS), the
  first JavaScript classes since round 107.

## 17. Round-113 addendum (2026-11-29) — two JavaScript classes: XXE + ReDoS

The return to JavaScript after the Solidity set closed in
round 112 — the first JavaScript classes since round 107.
Both detectors run on the shared taint engine
(`src/detection/taint-engine.js`) as thin configs; both
are documented in `docs/detection-tainted-xxe-v1.md` and
`docs/detection-tainted-redos-v1.md`. Round 113 is the
second round to EXTEND the shared engine for a new sink
shape (round 104 was the first), and the first round to
fix the subset parser's `new` target grammar.

- **XXE (`tainted-xxe`, CWE-611, severity high):** a
  tainted XML string reaching an XML parser that
  resolves entities. Sinks: `libxmljs.parseXml` /
  `libxmljs.parseXmlString` (gated — see below),
  `parseFromString` (xmldom, method sink),
  `parseString` / `parseStringPromise` (xml2js, method
  sinks), `parser.write` (sax, fixed two-part sink).
  Only the first argument (the XML string) is judged.
  `JSON.parse` is not a sink; a bare `parseXml` is not
  a sink (only the `libxmljs` root is); a three-part
  call is not resolved. xmldom expands internal
  entities by default and does not fetch external
  entities in current versions, and xml2js (over sax)
  likewise expands internal entities by default — so a
  finding on those sinks is a potential vector needing
  version-specific verification, stated in the doc.
- **ReDoS (`tainted-redos`, CWE-1333, severity
  medium):** a tainted regex pattern reaching regex
  construction or use. Sinks: bare `RegExp` (covers
  `RegExp(tainted)` and, via the engine extension,
  `new RegExp(tainted)`), and the method sinks
  `match` / `search` / `replace` / `split` (first
  argument judged). `match` / `search` coerce a
  string argument to a RegExp, so a tainted string
  pattern is a vector; `replace` / `split` match a
  string argument literally, so only a tainted RegExp
  object is a vector there — the engine cannot tell
  the two apart, so a finding there is `potential`
  and the operator checks the pattern's type.
  `regex.test` / `regex.exec` are NOT sinks (the
  danger lives in the receiver pattern, which the
  engine cannot analyze for catastrophic
  backtracking); `matchAll` is out of the brief's
  named scope. There is NO regex-complexity analysis:
  the engine never inspects pattern text — a tainted
  pattern is flagged because the attacker controls
  it, not because the pattern is proven catastrophic
  (nested quantifiers such as `(a+)+`, `(a|a)*`,
  `(a*)*` are the documented examples of what the
  attacker could supply). A clean pattern is never
  flagged, however catastrophic it looks.

**Engine extension 1 — `dangerousOptions` (XXE).** A
sink entry may carry `{ argIndex, props }`: the finding
fires only when the named argument is an object literal
containing one of the named properties with a strictly
equal literal value (identifier key or string key).
Anything else — no such argument, a variable, an object
without the property, a non-literal value — is not a
finding: the dangerous configuration cannot be
established, and the library default is safe. The gate
applies on the direct path (`judgeSinkCall`) and on the
aliased-call path of `checkSinkCall` alike. A literal
value is inspected only for this boolean decision and
never carried into a finding. Only the libxmljs pair
uses it (`noent: true` at argument 1 — libxmljs
substitutes entities only then). The gate is
config-driven and additive: detectors that declare no
`dangerousOptions` behave exactly as before.

**Engine extension 2 — `new` expressions are
sink-checked like calls (ReDoS).** `evalExpr` now calls
`checkSinkCall` for `NewExpression` nodes as well as
`CallExpression` nodes, so `new RegExp(tainted)` flags
exactly like `RegExp(tainted)`. No earlier detector
declares a sink named like a constructor, so the change
is invisible to them. A `new` expression whose callee
is itself a call (`new (f(x))`) evaluates the callee so
a sink nested in it is still checked.

**Parser fix — `new` target grammar (ReDoS).** The
subset parser mis-parsed `new RegExp(d)` as `new
(RegExp(d))`: `parsePostfix()` greedily consumed the
argument list as a call on the callee, leaving the
NewExpression with empty arguments. `parsePostfix`
now takes `allowCalls` (default true); the `new` case
parses its callee with calls disallowed, so the callee
is a member expression (`RegExp`, `Foo.bar`,
`Foo['bar']`) and the argument list belongs to the
NewExpression — `new RegExp(d)` is a NewExpression
with callee `RegExp` and arguments `[d]`, `new
Foo.bar(d)` with callee `Foo.bar`, `new Foo()` and
`new Foo` unchanged. Call postfixes after the
NewExpression (`new Foo().bar`, `(new Foo())()`) are
still parsed by the outer postfix loop. Only the `new`
case changes behavior; every other `parsePostfix`
caller keeps the default.

- **Deliberate exclusions, pinned by tests:** XXE —
  libxmljs without the `noent: true` literal (no
  options, `noent: false`, an options object without
  `noent`, options in a variable), a bare `parseXml`,
  a non-`libxmljs` root, `.write` on anything not
  named `parser`, `JSON.parse`, `xpath.parse`,
  `document.querySelector`, a sink in a comment or
  string, an unknown / relative / dynamic require;
  ReDoS — a clean pattern (however catastrophic it
  looks), a sanitized pattern, a tainted second
  argument (`RegExp` flags, `replace`'s replacement),
  `test` / `exec` / `matchAll`, a three-part
  `window.RegExp`, `RegExp` as a value (not a call),
  arbitrary constructors (`new Foo`, `new Date`), a
  sink in a comment or string, an unmapped module
  member.
- **Still open from §5:** Acorn (vendored) if the
  JavaScript grammar outgrows the subset. The next
  step is round 114 (prototype pollution), the last
  JavaScript class on the approved map before the
  language rounds (Python, PHP).
