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
