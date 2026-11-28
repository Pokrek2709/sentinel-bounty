# Detection — tainted-prototype-pollution (round 114)

Twenty-eighth real detector, thirteenth parser-based one.
`--detector tainted-prototype-pollution`.

## Rule

An attacker-controlled object (or key) that reaches an
unsafe property-writing sink is prototype pollution
(CWE-1321 Improperly Controlled Modification of
Object Prototype Attributes — the pollution CWE, not
CWE-400, because the flaw is the prototype modification
itself, not the resource exhaustion a polluted prototype
may later cause), severity high, one finding per sink
site, never carrying a literal value or source line into
a finding; every finding is confidence `potential`
because the detector cannot prove the call is reachable
or attacker-controlled.

## Sinks

The detector reuses the shared taint engine
(`src/detection/taint-engine.js`,
`createTaintDetector`) with its own sink table:

| Sink | Judged argument | Kind |
| --- | --- | --- |
| `Object.assign(target, ...sources)` | every source from index 1 | `tainted-arg` |
| `_.merge(target, ...sources)` | every source from index 1 | `tainted-arg` |
| `_.defaultsDeep(target, ...sources)` | every source from index 1 | `tainted-arg` |
| `_.set(object, path, value)` | the path (index 1) | `tainted-arg` |
| `$.extend(deep, target, ...sources)` | every source from index 2 | `tainted-arg` |
| `merge(target, ...sources)` (deepmerge) | every source from index 1 | `tainted-arg` |
| `merge.all([...])` (deepmerge) | index 0 | `tainted-arg` |
| dynamic-key assignment `obj[key] = value` / `obj[key] += value` | the key | `tainted-key-assign` |
| assignment with a dangerous key chain (`o.__proto__.polluted = 1`, `o[a].__proto__ = ...`) | the target chain | `dangerous-key-assign` |
| tainted object spread `{ ...tainted }` | the spread argument | `tainted-spread` |

A sink call through an alias (`const m = _.merge;
m({}, d)`) reports kind `aliased-call` with any
argument, like every other parser-based detector.
Import resolution (round 106) applies: lodash maps
to root `_`, jquery to `$`, deepmerge to bare sink
`merge` — `require('lodash').merge`, `const _ =
require('lodash')`, `import { merge } from 'lodash'`,
`import merge from 'deepmerge'` all resolve to their
canonical sink. See `docs/import-resolution-v1.md`.

## What is flagged

- **A tainted source merged into any target:**
  `Object.assign({}, req.body)`, `_.merge({}, d)`,
  `merge({}, d)`, `$.extend(true, {}, d)` — the merge
  copies the attacker's keys, including `__proto__`,
  into the target (or its prototype chain, for the
  deep variants).
- **A tainted key written dynamically:**
  `obj[req.body.key] = v` — the attacker chooses the
  property name; `__proto__` as the key pollutes the
  prototype.
- **A dangerous key chain, literal or tainted:**
  `o.__proto__.polluted = 1`, `o[a].__proto__ = x`,
  `o.constructor.prototype.polluted = 1` — the chain
  reaches the prototype regardless of taint, so the
  finding does not need a tainted argument. The rule
  is: `__proto__` anywhere in the chain, a consecutive
  `constructor` → `prototype` pair, or the root
  `Object.prototype`. A lone leaf `constructor` or
  `prototype` is clean (`Foo.prototype.constructor =
  Foo`, `fn.prototype = {}`), because assigning the
  constructor property or replacing a function's own
  prototype object does not pollute `Object.prototype`.
- **A tainted spread:** `{ ...d }` — the spread copies
  the attacker's own properties into a fresh object.
  The finding is conservative and documented as such:
  spreading `__proto__` copies it as an own property,
  it does not change the new object's prototype — so a
  spread alone pollutes only when the result is later
  merged unsafely. The detector flags it anyway,
  because a tainted spread into a merge target is the
  same data flow the merge sinks flag.

## What is NOT flagged

- **A static, known-safe key:** `obj.name = v`,
  `obj['safe'] = v`.
- **A null-prototype target:** `Object.assign(Object.
  create(null), d)`, `_.merge(Object.create(null), d)`
  — an object with no prototype cannot be polluted
  through its prototype chain (the null-prototype
  binding is tracked through identifiers, copies, and
  branch joins). `$.extend` has NO null-prototype
  exemption, because its deep flag sits in the first
  argument and the target position is ambiguous.
- **A merge that filters dangerous keys:** a merge
  preceded in the same function by an explicit check
  that rejects `__proto__`, `constructor`, or
  `prototype` as a key (`if (key === '__proto__')
  return;`, a key-filter call) is clean. The check is
  name-based: the literal key name must appear in the
  check.
- **`Object.freeze` on the prototype:** a merge in a
  function that calls `Object.freeze(Object.prototype)`
  (or freezes a `.prototype` member) is clean — the
  prototype cannot be written after freezing.
- **A clean source:** `Object.assign({}, {})`,
  `_.merge({}, { a: 1 })`.
- **A sanitized key:** a key passed through a
  sanitizer (`Number`, `parseInt`, `parseFloat`,
  `Boolean`, `encodeURIComponent`, `encodeURI`) is
  clean, like every other detector.
- **Assignment to a safe member of a dangerous chain:**
  `o.__proto__ = {}` assigns the prototype itself
  (not a property on it) and is clean; `o.
  constructor = C` assigns the constructor property
  and is clean. Only a write THROUGH the chain
  (`o.__proto__.polluted`, `o.constructor.prototype.
  polluted`) flags.

## Engine changes (round 114, third engine extension)

The shared engine gained four additive, config-driven
capabilities, in `src/detection/taint-engine.js`:

1. **`argIndexFrom` per sink entry** — judge every
   argument from that index onward (multi-source merge
   sinks: `Object.assign` / `_.merge` /
   `_.defaultsDeep` / `merge` from 1, `$.extend` from
   2). The single-index `argIndex` still applies
   where present.
2. **`flagAssignmentKeys`** — a computed-key
   assignment whose key is tainted reports kind
   `tainted-key-assign`, and an assignment whose
   target chain is dangerous reports kind
   `dangerous-key-assign` (the `__proto__` /
   `constructor` → `prototype` / `Object.prototype`
   rule above). A tainted key on a null-prototype
   target is suppressed.
3. **`flagTaintedSpread`** — a tainted object spread
   reports kind `tainted-spread`.
4. **`nullProtoTargetSafe` per sink entry + null-
   prototype binding tracking** — a sink whose target
   argument is a null-prototype object (via
   `Object.create(null)`, an identifier copy, or a
   branch join) is suppressed for key findings and
   merge sinks.
5. **`renderMember` extended** — a computed key that
   is itself a member expression (`o[d.key]`) renders
   instead of collapsing to the fallback, so evidence
   targets stay precise.

The alias check now runs BEFORE the bare-sink check
in `checkSinkCall` — round 114 overturns the
round-105 collision rule. A destructured alias whose
name collides with a bare sink name (`const { merge }
= _` vs the bare `merge` deepmerge sink) is judged as
the ALIAS, not as the bare sink. The old rule
misattributed the sink and suppressed the alias
finding for clean arguments; see
`docs/import-resolution-v1.md` and the §18 addendum
in `docs/parser-taint-scope-v1.md`. The earlier
detectors are unchanged except for that check order:
the SSRF colliding case (`const { request } = http`)
now reports sink `http.request`, kind `aliased-call`,
with any argument — the pinned test and docs were
updated in the same round.

## What is NOT modeled (pinned by tests)

- **Key-path splitting and loop assignment** —
  `key.split('.')` followed by a loop that assigns
  each segment is not tracked: the engine has no
  data-flow model for a string split into path
  segments. A tainted key that is split and then
  assigned segment-by-segment is a false negative.
- **A filter in a helper function** — a key filter
  that lives in another function (or a helper that
  sanitizes keys) is not modeled; only a filter in
  the same function body suppresses the finding.
  Cross-function filtering is the inter-procedural
  engine's taint flow, not a guard model.
- **A `__proto__` key inside a variable or a spread
  helper** — a dangerous key carried in a variable
  (`const k = '__proto__'; obj[k] = v`) is flagged
  only if the variable is tainted; a literal
  dangerous key stored in a variable is NOT flagged
  (no constant propagation). The `dangerous-key-
  assign` kind covers only literal chains in the
  target expression.
- **A bare `set` call** — `set` is a parser keyword
  (the round-101 limitation, like `get`), so a record
  calling a destructured `_.set` bare (`const { set }
  = require('lodash'); set({}, p, 1)`) does not parse
  at all and is skipped, never scanned silently. The
  member form (`_.set(...)`) parses and resolves
  normally.
- **Deep-merge depth and recursion** — the detector
  does not model how deep a merge recurses; a shallow
  `Object.assign` of a tainted source is flagged the
  same as a deep `_.merge`, even though only the deep
  merge reaches a nested `__proto__`.
- **Prototype pollution via JSON parsing** — a tainted
  JSON string parsed with `JSON.parse` and then merged
  is flagged at the merge, not at the parse; the
  parse itself is not a sink.
- **A user-defined `merge` function** — a bare
  `merge(...)` call with no import binding is judged
  as the deepmerge sink by name (the same
  name-based over-approximation as bare `fetch` in
  SSRF). An imported `merge` resolves through its
  import binding instead.

## Tests

`tests/tainted-prototype-pollution.test.js` — 27 tests:
positive merge sinks (all seven call sinks, aliased
calls, import-bound lodash/jquery/deepmerge), dynamic-
key assignment, dangerous key chains, tainted spread,
inter-procedural flow through helpers, and negatives
(static keys, null-prototype targets, key filters,
`Object.freeze`, clean sources, sanitized keys, safe
chain leaves). The inter-procedural battery in
`tests/inter-procedural-taint.test.js` runs the
detector through its shared cases (`Object.assign({},
arg)`, CWE-1321). Import-resolution cases live in
`tests/import-resolution.test.js` (lodash/jquery/
deepmerge require + ESM, the colliding `merge`
alias, the bare-`set` keyword pin).
