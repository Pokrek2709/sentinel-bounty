# Inter-procedural taint v1 (round 101, Phase 5)

Round 95 built the taint engine intra-procedurally: taint
did not flow from a call site into a callee, and a sink
inside a helper was flagged only because the helper's
parameter is a source by rule — not because the call graph
was analyzed. Round 101 closes that gap on the shared
engine (`src/detection/taint-engine.js`, extracted from the
round-95/100 per-detector copies in the same round): taint
now flows across function boundaries, through return
values, and the evidence chain proves the flow. This
document is the design record: the model, the algorithm,
the guards, and what is deliberately still not resolved.

## 1. The model

Three analysis modes, in one analyzer:

- **Call-site analysis.** When a call to a known user
  function is evaluated and at least one argument is
  tainted, the callee body is analyzed with its parameters
  bound to the actual argument taints. The parameter
  binding extends the chain: the argument's chain plus
  `parameter '<name>' of function '<callee>'`. A sink
  inside the callee is then reported with a chain that
  names the whole cross-function flow, e.g.
  `parameter 'req' of function 'handle' → req.body →
  parameter 'd' of function 'parse'`.
- **Clean-call analysis.** When a call to a known user
  function has all-clean arguments, the callee is analyzed
  with clean parameters — this computes its return taint
  (a callee returning a global source such as
  `process.argv[2]` propagates taint to the caller even
  with no tainted argument). The result is memoized per
  function, separately from the tainted-arguments
  analysis.
- **Fallback (parameters-as-sources).** After a defining
  scope's walk finishes, every registered function the
  call sites did not analyze with tainted arguments is
  analyzed once with its parameters as sources — the
  round-95 behavior. This is what flags a sink inside a
  helper that is never called, or called only with clean
  arguments. The finding carries the parameter chain only
  and does not claim the helper is reachable from a
  tainted call; it stays confidence `potential`.

One finding per distinct sink call site per record, as
before. When the same sink site is reached by more than
one analysis (fallback, then a tainted call site — or the
reverse), the FIRST chain wins: the `seen` set dedupes by
`sink:line:column:kind`, so the finding is emitted once
with the first flow's chain. Which chain wins is
deterministic (registration order decides which analysis
runs first) and is pinned by a test
(`tests/inter-procedural-taint.test.js`, "when the
fallback runs first, the first (fallback) chain wins
deterministically"). The finding is the same either way;
only the chain's richness varies.

## 2. The call graph

The analyzer keeps a registry parallel to its scope
stack: each scope has a map from function name to a
call-graph record `{ node, displayName, analyzedWithTainted,
analyzedClean, fallbackDone, returnsTainted,
cleanReturnTaint }`.

- **Registration.** Function declarations are registered
  by a pre-scan of each body before it is walked
  (hoisting: a call textually before the declaration still
  resolves, because declarations are hoisted in real
  JavaScript). A function value bound to a name
  (`const run = (cmd) => ...`, `f = function(d) {...}`)
  is registered at its binding site instead of being
  analyzed immediately. A bare identifier bound to a
  registered function (`const g = parse`) carries the
  record as a function alias, so a later call `g(x)`
  resolves to `parse`.
- **Resolution.** A call `name(args)` resolves through
  the binding's function alias first, then through the
  registry (innermost scope outward). A call through a
  member (`obj.method(args)`) is NOT resolved — methods
  are analyzed with parameters-as-sources when their
  class is walked, as in round 95.
- **IIFEs.** A call whose callee is an inline function
  expression (`(function(d) {...})(x)`) is analyzed with
  the actual argument taints, with the display name
  `anonymous`.
- **Anonymous callbacks.** A function value in any other
  unbound position (an argument, a return value) is
  analyzed immediately with parameters-as-sources — a
  callback's parameters are untrusted input by
  definition.

## 3. Return taint

`analyzeFunction` returns the joined taint of the
function's return statements (tracked in a per-invocation
frame; an arrow expression body contributes its own
taint). Consequences, each pinned by a test:

- `const y = id(userInput)` where `id` returns its
  argument: `y` is tainted.
- `const y = constant(userInput)` where `constant`
  returns a literal: `y` is clean.
- `const y = readArg()` where `readArg` returns
  `process.argv[2]`: `y` is tainted (a global source
  inside the callee).
- An unknown call keeps the round-95 over-approximation:
  tainted iff any argument is tainted (chain extended
  with `callee(...)`). A sanitizer call returns clean
  regardless (see `docs/sanitizer-modeling-v1.md`).
- A memoized callee (already analyzed with tainted
  arguments) reuses its computed `returnsTainted`
  boolean: a later tainted call returns clean when the
  callee provably returns clean, and otherwise returns
  tainted with the current call's argument chain plus
  `name(...)` (the unknown-call convention — the chain
  names the current call site, not the first one).

Note: the round-95 detector doc claimed "return values
of unknown calls are clean". That was inaccurate — the
round-95 code already returned tainted for an unknown
call with a tainted argument. Round 101 corrects the doc
to match the code and makes the return-value semantics
explicit (known functions: computed; unknown calls:
over-approximation; sanitizers: clean).

## 4. Termination guards

Analysis is bounded, never a hang:

- **Active set.** A function currently being analyzed is
  on the active stack; a call to it from inside its own
  analysis (direct or mutual recursion) is treated as an
  unknown call. The fallback pass still analyzes it once
  with parameters-as-sources, so its sink is flagged.
- **Depth cap.** `MAX_CALL_DEPTH` (8) bounds nested
  call-site analyses; beyond it a call is treated as an
  unknown call. The fallback pass analyzes the deeper
  helpers with parameters-as-sources, so their sinks are
  still flagged — the cap limits chain enrichment, not
  detection. A twelve-deep wrapper chain is pinned by a
  test (it terminates with exactly one finding, whose
  chain restarts at the depth-cap boundary).
- **Memoization.** A function is analyzed at most once
  per argument shape (tainted / all-clean) plus once by
  the fallback. Re-analysis is skipped, never repeated.

## 5. Known limitations (documented, not hidden)

- **Methods are not resolved.** `obj.method(tainted)`
  does not analyze the method with the argument taints;
  methods are analyzed with parameters-as-sources when
  their class is walked. A sink inside a method is still
  flagged (via the fallback), without a call-site chain.
- **No import resolution.** `require('child_process').exec`
  and `const cp = child_process; cp.exec(...)` stay
  unresolved (the round-100 pins stand).
- **No `this` modeling.** Calls through `this` are member
  calls and are not resolved.
- **Dynamic-scope approximation.** A callee is analyzed
  with the scope stack live at the call site, so a callee
  free variable that collides with a caller local resolves
  to the caller local. Bindings are function-scoped and
  the finding is confidence `potential` for exactly this
  reason. In practice the chain is only affected when a
  free variable is the SOLE taint carrier and its name
  collides with a caller local — narrow, and the sink
  argument's own chain is unaffected.
- **First flow wins.** See §1: when the fallback analyzes
  a helper before any tainted call site is reached, the
  fallback chain is the reported one. The finding is the
  same; a topological (callers-before-callees) ordering
  is future work, not a silent gap.
- **Function aliases through destructuring are not
  tracked** (`const { parse } = helpers` does not resolve
  `parse`); only direct identifier aliases are
  (`const g = parse`, `g = parse`).
- **First argument only.** A tainted argument vector (the
  second argument of `spawn` / `execFile`) is still not
  judged; only the command (first argument) is. The
  round-100 pin stands.
- **No reachability proof.** As in round 95: a sink inside
  dead code is still flagged, and every finding is
  confidence `potential`.
