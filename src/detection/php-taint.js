// Shared PHP taint analyzer (Phase 5, round 116).
//
// The taint analysis behind the FIRST PHP detectors
// (`tainted-include`, CWE-98, and `tainted-unserialize`,
// CWE-502). It parses nothing itself — it runs over the
// PHP subset AST produced by `src/detection/php-parser.js`
// (hand-written stdlib-only, never a regex, never
// executed) and tracks taint from attacker-controlled
// sources to a sink, reporting a raw sink hit only when
// its judged value is tainted or the sink is reached
// through a `use function` alias — never carrying a
// literal value or a source line into a finding; every
// finding is confidence `potential` because the analyzer
// cannot prove the sink is reachable or
// attacker-controlled. See docs/php-parser-v1.md for the
// parser scope and docs/detection-tainted-include-v1.md /
// docs/detection-tainted-unserialize-v1.md for the
// detector docs.
//
// This is a SEPARATE analysis path: it runs on the PHP
// subset AST, NOT on the JavaScript taint engine
// (`src/detection/taint-engine.js`), which is
// JavaScript-specific — its identifiers, member
// expressions, call shapes, import forms, and source
// model are all JavaScript — and NOT on the Python
// analyzer (`src/detection/tainted-pickle.js`), whose
// sources (Flask request, `sys.argv`) and sinks are
// Python-specific. Reusing either for PHP would mean
// lying about what the analysis models. The only shared
// code is the finding-id helper (findingIdFor), the
// content / finding caps, and the finding normalizer
// (normalizeRawFinding) — all language-neutral. The
// analyzer itself is modeled on the Python analyzer's
// shape (a per-function analysis class, memoized
// inter-procedural calls, a fallback pass analyzing
// every function with all parameters tainted), adapted
// to PHP.
//
// Analysis model (PHP taint):
// - Sources: every function parameter (the round-95
//   fallback: a helper never called, or called only with
//   clean arguments, is still analyzed with parameters as
//   sources), the superglobals `$_GET` / `$_POST` /
//   `$_REQUEST` / `$_COOKIE` / `$_FILES` — bare AND
//   subscripted (the array itself is attacker input) —
//   and `file_get_contents('php://input')` with the
//   literal argument. `$_SERVER`, `$_SESSION`, `$GLOBALS`
//   and `$_ENV` are NOT sources (operator-controlled
//   configuration / session state, not attacker input) —
//   pinned by tests.
// - Taint flows through assignments (including `list()`
//   and short-list unpacking, element-wise when the value
//   is an array literal of the same length), augmented
//   assignment, foreach targets, attribute / subscript
//   access, binary / boolean / comparison / conditional /
//   coalesce expressions, casts that do not cleanse,
//   containers, interpolated-string parts, and unknown
//   function calls (a call is tainted when its receiver
//   or any argument is tainted). Branches join by union
//   (a name tainted in either branch stays tainted); a
//   loop body is analyzed once and joined the same way.
// - Inter-procedural: a call to a known function
//   propagates taint into the callee's parameters and
//   through its return value, with the chain proving the
//   flow; analyses are memoized per (function,
//   tainted-parameter mask), recursion is cut by an
//   in-progress set, and the call-graph depth is capped
//   at 8 (the JavaScript engine's cap). Function names
//   are matched by bare name, case-insensitively (PHP
//   function names are case-insensitive), on the last
//   segment of a qualified name. Methods (`$this->m()`,
//   `Foo::m()`) are NOT resolved through the call graph
//   — the same limit the JavaScript and Python engines
//   carry.
// - Sanitizers are per-detector (a config): the include
//   detector models `basename()` and the
//   `(int)` / `(float)` / `(bool)` casts plus
//   `intval` / `floatval` / `boolval`; the unserialize
//   detector models the same casts plus `(array)` and
//   `json_decode` / `json_encode`. A `(string)` cast is
//   NOT a sanitizer for either detector (the attacker
//   string passes through unchanged). Sanitizer calls
//   resolve through the `use function` bindings, so an
//   alias cleanses too.
// - Guards are per-detector (the include detector only):
//   `in_array($x, $allowed, true)` — strict `true`
//   REQUIRED — `array_key_exists($x, $allowed)` and
//   `isset($allowed[$x])` in an `if` test guard the
//   variable in the consequent branch, and a `switch
//   ($var)` with NO `default` case guards the variable
//   inside its cases. Guards intersect on branch join (a
//   guard survives only if all joined branches —
//   including the pre-branch state — have it), so a
//   guard added by one branch never leaks past the
//   construct. A judged expression is guarded iff all
//   its variable leaves are guarded (a Variable, a `.`
//   concatenation of guarded parts, an interpolated
//   string of guarded parts; a Constant counts as
//   guarded). Guards do NOT apply to the unserialize
//   detector: an allow-list check on the data does not
//   make deserializing it safe.
// - `use function` bindings are recorded and resolved
//   (`use function unserialize as u;` makes `u($x)` the
//   sink, kind `aliased-call`); a bare `unserialize`
//   always resolves to the global sink (the PHP fallback
//   for unqualified function names); `\unserialize` is a
//   sink; a qualified `Foo\unserialize` is NOT a sink.
//   Plain `use` (class imports) do not affect call
//   resolution — classes and functions live in separate
//   symbol tables in PHP.
//
// Not modeled (pinned by tests, not silently included):
// variable function calls (`$f($x)`), `call_user_func`
// / `Closure::fromCallable`, object-attribute taint
// (`$obj->field = $tainted` then read), `include` /
// `require` cross-file resolution (other files are never
// loaded), and the early-return guard shape (`if
// (!in_array(...)) return;` — the guard applies to the
// fall-through path, which this analyzer does not model;
// only the consequent-branch shape is modeled).
//
// A sink is reported in two kinds:
//   - 'tainted-arg': a direct sink whose judged value is
//     tainted.
//   - 'aliased-call': a sink reached through a `use
//     function` binding — reported with ANY argument, the
//     same rule the JavaScript and Python engines apply
//     to aliased sinks, because the binding proves the
//     call IS the sink.
// A direct sink with a clean judged value is NOT
// reported. One raw hit per distinct sink site.
//
// Safety properties (tested, not assumed): a raw hit
// carries only the sink name, position, kind, and a
// taint chain of IDENTIFIER NAMES, never a literal value
// or a source line; caps, determinism, and the
// no-regex-fallback rule are enforced by each detector's
// own envelope (mirroring tainted-pickle.js).
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const parsePhp = require('./php-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');

const SUPERGLOBALS = new Set([
  '_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES',
]);

const CLEAN = Object.freeze({ tainted: false, chain: [] });

// Call-graph depth cap (the JavaScript engine's cap).
const MAX_CALL_DEPTH = 8;

// --- AST helpers ---------------------------------------------------------

// The dotted member chain of an expression, or null when
// it is not a pure name / attribute / subscript chain
// (`Foo::bar` -> 'Foo::bar'; `$_GET['page']` -> null —
// a Variable root is not a member chain). The subscript
// index is ignored — the chain is about the rooted
// object, not the key. Static access uses `::`, instance
// access uses `.`, matching PHP's own spelling.
function memberChain(node) {
  if (!node || typeof node !== 'object') return null;
  if (node.type === 'Name' || node.type === 'QualifiedName') return node.id;
  if (node.type === 'Attribute') {
    const base = memberChain(node.value);
    if (base === null) return null;
    return `${base}${node.isStatic ? '::' : '.'}${node.attr}`;
  }
  if (node.type === 'Subscript') return memberChain(node.value);
  return null;
}

// Resolve the first segment of a dotted chain through
// the `use function` bindings (`u` -> 'unserialize' when
// `use function unserialize as u;`). A fully-qualified
// chain (leading `\`) never resolves through bindings —
// it already names the global function — and the leading
// backslash is stripped. An unbound first segment
// resolves to itself.
function resolveChain(chain, bindings) {
  if (!chain) return null;
  if (chain.startsWith('\\')) return chain.slice(1);
  const dot = chain.indexOf('.');
  const sep = chain.indexOf('::');
  let end = chain.length;
  if (dot !== -1) end = Math.min(end, dot);
  if (sep !== -1) end = Math.min(end, sep);
  const first = chain.slice(0, end);
  const bound = bindings.get(first);
  if (bound === undefined) return chain;
  return bound + chain.slice(end);
}

// The Variable node at the root of an attribute /
// subscript chain (`$_GET['page']->x` -> `$_GET`), or
// null when the root is not a variable.
function rootVariable(node) {
  let current = node;
  while (current && typeof current === 'object'
    && (current.type === 'Attribute' || current.type === 'Subscript')) {
    current = current.value;
  }
  return current && current.type === 'Variable' ? current : null;
}

// Append a name to a taint chain (no consecutive
// duplicates — `x = x` does not grow the chain).
function chainWith(chain, name) {
  if (chain.length > 0 && chain[chain.length - 1] === name) return chain;
  return [...chain, name];
}

// Is this judged expression guarded — i.e. is every
// variable leaf of it in the guard set? A Constant
// counts as guarded (it carries no attacker input); a
// Variable is guarded iff its name is in the set; a `.`
// concatenation and an interpolated string are guarded
// iff every part is. Any other shape (a Subscript, a
// Cast, a Call that is not a modeled sanitizer) is NOT
// guarded — a conservative choice, documented in the
// include detector doc.
function isGuardedExpr(node, guards) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'Constant') return true;
  if (node.type === 'Variable') return guards.has(node.name);
  if (node.type === 'BinOp' && node.op === '.') {
    return isGuardedExpr(node.left, guards)
      && isGuardedExpr(node.right, guards);
  }
  if (node.type === 'JoinedStr') {
    return (node.values || []).every(
      (part) => part.type !== 'expr' || isGuardedExpr(part.node, guards),
    );
  }
  return false;
}

// The guard variables a test expression establishes for
// its consequent branch: `in_array($x, $allowed, true)`
// (strict `true` REQUIRED — a non-strict call proves
// nothing about the type), `array_key_exists($x,
// $allowed)`, and `isset($allowed[$x])` (the subscript
// form — a bare `isset($x)` only proves definedness).
// `&&` / `and` conjunctions contribute the guards of
// every conjunct (the consequent runs only when all of
// them hold); `||` / `or`, negation, and any other shape
// contribute none. Guard calls resolve through the `use
// function` bindings, so an alias guards too.
function guardsFromTest(node, bindings) {
  const guards = new Set();
  if (!node || typeof node !== 'object') return guards;
  if (node.type === 'BoolOp' && (node.op === '&&' || node.op === 'and')) {
    for (const value of node.values || []) {
      for (const guard of guardsFromTest(value, bindings)) guards.add(guard);
    }
    return guards;
  }
  if (node.type !== 'Call') return guards;
  const chain = memberChain(node.func);
  const resolved = resolveChain(chain, bindings);
  if (resolved === 'in_array' && node.args.length >= 3) {
    const needle = node.args[0];
    const strict = node.args[2];
    if (needle && needle.type === 'Variable'
      && strict && strict.type === 'Constant'
      && strict.kind === 'boolean' && strict.value === 'true') {
      guards.add(needle.name);
    }
    return guards;
  }
  if (resolved === 'array_key_exists' && node.args.length >= 2) {
    const key = node.args[0];
    if (key && key.type === 'Variable') guards.add(key.name);
    return guards;
  }
  if (resolved === 'isset') {
    for (const arg of node.args || []) {
      if (arg && arg.type === 'Subscript'
        && arg.value && arg.value.type === 'Variable'
        && arg.slice && arg.slice.type === 'Variable') {
        guards.add(arg.slice.name);
      }
    }
    return guards;
  }
  return guards;
}

// --- Analyzer ------------------------------------------------------------

// One analysis of a function body (or the module body):
// a taint environment (name -> { tainted, chain }), the
// local `use function` bindings, and the guard set
// (names proven to be allow-list members in the current
// branch). Entries are immutable — every update replaces
// the entry, so branch clones never alias each other's
// state.
//
// `config` is the per-detector configuration:
//   checkSink(node, state) -> null | { sink, kind,
//     judged, line, column } — the detector's sink
//     predicate; `judged` is the AST node whose taint
//     decides the finding.
//   sanitizerCalls: Set of resolved bare function names
//     whose calls cleanse their argument.
//   sanitizerCasts: Set of lowercased cast type names
//     that cleanse.
//   useGuards: whether allow-list guards apply.
//   optionsGate: ((node, state) => boolean) | null —
//     true when the sink call is gated clean by its
//     options (the unserialize `allowed_classes` gate);
//     null when the detector has no options gate.
class PhpTaintAnalyzer {
  constructor(program, config) {
    this.program = program;
    this.config = config;
    // Lowercased bare name -> FunctionDef (module-level
    // and nested; a later definition wins when names
    // collide). PHP function names are case-insensitive,
    // and the parser records no namespace scoping, so
    // the bare name is the key.
    this.functions = new Map();
    // Module-level `use function` bindings: local name
    // -> dotted target ('unserialize', 'foo\bar', ...).
    this.bindings = new Map();
    this.collectDefinitions(program.body);
    // Memoized function analyses: `${name}|${mask}` ->
    // { returnsTainted }. Findings are reported to the
    // global list as they are found (deduped by site).
    this.memo = new Map();
    this.inProgress = new Set();
    this.findings = [];
    this.seenFindings = new Set();
  }

  collectDefinitions(statements) {
    for (const stmt of statements || []) {
      if (!stmt || typeof stmt !== 'object') continue;
      if (stmt.type === 'FunctionDef') {
        this.functions.set(stmt.name.toLowerCase(), stmt);
        this.collectDefinitions(stmt.body);
        continue;
      }
      if (stmt.type === 'UseDecl' && stmt.kind === 'function') {
        for (const entry of stmt.names) {
          const local = entry.alias
            || entry.name.split('\\').pop();
          this.bindings.set(local, entry.name);
        }
        continue;
      }
      // Recurse into compound statements for nested defs.
      for (const value of Object.values(stmt)) {
        if (Array.isArray(value)) this.collectDefinitions(value);
      }
    }
  }

  newState(fn) {
    const state = {
      env: new Map(),
      bindings: new Map(this.bindings),
      guards: new Set(),
      returnsTainted: false,
      functionName: fn ? fn.name : '<module>',
    };
    return state;
  }

  cloneState(state) {
    return {
      env: new Map(state.env),
      bindings: new Map(state.bindings),
      guards: new Set(state.guards),
      returnsTainted: state.returnsTainted,
      functionName: state.functionName,
    };
  }

  // Join branch states back into `state`: taint is the
  // union (a name tainted in either branch stays
  // tainted); an alias binding survives only when all
  // branches agree on it (a disagreement is dropped
  // rather than misattributed); a tainted return in
  // either branch marks the function as returning taint.
  // Guards intersect across the pre-branch state and
  // every branch — a guard survives only if all joined
  // states have it, so a guard added by one branch (an
  // `if` test's consequent guard, a `switch` guard added
  // to every case body) never leaks past the construct,
  // while a guard from an enclosing construct survives.
  joinStates(state, branches) {
    for (const branch of branches) {
      for (const [name, entry] of branch.env) {
        const current = state.env.get(name);
        if (entry.tainted && (!current || !current.tainted)) {
          state.env.set(name, entry);
        }
      }
      for (const [name, target] of [...state.bindings]) {
        if (branch.bindings.get(name) !== target) state.bindings.delete(name);
      }
      if (branch.returnsTainted) state.returnsTainted = true;
    }
    const guardSets = [state.guards, ...branches.map((b) => b.guards)];
    const kept = new Set();
    for (const guard of guardSets[0]) {
      if (guardSets.every((set) => set.has(guard))) kept.add(guard);
    }
    state.guards = kept;
  }

  addFinding(raw) {
    const key = `${raw.sink}:${raw.line}:${raw.column}:${raw.kind}`;
    if (this.seenFindings.has(key)) return;
    this.seenFindings.add(key);
    this.findings.push(raw);
  }

  analyze() {
    const moduleState = this.newState(null);
    this.walkStatements(this.program.body, moduleState, 0);
    // Fallback (the round-95 rule): every function is
    // analyzed once with ALL of its parameters tainted,
    // so a helper never called (or called only with
    // clean arguments) still reports a sink reachable
    // from a parameter. Sites already found by the
    // module-driven analysis are deduped by site.
    for (const fn of this.functions.values()) {
      const allParams = new Set(fn.params.map((p) => p.name));
      this.analyzeFunction(fn, allParams, 0);
    }
    return this.findings;
  }

  // Analyze one function with the given tainted
  // parameters; memoized per (function, mask). Returns
  // { returnsTainted }. Recursion is cut by the
  // in-progress set (a recursive call does not propagate
  // taint — a documented false negative, not a loop),
  // and the call-graph depth is capped.
  analyzeFunction(fn, taintedParams, depth) {
    const mask = [...taintedParams].sort().join(',');
    const key = `${fn.name.toLowerCase()}|${mask}`;
    if (this.memo.has(key)) return this.memo.get(key);
    if (this.inProgress.has(key) || depth > MAX_CALL_DEPTH) {
      return { returnsTainted: false };
    }
    this.inProgress.add(key);
    const state = this.newState(fn);
    for (const param of fn.params) {
      if (taintedParams.has(param.name)) {
        state.env.set(param.name, { tainted: true, chain: [param.name] });
      }
    }
    this.walkStatements(fn.body, state, depth);
    const result = { returnsTainted: state.returnsTainted };
    this.memo.set(key, result);
    this.inProgress.delete(key);
    return result;
  }

  // Bind one assignment target to a taint value. List /
  // short-list targets bind element-wise when the value
  // is an Array literal of the same length; otherwise
  // every element gets the whole value's taint (a
  // conservative approximation, documented). A foreach
  // `key => value` Pair binds both sides. Attribute /
  // Subscript targets are analyzed for nested sink calls
  // but not tracked (object-attribute taint is not
  // modeled; documented).
  bindTarget(target, taint, state) {
    if (!target || typeof target !== 'object') return;
    if (target.type === 'Variable') {
      state.env.set(target.name, {
        tainted: taint.tainted,
        chain: taint.tainted ? chainWith(taint.chain, target.name) : [],
      });
      return;
    }
    if (target.type === 'Pair') {
      this.bindTarget(target.key, taint, state);
      this.bindTarget(target.value, taint, state);
      return;
    }
    if (target.type === 'List' || target.type === 'Array') {
      const elements = target.type === 'List'
        ? target.elts
        : target.elements.map((el) => (el && el.spread ? null : el && el.value));
      // Element-wise unpacking from an Array literal.
      if (taint.node && taint.node.type === 'Array'
        && taint.node.elements.length === elements.length) {
        for (let i = 0; i < elements.length; i += 1) {
          if (elements[i] === null) continue;
          const elementNode = taint.node.elements[i];
          const elementTaint = this.analyzeExpr(elementNode.value, state, 0);
          this.bindTarget(elements[i], { ...elementTaint, node: elementNode.value }, state);
        }
        return;
      }
      for (const element of elements) {
        if (element === null) continue;
        this.bindTarget(element, taint, state);
      }
      return;
    }
    // Attribute / Subscript targets: analyze for nested
    // sink calls, do not track the write.
    this.analyzeExpr(target, state, 0);
  }

  walkStatements(statements, state, depth) {
    for (const stmt of statements || []) {
      this.walkStatement(stmt, state, depth);
    }
  }

  walkStatement(node, state, depth) {
    if (!node || typeof node !== 'object') return;
    switch (node.type) {
      case 'FunctionDef':
        // Registered in the function table; analyzed on
        // demand (a call) or by the fallback pass.
        return;
      case 'UseDecl':
      case 'Namespace':
        if (node.body) this.walkStatements(node.body, state, depth);
        return;
      case 'Declare':
        if (node.body) this.walkStatements(node.body, state, depth);
        return;
      case 'Const':
      case 'Global':
        return;
      case 'Static': {
        for (const entry of node.names || []) {
          if (entry.value) {
            const taint = this.analyzeExpr(entry.value, state, depth);
            state.env.set(entry.name, {
              tainted: taint.tainted,
              chain: taint.tainted ? chainWith(taint.chain, entry.name) : [],
            });
          }
        }
        return;
      }
      case 'Return': {
        if (node.value) {
          const taint = this.analyzeExpr(node.value, state, depth);
          if (taint.tainted) state.returnsTainted = true;
        }
        return;
      }
      case 'Expr':
        this.analyzeExpr(node.value, state, depth);
        return;
      case 'Echo':
        for (const value of node.values || []) this.analyzeExpr(value, state, depth);
        return;
      case 'Print':
      case 'Exit':
        if (node.value) this.analyzeExpr(node.value, state, depth);
        return;
      case 'Throw':
        if (node.exc) this.analyzeExpr(node.exc, state, depth);
        return;
      case 'If': {
        this.analyzeExpr(node.test, state, depth);
        const consequent = this.cloneState(state);
        for (const guard of guardsFromTest(node.test, state.bindings)) {
          consequent.guards.add(guard);
        }
        this.walkStatements(node.body, consequent, depth);
        const alternate = this.cloneState(state);
        this.walkStatements(node.orelse, alternate, depth);
        this.joinStates(state, [consequent, alternate]);
        return;
      }
      case 'Foreach': {
        const iterTaint = this.analyzeExpr(node.iter, state, depth);
        this.bindTarget(node.target, { ...iterTaint, node: node.iter }, state);
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        this.joinStates(state, [body]);
        return;
      }
      case 'For': {
        for (const part of [node.init, node.test, node.update]) {
          if (part) this.analyzeExpr(part, state, depth);
        }
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        this.joinStates(state, [body]);
        return;
      }
      case 'While':
      case 'DoWhile': {
        this.analyzeExpr(node.test, state, depth);
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        this.joinStates(state, [body]);
        return;
      }
      case 'Switch': {
        this.analyzeExpr(node.test, state, depth);
        const hasDefault = (node.cases || []).some((c) => c.test === null);
        let switchGuard = null;
        if (!hasDefault && node.test && node.test.type === 'Variable') {
          switchGuard = node.test.name;
        }
        const branches = [];
        for (const c of node.cases || []) {
          const branch = this.cloneState(state);
          if (switchGuard) branch.guards.add(switchGuard);
          if (c.test) this.analyzeExpr(c.test, branch, depth);
          this.walkStatements(c.body, branch, depth);
          branches.push(branch);
        }
        this.joinStates(state, branches);
        return;
      }
      case 'Try': {
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        const branches = [body];
        for (const handler of node.handlers || []) {
          const handlerState = this.cloneState(state);
          if (handler.name) {
            // An exception object is not tainted (it is
            // not attacker input in the modeled sources).
            handlerState.env.set(handler.name, CLEAN);
          }
          this.walkStatements(handler.body, handlerState, depth);
          branches.push(handlerState);
        }
        const finalbody = this.cloneState(state);
        this.walkStatements(node.finalbody, finalbody, depth);
        branches.push(finalbody);
        this.joinStates(state, branches);
        return;
      }
      default:
        return;
    }
  }

  analyzeExpr(node, state, depth) {
    if (!node || typeof node !== 'object') return CLEAN;
    switch (node.type) {
      case 'Constant':
        return CLEAN;
      case 'Variable': {
        if (SUPERGLOBALS.has(node.name)) {
          return { tainted: true, chain: [node.name] };
        }
        const entry = state.env.get(node.name);
        if (entry && entry.tainted) return entry;
        return CLEAN;
      }
      case 'Name':
      case 'QualifiedName':
        // A bare name as a value (a constant, a class
        // name) carries no taint.
        return CLEAN;
      case 'Attribute':
      case 'Subscript': {
        // Source check first: `$_GET['page']`,
        // `$_FILES['f']['tmp_name']` — any access rooted
        // at a superglobal is attacker input.
        const root = rootVariable(node);
        if (root && SUPERGLOBALS.has(root.name)) {
          return { tainted: true, chain: [root.name] };
        }
        const objectTaint = this.analyzeExpr(node.value, state, depth);
        if (node.type === 'Subscript' && node.slice) {
          const sliceTaint = this.analyzeExpr(node.slice, state, depth);
          if (sliceTaint.tainted) return sliceTaint;
        }
        return objectTaint;
      }
      case 'Include': {
        // The include sink is judged here (the
        // detector's checkSink decides whether this
        // Include node is a sink at all).
        const hit = this.config.checkSink(node, state);
        const valueTaint = this.analyzeExpr(node.value, state, depth);
        if (hit) {
          const guarded = this.config.useGuards
            && isGuardedExpr(hit.judged, state.guards);
          if (!guarded && valueTaint.tainted) {
            this.addFinding({
              sink: hit.sink,
              kind: hit.kind,
              line: hit.line,
              column: hit.column,
              chain: valueTaint.chain,
              functionName: state.functionName,
            });
          }
        }
        return valueTaint;
      }
      case 'Assign': {
        // Assignment IS an expression in PHP (`$a = $b =
        // 1`, `$x = $y = foo()`) — the parser wraps it in
        // an Expr statement, so it is analyzed here, not
        // in walkStatement. The expression's value is the
        // assigned value's taint.
        const taint = this.analyzeExpr(node.value, state, depth);
        for (const target of node.targets) {
          this.bindTarget(target, { ...taint, node: node.value }, state);
        }
        return taint;
      }
      case 'AugAssign': {
        const taint = this.analyzeExpr(node.value, state, depth);
        if (node.target.type === 'Variable') {
          const current = state.env.get(node.target.name) || CLEAN;
          const merged = {
            tainted: current.tainted || taint.tainted,
            chain: current.tainted ? current.chain : chainWith(taint.chain, node.target.name),
          };
          state.env.set(node.target.name, merged);
          return merged;
        }
        this.analyzeExpr(node.target, state, depth);
        return taint;
      }
      case 'BinOp':
      case 'BoolOp': {
        const parts = node.type === 'BinOp' ? [node.left, node.right] : node.values;
        for (const part of parts || []) {
          const taint = this.analyzeExpr(part, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'Compare': {
        const left = this.analyzeExpr(node.left, state, depth);
        if (left.tainted) return left;
        for (const comparator of node.comparators || []) {
          const taint = this.analyzeExpr(comparator, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'Conditional': {
        const test = this.analyzeExpr(node.test, state, depth);
        if (test.tainted) return test;
        const body = this.analyzeExpr(node.body, state, depth);
        if (body.tainted) return body;
        return this.analyzeExpr(node.orelse, state, depth);
      }
      case 'UnaryOp':
        return this.analyzeExpr(node.operand, state, depth);
      case 'Cast': {
        const valueTaint = this.analyzeExpr(node.value, state, depth);
        if (this.config.sanitizerCasts.has(String(node.castType).toLowerCase())) {
          return CLEAN;
        }
        return valueTaint;
      }
      case 'Clone':
        return this.analyzeExpr(node.value, state, depth);
      case 'PrefixIncDec':
      case 'PostfixIncDec':
        return this.analyzeExpr(node.value, state, depth);
      case 'Array': {
        for (const element of node.elements || []) {
          if (!element) continue;
          if (element.key) {
            const keyTaint = this.analyzeExpr(element.key, state, depth);
            if (keyTaint.tainted) return keyTaint;
          }
          const valueTaint = this.analyzeExpr(element.value, state, depth);
          if (valueTaint.tainted) return valueTaint;
        }
        return CLEAN;
      }
      case 'List':
      case 'Tuple': {
        for (const element of node.elts || []) {
          const taint = this.analyzeExpr(element, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'JoinedStr': {
        for (const part of node.values || []) {
          if (part.type !== 'expr') continue;
          const taint = this.analyzeExpr(part.node, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'Spread':
        return this.analyzeExpr(node.value, state, depth);
      case 'New': {
        // `new` is analyzed like a call: the class
        // expression and the constructor arguments.
        this.analyzeExpr(node.class, state, depth);
        let firstTainted = null;
        for (const arg of node.args || []) {
          const taint = this.analyzeExpr(arg, state, depth);
          if (taint.tainted && !firstTainted) firstTainted = taint;
        }
        for (const kw of node.keywords || []) {
          const taint = this.analyzeExpr(kw.value, state, depth);
          if (taint.tainted && !firstTainted) firstTainted = taint;
        }
        return firstTainted || CLEAN;
      }
      case 'Print':
      case 'Exit':
        return node.value ? this.analyzeExpr(node.value, state, depth) : CLEAN;
      case 'Call':
        return this.analyzeCall(node, state, depth);
      default:
        return CLEAN;
    }
  }

  // Analyze a call expression. Returns the taint of the
  // call's return value. Sink calls are reported as a
  // side effect (via addFinding).
  analyzeCall(node, state, depth) {
    const func = node.func;
    const chain = memberChain(func);
    const resolved = resolveChain(chain, state.bindings);
    // The receiver of a method call (`$obj->m()`): its
    // taint flows into the call's return value, and
    // nested sink calls inside it are real calls. (A
    // bare name has no receiver.)
    const receiverTaint = func.type === 'Attribute'
      ? this.analyzeExpr(func.value, state, depth)
      : CLEAN;

    // Analyze every argument once (nested sink calls
    // inside arguments are real calls too), capturing
    // each argument's taint for the sink judgment below.
    const argTaints = (node.args || []).map((arg) => this.analyzeExpr(arg, state, depth));
    const keywordTaints = (node.keywords || []).map((kw) => ({
      arg: kw.arg,
      value: kw.value,
      taint: this.analyzeExpr(kw.value, state, depth),
    }));

    // 1. Sink (the detector's checkSink decides what
    // counts — an Include node never reaches here, a
    // Call reaches here only for the unserialize
    // detector).
    const hit = this.config.checkSink(node, state);
    if (hit) {
      if (this.config.optionsGate && this.config.optionsGate(node, state)) {
        return CLEAN;
      }
      // The judged argument's taint, reused from the
      // single argument analysis above (never
      // re-analyzed — a second pass would re-report
      // nested sinks).
      let judgedTaint = CLEAN;
      if (hit.judged) {
        const argIndex = (node.args || []).findIndex(
          (arg) => arg === hit.judged
            || (arg.type === 'Spread' && arg.value === hit.judged),
        );
        if (argIndex !== -1) judgedTaint = argTaints[argIndex];
        else {
          const kwEntry = keywordTaints.find((k) => k.value === hit.judged);
          if (kwEntry) judgedTaint = kwEntry.taint;
        }
      }
      const guarded = this.config.useGuards && hit.judged
        && isGuardedExpr(hit.judged, state.guards);
      if (!guarded && (judgedTaint.tainted || hit.kind === 'aliased-call')) {
        this.addFinding({
          sink: hit.sink,
          kind: hit.kind,
          line: hit.line,
          column: hit.column,
          chain: judgedTaint.chain,
          functionName: state.functionName,
        });
      }
      return judgedTaint;
    }

    // 2. Sanitizer (a call whose result cannot carry
    // attacker input in the judged form).
    if (resolved && this.config.sanitizerCalls.has(resolved)) {
      return CLEAN;
    }

    // 3. Source: `file_get_contents('php://input')`
    // with the literal argument. This runs before the
    // known-function check on purpose: in global scope
    // a bare call to this built-in IS the built-in (a
    // user function of the same name cannot exist there
    // — redeclaring a built-in is fatal), and the
    // parser records no namespace scoping, so the
    // analysis treats all code as global scope.
    if (resolved === 'file_get_contents' && node.args.length >= 1) {
      const first = node.args[0];
      if (first && first.type === 'Constant'
        && first.kind === 'string' && first.value === 'php://input') {
        return { tainted: true, chain: ['php://input'] };
      }
    }

    // 4. `unset($x)` removes the name's taint (like the
    // Python engine's Delete); `isset` / `empty` are
    // boolean tests — their arguments were analyzed
    // above for nested sinks, and they return clean.
    if (func.type === 'Name' && func.id === 'unset') {
      for (const arg of node.args || []) {
        if (arg && arg.type === 'Variable') state.env.delete(arg.name);
      }
      return CLEAN;
    }
    if (func.type === 'Name' && (func.id === 'isset' || func.id === 'empty')) {
      return CLEAN;
    }

    // 5. Known user function (bare or fully-qualified
    // name only — methods are not resolved through the
    // call graph).
    if ((func.type === 'Name' || func.type === 'QualifiedName')
      && this.functions.has(func.id.split('\\').pop().toLowerCase())) {
      const callee = this.functions.get(func.id.split('\\').pop().toLowerCase());
      const taintedParams = new Set();
      let firstTaintedChain = null;
      const paramNames = callee.params.map((p) => p.name);
      (node.args || []).forEach((arg, index) => {
        const taint = argTaints[index] || CLEAN;
        if (taint.tainted) {
          if (!firstTaintedChain) firstTaintedChain = taint.chain;
          if (paramNames[index]) taintedParams.add(paramNames[index]);
          if (arg.type === 'Spread') {
            for (const param of callee.params) {
              if (param.kind === 'var_arg') taintedParams.add(param.name);
            }
          }
        }
      });
      for (const kw of keywordTaints) {
        if (kw.taint.tainted) {
          if (!firstTaintedChain) firstTaintedChain = kw.taint.chain;
          if (kw.arg) taintedParams.add(kw.arg);
        }
      }
      const result = this.analyzeFunction(callee, taintedParams, depth + 1);
      if (result.returnsTainted) {
        return {
          tainted: true,
          chain: chainWith(firstTaintedChain || [], func.id.split('\\').pop()),
        };
      }
      return CLEAN;
    }

    // 6. Unknown function: tainted when the receiver
    // or any argument is.
    let firstTainted = receiverTaint.tainted ? receiverTaint : null;
    for (const taint of argTaints) {
      if (taint.tainted && !firstTainted) firstTainted = taint;
    }
    for (const kw of keywordTaints) {
      if (kw.taint.tainted && !firstTainted) firstTainted = kw.taint;
    }
    return firstTainted || CLEAN;
  }
}

// --- entry point ---------------------------------------------------------

// Parse PHP source and run the taint analysis with the
// given per-detector config. Returns the raw sink hits
// ({ sink, kind, line, column, chain, functionName }).
function analyzePhp(source, config) {
  const program = parsePhp(source);
  const analyzer = new PhpTaintAnalyzer(program, config);
  return analyzer.analyze();
}

module.exports = {
  PhpTaintAnalyzer,
  analyzePhp,
  memberChain,
  resolveChain,
  rootVariable,
  isGuardedExpr,
  guardsFromTest,
  SUPERGLOBALS,
  MAX_CALL_DEPTH,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
};
