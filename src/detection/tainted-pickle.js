// Twenty-ninth REAL detector (Phase 5, round 115): tainted-pickle.
//
// The FIRST Python detector. It parses the `content`
// string of a local input record as Python (hand-written
// stdlib-only subset parser, `src/detection/py-parser.js`
// — never a regex, never executed) and tracks taint to
// unsafe deserialization sinks (pickle.load / loads,
// marshal.load / loads, yaml.load without a safe Loader,
// shelve.open), reporting a sink call only when its
// judged argument is tainted or the call is reached
// through an alias — never carrying a literal value or a
// source line into a finding; every finding is confidence
// `potential` because the detector cannot prove the call
// is reachable or attacker-controlled. See
// docs/python-parser-v1.md for the parser scope and
// docs/detection-tainted-pickle-v1.md for the detector doc.
//
// This is a SEPARATE analysis path: it runs on the Python
// subset AST, NOT on the JavaScript taint engine
// (`src/detection/taint-engine.js`), which is
// JavaScript-specific — its identifiers, member
// expressions, call shapes, import forms, and source
// model are all JavaScript. Reusing it for Python would
// mean lying about what the engine models. The only
// shared code is the finding-id helper (findingIdFor),
// the content / finding caps, and the finding normalizer
// (normalizeRawFinding) — all language-neutral. Even the
// envelope is its own function following
// createTaintDetector's pattern, because that factory's
// scanRecord parses JavaScript and runs TaintAnalyzer;
// this detector's scanRecord parses Python instead. The
// CLI and the finding record look identical to a caller
// either way.
//
// Analysis model (Python taint, modeled on the shared
// JavaScript engine's rules — round 101's inter-procedural
// pass and sanitizer modeling, adapted to Python):
// - Sources: every function parameter (the round-95
//   fallback: a helper never called, or called only with
//   clean arguments, is still analyzed with parameters as
//   sources), `input()`, `sys.argv` (any member /
//   subscript of it), and Flask `request.args` / `form` /
//   `data` / `json` / `values` / `files` / `cookies` /
//   `get_json()` / `get_data()` (also via `flask.request`
//   and a `from flask import request as <alias>` binding).
//   `os.environ` is NOT a source (operator-controlled
//   configuration, not attacker input) — pinned by tests.
// - Taint flows through assignments (including tuple
//   unpacking), augmented assignment, for-loop targets,
//   with-targets, attribute / subscript access, binary /
//   boolean / comparison / conditional expressions,
//   containers, f-string interpolations, and unknown
//   function calls (a call is tainted when any argument
//   is tainted). Branches join by union (a name tainted
//   in either branch stays tainted); a loop body is
//   analyzed once and joined the same way.
// - Inter-procedural: a call to a known module-level (or
//   nested) function propagates taint into the callee's
//   parameters and through its return value, with the
//   chain proving the flow; analyses are memoized per
//   (function, tainted-parameter mask), recursion is cut
//   by an in-progress set, and the call-graph depth is
//   capped at 8 (the JavaScript engine's cap). Methods
//   (`self.helper(...)`) are NOT resolved through the
//   call graph — the same limit the JavaScript engine
//   carries.
// - Sanitizers (the allow-list, mirroring the JavaScript
//   engine's): `int`, `float`, `str`, `bool`, `len`,
//   `hash`, `repr`, `json.loads`, `json.load`,
//   `int.from_bytes`, and the methods `.decode()` /
//   `.hex()` (bytes -> str, so the result cannot be
//   unpickled as attacker bytes). Encoding and
//   content-preserving calls do not cleanse.
//
// Sinks (Python): pickle.load / loads, marshal.load /
// loads, yaml.load, shelve.open. `yaml.safe_load` /
// `safe_load_all` and `json.loads` / `json.load` are NOT
// sinks. `pickle.Unpickler(...).load()` and `dill` are
// out of scope this round (pinned by tests, not silently
// included). A bare `loads(...)` with no import binding
// is NOT a sink — `json.loads` is the commonest `loads`,
// so a name-based bare sink would misattribute it (unlike
// JavaScript's bare `unserialize`, which is distinctive).
//
// A sink call is reported in two kinds:
//   - 'tainted-arg': a direct member call (`pickle.loads`)
//     whose judged argument is tainted.
//   - 'aliased-call': a sink reached through a name
//     binding (`from pickle import loads`, `ld =
//     pickle.loads`) — reported with ANY argument, the
//     same rule the JavaScript engine applies to aliased
//     sinks, because the binding proves the call IS the
//     sink.
// A direct sink call with a clean argument is NOT
// reported. `yaml.load` with a `Loader=yaml.SafeLoader`
// (or `CSafeLoader`, or the bare names when bound by a
// from-import) is clean; any other Loader, or no Loader
// at all, is flagged (the classic unsafe pattern —
// modern PyYAML raises without a Loader, so the finding
// is about the pattern, and the doc says so).
//
// Safety properties (tested, not assumed): a finding
// carries only the sink name, position, and a taint chain
// of IDENTIFIER NAMES, never a literal value or a source
// line; one finding per distinct sink call site per
// record; caps, determinism, and the no-regex-fallback
// rule are enforced by this module's own envelope.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const parsePython = require('./py-parser.js');
const { PyParseError } = require('./py-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');
const { normalizeRawFinding } = require('./normalized-record.js');

const DETECTOR_NAME = 'tainted-pickle';

// Canonical sink name -> { label, judged keyword name }.
// The judged argument is positional argument 0, or the
// named keyword when no positional argument is given.
const SINKS = {
  'pickle.load': { label: 'pickle.load() call', keyword: 'file' },
  'pickle.loads': { label: 'pickle.loads() call', keyword: 'data' },
  'marshal.load': { label: 'marshal.load() call', keyword: 'file' },
  'marshal.loads': { label: 'marshal.loads() call', keyword: 'data' },
  'yaml.load': { label: 'yaml.load() call', keyword: 'stream', loaderGate: true },
  'shelve.open': { label: 'shelve.open() call', keyword: 'filename' },
};

// Loader values that make `yaml.load` safe (after
// resolving the value through the import bindings, so
// `from yaml import SafeLoader` and `yaml.SafeLoader`
// both resolve here).
const SAFE_LOADERS = new Set([
  'yaml.SafeLoader',
  'yaml.CSafeLoader',
  'SafeLoader',
  'CSafeLoader',
]);

// Sanitizer calls: the result cannot be unpickled as
// attacker bytes (a scalar, or data parsed from a
// data-only format). Resolved through the import
// bindings, so `import json as j; j.loads(x)` cleanses
// too.
const SANITIZER_CALLS = new Set([
  'int', 'float', 'str', 'bool', 'len', 'hash', 'repr',
  'json.loads', 'json.load', 'int.from_bytes',
]);

// Sanitizer methods (bytes -> str).
const SANITIZER_METHODS = new Set(['decode', 'hex']);

// Flask request attributes that carry attacker input
// (any member / subscript of one of these is tainted).
const REQUEST_ATTRS = new Set([
  'args', 'form', 'data', 'json', 'values', 'files',
  'cookies', 'get_json', 'get_data',
]);

const CLEAN = Object.freeze({ tainted: false, chain: [] });

// Call-graph depth cap (the JavaScript engine's cap).
const MAX_CALL_DEPTH = 8;

const IMPACT = 'These calls reconstruct objects from untrusted bytes, so attacker-controlled input reaching them can instantiate arbitrary classes and execute code during deserialization (pickle and marshal execute arbitrary code by design; yaml.load without a safe Loader does the same for YAML tags; shelve unpickles values on read).';
const REMEDIATION = 'Never deserialize untrusted input with these calls: use a data-only format (JSON) or a safe loader (yaml.safe_load, pickle only on bytes you produced yourself) and validate the result before use.';
const PY_LANGUAGES = new Set(['python', 'py']);

// --- AST helpers ---------------------------------------------------------

// The dotted member chain of an expression, or null when
// it is not a pure name / attribute / subscript chain
// (`sys.argv[1]` -> 'sys.argv'; `request.args.get` ->
// 'request.args.get'). The subscript index is ignored —
// the chain is about the rooted object, not the key.
function memberChain(node) {
  if (!node || typeof node !== 'object') return null;
  if (node.type === 'Name') return node.id;
  if (node.type === 'Attribute') {
    const base = memberChain(node.value);
    return base === null ? null : `${base}.${node.attr}`;
  }
  if (node.type === 'Subscript') return memberChain(node.value);
  return null;
}

// Resolve the first segment of a dotted chain through
// the import bindings (`pk.loads` -> 'pickle.loads' when
// `pk` is bound to 'pickle'; `loads` -> 'pickle.loads'
// when bound by a from-import). An unbound first segment
// resolves to itself.
function resolveChain(chain, bindings) {
  if (!chain) return null;
  const dot = chain.indexOf('.');
  const first = dot === -1 ? chain : chain.slice(0, dot);
  const bound = bindings.get(first);
  if (bound === undefined) return chain;
  return dot === -1 ? bound : bound + chain.slice(dot);
}

// Is this resolved chain a taint source? Returns the
// source name, or null. `sys.argv` (any suffix) and
// Flask request attributes (via `request`, `flask.request`,
// or a `from flask import request as <alias>` binding —
// the binding is already applied by resolveChain, so the
// chain arrives as 'flask.request.args', ...).
function sourceOfChain(chain) {
  if (!chain) return null;
  if (chain === 'sys.argv' || chain.startsWith('sys.argv.')) return 'sys.argv';
  const parts = chain.split('.');
  let rest = null;
  if (parts[0] === 'request') rest = parts.slice(1);
  else if (parts[0] === 'flask' && parts[1] === 'request') rest = parts.slice(2);
  if (rest && rest.length > 0 && REQUEST_ATTRS.has(rest[0])) return 'request';
  return null;
}

// Append a name to a taint chain (no consecutive
// duplicates — `x = x` does not grow the chain).
function chainWith(chain, name) {
  if (chain.length > 0 && chain[chain.length - 1] === name) return chain;
  return [...chain, name];
}

// --- Analyzer ------------------------------------------------------------

// One analysis of a function body (or the module body):
// a taint environment (name -> { tainted, chain }) and
// the local import bindings. Entries are immutable —
// every update replaces the entry, so branch clones
// never alias each other's state.
class PyTaintAnalyzer {
  constructor(program) {
    this.program = program;
    // name -> FunctionDef (module-level and nested; a
    // later definition wins when names collide).
    this.functions = new Map();
    // Module-level import bindings: local name ->
    // dotted target ('pickle', 'pickle.loads',
    // 'flask.request', 'sys.argv', ...).
    this.bindings = new Map();
    this.collectDefinitions(program.body);
    // Module-level alias bindings from assignments
    // (`p = pickle`, `ld = pickle.loads`), collected in
    // source order before any analysis so function
    // analyses see them. Flow-insensitive may-alias: a
    // name rebound in a branch keeps its sink binding.
    this.collectModuleAliases();
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
        this.functions.set(stmt.name, stmt);
        this.collectDefinitions(stmt.body);
        continue;
      }
      if (stmt.type === 'Import') {
        for (const entry of stmt.names) {
          this.bindings.set(entry.alias || entry.module.split('.')[0], entry.module);
        }
        continue;
      }
      if (stmt.type === 'ImportFrom' && stmt.level === 0 && stmt.module) {
        for (const entry of stmt.names) {
          this.bindings.set(entry.alias || entry.name, `${stmt.module}.${entry.name}`);
        }
        continue;
      }
      // Recurse into compound statements for nested defs.
      for (const value of Object.values(stmt)) {
        if (Array.isArray(value)) this.collectDefinitions(value);
      }
    }
  }

  // Module-level alias bindings from assignments
  // (`p = pickle`, `ld = pickle.loads`), collected in
  // source order before any analysis so function
  // analyses see them. Flow-insensitive may-alias: a
  // name rebound in a branch keeps its sink binding.
  collectModuleAliases() {
    for (const stmt of this.program.body || []) {
      if (stmt.type !== 'Assign' && stmt.type !== 'AnnAssign') continue;
      const targets = stmt.type === 'Assign' ? stmt.targets : [stmt.target];
      const value = stmt.value;
      if (!value || targets.length !== 1) continue;
      const target = targets[0];
      if (!target || target.type !== 'Name') continue;
      const probe = {
        env: new Map(), bindings: this.bindings,
        returnsTainted: false, functionName: '<module>',
      };
      const resolved = this.resolveBindingTarget(value, probe);
      if (resolved) this.bindings.set(target.id, resolved);
    }
  }

  // Import bindings declared inside one function body
  // (flow-insensitive: collected regardless of the branch
  // they sit in, exactly like the module-level table).
  collectFunctionImports(statements, bindings) {
    for (const stmt of statements || []) {
      if (!stmt || typeof stmt !== 'object') continue;
      if (stmt.type === 'Import') {
        for (const entry of stmt.names) {
          bindings.set(entry.alias || entry.module.split('.')[0], entry.module);
        }
        continue;
      }
      if (stmt.type === 'ImportFrom' && stmt.level === 0 && stmt.module) {
        for (const entry of stmt.names) {
          bindings.set(entry.alias || entry.name, `${stmt.module}.${entry.name}`);
        }
        continue;
      }
      for (const value of Object.values(stmt)) {
        if (Array.isArray(value)) this.collectFunctionImports(value, bindings);
      }
    }
  }

  newState(fn) {
    const state = {
      env: new Map(),
      bindings: new Map(this.bindings),
      returnsTainted: false,
      functionName: fn ? fn.name : '<module>',
    };
    if (fn) this.collectFunctionImports(fn.body, state.bindings);
    return state;
  }

  cloneState(state) {
    return {
      env: new Map(state.env),
      bindings: new Map(state.bindings),
      returnsTainted: state.returnsTainted,
      functionName: state.functionName,
    };
  }

  // Join branch states back into `state`: taint is the
  // union (a name tainted in either branch stays
  // tainted); an alias binding survives only when both
  // branches agree on it (a disagreement is dropped
  // rather than misattributed); a tainted return in
  // either branch marks the function as returning taint.
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
    // Aliases discovered during the module walk (for
    // example inside a module-level branch) become
    // visible to function analyses too.
    for (const [name, target] of moduleState.bindings) {
      if (!this.bindings.has(name)) this.bindings.set(name, target);
    }
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
    const key = `${fn.name}|${mask}`;
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

  // Bind assignment targets to a taint value. Tuple
  // targets bind element-wise when the value is a Tuple
  // of the same length; otherwise every target gets the
  // whole value's taint (a conservative approximation,
  // documented). A single Name target whose value
  // resolves to a module or a sink also records an
  // alias binding (`p = pickle`, `ld = pickle.loads`).
  bindTargets(targets, taint, state) {
    if (!targets) return;
    const list = targets.type === 'Tuple' ? targets.elts : [targets];
    // Element-wise tuple unpacking.
    if (list.length > 1 && taint.node && taint.node.type === 'Tuple'
      && taint.node.elts.length === list.length) {
      for (let i = 0; i < list.length; i += 1) {
        const elementTaint = this.analyzeExpr(taint.node.elts[i], state, 0);
        this.bindTargets(list[i], { ...elementTaint, node: taint.node.elts[i] }, state);
      }
      return;
    }
    for (const target of list) {
      if (!target) continue;
      if (target.type === 'Name') {
        state.env.set(target.id, {
          tainted: taint.tainted,
          chain: taint.tainted ? chainWith(taint.chain, target.id) : [],
        });
        // Alias binding: `p = pickle`, `ld = pickle.loads`.
        if (taint.node) {
          const aliasTarget = this.resolveBindingTarget(taint.node, state);
          if (aliasTarget) state.bindings.set(target.id, aliasTarget);
        }
        continue;
      }
      if (target.type === 'Tuple' || target.type === 'List') {
        // Nested unpacking: every element gets the
        // whole value's taint (no element-wise mapping
        // without a matching Tuple value).
        this.bindTargets(target, taint, state);
        continue;
      }
      if (target.type === 'Starred') {
        this.bindTargets(target.value, taint, state);
        continue;
      }
      // Attribute / Subscript targets: the taint flows
      // into the object, not into a name — analyze the
      // target expression for nested sink calls, but do
      // not track the write (object-attribute taint is
      // not modeled; documented).
      this.analyzeExpr(target, state, 0);
    }
  }

  // The dotted target a value expression resolves to
  // when it is a module or a sink (`pickle`,
  // `pickle.loads`, `loads` bound by a from-import), or
  // null when it is neither. Used for alias bindings.
  resolveBindingTarget(node, state) {
    if (!node || typeof node !== 'object') return null;
    const chain = memberChain(node);
    if (!chain) return null;
    const resolved = resolveChain(chain, state.bindings);
    if (!resolved) return null;
    if (SINKS[resolved]) return resolved;
    // A module name is a bare dotted name that is a
    // prefix of a sink, or a binding target itself.
    const first = resolved.split('.')[0];
    if (state.bindings.has(first) && resolved === state.bindings.get(first)) return resolved;
    if (Object.keys(SINKS).some((sink) => sink.startsWith(`${resolved}.`))) return resolved;
    return null;
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
      case 'Import':
      case 'ImportFrom':
        // Bindings are collected up front (module-level
        // and per-function); nothing to do at walk time.
        return;
      case 'Return': {
        if (node.value) {
          const taint = this.analyzeExpr(node.value, state, depth);
          if (taint.tainted) state.returnsTainted = true;
        }
        return;
      }
      case 'Assign': {
        const taint = this.analyzeExpr(node.value, state, depth);
        for (const target of node.targets) {
          this.bindTargets(target, { ...taint, node: node.value }, state);
        }
        return;
      }
      case 'AnnAssign': {
        if (node.value) {
          const taint = this.analyzeExpr(node.value, state, depth);
          this.bindTargets(node.target, { ...taint, node: node.value }, state);
        }
        if (node.annotation) this.analyzeExpr(node.annotation, state, depth);
        return;
      }
      case 'AugAssign': {
        const taint = this.analyzeExpr(node.value, state, depth);
        if (node.target.type === 'Name') {
          const current = state.env.get(node.target.id) || CLEAN;
          state.env.set(node.target.id, {
            tainted: current.tainted || taint.tainted,
            chain: current.tainted ? current.chain : chainWith(taint.chain, node.target.id),
          });
        } else {
          this.analyzeExpr(node.target, state, depth);
        }
        return;
      }
      case 'Expr':
        this.analyzeExpr(node.value, state, depth);
        return;
      case 'If': {
        this.analyzeExpr(node.test, state, depth);
        const consequent = this.cloneState(state);
        this.walkStatements(node.body, consequent, depth);
        const alternate = this.cloneState(state);
        this.walkStatements(node.orelse, alternate, depth);
        this.joinStates(state, [consequent, alternate]);
        return;
      }
      case 'For': {
        const iterTaint = this.analyzeExpr(node.iter, state, depth);
        this.bindTargets(node.target, { ...iterTaint, node: node.iter }, state);
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        const orelse = this.cloneState(state);
        this.walkStatements(node.orelse, orelse, depth);
        this.joinStates(state, [body, orelse]);
        return;
      }
      case 'While': {
        this.analyzeExpr(node.test, state, depth);
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        const orelse = this.cloneState(state);
        this.walkStatements(node.orelse, orelse, depth);
        this.joinStates(state, [body, orelse]);
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
        const orelse = this.cloneState(state);
        this.walkStatements(node.orelse, orelse, depth);
        branches.push(orelse);
        const finalbody = this.cloneState(state);
        this.walkStatements(node.finalbody, finalbody, depth);
        branches.push(finalbody);
        this.joinStates(state, branches);
        return;
      }
      case 'With': {
        for (const item of node.items || []) {
          const taint = this.analyzeExpr(item.context, state, depth);
          if (item.optionalVars) {
            this.bindTargets(item.optionalVars, { ...taint, node: item.context }, state);
          }
        }
        const body = this.cloneState(state);
        this.walkStatements(node.body, body, depth);
        this.joinStates(state, [body]);
        return;
      }
      case 'Assert':
        this.analyzeExpr(node.test, state, depth);
        if (node.msg) this.analyzeExpr(node.msg, state, depth);
        return;
      case 'Raise':
        if (node.exc) this.analyzeExpr(node.exc, state, depth);
        if (node.cause) this.analyzeExpr(node.cause, state, depth);
        return;
      case 'Delete': {
        const targets = node.targets.type === 'Tuple' ? node.targets.elts : [node.targets];
        for (const target of targets) {
          if (target && target.type === 'Name') state.env.delete(target.id);
          else if (target) this.analyzeExpr(target, state, depth);
        }
        return;
      }
      case 'Pass':
      case 'Break':
      case 'Continue':
      case 'Global':
      case 'Nonlocal':
        return;
      default:
        return;
    }
  }

  analyzeExpr(node, state, depth) {
    if (!node || typeof node !== 'object') return CLEAN;
    switch (node.type) {
      case 'Constant':
        return CLEAN;
      case 'Name': {
        const entry = state.env.get(node.id);
        if (entry && entry.tainted) return entry;
        // A bare name bound to `sys.argv` by a
        // from-import (`from sys import argv`).
        const bound = state.bindings.get(node.id);
        if (bound === 'sys.argv') return { tainted: true, chain: [node.id] };
        return CLEAN;
      }
      case 'Attribute':
      case 'Subscript': {
        // Source check first: `sys.argv[1]`,
        // `request.args['q']`, `flask.request.form`.
        const chain = memberChain(node);
        const resolved = resolveChain(chain, state.bindings);
        const source = sourceOfChain(resolved);
        if (source) return { tainted: true, chain: [source] };
        const objectTaint = this.analyzeExpr(node.value, state, depth);
        if (node.type === 'Subscript') {
          const sliceTaint = this.analyzeExpr(node.slice, state, depth);
          if (sliceTaint.tainted) return sliceTaint;
        }
        return objectTaint;
      }
      case 'Slice': {
        for (const part of [node.lower, node.upper, node.step]) {
          const taint = this.analyzeExpr(part, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'BinOp':
      case 'BoolOp': {
        const parts = node.type === 'BinOp' ? [node.left, node.right] : node.values;
        for (const part of parts) {
          const taint = this.analyzeExpr(part, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'UnaryOp':
        return this.analyzeExpr(node.operand, state, depth);
      case 'Compare': {
        const left = this.analyzeExpr(node.left, state, depth);
        if (left.tainted) return left;
        for (const comparator of node.comparators || []) {
          const taint = this.analyzeExpr(comparator, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'IfExp': {
        const test = this.analyzeExpr(node.test, state, depth);
        if (test.tainted) return test;
        const body = this.analyzeExpr(node.body, state, depth);
        if (body.tainted) return body;
        return this.analyzeExpr(node.orelse, state, depth);
      }
      case 'List':
      case 'Set':
      case 'Tuple': {
        for (const element of node.elts || []) {
          const taint = this.analyzeExpr(element, state, depth);
          if (taint.tainted) return taint;
        }
        return CLEAN;
      }
      case 'Dict': {
        for (let i = 0; i < (node.keys || []).length; i += 1) {
          const keyTaint = this.analyzeExpr(node.keys[i], state, depth);
          if (keyTaint.tainted) return keyTaint;
          const valueTaint = this.analyzeExpr(node.values[i], state, depth);
          if (valueTaint.tainted) return valueTaint;
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
      case 'Starred':
        return this.analyzeExpr(node.value, state, depth);
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
    // The receiver of a method call (`blob.strip()`):
    // its taint flows into the call's return value, and
    // nested sink calls inside it are real calls. (A
    // bare name has no receiver.)
    const receiverTaint = func.type === 'Attribute'
      ? this.analyzeExpr(func.value, state, depth)
      : CLEAN;

    // 1. Sink (a member chain resolving to a sink, or a
    // bare name bound to one by a from-import / alias).
    if (resolved && SINKS[resolved]) {
      const sink = SINKS[resolved];
      const isAliased = func.type === 'Name';
      // Analyze every argument (nested sink calls
      // inside arguments are real calls too).
      const argTaints = node.args.map((arg) => this.analyzeExpr(arg, state, depth));
      const keywordTaints = (node.keywords || []).map((kw) => ({
        arg: kw.arg,
        taint: this.analyzeExpr(kw.value, state, depth),
      }));
      if (sink.loaderGate && this.hasSafeLoader(node, state)) {
        return CLEAN;
      }
      let judgedTaint = CLEAN;
      if (node.args.length > 0) judgedTaint = argTaints[0];
      else {
        const named = keywordTaints.find((kw) => kw.arg === sink.keyword);
        if (named) judgedTaint = named.taint;
      }
      if (judgedTaint.tainted || isAliased) {
        this.addFinding(makeFinding({
          sink: resolved,
          kind: isAliased ? 'aliased-call' : 'tainted-arg',
          line: node.line,
          column: node.column,
          chain: judgedTaint.chain,
          functionName: state.functionName,
        }));
      }
      return judgedTaint;
    }

    // 2. Sanitizer (a call whose result cannot be
    // unpickled as attacker bytes).
    if (resolved && SANITIZER_CALLS.has(resolved)) {
      for (const arg of node.args) this.analyzeExpr(arg, state, depth);
      for (const kw of node.keywords || []) this.analyzeExpr(kw.value, state, depth);
      return CLEAN;
    }
    if (func.type === 'Attribute' && SANITIZER_METHODS.has(func.attr)) {
      for (const arg of node.args) this.analyzeExpr(arg, state, depth);
      for (const kw of node.keywords || []) this.analyzeExpr(kw.value, state, depth);
      return CLEAN;
    }

    // 3. Known user function (bare name only — methods
    // are not resolved through the call graph).
    if (func.type === 'Name' && this.functions.has(func.id)) {
      const callee = this.functions.get(func.id);
      const taintedParams = new Set();
      let firstTaintedChain = null;
      const paramNames = callee.params.map((p) => p.name);
      node.args.forEach((arg, index) => {
        const taint = this.analyzeExpr(arg, state, depth);
        if (taint.tainted) {
          if (!firstTaintedChain) firstTaintedChain = taint.chain;
          if (paramNames[index]) taintedParams.add(paramNames[index]);
          if (arg.type === 'Starred') {
            for (const param of callee.params) {
              if (param.kind === 'var_arg' || param.kind === 'var_kw') taintedParams.add(param.name);
            }
          }
        }
      });
      for (const kw of node.keywords || []) {
        const taint = this.analyzeExpr(kw.value, state, depth);
        if (taint.tainted) {
          if (!firstTaintedChain) firstTaintedChain = taint.chain;
          if (kw.arg) taintedParams.add(kw.arg);
          else {
            for (const param of callee.params) {
              if (param.kind === 'var_kw') taintedParams.add(param.name);
            }
          }
        }
      }
      const result = this.analyzeFunction(callee, taintedParams, depth + 1);
      if (result.returnsTainted) {
        return {
          tainted: true,
          chain: chainWith(firstTaintedChain || [], func.id),
        };
      }
      return CLEAN;
    }

    // 4. Source: `input()` (a user-defined `input` is
    // not distinguished — documented).
    if (func.type === 'Name' && func.id === 'input') {
      for (const arg of node.args) this.analyzeExpr(arg, state, depth);
      return { tainted: true, chain: ['input'] };
    }

    // 5. Source: `request.get_json()` / `get_data()`
    // (the attribute forms are caught by the Attribute
    // source check; a call on one is still a source).
    if (resolved && sourceOfChain(resolved)) {
      for (const arg of node.args) this.analyzeExpr(arg, state, depth);
      return { tainted: true, chain: ['request'] };
    }

    // 6. Unknown function: tainted when the receiver
    // or any argument is.
    let firstTainted = receiverTaint.tainted ? receiverTaint : null;
    for (const arg of node.args) {
      const taint = this.analyzeExpr(arg, state, depth);
      if (taint.tainted && !firstTainted) firstTainted = taint;
    }
    for (const kw of node.keywords || []) {
      const taint = this.analyzeExpr(kw.value, state, depth);
      if (taint.tainted && !firstTainted) firstTainted = taint;
    }
    return firstTainted || CLEAN;
  }

  // Does this `yaml.load` call pass a safe Loader?
  // A Loader keyword whose resolved value is SafeLoader
  // / CSafeLoader (by name or by `yaml.` member) makes
  // the call clean; any other Loader, or no Loader at
  // all, does not.
  hasSafeLoader(node, state) {
    for (const kw of node.keywords || []) {
      if (kw.arg !== 'Loader') continue;
      const chain = memberChain(kw.value);
      if (!chain) return false;
      const resolved = resolveChain(chain, state.bindings);
      return SAFE_LOADERS.has(resolved);
    }
    return false;
  }
}

// --- findings ------------------------------------------------------------

function makeFinding({ sink, kind, line, column, chain, functionName }) {
  const label = SINKS[sink].label;
  const where = `line ${line}, column ${column}`;
  const chainText = chain && chain.length > 0 ? chain.join(' -> ') : 'an alias binding';
  const notes = `${label} at ${where} in function ${functionName}; taint flows via ${chainText}`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, sink, line, column, kind),
    title: `Unsafe deserialization: tainted data reaches ${sink}`,
    vulnerability_type: 'insecure deserialization',
    description: `Tainted data reaches ${sink} (${label}), which reconstructs objects from untrusted bytes. An attacker who controls the input can instantiate arbitrary classes and execute code during deserialization.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-502',
    steps_to_reproduce: [
      'Run `sentinel detect --detector tainted-pickle --input <record.json>` over the record carrying the Python source.',
      `Observe the finding for ${sink} at ${where}.`,
      'Verify out of band whether the input is really attacker-controlled and the deserialized object is used, before reporting — the detector never executes the code, so exploitability is unproven.',
    ],
    proof_of_concept: `Matched ${sink} at ${where}: ${kind} via ${chainText}`,
    evidence: [{
      type: 'ast-call',
      sink,
      kind,
      line,
      column,
      call: sink,
      function: functionName,
      chain: chain || [],
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- detector ------------------------------------------------------------

function analyzePython(source) {
  const program = parsePython(source);
  const analyzer = new PyTaintAnalyzer(program);
  return analyzer.analyze();
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those
// in `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows createTaintDetector's pattern
// (batch / single, content cap, finding cap, ids from
// the record, normalization through normalizeRawFinding)
// but it is its OWN function: createTaintDetector's
// scanRecord is JavaScript-specific — it parses with
// parseJavaScript, rejects non-JavaScript languages, and
// runs TaintAnalyzer. None of that applies to Python, so
// reusing it would mean parsing Python as JavaScript.
function scanRecord(record) {
  if (typeof record.content !== 'string' || record.content.trim() === '') {
    throw new Error(`${DETECTOR_NAME}: record has no non-empty string "content" to scan.`);
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`${DETECTOR_NAME}: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.language !== undefined && record.language !== null) {
    if (typeof record.language !== 'string' || !PY_LANGUAGES.has(record.language.toLowerCase())) {
      throw new Error(`${DETECTOR_NAME}: record language is "${String(record.language)}", not Python.`);
    }
  }
  let rawFindings;
  try {
    rawFindings = analyzePython(record.content);
  } catch (error) {
    if (error instanceof PyParseError) {
      throw new Error(`${DETECTOR_NAME}: failed to parse content as Python: ${error.message}`);
    }
    throw error;
  }
  const truncated = Math.max(0, rawFindings.length - MAX_FINDINGS_PER_RECORD);
  const kept = rawFindings.slice(0, MAX_FINDINGS_PER_RECORD);

  // Ids come from the record itself (else from `defaults`
  // at normalization); a detector never invents them.
  for (const raw of kept) {
    if (typeof record.session_id === 'string' && record.session_id.trim() !== '') raw.session_id = record.session_id;
    if (typeof record.target_id === 'string' && record.target_id.trim() !== '') raw.target_id = record.target_id;
    if (typeof record.asset_id === 'string' && record.asset_id.trim() !== '') raw.asset_id = record.asset_id;
  }
  return { rawFindings: kept, truncated };
}

// Build the detector envelope for this detector:
// detector(input, defaults) -> { findings, skipped, errors }.
// A batch record `{ tool, results: [...] }` scans each result
// with the batch tool forced as discovery_tool (the stub
// convention); any other object is treated as a single
// content record. A non-object input throws
// DETECTOR_INVALID_INPUT. Bad records are counted in
// `skipped`, never thrown.
function taintedPickleDetector(input, defaults) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('DETECTOR_INVALID_INPUT: detector input must be an object (a content record or a { tool, results } batch).');
  }
  let records;
  let tool;
  if (Array.isArray(input.results)) {
    if (input.tool !== undefined && input.tool !== null && (typeof input.tool !== 'string' || input.tool.trim() === '')) {
      throw new Error('DETECTOR_INVALID_INPUT: batch tool must be a non-empty string when present.');
    }
    records = input.results;
    tool = typeof input.tool === 'string' && input.tool.trim() !== '' ? input.tool : undefined;
  } else {
    records = [input];
    tool = undefined;
  }

  const findings = [];
  const errors = [];
  let skipped = 0;
  for (const record of records) {
    try {
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new Error(`${DETECTOR_NAME}: each record must be an object with a "content" string.`);
      }
      const { rawFindings, truncated } = scanRecord(record);
      for (const raw of rawFindings) {
        if (tool) raw.discovery_tool = tool;
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`${DETECTOR_NAME}: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = taintedPickleDetector;
module.exports.taintedPickleDetector = taintedPickleDetector;
module.exports.analyzePython = analyzePython;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
