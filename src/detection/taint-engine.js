// Shared taint engine for the parser-based detectors (Phase 5,
// round 101).
//
// Rounds 95 and 100 each shipped a parser-based detector
// (`tainted-deserialize`, `tainted-command-execution`) with its
// own near-identical copy of the taint analyzer (~700 lines
// each, parameterized only by the sink table and the finding
// metadata). Round 101 extracts the one shared engine both
// detectors run on, and extends it in two ways the copies could
// not do alone:
//
//   1. INTER-PROCEDURAL TAINT (call graph). Taint flows from a
//      call site into a callee: a sink inside a helper called
//      with a tainted argument is reported with a chain that
//      proves the cross-function flow (call-site values ->
//      callee parameter -> sink). Functions are analyzed
//      lazily: on demand at a call site with the actual
//      argument taints, and once at the end of their defining
//      scope with parameters-as-sources (the fallback — the
//      round-95 behavior — so a helper never called, or called
//      only with clean arguments, still flags its sink). The
//      engine also computes a callee's RETURN taint, so
//      `const y = id(userInput); yaml.load(y)` flags while
//      `const y = constant(userInput); yaml.load(y)` does not.
//      Recursion and deep call chains are bounded (an active
//      set plus MAX_CALL_DEPTH); beyond the bound a call is
//      treated as an unknown call (the round-95
//      over-approximation), never as a hang.
//   2. SANITIZER MODELING. An explicit allow-list of cleansing
//      calls (`SANITIZERS` below) whose return value is clean
//      regardless of argument taint: the value provably cannot
//      carry a string payload into a string sink. Each entry
//      is pinned by a test in
//      tests/inter-procedural-taint.test.js, and the exclusions
//      are pinned too (see docs/sanitizer-modeling-v1.md for
//      the rationale — encoding functions do NOT cleanse).
//
// The engine is parameterized by a detector config (sink
// tables, finding metadata); `createTaintDetector(config)`
// builds the detector envelope (record/batch handling, caps,
// determinism, no-secret rule) all parser-based detectors
// share. The detector modules are thin wrappers that supply
// their config and re-export the constants tests and
// `detector.js` rely on. A config carries up to three sink
// tables: `sinks` (fixed member calls and bare names),
// `methodSinks` (calls matched by method name alone,
// whatever the receiver), and `assignmentSinks`
// (properties whose assignment is a sink). A sink entry
// may name `argIndex` — the judged argument (the first by
// default); a tainted argument outside the judged index is
// not covered, by design.
//
// Design invariants (tested, not assumed) — see
// docs/inter-procedural-taint-v1.md and
// docs/sanitizer-modeling-v1.md:
// - JavaScript only, stdlib-only, synchronous, deterministic,
//   no I/O, never executes the code it scans. Content that
//   does not parse under the subset grammar is skipped with
//   a parse error — the engine NEVER falls back to scanning
//   text with a regex.
// - A finding carries only the sink name, position, and a
//   taint chain of IDENTIFIER NAMES — never a literal value,
//   never a source line, never an argument's text.
// - One finding per distinct sink call site per record; at
//   most MAX_FINDINGS_PER_RECORD (100) findings per record.
// - Methods (`obj.method(...)`) are NOT resolved through the
//   call graph (documented limit); they are analyzed with
//   parameters-as-sources, as in round 95. Import resolution
//   is NOT modeled (`require('child_process').exec` and
//   `const cp = child_process` stay unresolved). Only the
//   judged argument of a sink is judged (the first argument
//   by default; a sink entry may name another index —
//   insertAdjacentHTML judges its second argument, the
//   HTML, because its first is the position constant). A
//   tainted argument outside the judged index is not
//   covered — the round-100 pin stands, generalized.
// - Assignment sinks (`el.innerHTML = x`) are judged on
//   the assigned value; method sinks
//   (`el.insertAdjacentHTML(...)`) match by method name
//   alone, whatever the receiver. Both are config tables
//   like `sinks`; a detector that defines neither behaves
//   exactly as before.
// - Bindings are function-scoped (block scoping is not
//   modeled — the round-95 simplification). A callee is
//   analyzed with the scope stack live at the call site, so
//   a callee free variable that collides with a caller local
//   resolves to the caller local (a dynamic-scope
//   approximation, documented); the finding is confidence
//   `potential` for exactly this reason.
// - Unknown calls keep the round-95 over-approximation: a
//   call with a tainted argument returns a tainted value
//   (chain extended with `callee(...)`), unless the callee
//   is a sanitizer (clean) or a known function (computed
//   return taint).
'use strict';

const crypto = require('node:crypto');
const { normalizeRawFinding } = require('./normalized-record');
const { parseJavaScript, JSParseError } = require('./js-parser');

const MAX_CONTENT_CHARS = 1_000_000;
const MAX_FINDINGS_PER_RECORD = 100;
const MAX_TAINT_CHAIN = 10;
// Maximum nesting of call-site analyses. Beyond this a call
// is treated as an unknown call (tainted iff its arguments
// are), never as a hang.
const MAX_CALL_DEPTH = 8;

const JS_LANGUAGES = new Set(['javascript', 'js', 'node']);

// Sanitizer allow-list: calls whose return value provably
// cannot carry a string payload into a string sink, so the
// return value is clean regardless of argument taint. Each
// entry is pinned by a test; the exclusions are pinned too
// (docs/sanitizer-modeling-v1.md):
//   - Number / parseInt / parseFloat: return a number.
//   - Boolean: returns a boolean.
//   - Number.parseInt / Number.parseFloat: the same
//     functions reached as members of Number.
// NOT sanitizers (content-preserving, still tainted):
// String, JSON.stringify, encodeURIComponent, encodeURI,
// trim/toUpperCase and other string methods. A user binding
// that shadows a sanitizer name disables it for that scope
// (a local `function Number(x) { return x; }` is not a
// sanitizer — pinned by a test).
const SANITIZERS = new Set([
  'Number',
  'parseInt',
  'parseFloat',
  'Boolean',
  'Number.parseInt',
  'Number.parseFloat',
]);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(detectorName, sink, lineNumber, column, kind) {
  const digest = crypto
    .createHash('sha256')
    .update(`${detectorName}:${sink}:${lineNumber}:${column}:${kind}`, 'utf8')
    .digest('hex');
  return `${detectorName}-${digest.slice(0, 16)}`;
}

// Render a member expression as dotted text when it is a
// chain of identifiers / string literals rooted at an
// identifier (`yaml.load`, `req.body`, `a['b']`); otherwise
// null (the callee is not a simple name).
function memberName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type !== 'MemberExpression') return null;
  const object = memberName(node.object);
  if (object === null) return null;
  let prop = null;
  if (!node.computed && node.property.type === 'Identifier') prop = node.property.name;
  else if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') prop = node.property.value;
  if (prop === null) return null;
  return `${object}.${prop}`;
}

// The property name of a member expression (`innerHTML`
// for `el.innerHTML` and for `el['innerHTML']`); otherwise
// null. Used for method sinks and assignment sinks, which
// match by property name alone.
function memberPropertyName(node) {
  if (!node || node.type !== 'MemberExpression') return null;
  if (!node.computed && node.property.type === 'Identifier') return node.property.name;
  if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') return node.property.value;
  return null;
}

function capChain(chain) {
  return chain.length > MAX_TAINT_CHAIN ? [...chain.slice(0, MAX_TAINT_CHAIN), '…'] : chain;
}

// Render a member expression as source-like text
// (`req.body`, `a['b']`, `a[0]`, `a[b]`) for taint chains;
// returns null when the shape is not renderable.
function renderMember(node) {
  if (node.type === 'Identifier') return node.name;
  if (node.type !== 'MemberExpression') return null;
  const object = renderMember(node.object);
  if (object === null) return null;
  if (!node.computed && node.property.type === 'Identifier') return `${object}.${node.property.name}`;
  if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') return `${object}['${node.property.value}']`;
  if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'number') return `${object}[${node.property.value}]`;
  if (node.computed && node.property.type === 'Identifier') return `${object}[${node.property.name}]`;
  return null;
}

function clean() {
  return { tainted: false, chain: [] };
}

function tainted(chain) {
  return { tainted: true, chain: capChain(chain) };
}

function joinTaint(a, b) {
  if (!a.tainted) return b;
  if (!b.tainted) return a;
  return tainted([...a.chain, ...b.chain]);
}

function cloneTaint(taint) {
  return { tainted: taint.tainted, chain: [...taint.chain] };
}

// A binding: { tainted, chain, aliasSink, fnTarget } —
// aliasSink is the canonical sink name this identifier is
// bound to (or null); fnTarget is the call-graph record of
// the user function this identifier is bound to (or null),
// so `const g = parse` resolves a later call `g(x)` to
// `parse`.
function bindingFor(taint, aliasSink = null, fnTarget = null) {
  return { tainted: taint.tainted, chain: [...taint.chain], aliasSink, fnTarget };
}

function cloneBinding(binding) {
  return {
    tainted: binding.tainted,
    chain: [...binding.chain],
    aliasSink: binding.aliasSink,
    fnTarget: binding.fnTarget,
  };
}

// Bound names of a parameter / pattern node.
function collectParamNames(pattern, out = []) {
  if (!pattern) return out;
  switch (pattern.type) {
    case 'Identifier':
      out.push(pattern.name);
      break;
    case 'ObjectPattern':
      for (const prop of pattern.properties || []) {
        if (prop.type === 'RestElement') collectParamNames(prop.argument, out);
        else collectParamNames(prop.value, out);
      }
      break;
    case 'ArrayPattern':
      for (const el of pattern.elements || []) {
        if (!el) continue;
        if (el.type === 'RestElement') collectParamNames(el.argument, out);
        else collectParamNames(el, out);
      }
      break;
    case 'AssignmentPattern':
      collectParamNames(pattern.left, out);
      break;
    case 'RestElement':
      collectParamNames(pattern.argument, out);
      break;
    default:
      break;
  }
  return out;
}

// A call-graph record for one user function: the AST node,
// the display name for taint chains, and the analysis
// memo. `analyzedWithTainted` / `analyzedClean` record
// which argument shapes have been analyzed; `fallbackDone`
// records the parameters-as-sources pass;
// `returnsTainted` is the computed return taint (boolean)
// of the tainted-arguments analysis, `cleanReturnTaint`
// the computed return taint of the all-clean analysis.
function newFnRecord(node, displayName) {
  return {
    node,
    displayName,
    analyzedWithTainted: false,
    analyzedClean: false,
    fallbackDone: false,
    returnsTainted: null,
    cleanReturnTaint: null,
  };
}

class TaintAnalyzer {
  constructor(config) {
    this.config = config;
    // Scope stack: array of Map<name, binding>. The program
    // scope is the root; each function pushes one scope.
    // Block scoping is NOT modeled (bindings are
    // function-scoped — a documented simplification).
    this.scopes = [new Map()];
    // Call-graph registry, parallel to the scope stack:
    // array of Map<name, fnRecord>. Registration is
    // monotonic (definitions never un-register), so branch
    // snapshots never touch it.
    this.fnScopes = [new Map()];
    // Functions currently being analyzed (recursion guard
    // and depth bound for call-site analysis).
    this.activeFunctions = [];
    // Return-taint frames, one per analyzeFunction
    // invocation: { taint } joined from its ReturnStatements.
    this.returnFrames = [];
    this.findings = [];
    this.dropped = 0;
    this.seen = new Set();
  }

  lookup(name) {
    for (let i = this.scopes.length - 1; i >= 0; i -= 1) {
      const binding = this.scopes[i].get(name);
      if (binding) return binding;
    }
    return undefined;
  }

  lookupFunction(name) {
    for (let i = this.fnScopes.length - 1; i >= 0; i -= 1) {
      const record = this.fnScopes[i].get(name);
      if (record) return record;
    }
    return undefined;
  }

  // Resolve a call target by name: a function-alias binding
  // first (`const g = parse`), then the registry.
  resolveFunction(name) {
    const binding = this.lookup(name);
    if (binding && binding.fnTarget) return binding.fnTarget;
    return this.lookupFunction(name) || null;
  }

  declare(name, binding) {
    this.scopes[this.scopes.length - 1].set(name, binding);
  }

  assign(name, binding) {
    for (let i = this.scopes.length - 1; i >= 0; i -= 1) {
      if (this.scopes[i].has(name)) {
        this.scopes[i].set(name, binding);
        return;
      }
    }
    this.declare(name, binding);
  }

  // Register a user function in the current call-graph
  // scope (first registration wins — a later redefinition
  // in the same scope does not replace the record).
  registerFunction(name, node, displayName) {
    const fnScope = this.fnScopes[this.fnScopes.length - 1];
    const existing = fnScope.get(name);
    if (existing) return existing;
    const record = newFnRecord(node, displayName);
    fnScope.set(name, record);
    return record;
  }

  // Register the function declarations hoisted in a body
  // (direct declarations, plus ones wrapped in an export),
  // so a call textually before the declaration still
  // resolves — function declarations are hoisted in real
  // JavaScript, so the call graph must see them early.
  registerHoistedFunctions(statements) {
    for (const stmt of statements || []) {
      let decl = null;
      if (stmt.type === 'FunctionDeclaration') decl = stmt;
      else if ((stmt.type === 'ExportNamedDeclaration' || stmt.type === 'ExportDefaultDeclaration')
        && stmt.declaration && stmt.declaration.type === 'FunctionDeclaration') {
        decl = stmt.declaration;
      }
      if (decl && decl.id) this.registerFunction(decl.id.name, decl, decl.id.name);
    }
  }

  snapshotStack() {
    return this.scopes.map((scope) => {
      const copy = new Map();
      for (const [name, binding] of scope) copy.set(name, cloneBinding(binding));
      return copy;
    });
  }

  restoreStack(snapshot) {
    this.scopes = snapshot.map((scope) => {
      const copy = new Map();
      for (const [name, binding] of scope) copy.set(name, cloneBinding(binding));
      return copy;
    });
  }

  // Branch join (OR): tainted on any path stays tainted; an
  // alias (sink or function) survives only when both paths
  // agree on it.
  mergeStacks(a, b) {
    const merged = [];
    for (let i = 0; i < a.length; i += 1) {
      const scope = new Map();
      const names = new Set([...a[i].keys(), ...b[i].keys()]);
      for (const name of names) {
        const left = a[i].get(name);
        const right = b[i].get(name);
        if (!left) { scope.set(name, cloneBinding(right)); continue; }
        if (!right) { scope.set(name, cloneBinding(left)); continue; }
        scope.set(name, {
          tainted: left.tainted || right.tainted,
          chain: capChain(left.tainted ? left.chain : right.chain),
          aliasSink: left.aliasSink === right.aliasSink ? left.aliasSink : null,
          fnTarget: left.fnTarget === right.fnTarget ? left.fnTarget : null,
        });
      }
      merged.push(scope);
    }
    return merged;
  }

  emitFinding(sink, callNode, kind, taintInfo, aliasInfo) {
    const { detectorName, sinks } = this.config;
    const line = callNode.line;
    const column = callNode.column;
    const key = `${sink}:${line}:${column}:${kind}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    if (this.findings.length >= MAX_FINDINGS_PER_RECORD) {
      this.dropped += 1;
      return;
    }
    // The sink label lives in whichever sink table the
    // sink came from (`sinks`, `methodSinks`, or
    // `assignmentSinks`).
    const sinkEntry = sinks[sink]
      || (this.config.methodSinks && this.config.methodSinks[sink])
      || (this.config.assignmentSinks && this.config.assignmentSinks[sink]);
    const sinkLabel = sinkEntry.label;
    const where = `line ${line}, column ${column}`;
    let description;
    let title;
    let evidence;
    if (kind === 'tainted-arg') {
      title = `Tainted ${sinkLabel} in supplied JavaScript`;
      // The judged argument is the first by default; a sink
      // entry may name another index (insertAdjacentHTML
      // judges its second argument), and the description
      // names it so the finding stays precise.
      const argPhrase = taintInfo.argIndex
        ? `a tainted argument (argument ${taintInfo.argIndex + 1})`
        : 'a tainted first argument';
      description = `A ${sinkLabel} (${detectorName}) was found in operator-supplied JavaScript at ${where}, with ${argPhrase}. Taint flow: ${taintInfo.chain.join(' → ')}. The detector parses the code and tracks the flow; it never executes the code. Whether the call is reachable with attacker-controlled input in production is unproven — verify out of band before reporting.`;
      evidence = [{
        type: 'ast-call',
        sink,
        kind,
        line,
        column,
        call: taintInfo.call,
        taint: { source: taintInfo.chain[0], chain: [...taintInfo.chain] },
      }];
    } else if (kind === 'aliased-call') {
      title = `Aliased ${sinkLabel} in supplied JavaScript`;
      description = `A ${sinkLabel} (${detectorName}) was found in operator-supplied JavaScript at ${where}, reached through the alias '${aliasInfo.name}' bound to ${sink}. The regex detector cannot see aliased calls; this finding exists because the code was parsed. The detector never executes the code. Whether the call is reachable with attacker-controlled input in production is unproven — verify out of band before reporting.`;
      evidence = [{
        type: 'ast-call',
        sink,
        kind,
        line,
        column,
        call: aliasInfo.name,
        alias: { name: aliasInfo.name, boundTo: sink },
        ...(taintInfo && taintInfo.tainted
          ? { taint: { source: taintInfo.chain[0], chain: [...taintInfo.chain] } }
          : {}),
      }];
    } else if (kind === 'tainted-assign') {
      title = `Tainted ${sinkLabel} in supplied JavaScript`;
      description = `An ${sinkLabel} (${detectorName}) was found in operator-supplied JavaScript at ${where}, with a tainted assigned value. Taint flow: ${taintInfo.chain.join(' → ')}. The detector parses the code and tracks the flow; it never executes the code. Whether the assignment is reachable with attacker-controlled input in production is unproven — verify out of band before reporting.`;
      evidence = [{
        type: 'ast-assign',
        sink,
        kind,
        line,
        column,
        target: taintInfo.call,
        property: taintInfo.property,
        taint: { source: taintInfo.chain[0], chain: [...taintInfo.chain] },
      }];
    }
    this.findings.push({
      finding_id: findingIdFor(detectorName, sink, line, column, kind),
      title,
      vulnerability_type: this.config.vulnerabilityType,
      description,
      impact: this.config.impact,
      remediation: this.config.remediation,
      severity: this.config.severity,
      cwe_id: this.config.cweId,
      steps_to_reproduce: [
        `Run \`sentinel detect --detector ${detectorName} --input <record.json>\` over the record carrying the JavaScript.`,
        `Observe the finding for ${sink} at ${where}.`,
        'Verify out of band whether the call is reachable with attacker-controlled input before reporting — the detector never executes the code, so exploitability is unproven.',
      ],
      proof_of_concept: `Matched ${sink} at ${where}: ${kind === 'aliased-call' ? aliasInfo.name : taintInfo.call}`,
      evidence,
      discovery_tool: detectorName,
    });
  }

  // Analyze a function-like node (declaration, expression,
  // arrow, method value). `paramTaints` is null for the
  // parameters-as-sources mode (the round-95 fallback), or
  // an array of taint values aligned with node.params for a
  // call-site analysis. `record` is the call-graph record
  // when one exists (null for methods and anonymous
  // callbacks). Returns the joined taint of the function's
  // return statements (clean when the body never returns a
  // tainted value).
  analyzeFunction(node, displayName, paramTaints, record) {
    const scope = new Map();
    for (let i = 0; i < (node.params || []).length; i += 1) {
      const param = node.params[i];
      for (const name of collectParamNames(param)) {
        if (paramTaints === null) {
          scope.set(name, bindingFor(tainted([`parameter '${name}' of function '${displayName}'`])));
        } else {
          const argTaint = paramTaints[i] || clean();
          scope.set(name, bindingFor(argTaint.tainted
            ? tainted([...argTaint.chain, `parameter '${name}' of function '${displayName}'`])
            : clean()));
        }
      }
    }
    this.scopes.push(scope);
    this.fnScopes.push(new Map());
    if (record) this.activeFunctions.push(record);
    this.returnFrames.push({ taint: clean() });
    if (node.body && node.body.type === 'BlockStatement') {
      this.registerHoistedFunctions(node.body.body);
      this.walkStatements(node.body.body);
      this.runFallbackForCurrentScope();
    } else if (node.body) {
      // Arrow with an expression body.
      const bodyTaint = this.evalExpr(node.body);
      const frame = this.returnFrames[this.returnFrames.length - 1];
      frame.taint = joinTaint(frame.taint, bodyTaint);
    }
    const returnTaint = this.returnFrames.pop().taint;
    if (record) this.activeFunctions.pop();
    this.fnScopes.pop();
    this.scopes.pop();
    return returnTaint;
  }

  // Fallback pass for the current scope: analyze every
  // registered function that no call site analyzed with
  // tainted arguments, with parameters-as-sources (the
  // round-95 behavior). This is what flags a sink inside a
  // helper that is never called, or called only with clean
  // arguments — the detector does not claim the helper is
  // reachable from a tainted call, and the finding stays
  // confidence `potential`.
  runFallbackForCurrentScope() {
    const fnScope = this.fnScopes[this.fnScopes.length - 1];
    let progress = true;
    while (progress) {
      progress = false;
      for (const record of [...fnScope.values()]) {
        if (record.analyzedWithTainted || record.fallbackDone) continue;
        record.fallbackDone = true;
        progress = true;
        this.analyzeFunction(record.node, record.displayName, null, record);
      }
    }
  }

  // Analyze a whole program: hoisted declarations first,
  // then the top-level walk, then the fallback pass for the
  // program scope.
  analyzeProgram(program) {
    this.registerHoistedFunctions(program.body);
    this.walkStatements(program.body);
    this.runFallbackForCurrentScope();
  }

  // The round-95 over-approximation for a call the engine
  // cannot resolve precisely: tainted iff any argument is
  // tainted, the chain extended with `name(...)`.
  unknownCallTaint(argTaints, callName) {
    let result = clean();
    for (const t of argTaints) result = joinTaint(result, t);
    if (result.tainted) return tainted([...result.chain, `${callName}(…)`]);
    return clean();
  }

  // Analyze a call to a registered user function with the
  // actual argument taints. Returns the callee's computed
  // return taint. Memoized per argument shape (tainted vs
  // all-clean); recursion and depth are bounded by the
  // active-functions stack, and a bounded call falls back
  // to the unknown-call convention — never a hang.
  analyzeCallTarget(record, argTaints, callName) {
    const anyTainted = argTaints.some((t) => t.tainted);
    if (this.activeFunctions.includes(record)) {
      return this.unknownCallTaint(argTaints, callName);
    }
    if (this.activeFunctions.length >= MAX_CALL_DEPTH) {
      return this.unknownCallTaint(argTaints, callName);
    }
    if (anyTainted) {
      if (record.analyzedWithTainted) {
        if (record.returnsTainted === false) return clean();
        return this.unknownCallTaint(argTaints, callName);
      }
      record.analyzedWithTainted = true;
      const returnTaint = this.analyzeFunction(record.node, record.displayName, argTaints, record);
      record.returnsTainted = returnTaint.tainted;
      return returnTaint;
    }
    if (record.analyzedClean) {
      return record.cleanReturnTaint ? cloneTaint(record.cleanReturnTaint) : clean();
    }
    record.analyzedClean = true;
    const returnTaint = this.analyzeFunction(record.node, record.displayName, argTaints, record);
    record.cleanReturnTaint = returnTaint;
    return returnTaint;
  }

  // Is this call a sanitizer? A bare identifier or a
  // member call whose name is in the allow-list — unless a
  // user binding shadows the root name in scope (a local
  // `function Number(x) { return x; }` is not a sanitizer).
  isSanitizerCall(node) {
    const name = memberName(node.callee);
    if (!name || !SANITIZERS.has(name)) return false;
    const root = name.split('.')[0];
    return this.lookup(root) === undefined;
  }

  walkStatements(statements) {
    for (const stmt of statements || []) this.walkStatement(stmt);
  }

  walkStatement(node) {
    if (!node) return;
    switch (node.type) {
      case 'VariableDeclaration': {
        for (const decl of node.declarations) {
          // A function value bound to a name joins the call
          // graph instead of being analyzed immediately:
          // it is analyzed lazily at its call sites (with
          // the actual argument taints) or by the fallback
          // pass (parameters-as-sources).
          if (decl.init
            && (decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression')
            && decl.id && decl.id.type === 'Identifier') {
            const record = this.registerFunction(decl.id.name, decl.init, decl.id.name);
            this.declare(decl.id.name, bindingFor(clean(), null, record));
            continue;
          }
          const initTaint = decl.init ? this.evalExpr(decl.init) : clean();
          this.bindPattern(decl.id, decl.init, initTaint);
        }
        return;
      }
      case 'FunctionDeclaration': {
        // Register only — the body is analyzed lazily at a
        // call site or by the fallback pass, never here.
        if (node.id) {
          this.declare(node.id.name, bindingFor(clean()));
          this.registerFunction(node.id.name, node, node.id.name);
        }
        return;
      }
      case 'ClassDeclaration':
      case 'ClassExpression': {
        if (node.id) this.declare(node.id.name, bindingFor(clean()));
        if (node.superClass) this.evalExpr(node.superClass);
        for (const member of node.body || []) {
          if (member.type === 'MethodDefinition') {
            // Methods are NOT resolved through the call
            // graph (documented limit): analyze immediately
            // with parameters-as-sources, as in round 95.
            const methodName = member.key && member.key.name ? member.key.name : 'anonymous';
            this.analyzeFunction(member.value, methodName, null, null);
          } else if (member.type === 'ClassField' && member.init) {
            // Field initializers are analyzed in class scope;
            // their taint does not bind a name.
            this.evalExpr(member.init);
          }
        }
        return;
      }
      case 'ExpressionStatement':
        this.evalExpr(node.expression);
        return;
      case 'ReturnStatement': {
        if (node.argument) {
          const taint = this.evalExpr(node.argument);
          const frame = this.returnFrames[this.returnFrames.length - 1];
          if (frame) frame.taint = joinTaint(frame.taint, taint);
        }
        return;
      }
      case 'ThrowStatement':
        this.evalExpr(node.argument);
        return;
      case 'IfStatement': {
        this.evalExpr(node.test);
        const before = this.snapshotStack();
        this.walkStatement(node.consequent);
        const thenState = this.snapshotStack();
        this.restoreStack(before);
        if (node.alternate) this.walkStatement(node.alternate);
        const elseState = this.snapshotStack();
        this.scopes = this.mergeStacks(thenState, elseState);
        return;
      }
      case 'WhileStatement': {
        this.evalExpr(node.test);
        const before = this.snapshotStack();
        this.walkStatement(node.body);
        const after = this.snapshotStack();
        this.scopes = this.mergeStacks(before, after);
        return;
      }
      case 'DoWhileStatement': {
        const before = this.snapshotStack();
        this.walkStatement(node.body);
        this.evalExpr(node.test);
        const after = this.snapshotStack();
        this.scopes = this.mergeStacks(before, after);
        return;
      }
      case 'ForStatement': {
        if (node.init) {
          if (node.init.type === 'VariableDeclaration') this.walkStatement(node.init);
          else this.evalExpr(node.init);
        }
        if (node.test) this.evalExpr(node.test);
        const before = this.snapshotStack();
        this.walkStatement(node.body);
        if (node.update) this.evalExpr(node.update);
        const after = this.snapshotStack();
        this.scopes = this.mergeStacks(before, after);
        return;
      }
      case 'ForOfStatement':
      case 'ForInStatement': {
        const rightTaint = this.evalExpr(node.right);
        if (node.left && node.left.type === 'VariableDeclaration') {
          for (const decl of node.left.declarations) {
            this.bindPattern(decl.id, null, rightTaint);
          }
        } else if (node.left) {
          this.assignPattern(node.left, rightTaint);
        }
        const before = this.snapshotStack();
        this.walkStatement(node.body);
        const after = this.snapshotStack();
        this.scopes = this.mergeStacks(before, after);
        return;
      }
      case 'TryStatement': {
        const before = this.snapshotStack();
        this.walkStatement(node.block);
        const tryState = this.snapshotStack();
        this.restoreStack(before);
        if (node.handler) {
          if (node.handler.param) {
            for (const name of collectParamNames(node.handler.param)) {
              this.declare(name, bindingFor(clean()));
            }
          }
          this.walkStatement(node.handler.body);
        }
        const catchState = this.snapshotStack();
        this.scopes = this.mergeStacks(tryState, catchState);
        if (node.finalizer) this.walkStatement(node.finalizer);
        return;
      }
      case 'SwitchStatement': {
        this.evalExpr(node.discriminant);
        let state = this.snapshotStack();
        for (const caseNode of node.cases || []) {
          if (caseNode.test) this.evalExpr(caseNode.test);
          this.restoreStack(state);
          this.walkStatements(caseNode.consequent);
          state = this.mergeStacks(state, this.snapshotStack());
        }
        this.scopes = state;
        return;
      }
      case 'BlockStatement':
        this.walkStatements(node.body);
        return;
      case 'ExportNamedDeclaration':
        if (node.declaration) this.walkStatement(node.declaration);
        return;
      case 'ExportDefaultDeclaration':
        if (node.declaration) {
          if (node.declaration.type === 'FunctionDeclaration' || node.declaration.type === 'ClassDeclaration') {
            this.walkStatement(node.declaration);
          } else {
            this.evalExpr(node.declaration);
          }
        }
        return;
      case 'WithStatement':
        this.evalExpr(node.object);
        this.walkStatement(node.body);
        return;
      case 'BreakStatement':
      case 'ContinueStatement':
      case 'EmptyStatement':
      case 'ImportDeclaration':
      case 'ExportAllDeclaration':
        return;
      default:
        // Unknown statement shape: evaluate nothing, miss
        // nothing silently — the parser only produces known
        // shapes, so this is unreachable in practice.
        return;
    }
  }

  // Bind a pattern (identifier / object / array / default)
  // to a taint value. `initNode` is the initializer AST (or
  // null for for-of/in, where only the taint is known).
  bindPattern(pattern, initNode, initTaint) {
    if (!pattern) return;
    switch (pattern.type) {
      case 'Identifier': {
        let aliasSink = null;
        let fnTarget = null;
        if (initNode) {
          aliasSink = aliasSinkOf(initNode, this);
          if (initNode.type === 'Identifier') fnTarget = this.lookupFunction(initNode.name);
        }
        this.declare(pattern.name, bindingFor(
          initTaint.tainted ? tainted([...initTaint.chain, pattern.name]) : clean(),
          aliasSink,
          fnTarget,
        ));
        return;
      }
      case 'ObjectPattern': {
        // Destructured sink: `const { load } = yaml`.
        const rootName = initNode && initNode.type === 'Identifier' ? initNode.name : null;
        const sinkProps = rootName ? this.config.sinkRoots[rootName] : null;
        for (const prop of pattern.properties || []) {
          if (prop.type === 'RestElement') {
            this.bindPattern(prop.argument, null, initTaint);
            continue;
          }
          const propName = prop.key && prop.key.type === 'Identifier'
            ? prop.key.name
            : (prop.key && prop.key.type === 'Literal' ? String(prop.key.value) : null);
          if (sinkProps && propName && sinkProps.includes(propName)) {
            for (const name of collectParamNames(prop.value)) {
              this.declare(name, bindingFor(clean(), `${rootName}.${propName}`));
            }
            continue;
          }
          const valueTaint = initTaint.tainted
            ? tainted([...initTaint.chain, propName || '?'])
            : clean();
          this.bindPattern(prop.value, null, valueTaint);
        }
        return;
      }
      case 'ArrayPattern': {
        for (const el of pattern.elements || []) {
          if (!el) continue;
          if (el.type === 'RestElement') this.bindPattern(el.argument, null, initTaint);
          else this.bindPattern(el, null, initTaint);
        }
        return;
      }
      case 'AssignmentPattern': {
        // Default value does not cleanse the initializer's
        // taint; the name binds to the initializer's taint.
        this.bindPattern(pattern.left, initNode, initTaint);
        return;
      }
      default:
        return;
    }
  }

  // Assignment to a pattern on the left of `=` (for-of/in
  // targets, plain assignments).
  assignPattern(pattern, valueTaint) {
    if (!pattern) return;
    switch (pattern.type) {
      case 'Identifier':
        this.assign(pattern.name, bindingFor(
          valueTaint.tainted ? tainted([...valueTaint.chain, pattern.name]) : clean(),
        ));
        return;
      case 'ObjectPattern':
        for (const prop of pattern.properties || []) {
          if (prop.type === 'RestElement') this.assignPattern(prop.argument, valueTaint);
          else this.assignPattern(prop.value, valueTaint);
        }
        return;
      case 'ArrayPattern':
        for (const el of pattern.elements || []) {
          if (!el) continue;
          if (el.type === 'RestElement') this.assignPattern(el.argument, valueTaint);
          else this.assignPattern(el, valueTaint);
        }
        return;
      case 'AssignmentPattern':
        this.assignPattern(pattern.left, valueTaint);
        return;
      default:
        return;
    }
  }

  // Evaluate an expression, returning { tainted, chain }.
  // Sink calls are checked here (their arguments are
  // evaluated first, so taint is known when the call is
  // judged).
  evalExpr(node) {
    if (!node) return clean();
    switch (node.type) {
      case 'Identifier': {
        const binding = this.lookup(node.name);
        if (!binding) return clean();
        return { tainted: binding.tainted, chain: [...binding.chain] };
      }
      case 'Literal':
        return clean();
      case 'TemplateLiteral': {
        let result = clean();
        for (const expr of node.expressions || []) {
          result = joinTaint(result, this.evalExpr(expr));
        }
        return result;
      }
      case 'MemberExpression': {
        // Source: member access rooted at process.argv.
        if (node.object.type === 'Identifier' && node.object.name === 'process'
          && !node.computed && node.property.type === 'Identifier' && node.property.name === 'argv') {
          return tainted(['process.argv']);
        }
        const objectTaint = this.evalExpr(node.object);
        let propTaint = clean();
        if (node.computed) propTaint = this.evalExpr(node.property);
        if (objectTaint.tainted || propTaint.tainted) {
          const text = renderMember(node) || '?.';
          const chain = [...(objectTaint.tainted ? objectTaint.chain : propTaint.chain), text];
          return tainted(chain);
        }
        return clean();
      }
      case 'CallExpression':
      case 'NewExpression': {
        const argTaints = (node.arguments || []).map((arg) => this.evalExpr(arg));
        if (node.type === 'CallExpression') this.checkSinkCall(node, argTaints);
        if (node.type === 'CallExpression') {
          // Sanitizer: the return value is clean regardless
          // of argument taint (the arguments were already
          // evaluated above, so a sink nested in one is
          // still checked).
          if (this.isSanitizerCall(node)) return clean();
          // IIFE: the callee is an inline function — analyze
          // it with the actual argument taints.
          if (node.callee.type === 'FunctionExpression' || node.callee.type === 'ArrowFunctionExpression') {
            if (this.activeFunctions.length >= MAX_CALL_DEPTH) {
              return this.unknownCallTaint(argTaints, 'anonymous');
            }
            return this.analyzeFunction(node.callee, 'anonymous', argTaints, null);
          }
          // Named call: resolve a registered user function
          // (directly, or through a function-alias binding)
          // and analyze it with the actual argument taints.
          if (node.callee.type === 'Identifier') {
            const record = this.resolveFunction(node.callee.name);
            if (record) return this.analyzeCallTarget(record, argTaints, node.callee.name);
          }
        }
        let result = clean();
        for (const t of argTaints) result = joinTaint(result, t);
        // The callee's object contributes taint too
        // (`x.y(z)` where x is tainted).
        if (node.callee && node.callee.type === 'MemberExpression') {
          const objectTaint = this.evalExpr(node.callee.object);
          if (objectTaint.tainted) result = joinTaint(result, objectTaint);
        }
        if (result.tainted) {
          const calleeText = node.callee && node.callee.type === 'Identifier'
            ? node.callee.name
            : (memberName(node.callee) || 'call');
          return tainted([...result.chain, `${calleeText}(…)`]);
        }
        return clean();
      }
      case 'AssignmentExpression': {
        // A function value assigned to a name joins the call
        // graph instead of being analyzed immediately.
        if (node.operator === '=' && node.left.type === 'Identifier'
          && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
          const record = this.registerFunction(node.left.name, node.right, node.left.name);
          this.assign(node.left.name, bindingFor(clean(), null, record));
          return clean();
        }
        const rightTaint = this.evalExpr(node.right);
        if (node.left.type === 'Identifier') {
          let aliasSink = null;
          let fnTarget = null;
          if (node.operator === '=') {
            aliasSink = aliasSinkOf(node.right, this);
            if (node.right.type === 'Identifier') fnTarget = this.lookupFunction(node.right.name);
          }
          const prior = node.operator === '=' ? null : this.lookup(node.left.name);
          const combined = prior && prior.tainted ? joinTaint({ tainted: true, chain: prior.chain }, rightTaint) : rightTaint;
          this.assign(node.left.name, bindingFor(
            combined.tainted ? tainted([...combined.chain, node.left.name]) : clean(),
            aliasSink,
            fnTarget,
          ));
        } else if (node.left.type === 'MemberExpression') {
          this.evalExpr(node.left.object);
          if (node.left.computed) this.evalExpr(node.left.property);
          // An assignment to a sink property
          // (`el.innerHTML = x`) is judged on the assigned
          // value: the property is the sink, the receiver
          // is irrelevant. Compound assignment (`+=`) judges
          // the right-hand value only — the engine does not
          // track property taint, so a tainted prior value
          // of the property itself is not visible here.
          const { assignmentSinks } = this.config;
          const prop = memberPropertyName(node.left);
          if (prop && assignmentSinks && assignmentSinks[prop] && rightTaint.tainted) {
            this.emitFinding(prop, node.left, 'tainted-assign', {
              call: renderMember(node.left) || prop,
              property: prop,
              chain: rightTaint.chain,
            }, null);
          }
        } else {
          this.assignPattern(node.left, rightTaint);
        }
        return rightTaint;
      }
      case 'BinaryExpression':
      case 'LogicalExpression': {
        const left = this.evalExpr(node.left);
        const right = this.evalExpr(node.right);
        return joinTaint(left, right);
      }
      case 'ConditionalExpression': {
        this.evalExpr(node.test);
        return joinTaint(this.evalExpr(node.consequent), this.evalExpr(node.alternate));
      }
      case 'UnaryExpression': {
        if (node.operator === '!' || node.operator === 'typeof'
          || node.operator === 'void' || node.operator === 'delete') {
          this.evalExpr(node.argument);
          return clean();
        }
        return this.evalExpr(node.argument);
      }
      case 'UpdateExpression':
        return this.evalExpr(node.argument);
      case 'AwaitExpression':
      case 'YieldExpression':
        return node.argument ? this.evalExpr(node.argument) : clean();
      case 'ObjectExpression': {
        let result = clean();
        for (const prop of node.properties || []) {
          if (prop.type === 'SpreadElement') result = joinTaint(result, this.evalExpr(prop.argument));
          else result = joinTaint(result, this.evalExpr(prop.value));
        }
        return result;
      }
      case 'ArrayExpression': {
        let result = clean();
        for (const el of node.elements || []) {
          if (!el) continue;
          result = joinTaint(result, this.evalExpr(el));
        }
        return result;
      }
      case 'SpreadElement':
        return this.evalExpr(node.argument);
      case 'SequenceExpression': {
        let result = clean();
        for (const expr of node.expressions || []) result = this.evalExpr(expr);
        return result;
      }
      case 'FunctionExpression':
      case 'ArrowFunctionExpression': {
        // Anonymous callback (argument, return value, or
        // any other unbound position): analyze immediately
        // with parameters-as-sources — a callback's
        // parameters are untrusted input by definition.
        const displayName = node.id && node.id.name ? node.id.name : 'anonymous';
        this.analyzeFunction(node, displayName, null, null);
        return clean();
      }
      case 'ClassExpression': {
        if (node.superClass) this.evalExpr(node.superClass);
        for (const member of node.body || []) {
          if (member.type === 'MethodDefinition') {
            this.analyzeFunction(member.value, member.key && member.key.name ? member.key.name : 'anonymous', null, null);
          } else if (member.type === 'ClassField' && member.init) {
            this.evalExpr(member.init);
          }
        }
        return clean();
      }
      case 'TaggedTemplateExpression':
        return this.evalExpr(node.quasi);
      default:
        return clean();
    }
  }

  // Judge one direct sink call against its sink entry:
  // the sink's judged argument (the first argument by
  // default; a sink entry may name another index with
  // `argIndex`). A call with no judged argument, or a
  // clean one, is not a finding.
  judgeSinkCall(sink, sinkEntry, callNode, callText, argTaints) {
    const index = sinkEntry && typeof sinkEntry.argIndex === 'number' ? sinkEntry.argIndex : 0;
    const judged = argTaints[index];
    if (judged && judged.tainted) {
      this.emitFinding(sink, callNode, 'tainted-arg', {
        call: callText,
        chain: judged.chain,
        argIndex: index || undefined,
      }, null);
    }
  }

  // Judge one call: direct sink with a tainted judged
  // argument, or an aliased sink call with any argument.
  // Zero-argument calls cannot carry attacker data and
  // are not reported.
  checkSinkCall(node, argTaints) {
    const { sinks, methodSinks } = this.config;
    if (!argTaints || argTaints.length === 0) return;
    const callee = node.callee;
    if (callee.type === 'MemberExpression') {
      const name = memberName(callee);
      if (name && sinks[name]) {
        this.judgeSinkCall(name, sinks[name], callee, name, argTaints);
        return;
      }
      // A method sink matches by method name alone,
      // whatever the receiver (`el.insertAdjacentHTML(...)`):
      // the method exists only on DOM elements, so the name
      // is distinctive enough to judge without a receiver
      // list.
      const prop = memberPropertyName(callee);
      if (prop && methodSinks && methodSinks[prop]) {
        this.judgeSinkCall(prop, methodSinks[prop], callee, name || prop, argTaints);
      }
      return;
    }
    if (callee.type === 'Identifier') {
      // A bare-name sink (`unserialize(d)`) is a direct sink
      // call; anything else is judged by its alias binding.
      if (sinks[callee.name]) {
        this.judgeSinkCall(callee.name, sinks[callee.name], callee, callee.name, argTaints);
        return;
      }
      if (methodSinks && methodSinks[callee.name]) {
        this.judgeSinkCall(callee.name, methodSinks[callee.name], callee, callee.name, argTaints);
        return;
      }
      const binding = this.lookup(callee.name);
      if (binding && binding.aliasSink) {
        // The aliased call is reported with any argument;
        // the judged argument (not necessarily the first)
        // carries the taint evidence when it is tainted.
        const entry = (sinks && sinks[binding.aliasSink])
          || (methodSinks && methodSinks[binding.aliasSink]);
        const index = entry && typeof entry.argIndex === 'number' ? entry.argIndex : 0;
        const judged = argTaints[index] || argTaints[0];
        this.emitFinding(binding.aliasSink, callee, 'aliased-call', judged, {
          name: callee.name,
        });
      }
    }
  }
}

// The canonical sink name an expression resolves to when
// used as an alias initializer (`yaml.load`,
// `yaml['load']`, `el.insertAdjacentHTML`, or an
// identifier already aliased to one); otherwise null. A
// method sink resolves by its method name alone.
function aliasSinkOf(node, analyzer) {
  if (!node) return null;
  if (node.type === 'MemberExpression') {
    const name = memberName(node);
    if (name && analyzer.config.sinks[name]) return name;
    const prop = memberPropertyName(node);
    if (prop && analyzer.config.methodSinks && analyzer.config.methodSinks[prop]) return prop;
    return null;
  }
  if (node.type === 'Identifier') {
    // A bare-name sink bound to a new name (`const f =
    // fetch`, `const f = unserialize`) is an alias of
    // that sink: the bare name IS the sink value, so the
    // binding carries it. (Round 105: without this, only
    // member-expression aliases resolved.)
    if (analyzer.config.sinks[node.name]) return node.name;
    const binding = analyzer.lookup(node.name);
    return binding ? binding.aliasSink : null;
  }
  return null;
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
function scanRecord(config, record) {
  const detectorName = config.detectorName;
  if (!isNonEmptyString(record.content)) {
    throw new Error(`${detectorName}: record has no non-empty string "content" to scan.`);
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`${detectorName}: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error(`${detectorName}: "source" must be a non-empty string when present.`);
  }
  if (record.language !== undefined && record.language !== null) {
    if (typeof record.language !== 'string' || !JS_LANGUAGES.has(record.language.toLowerCase())) {
      throw new Error(`${detectorName}: record language is "${String(record.language)}", not JavaScript.`);
    }
  }
  const source = isNonEmptyString(record.source) ? record.source : null;

  let program;
  try {
    program = parseJavaScript(record.content);
  } catch (error) {
    if (error instanceof JSParseError) {
      throw new Error(`${detectorName}: failed to parse content as JavaScript: ${error.message}`);
    }
    throw error;
  }

  const analyzer = new TaintAnalyzer(config);
  analyzer.analyzeProgram(program);
  const rawFindings = analyzer.findings;
  const truncated = analyzer.dropped;

  // Ids come from the record itself (else from `defaults` at
  // normalization); a detector never invents them.
  for (const raw of rawFindings) {
    if (isNonEmptyString(record.session_id)) raw.session_id = record.session_id;
    if (isNonEmptyString(record.target_id)) raw.target_id = record.target_id;
    if (isNonEmptyString(record.asset_id)) raw.asset_id = record.asset_id;
  }

  for (const raw of rawFindings) {
    if (source) {
      raw.description = raw.description.replace(
        'in operator-supplied JavaScript at ',
        `in operator-supplied JavaScript (source "${source}") at `,
      );
      raw.proof_of_concept = raw.proof_of_concept.replace('Matched ', `Matched (source "${source}") `);
    }
  }
  return { rawFindings, truncated };
}

// Build the detector envelope for one detector config:
// detector(input, defaults) -> { findings, skipped, errors }.
// A batch record `{ tool, results: [...] }` scans each result
// with the batch tool forced as discovery_tool (the stub
// convention); any other object is treated as a single
// content record. A non-object input throws
// DETECTOR_INVALID_INPUT. Bad records are counted in
// `skipped`, never thrown.
function createTaintDetector(config) {
  function detector(input, defaults) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new Error('DETECTOR_INVALID_INPUT: detector input must be an object (a content record or a { tool, results } batch).');
    }
    let records;
    let tool;
    if (Array.isArray(input.results)) {
      if (input.tool !== undefined && input.tool !== null && !isNonEmptyString(input.tool)) {
        throw new Error('DETECTOR_INVALID_INPUT: batch tool must be a non-empty string when present.');
      }
      records = input.results;
      tool = isNonEmptyString(input.tool) ? input.tool : undefined;
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
          throw new Error(`${config.detectorName}: each record must be an object with a "content" string.`);
        }
        const { rawFindings, truncated } = scanRecord(config, record);
        for (const raw of rawFindings) {
          if (tool) raw.discovery_tool = tool;
          findings.push(normalizeRawFinding(raw, defaults));
        }
        if (truncated > 0) {
          errors.push(`${config.detectorName}: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
        }
      } catch (error) {
        skipped += 1;
        errors.push(error instanceof Error ? error.message : String(error));
      }
    }
    return { findings, skipped, errors };
  }
  return detector;
}

module.exports = {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  MAX_TAINT_CHAIN,
  MAX_CALL_DEPTH,
  SANITIZERS,
  JS_LANGUAGES,
  memberName,
  memberPropertyName,
  renderMember,
  collectParamNames,
  findingIdFor,
  TaintAnalyzer,
  createTaintDetector,
};
