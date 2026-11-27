// Sixth REAL detector (Phase 5, round 95): tainted-deserialize.
//
// The first PARSER-BASED detector. The five regex detectors
// (rounds 86–90) proved the framework on call-site text; this
// one proves it on structure and flow. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint
// intra-procedurally from sources to unsafe deserialization
// sinks. See docs/parser-taint-scope-v1.md for the scoping
// (what regex cannot do, the subset grammar, the dependency
// decision) and docs/detection-tainted-deserialize-v1.md for
// the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument is tainted
//     (kind 'tainted-arg', evidence carries the taint chain);
//   - an ALIASED sink call (`const l = yaml.load`,
//     `const { load } = yaml`) with any first argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these calls
//     at all).
// A direct sink call with a clean argument is NOT reported:
// the regex detector already flags that call site, and the
// AST detector adds nothing. `JSON.parse` and
// `yaml.safeLoad` are not sinks (safe loaders).
//
// Sinks (JavaScript): yaml.load, YAML.load, yaml.loadAll,
// unserialize (js-yaml / phpjs-style). Python's pickle /
// marshal / shelve stay regex-covered by dangerous-call —
// this parser is JavaScript-only by design.
//
// Sources: every function parameter (untrusted input by
// definition) and member access rooted at `process.argv`.
// Propagation: assignment / declaration, member access on a
// tainted base, binary / logical / conditional expressions,
// template interpolations, array / object literals, await,
// unary `-` / `+` / `~`. `!`, `typeof`, `void`, `delete`
// cleanse (they produce a boolean or nothing, not the data).
// Return values of unknown calls are clean (an
// under-approximation, documented). Taint does not cross
// function boundaries; branch joins are OR (tainted on any
// path stays tainted). No sanitizer modeling: a validate()
// call does not cleanse taint. Block scoping is not modeled:
// bindings are function-scoped (a simplification,
// documented).
//
// Safety properties (tested, not assumed):
// - A finding carries only the sink name, position, and a
//   taint chain of IDENTIFIER NAMES — never a literal value,
//   never a source line, never an argument's text. The
//   chain proves the flow; the values stay in the
//   operator's record.
// - `finding_id` is deterministic: `tainted-deserialize-` +
//   the first 16 hex chars of SHA-256
//   (`tainted-deserialize:<sink>:<line>:<column>:<kind>`).
// - One finding per distinct sink call site per record; at
//   most MAX_FINDINGS_PER_RECORD (100) findings per record.
// - Content over MAX_CONTENT_CHARS (1,000,000) is skipped,
//   not scanned. A record without a non-empty string
//   `content` is counted in `skipped` with its error
//   recorded, never thrown. A record whose `language` is
//   present and not JavaScript is skipped. Content that
//   does not parse under the subset grammar is skipped
//   with a parse error (position included) — the detector
//   NEVER falls back to scanning text with a regex.
// - A non-object input throws DETECTOR_INVALID_INPUT,
//   exactly like the other detectors. Batch records
//   `{ tool, results: [...] }` follow the stub convention.
// - session_id / target_id / asset_id come from the record
//   itself, else from `defaults`; a record missing an id
//   after defaults is counted in `skipped`, never invented.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const crypto = require('node:crypto');
const { normalizeRawFinding } = require('./normalized-record');
const { parseJavaScript, JSParseError } = require('./js-parser');

const MAX_CONTENT_CHARS = 1_000_000;
const MAX_FINDINGS_PER_RECORD = 100;
const MAX_TAINT_CHAIN = 10;

// Canonical sink name -> { label }.
const SINKS = {
  'yaml.load': { label: 'yaml.load() call' },
  'YAML.load': { label: 'YAML.load() call' },
  'yaml.loadAll': { label: 'yaml.loadAll() call' },
  unserialize: { label: 'unserialize() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { load } = yaml` binds `load` to `yaml.load`.
const SINK_ROOTS = {
  yaml: ['load', 'loadAll'],
  YAML: ['load', 'loadAll'],
};

const JS_LANGUAGES = new Set(['javascript', 'js', 'node']);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(sink, lineNumber, column, kind) {
  const digest = crypto
    .createHash('sha256')
    .update(`tainted-deserialize:${sink}:${lineNumber}:${column}:${kind}`, 'utf8')
    .digest('hex');
  return `tainted-deserialize-${digest.slice(0, 16)}`;
}

// Render a member expression as dotted text when it is a
// chain of identifiers / string literals rooted at an
// identifier (`yaml.load`, `req.body`, `a['b']`); otherwise
// null (the callee is not a simple name).
function memberName(node) {
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

// A binding: { tainted, chain, aliasSink } — aliasSink is
// the canonical sink name this identifier is bound to, or
// null.
function bindingFor(taint, aliasSink = null) {
  return { tainted: taint.tainted, chain: [...taint.chain], aliasSink };
}

function cloneBinding(binding) {
  return { tainted: binding.tainted, chain: [...binding.chain], aliasSink: binding.aliasSink };
}

class TaintAnalyzer {
  constructor() {
    // Scope stack: array of Map<name, binding>. The program
    // scope is the root; each function pushes one scope.
    // Block scoping is NOT modeled (bindings are
    // function-scoped — a documented simplification).
    this.scopes = [new Map()];
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
  // alias survives only when both paths agree on it.
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
        });
      }
      merged.push(scope);
    }
    return merged;
  }

  emitFinding(sink, callNode, kind, taintInfo, aliasInfo) {
    const line = callNode.line;
    const column = callNode.column;
    const key = `${sink}:${line}:${column}:${kind}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    if (this.findings.length >= MAX_FINDINGS_PER_RECORD) {
      this.dropped += 1;
      return;
    }
    const sinkLabel = SINKS[sink].label;
    const where = `line ${line}, column ${column}`;
    let description;
    let title;
    let evidence;
    if (kind === 'tainted-arg') {
      title = `Tainted ${sinkLabel} in supplied JavaScript`;
      description = `A ${sinkLabel} (tainted-deserialize) was found in operator-supplied JavaScript at ${where}, with a tainted first argument. Taint flow: ${taintInfo.chain.join(' → ')}. The detector parses the code and tracks the flow; it never executes the code. Whether the call is reachable with attacker-controlled input in production is unproven — verify out of band before reporting.`;
      evidence = [{
        type: 'ast-call',
        sink,
        kind,
        line,
        column,
        call: taintInfo.call,
        taint: { source: taintInfo.chain[0], chain: [...taintInfo.chain] },
      }];
    } else {
      title = `Aliased ${sinkLabel} in supplied JavaScript`;
      description = `A ${sinkLabel} (tainted-deserialize) was found in operator-supplied JavaScript at ${where}, reached through the alias '${aliasInfo.name}' bound to ${sink}. The regex detector cannot see aliased calls; this finding exists because the code was parsed. The detector never executes the code. Whether the call is reachable with attacker-controlled input in production is unproven — verify out of band before reporting.`;
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
    }
    this.findings.push({
      finding_id: findingIdFor(sink, line, column, kind),
      title,
      vulnerability_type: 'insecure deserialization',
      description,
      impact: 'These calls reconstruct objects from untrusted bytes, so attacker-controlled input reaching them can instantiate arbitrary classes and execute code during deserialization (in Python, pickle/marshal/shelve; in PHP, unserialize; yaml.load without a safe Loader).',
      remediation: 'Never deserialize untrusted input with these calls: use a data-only format (JSON) or a safe loader (yaml.safe_load, pickle only on bytes you produced yourself) and validate the result.',
      severity: 'high',
      cwe_id: 'CWE-502',
      steps_to_reproduce: [
        'Run `sentinel detect --detector tainted-deserialize --input <record.json>` over the record carrying the JavaScript.',
        `Observe the finding for ${sink} at ${where}.`,
        'Verify out of band whether the call is reachable with attacker-controlled input before reporting — the detector never executes the code, so exploitability is unproven.',
      ],
      proof_of_concept: `Matched ${sink} at ${where}: ${kind === 'tainted-arg' ? taintInfo.call : aliasInfo.name}`,
      evidence,
      discovery_tool: 'tainted-deserialize',
    });
  }

  // Analyze a function-like node (declaration, expression,
  // arrow, method value) in a fresh scope whose parameters
  // are tainted sources. `displayName` names the function
  // in taint chains.
  analyzeFunction(node, displayName) {
    const scope = new Map();
    for (const param of node.params || []) {
      for (const name of collectParamNames(param)) {
        scope.set(name, bindingFor(tainted([`parameter '${name}' of function '${displayName}'`])));
      }
    }
    this.scopes.push(scope);
    if (node.body && node.body.type === 'BlockStatement') {
      this.walkStatements(node.body.body);
    } else if (node.body) {
      // Arrow with an expression body.
      this.evalExpr(node.body);
    }
    this.scopes.pop();
  }

  walkStatements(statements) {
    for (const stmt of statements || []) this.walkStatement(stmt);
  }

  walkStatement(node) {
    if (!node) return;
    switch (node.type) {
      case 'VariableDeclaration': {
        for (const decl of node.declarations) {
          const initTaint = decl.init ? this.evalExpr(decl.init) : clean();
          this.bindPattern(decl.id, decl.init, initTaint);
        }
        return;
      }
      case 'FunctionDeclaration': {
        if (node.id) this.declare(node.id.name, bindingFor(clean()));
        this.analyzeFunction(node, node.id ? node.id.name : 'anonymous');
        return;
      }
      case 'ClassDeclaration':
      case 'ClassExpression': {
        if (node.id) this.declare(node.id.name, bindingFor(clean()));
        if (node.superClass) this.evalExpr(node.superClass);
        for (const member of node.body || []) {
          if (member.type === 'MethodDefinition') {
            const methodName = member.key && member.key.name ? member.key.name : 'anonymous';
            this.analyzeFunction(member.value, methodName);
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
      case 'ReturnStatement':
        if (node.argument) this.evalExpr(node.argument);
        return;
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
        if (initNode) aliasSink = aliasSinkOf(initNode, this);
        this.declare(pattern.name, bindingFor(
          initTaint.tainted ? tainted([...initTaint.chain, pattern.name]) : clean(),
          aliasSink,
        ));
        return;
      }
      case 'ObjectPattern': {
        // Destructured sink: `const { load } = yaml`.
        const rootName = initNode && initNode.type === 'Identifier' ? initNode.name : null;
        const sinkProps = rootName ? SINK_ROOTS[rootName] : null;
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
        let result = clean();
        for (const t of argTaints) result = joinTaint(result, t);
        // The callee's object contributes taint too
        // (`x.y(z)` where x is tainted).
        if (node.callee && node.callee.type === 'MemberExpression') {
          const objectTaint = this.evalExpr(node.callee.object);
          if (objectTaint.tainted) result = joinTaint(result, objectTaint);
        }
        if (node.type === 'CallExpression') this.checkSinkCall(node, argTaints);
        if (result.tainted) {
          const calleeText = node.callee && node.callee.type === 'Identifier'
            ? node.callee.name
            : (memberName(node.callee) || 'call');
          return tainted([...result.chain, `${calleeText}(…)`]);
        }
        return clean();
      }
      case 'AssignmentExpression': {
        const rightTaint = this.evalExpr(node.right);
        if (node.left.type === 'Identifier') {
          let aliasSink = null;
          if (node.operator === '=') aliasSink = aliasSinkOf(node.right, this);
          const prior = node.operator === '=' ? null : this.lookup(node.left.name);
          const combined = prior && prior.tainted ? joinTaint({ tainted: true, chain: prior.chain }, rightTaint) : rightTaint;
          this.assign(node.left.name, bindingFor(
            combined.tainted ? tainted([...combined.chain, node.left.name]) : clean(),
            aliasSink,
          ));
        } else if (node.left.type === 'MemberExpression') {
          this.evalExpr(node.left.object);
          if (node.left.computed) this.evalExpr(node.left.property);
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
        const displayName = 'anonymous';
        this.analyzeFunction(node, displayName);
        return clean();
      }
      case 'ClassExpression': {
        if (node.superClass) this.evalExpr(node.superClass);
        for (const member of node.body || []) {
          if (member.type === 'MethodDefinition') {
            this.analyzeFunction(member.value, member.key && member.key.name ? member.key.name : 'anonymous');
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

  // Judge one call: direct sink with a tainted first
  // argument, or an aliased sink call with any first
  // argument. Zero-argument calls cannot deserialize
  // attacker data and are not reported.
  checkSinkCall(node, argTaints) {
    if (!argTaints || argTaints.length === 0) return;
    const callee = node.callee;
    if (callee.type === 'MemberExpression') {
      const name = memberName(callee);
      if (name && SINKS[name]) {
        const first = argTaints[0];
        if (first.tainted) {
          this.emitFinding(name, callee, 'tainted-arg', {
            call: name,
            chain: first.chain,
          }, null);
        }
        return;
      }
      return;
    }
    if (callee.type === 'Identifier') {
      // Bare-name sink (`unserialize(d)`) is a direct sink
      // call; anything else is judged by its alias binding.
      if (SINKS[callee.name]) {
        const first = argTaints[0];
        if (first.tainted) {
          this.emitFinding(callee.name, callee, 'tainted-arg', {
            call: callee.name,
            chain: first.chain,
          }, null);
        }
        return;
      }
      const binding = this.lookup(callee.name);
      if (binding && binding.aliasSink) {
        const first = argTaints[0];
        this.emitFinding(binding.aliasSink, callee, 'aliased-call', first, {
          name: callee.name,
        });
      }
    }
  }
}

// The canonical sink name an expression resolves to when
// used as an alias initializer (`yaml.load`,
// `yaml['load']`, or an identifier already aliased to one);
// otherwise null.
function aliasSinkOf(node, analyzer) {
  if (!node) return null;
  if (node.type === 'MemberExpression') {
    const name = memberName(node);
    return name && SINKS[name] ? name : null;
  }
  if (node.type === 'Identifier') {
    const binding = analyzer.lookup(node.name);
    return binding ? binding.aliasSink : null;
  }
  return null;
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

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('tainted-deserialize: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`tainted-deserialize: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('tainted-deserialize: "source" must be a non-empty string when present.');
  }
  if (record.language !== undefined && record.language !== null) {
    if (typeof record.language !== 'string' || !JS_LANGUAGES.has(record.language.toLowerCase())) {
      throw new Error(`tainted-deserialize: record language is "${String(record.language)}", not JavaScript.`);
    }
  }
  const source = isNonEmptyString(record.source) ? record.source : null;

  let program;
  try {
    program = parseJavaScript(record.content);
  } catch (error) {
    if (error instanceof JSParseError) {
      throw new Error(`tainted-deserialize: failed to parse content as JavaScript: ${error.message}`);
    }
    throw error;
  }

  const analyzer = new TaintAnalyzer();
  analyzer.walkStatements(program.body);
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

// The detector: taintedDeserializeDetector(input, defaults)
// -> { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any
// other object is treated as a single content record. A
// non-object input throws DETECTOR_INVALID_INPUT. Bad records
// are counted in `skipped`, never thrown.
function taintedDeserializeDetector(input, defaults) {
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
        throw new Error('tainted-deserialize: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        if (tool) raw.discovery_tool = tool;
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`tainted-deserialize: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = taintedDeserializeDetector;
module.exports.taintedDeserializeDetector = taintedDeserializeDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = findingIdFor;
module.exports.memberName = memberName;
