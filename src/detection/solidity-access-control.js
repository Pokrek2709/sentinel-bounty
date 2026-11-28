// Solidity access-control detector (Phase 5, round 109):
// flags an external/public function that performs a
// sensitive operation with no access control at all — no
// onlyOwner/role modifier, no require(msg.sender == ...)
// check, no if-revert guard on msg.sender. The guard
// rule lives in sol-guards.js (shared with the
// unprotected-initializer detector); this file owns the
// "sensitive operation" half.
// CWE-862 (Missing Authorization), not CWE-284: the flaw
// is the complete absence of an authorization check
// before a sensitive operation. CWE-284 (Improper Access
// Control) is the broader parent — it covers a check
// that exists but is wrong or incomplete (a tx.origin
// check is round 110 territory, not this detector).
//
// A sensitive operation is, per the approved round-109
// scope:
//   - a write to a state variable (assignment, update,
//     delete), or
//   - an external fund-moving call (.call / .transfer /
//     .send on any receiver), or
//   - a selfdestruct call, or
//   - a delegatecall (arbitrary code in this contract's
//     context — the SWC-112 shape; the call itself moves
//     no funds, but an unprotected delegatecall is the
//     canonical "unprotected sensitive function").
// Visibility is a filter, not a detail: only external /
// public functions are flagged (an internal / private
// function cannot be called by anyone directly, and a
// function with no visibility qualifier is internal by
// the language default). Constructors, receive, and
// fallback are not analyzed; interface functions without
// bodies are skipped.
//
// This is a SEPARATE analysis path like the reentrancy
// detector: it runs on the Solidity subset AST from
// sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// guard helpers in sol-guards.js — all language-neutral.
//
// FALSE-POSITIVE PROFILE — read this before trusting a
// finding: the detector cannot tell intent. A public
// function that is MEANT to be public — deposit(),
// vote(), claim() — writes state with no access control
// and is flagged. That is by design: the brief defines
// "sensitive" as state-write / fund-move / ownership
// change, and the detector reports every externally
// callable function matching it. A finding here is a
// candidate for manual review — the reviewer dismisses
// the ones that are public by design. The same posture
// as every detector in this repo: a precise,
// evidence-backed signal, not a verdict.
'use strict';

const parseSolidity = require('./sol-parser.js');
const { SolParseError } = require('./sol-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');
const { normalizeRawFinding } = require('./normalized-record.js');
const {
  walkExpression,
  hasAccessControl,
  effectiveStateVars,
} = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-access-control';
const FUND_MEMBERS = new Set(['call', 'transfer', 'send']);
const EXTERNAL_VISIBILITY = new Set(['external', 'public']);
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// --- AST helpers ---------------------------------------------------------

// The root identifier of an lvalue expression, or null
// when the target is not identifier-rooted (`arr[i].x`
// has root `arr`; `foo().x` has none).
function rootIdentifier(node) {
  let current = node;
  while (current) {
    if (current.type === 'Identifier') return current.name;
    if (current.type === 'MemberExpression') { current = current.object; continue; }
    return null;
  }
  return null;
}

// Render a callee for the evidence record: `msg.sender`,
// `token`, `addr.call`. A call's callee is rendered from
// its receiver chain; when the callee is a plain function
// name it is the name itself. Call arguments are elided
// as `(...)` — argument contents (which may be literals)
// never land in a finding.
function renderCallee(node) {
  if (!node) return '<unknown>';
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'MemberExpression': {
      const object = renderCallee(node.object);
      if (node.computed) return `${object}[...]`;
      return `${object}.${node.property.name}`;
    }
    case 'CallExpression':
      return `${renderCallee(node.callee)}(...)`;
    default:
      return node.type;
  }
}

// --- scope ---------------------------------------------------------------

// A stack of scopes (Sets of names). Shadowing: a name is
// a state variable only when no enclosing local scope
// declares it. Same shape as the reentrancy detector's
// scope stack — the two detectors track shadowing the
// same way, so a local named like a state variable never
// produces a write here either.
class ScopeStack {
  constructor(stateVars) {
    this.stateVars = stateVars;
    this.stack = [];
  }

  isStateVar(name) {
    if (this.stack.some((scope) => scope.has(name))) return false;
    return this.stateVars.has(name);
  }

  push(names) {
    this.stack.push(new Set(names || []));
  }

  // Add names to the innermost (current block's) scope.
  add(names) {
    if (this.stack.length === 0) this.push([]);
    for (const name of names || []) this.stack[this.stack.length - 1].add(name);
  }

  pop() {
    this.stack.pop();
  }
}

// --- sensitive-operation scan --------------------------------------------

// Collect the state writes in a function body,
// scope-aware: a write counts only when its root
// identifier is a state variable NOT shadowed by a
// parameter or a local in scope. Returns
// [{ variable, line, column }] in source order.
// The walk mirrors the reentrancy detector's statement
// walker (blocks, branches, loops) minus the
// segment/event logic — existence is all this detector
// needs, so a write in any branch counts.
function collectStateWrites(fn, stateVars) {
  const scopes = new ScopeStack(stateVars);
  const writes = [];

  const checkExpression = (node) => {
    if (!node) return;
    walkExpression(node, (current) => {
      if (current.type === 'AssignmentExpression') {
        const root = rootIdentifier(current.left);
        if (root && scopes.isStateVar(root)) {
          writes.push({ variable: root, line: current.left.line, column: current.left.column });
        }
        return;
      }
      if (current.type === 'UpdateExpression') {
        const root = rootIdentifier(current.argument);
        if (root && scopes.isStateVar(root)) {
          writes.push({ variable: root, line: current.argument.line, column: current.argument.column });
        }
        return;
      }
      if (current.type === 'UnaryExpression' && current.operator === 'delete') {
        const root = rootIdentifier(current.argument);
        if (root && scopes.isStateVar(root)) {
          writes.push({ variable: root, line: current.argument.line, column: current.argument.column });
        }
      }
    });
  };

  const walk = (statements) => {
    for (const statement of statements || []) {
      if (!statement) continue;
      switch (statement.type) {
        case 'BlockStatement':
          scopes.push([]);
          walk(statement.body);
          scopes.pop();
          break;
        case 'VariableDeclarationStatement': {
          // Initializers are evaluated before the declared
          // names exist, so they are checked first and the
          // names are added after.
          for (const declaration of statement.declarations) {
            if (declaration.initialValue) checkExpression(declaration.initialValue);
          }
          if (statement.initialValue) checkExpression(statement.initialValue);
          scopes.add(statement.declarations.map((d) => d.name));
          break;
        }
        case 'ExpressionStatement':
          checkExpression(statement.expression);
          break;
        case 'IfStatement':
          checkExpression(statement.test);
          scopes.push([]);
          walk([statement.consequent]);
          scopes.pop();
          if (statement.alternate) {
            scopes.push([]);
            walk([statement.alternate]);
            scopes.pop();
          }
          break;
        case 'ForStatement':
          scopes.push([]);
          if (statement.init) {
            if (statement.init.type === 'VariableDeclarationStatement') walk([statement.init]);
            else checkExpression(statement.init);
          }
          if (statement.test) checkExpression(statement.test);
          walk([statement.body]);
          if (statement.update) checkExpression(statement.update);
          scopes.pop();
          break;
        case 'WhileStatement':
          if (statement.test) checkExpression(statement.test);
          scopes.push([]);
          walk([statement.body]);
          scopes.pop();
          break;
        case 'DoWhileStatement':
          scopes.push([]);
          walk([statement.body]);
          scopes.pop();
          if (statement.test) checkExpression(statement.test);
          break;
        case 'ReturnStatement':
          if (statement.argument) checkExpression(statement.argument);
          break;
        case 'EmitStatement':
          checkExpression(statement.call);
          break;
        case 'UncheckedBlock':
          walk(statement.body.body);
          break;
        default:
          break;
      }
    }
  };

  const paramNames = (fn.params || []).map((p) => p.name).filter(Boolean);
  scopes.push(paramNames);
  if (fn.body) walk(fn.body.body);
  scopes.pop();
  return writes;
}

// Collect the fund-moving / destructive calls in a
// function body: .call / .transfer / .send on any
// receiver, selfdestruct, and .delegatecall. One pass
// over the whole body — no scope is needed, a call is a
// call wherever it sits. Returns
// [{ sink, kind, line, column }] in source order.
function collectSensitiveCalls(fn) {
  const calls = [];
  if (!fn.body) return calls;
  walkExpression(fn.body, (node) => {
    if (node.type !== 'CallExpression') return;
    const callee = node.callee;
    if (!callee) return;
    if (callee.type === 'MemberExpression' && !callee.computed
      && callee.property && callee.property.type === 'Identifier') {
      const member = callee.property.name;
      if (FUND_MEMBERS.has(member)) {
        calls.push({ sink: renderCallee(callee), kind: 'fund-call', line: node.line, column: node.column });
      } else if (member === 'delegatecall') {
        calls.push({ sink: renderCallee(callee), kind: 'delegatecall', line: node.line, column: node.column });
      }
      return;
    }
    if (callee.type === 'Identifier' && callee.name === 'selfdestruct') {
      calls.push({ sink: 'selfdestruct', kind: 'selfdestruct', line: node.line, column: node.column });
    }
  });
  return calls;
}

// --- findings ------------------------------------------------------------

const IMPACT = 'An unauthenticated caller can invoke this function and perform the sensitive operation it guards nothing against — changing state, moving funds, or destroying the contract — with no authorization check in the way. The impact depends on the operation: an unprotected ownership write hands the contract over, an unprotected withdrawal drains it, an unprotected selfdestruct ends it.';
const REMEDIATION = 'Add an access-control modifier (onlyOwner, or a role check such as onlyRole) or a require(msg.sender == ...) guard at the top of the function. If the function is meant to be public (a deposit, a vote, a claim), document that explicitly — the detector cannot tell intent, so a deliberate public function should carry a comment saying so.';

function describeOperation(op) {
  switch (op.type) {
    case 'state-write':
      return `writes state variable ${op.variable}`;
    case 'fund-call':
      return `performs external fund-moving call ${op.sink}`;
    case 'selfdestruct':
      return 'calls selfdestruct';
    case 'delegatecall':
      return `performs delegatecall ${op.sink}`;
    default:
      return 'performs a sensitive operation';
  }
}

function makeFinding({ op, functionName, contractName }) {
  const line = op.line;
  const column = op.column;
  const where = `line ${line}, column ${column}`;
  const opKey = op.type === 'state-write' ? op.variable : op.sink;
  const notes = `function ${functionName} in contract ${contractName} ${describeOperation(op)} at line ${line} with no access control (no onlyOwner/role modifier, no require(msg.sender == ...) check, no if-revert guard)`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, opKey, line, column, 'unprotected-sensitive-function'),
    title: `Missing access control on sensitive function ${functionName}`,
    vulnerability_type: 'broken access control',
    description: `Function ${functionName} in contract ${contractName} ${describeOperation(op)} without any access control. Anyone can call it, so the sensitive operation is exposed to unauthenticated callers.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-862',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-access-control --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${functionName} at ${where}.`,
      'Verify out of band whether the function is meant to be public — a deposit, vote, or claim function that anyone may call is a false positive by design, and the detector cannot tell intent.',
    ],
    proof_of_concept: `Matched ${describeOperation(op)} at ${where} in function ${functionName}: no access control (no onlyOwner/role modifier, no require(msg.sender == ...) check, no if-revert guard)`,
    evidence: [{
      type: 'ast-function',
      kind: 'unprotected-sensitive-function',
      function: functionName,
      contract: contractName,
      line,
      column,
      operation: op,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const byName = new Map(contracts.map((contract) => [contract.name, contract]));
  const findings = [];
  for (const contract of contracts) {
    const stateVars = effectiveStateVars(contract, byName);
    for (const fn of contract.functions || []) {
      if (fn.kind !== 'function') continue;
      if (!fn.body) continue;
      if (!EXTERNAL_VISIBILITY.has(fn.visibility)) continue;
      const guard = hasAccessControl(fn);
      if (guard.guarded) continue;
      const writes = collectStateWrites(fn, stateVars).map((w) => ({
        type: 'state-write', variable: w.variable, line: w.line, column: w.column,
      }));
      const calls = collectSensitiveCalls(fn).map((c) => ({
        type: c.kind, sink: c.sink, line: c.line, column: c.column,
      }));
      const ops = [...writes, ...calls].sort((a, b) => (
        a.line - b.line || a.column - b.column
      ));
      if (ops.length === 0) continue;
      findings.push(makeFinding({
        op: ops[0],
        functionName: fn.name,
        contractName: contract.name,
      }));
    }
  }
  return findings;
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows the reentrancy detector's pattern
// (batch / single, content cap, finding cap, ids from the
// record, normalization through normalizeRawFinding) but
// it is its OWN function: the reentrancy envelope is
// specific to that detector's analysis, and this
// detector's scanRecord parses Solidity and runs the
// access-control analysis instead.
function scanRecord(record) {
  if (typeof record.content !== 'string' || record.content.trim() === '') {
    throw new Error(`${DETECTOR_NAME}: record has no non-empty string "content" to scan.`);
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`${DETECTOR_NAME}: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.language !== undefined && record.language !== null) {
    if (typeof record.language !== 'string' || !SOL_LANGUAGES.has(record.language.toLowerCase())) {
      throw new Error(`${DETECTOR_NAME}: record language is "${String(record.language)}", not Solidity.`);
    }
  }
  let rawFindings;
  try {
    rawFindings = analyzeSolidity(record.content);
  } catch (error) {
    if (error instanceof SolParseError) {
      throw new Error(`${DETECTOR_NAME}: failed to parse content as Solidity: ${error.message}`);
    }
    throw error;
  }
  const truncated = Math.max(0, rawFindings.length - MAX_FINDINGS_PER_RECORD);
  const kept = rawFindings.slice(0, MAX_FINDINGS_PER_RECORD);

  // Ids come from the record itself (else from `defaults` at
  // normalization); a detector never invents them.
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
function solidityAccessControlDetector(input, defaults) {
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

module.exports = solidityAccessControlDetector;
module.exports.solidityAccessControlDetector = solidityAccessControlDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
