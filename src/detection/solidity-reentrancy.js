// Solidity reentrancy detector (Phase 5, round 108):
// flags a function that performs an external call and
// then writes state afterwards — the classic
// checks-effects-interactions violation (SWC-107).
// CWE-841 (Improper Enforcement of Behavioral Workflow),
// not CWE-362: reentrancy is a state-machine ordering
// violation (an untrusted call happens before the state
// transition that should have closed the workflow), while
// CWE-362 is the broader race-condition parent. See
// docs/detection-solidity-reentrancy-v1.md for the full
// reasoning and the sibling SWC-107 mapping.
//
// This is a SEPARATE analysis path: it runs on the
// Solidity subset AST from sol-parser.js, NOT on the
// JavaScript taint engine (src/detection/taint-engine.js),
// which is JavaScript-specific — its identifiers, member
// expressions, call shapes and source model are all
// JavaScript. Reusing it for Solidity would mean lying
// about what the engine models. The only shared code is
// the finding-id helper (findingIdFor), the content /
// finding caps, and the finding normalizer
// (normalizeRawFinding) — all language-neutral. Even the
// envelope is its own function following
// createTaintDetector's pattern, because that factory's
// scanRecord parses JavaScript and runs TaintAnalyzer;
// this detector's scanRecord parses Solidity instead.
// The CLI and the finding record look identical to a
// caller either way.
//
// Analysis model (segment-based, branch-sensitive):
// - Statements are walked in source order, collecting
//   events per segment: an external call (sink) or a
//   state write.
// - A branch (if) evaluates its test first, then walks
//   the consequent and the alternate as separate segments
//   seeded with the events before the branch — events
//   inside a branch never leak out of it (the write may
//   or may not happen).
// - A loop body is seeded with the events before the loop
//   and the test; the loop's update (for) is analyzed as
//   a segment seeded with the body events.
// - return / revert(...) / break / continue end a
//   segment: dead code after them is not analyzed (a
//   return after a call is the correct pattern).
// - A function with the `nonReentrant` modifier is not
//   flagged. A constructor is not analyzed (it cannot be
//   re-entered while it is still constructing).
// - One finding per call site: the call and the FIRST
//   state write after it in the same segment.
//
// Sinks: `.call`, `.transfer`, `.send` on ANY receiver
// (in Solidity the member name is distinctive —
// `token.transfer(...)` is an external call to another
// contract too). `.delegatecall` / `.staticcall` are NOT
// sinks this round (a delegatecall class of its own; pin
// it in the tests, don't silently include it).
//
// A state write is an assignment (simple or compound), an
// update (`x++`), or `delete` whose target's root
// identifier is a state variable of this contract or of
// one of its bases declared in the same file. A local
// variable or a parameter with the same name shadows the
// state variable inside its scope (tracked while walking).
//
// NOT modeled (pinned by tests, see the doc):
// cross-function reentrancy, storage-reference aliasing,
// cross-iteration writes inside one loop body, `this.`
// calls. A finding here is a candidate for manual review
// — the same posture as every detector in this repo: a
// precise, evidence-backed signal, not a verdict.
'use strict';

const parseSolidity = require('./sol-parser.js');
const { SolParseError } = require('./sol-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');
const { normalizeRawFinding } = require('./normalized-record.js');

const SINK_MEMBERS = new Set(['call', 'transfer', 'send']);
const TERMINATING_CALLS = new Set(['revert']);
const DETECTOR_NAME = 'solidity-reentrancy';

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

// Walk an expression tree, calling `visit(node)` on every
// node (pre-order). A call node is visited once; its
// callee and arguments are walked too, so a sink nested
// inside an argument (`x.transfer(f())`) is still seen,
// and so is a sink inside a condition or an initializer.
function walkExpression(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  if (node.type === 'TupleExpression') {
    for (const element of node.elements) walkExpression(element, visit);
    return;
  }
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const item of value) walkExpression(item, visit);
    } else if (value && typeof value === 'object' && value.type) {
      walkExpression(value, visit);
    }
  }
}

// Is this expression (or any sub-expression) an external
// call sink? Returns the CallExpression node, or null.
function findSinkInExpression(node) {
  let found = null;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type !== 'CallExpression') return;
    const callee = current.callee;
    if (callee && callee.type === 'MemberExpression'
      && !callee.computed && SINK_MEMBERS.has(callee.property.name)) {
      found = current;
    }
  });
  return found;
}

// Is this expression a state write? Returns
// { variable, line, column } for the written variable, or
// null. Assignment / update / delete only; a read
// (`balances[msg.sender]`) is not a write.
function findWriteInExpression(node, isStateVar) {
  let found = null;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type === 'AssignmentExpression') {
      const root = rootIdentifier(current.left);
      if (root && isStateVar(root)) {
        found = {
          variable: root,
          line: current.left.line,
          column: current.left.column,
        };
      }
      return;
    }
    if (current.type === 'UpdateExpression') {
      const root = rootIdentifier(current.argument);
      if (root && isStateVar(root)) {
        found = {
          variable: root,
          line: current.argument.line,
          column: current.argument.column,
        };
      }
      return;
    }
    if (current.type === 'UnaryExpression' && current.operator === 'delete') {
      const root = rootIdentifier(current.argument);
      if (root && isStateVar(root)) {
        found = {
          variable: root,
          line: current.argument.line,
          column: current.argument.column,
        };
      }
    }
  });
  return found;
}

// Is this statement (or an expression inside it) a
// terminating call — `revert(...)`? A return statement is
// handled by the caller.
function isRevertStatement(node) {
  if (!node || node.type !== 'ExpressionStatement') return false;
  const expr = node.expression;
  return expr && expr.type === 'CallExpression'
    && expr.callee && expr.callee.type === 'Identifier'
    && TERMINATING_CALLS.has(expr.callee.name);
}

// --- scope ---------------------------------------------------------------

// A stack of scopes (Sets of names). Shadowing: a name is
// a state variable only when no enclosing local scope
// declares it.
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

  // Add names to the innermost (current block's) scope:
  // a declaration shadows a state variable from here to
  // the end of its enclosing block, and the block's pop
  // removes it. Pushing a fresh scope per declaration
  // would leak it past the block (the block pops once).
  add(names) {
    if (this.stack.length === 0) this.push([]);
    for (const name of names || []) this.stack[this.stack.length - 1].add(name);
  }

  pop() {
    this.stack.pop();
  }
}

// --- segment walker ------------------------------------------------------

// The analyzer walks one function's body as a list of
// segments. A segment is the ordered events (calls and
// writes) of one straight-line stretch of code; a finding
// is a call followed by a write in the SAME segment.
// `events` is the running list for the current segment;
// `findings` collects findings (deduped by call site).
class Analyzer {
  constructor(stateVars, functionName, findings, contractName) {
    this.scopes = new ScopeStack(stateVars);
    this.functionName = functionName;
    this.findings = findings;
    this.contractName = contractName;
    this.seenCallSites = new Set();
  }

  isStateVar(name) {
    return this.scopes.isStateVar(name);
  }

  // Record one event in the current segment; when a write
  // follows a call in the same segment, emit a finding
  // for that call site. The write pairs with the NEAREST
  // preceding call in the segment (two call sites with a
  // write each are two findings, not one).
  record(event, events) {
    events.push(event);
    if (event.kind !== 'write') return;
    const call = [...events].reverse().find((e) => e.kind === 'call');
    if (!call) return;
    const site = `${call.line}:${call.column}`;
    if (this.seenCallSites.has(site)) return;
    this.seenCallSites.add(site);
    this.findings.push(makeFinding({
      call,
      write: event,
      functionName: this.functionName,
      contractName: this.contractName,
    }));
  }

  // Analyze one expression for sinks and writes, in
  // execution order: a sink is recorded before a write
  // in the same expression. That matters for an
  // assignment whose value is the call —
  // `balances[x] = addr.call{value: 1}("")` writes the
  // state variable AFTER the call returns, so it IS a
  // call-then-write and it is flagged.
  analyzeExpression(node, events) {
    if (!node) return;
    const sink = findSinkInExpression(node);
    if (sink) {
      this.record({
        kind: 'call',
        line: sink.line,
        column: sink.column,
        sink: renderCallee(sink.callee),
      }, events);
    }
    const write = findWriteInExpression(node, (name) => this.isStateVar(name));
    if (write) {
      this.record({
        kind: 'write',
        variable: write.variable,
        line: write.line,
        column: write.column,
      }, events);
    }
  }

  // Analyze a statement list as one segment (the caller
  // owns the segment's lifetime: a branch or a loop
  // passes a fresh list seeded with the caller's events).
  analyzeStatements(statements, events) {
    for (const statement of statements || []) {
      if (this.analyzeStatement(statement, events)) break;
    }
  }

  // Analyze one statement into the current segment.
  // Returns true when the segment ends here (return /
  // revert / break / continue) so the caller stops the
  // segment — dead code after it is not analyzed.
  analyzeStatement(node, events) {
    if (!node) return false;
    switch (node.type) {
      case 'BlockStatement': {
        this.scopes.push([]);
        this.analyzeStatements(node.body, events);
        this.scopes.pop();
        return false;
      }
      case 'EmptyStatement':
        return false;
      case 'ExpressionStatement':
        this.analyzeExpression(node.expression, events);
        return isRevertStatement(node);
      case 'VariableDeclarationStatement': {
        const names = node.declarations.map((d) => d.name);
        this.scopes.add(names);
        for (const declaration of node.declarations) {
          this.analyzeExpression(declaration.initialValue, events);
        }
        this.analyzeExpression(node.initialValue, events);
        // The names stay in the enclosing block's scope
        // (added above) and are removed when the block
        // ends — a declaration never shadows past its
        // own block.
        return false;
      }
      case 'UncheckedBlock':
        this.analyzeStatements(node.body.body, events);
        return false;
      case 'IfStatement': {
        this.analyzeExpression(node.test, events);
        const consequentEvents = [...events];
        this.analyzeStatement(node.consequent, consequentEvents);
        if (node.alternate) {
          const alternateEvents = [...events];
          this.analyzeStatement(node.alternate, alternateEvents);
        }
        // Branch events never leak out of the branch:
        // the write may or may not happen.
        return false;
      }
      case 'ForStatement': {
        // The init declaration (if any) is scoped to the
        // loop: push a scope for the whole loop and pop it
        // after, so a loop-local name never shadows a
        // state variable in the code after the loop.
        this.scopes.push([]);
        if (node.init) {
          if (node.init.type === 'VariableDeclarationStatement') {
            this.analyzeStatement(node.init, events);
          } else {
            this.analyzeExpression(node.init, events);
          }
        }
        if (node.test) this.analyzeExpression(node.test, events);
        const bodyEvents = [...events];
        this.analyzeStatement(node.body, bodyEvents);
        if (node.update) {
          const updateEvents = [...bodyEvents];
          this.analyzeExpression(node.update, updateEvents);
        }
        this.scopes.pop();
        return false;
      }
      case 'WhileStatement': {
        if (node.test) this.analyzeExpression(node.test, events);
        const bodyEvents = [...events];
        this.analyzeStatement(node.body, bodyEvents);
        return false;
      }
      case 'DoWhileStatement': {
        const bodyEvents = [...events];
        this.analyzeStatement(node.body, bodyEvents);
        if (node.test) this.analyzeExpression(node.test, bodyEvents);
        return false;
      }
      case 'ReturnStatement':
        if (node.argument) this.analyzeExpression(node.argument, events);
        return true;
      case 'BreakStatement':
      case 'ContinueStatement':
        return true;
      case 'EmitStatement':
        // An event log is not an external call and not a
        // state write; its arguments are still scanned
        // (a sink inside an emit argument is a real call).
        this.analyzeExpression(node.call, events);
        return false;
      default:
        return false;
    }
  }

  // Analyze one function body. Parameters shadow state
  // variables for the whole body; locals are scoped by
  // the block walker (the body is walked as a block, so
  // its declarations are popped when it ends).
  analyzeFunction(fn) {
    const paramNames = (fn.params || []).map((p) => p.name).filter(Boolean);
    this.scopes.push(paramNames);
    const events = [];
    if (fn.body) this.analyzeStatement(fn.body, events);
    this.scopes.pop();
  }
}

// --- findings ------------------------------------------------------------

const IMPACT = 'A re-entered call runs against stale state, so an attacker can repeat the guarded operation — typically draining funds — before the state update that should have prevented the second run takes effect. This is the classic DAO-style reentrancy failure (SWC-107).';
const REMEDIATION = 'Follow checks-effects-interactions: update all state (balances, totals, flags) BEFORE the external call, or guard the function with a nonReentrant modifier (OpenZeppelin ReentrancyGuard). Never let an untrusted call happen while state still reflects the pre-call world.';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

function makeFinding({ call, write, functionName, contractName }) {
  const sink = call.sink;
  const line = call.line;
  const column = call.column;
  const where = `line ${line}, column ${column}`;
  const notes = `external call ${sink} at line ${line} precedes state write to ${write.variable} at line ${write.line} in function ${functionName}`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, sink, line, column, 'call-then-write'),
    title: `Reentrancy: external call before state update in ${functionName}`,
    vulnerability_type: 'reentrancy',
    description: `Function ${functionName} performs an external call (${sink}) and then writes to state variable ${write.variable}. A malicious callee can re-enter the function before the state update takes effect, so the checks-effects-interactions pattern is violated.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-841',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-reentrancy --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${sink} at ${where}.`,
      'Verify out of band whether the callee is untrusted and the write guards a value (a balance, a total, a claimed flag) before reporting — the detector never executes the code, so exploitability is unproven.',
    ],
    proof_of_concept: `Matched ${sink} at ${where}: call-then-write to ${write.variable}`,
    evidence: [{
      type: 'ast-call',
      sink,
      kind: 'call-then-write',
      line,
      column,
      call: sink,
      function: functionName,
      contract: contractName,
      write: { variable: write.variable, line: write.line, column: write.column },
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- detector ------------------------------------------------------------

// Collect the effective state variables of a contract:
// its own declarations plus those of its bases declared
// in the same file (transitive, cycle-guarded). A base
// from another file is not resolved — the doc says so,
// and the detector still analyzes the contract with its
// own variables (a miss on an inherited write is a
// documented limitation, not a silent wrong answer about
// what it did see).
function effectiveStateVars(contract, byName) {
  const vars = new Set();
  const seen = new Set();
  const queue = [contract];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || seen.has(current.name)) continue;
    seen.add(current.name);
    for (const stateVar of current.stateVars || []) vars.add(stateVar.name);
    for (const baseName of current.bases || []) {
      if (byName.has(baseName)) queue.push(byName.get(baseName));
    }
  }
  return vars;
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const byName = new Map(contracts.map((contract) => [contract.name, contract]));
  const findings = [];
  for (const contract of contracts) {
    const stateVars = effectiveStateVars(contract, byName);
    for (const fn of contract.functions || []) {
      if (fn.kind === 'constructor') continue;
      if (!fn.body) continue;
      if ((fn.modifiers || []).includes('nonReentrant')) continue;
      const analyzer = new Analyzer(stateVars, fn.name, findings, contract.name);
      analyzer.analyzeFunction(fn);
    }
  }
  return findings;
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows createTaintDetector's pattern
// (batch / single, content cap, finding cap, ids from the
// record, normalization through normalizeRawFinding) but it
// is its OWN function: createTaintDetector's scanRecord is
// JavaScript-specific — it parses with parseJavaScript,
// rejects non-JavaScript languages, and runs TaintAnalyzer.
// None of that applies to Solidity, so reusing it would
// mean parsing Solidity as JavaScript.
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
function solidityReentrancyDetector(input, defaults) {
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

module.exports = solidityReentrancyDetector;
module.exports.solidityReentrancyDetector = solidityReentrancyDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
