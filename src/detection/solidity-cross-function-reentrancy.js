// Solidity cross-function reentrancy detector (Phase 5,
// round 112): flags the reentrancy variant that the
// single-function detector (round 108) cannot see. A
// function A performs an external call and then READS a
// state variable; a DIFFERENT external/public function B
// of the same contract WRITES that variable. An attacker
// re-entering through B during A's call changes the
// state A's post-call logic reads, so A runs against a
// world that no longer matches what it checked before
// the call. The classic shape is a vault whose
// `settle()` calls out and then reads `pending[user]`
// while `adjust()` can rewrite `pending` — the
// single-function detector stays silent (A never writes
// after the call) and the flaw is real.
// CWE-841 (Improper Enforcement of Behavioral Workflow),
// the same CWE as the single-function detector: this is
// the same state-machine ordering violation, spread
// across two functions. See
// docs/detection-solidity-cross-function-reentrancy-v1.md
// for the full reasoning.
//
// This is a SEPARATE analysis path like the other
// Solidity detectors: it runs on the Solidity subset AST
// from sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// expression walker + renderer + call-name helper +
// effective state variables in sol-guards.js — all
// language-neutral.
//
// The rule, per contract (own functions plus same-file
// bases, like the effective state variables):
//   1. Candidate A is an external/public function
//      (kind 'function', not a constructor) with a body.
//      Candidate B is a different external/public
//      function with a body. Both must be callable
//      from outside — an internal function can neither
//      be the entry point nor the re-entry point.
//   2. A contains an external-call sink (`.call` /
//      `.transfer` / `.send` — the same sinks as the
//      single-function detector; `.delegatecall` /
//      `.staticcall` are not sinks here either, they
//      are a class of their own).
//   3. A READS a state variable after the call: an
//      identifier naming a state variable (locals and
//      parameters shadow it — tracked by a scope stack
//      while walking) whose source position is after
//      the call's position and which is not inside the
//      call's own subtree (the receiver and the
//      arguments are evaluated BEFORE the call, so a
//      read inside them is not a post-call read) and
//      which is not a write target (a write after the
//      call is the single-function detector's domain —
//      this detector only fires for variables A reads
//      without writing).
//   4. B WRITES that variable anywhere in its body
//      (assignment, update, delete — same write model
//      as the single-function detector).
//   5. The (A, B) pair is suppressed only when BOTH
//      functions carry the `nonReentrant` modifier:
//      with a shared ReentrancyGuard, B cannot be
//      entered while A is running. Either modifier
//      alone does NOT suppress — if A is guarded but B
//      is not, B has no guard to check; if B is
//      guarded but A is not, the guard is not entered
//      during A's call, so B is callable.
// One finding per (call site, variable, B) triple.
//
// NOT modeled (pinned by tests, see the doc):
// receive / fallback as A or B; a modifier writing
// the variable (only functions are B); inheritance
// from another file (bases declared elsewhere are not
// resolved, like the state variables); `this.` calls
// (not a sink); storage-reference aliasing; a mutex
// via a shared `locked` state variable (not a
// modifier, so not recognized as a guard); reads
// inside a branch after the call count (the detector
// does not prove the branch is taken — branch
// sensitivity is position-based, not segment-based,
// so a read in an untaken branch is a false positive
// by design); a read that is also written by A after
// the call is excluded (the single-function detector
// owns that variable).
// A finding here is a candidate for manual review —
// the same posture as every detector in this repo: a
// precise, evidence-backed signal, not a verdict. A
// read that happens to see the same value is still
// flagged — the detector cannot prove B cannot be
// called between the call and the read.
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
  walkExpression, renderExpression, callName, effectiveStateVars,
} = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-cross-function-reentrancy';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// Same sinks as the single-function reentrancy
// detector (round 108): `.delegatecall` /
// `.staticcall` are a class of their own, not sinks.
const SINK_MEMBERS = new Set(['call', 'transfer', 'send']);

// --- findings ------------------------------------------------------------

const IMPACT = 'A function reads state after an external call while a different externally-callable function of the same contract writes that state, so an attacker who re-enters through the second function during the call changes what the first function\'s post-call logic sees — the checks made before the call no longer describe the world, and the post-call logic runs against attacker-chosen state, typically draining funds or double-paying a claim.';
const REMEDIATION = 'Apply checks-effects-interactions ACROSS functions, not just within one: update all state the post-call logic reads BEFORE the external call, or guard every externally-callable function that touches the shared state with the same `nonReentrant` modifier (OpenZeppelin ReentrancyGuard) so no function can be entered while another is mid-call. Never let a post-call read depend on state another public function can rewrite.';

function makeFinding({ call, read, write, aName, bName, contractName }) {
  const line = call.line;
  const column = call.column;
  const where = `line ${line}, column ${column}`;
  const notes = `function ${aName} in contract ${contractName} performs external call ${call.text} at line ${line} and then reads state variable ${read.name} at line ${read.line}, while function ${bName} writes ${read.name} at line ${write.line}`;
  return {
    finding_id: findingIdFor(
      DETECTOR_NAME, call.text, line, column,
      `cross-function-reentrancy:${read.name}:${bName}`,
    ),
    title: `Cross-function reentrancy: ${aName} reads ${read.name} after a call that ${bName} can change`,
    vulnerability_type: 'cross-function reentrancy',
    description: `Function ${aName} in contract ${contractName} performs an external call (${call.text}) and then reads state variable ${read.name}, while function ${bName} of the same contract writes ${read.name}. An attacker re-entering through ${bName} during the call changes the state ${aName}'s post-call logic reads.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-841',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-cross-function-reentrancy --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${call.text} at ${where}.`,
      'Verify out of band whether the re-entered function is actually reachable during the call and whether the changed state affects value — a write that cannot change the read outcome makes the finding a false positive, and the detector cannot prove either statically.',
    ],
    proof_of_concept: `Matched ${call.text} at ${where}: post-call read of ${read.name}, written by ${bName} at line ${write.line}`,
    evidence: [{
      type: 'ast-cross-function',
      kind: 'cross-function-reentrancy',
      call: call.text,
      function: aName,
      contract: contractName,
      reenteredFunction: bName,
      variable: read.name,
      line,
      column,
      readLine: read.line,
      readColumn: read.column,
      writeLine: write.line,
      writeColumn: write.column,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Is this call node an external-call sink?
function isSink(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const name = callName(node);
  return !!name && SINK_MEMBERS.has(name);
}

// The root identifier of an lvalue expression, or null
// when the target is not identifier-rooted (`arr[i].x`
// has root `arr`; `foo().x` has none). Same rule as the
// single-function detector.
function rootIdentifier(node) {
  let current = node;
  while (current) {
    if (current.type === 'Identifier') return current;
    if (current.type === 'MemberExpression') { current = current.object; continue; }
    return null;
  }
  return null;
}

// Compare two (line, column) positions: negative when a
// is before b, positive when after, zero when equal.
function comparePosition(a, b) {
  if (a.line !== b.line) return a.line - b.line;
  return a.column - b.column;
}

// Analyze one function body with a scope-tracking
// statement walk. Returns:
//   sinks: [{ node, text, line, column, subtree }]
//     — external-call sinks, each with the set of AST
//     nodes in its own subtree (receiver + arguments
//     are evaluated BEFORE the call, so a read inside
//     them is not a post-call read);
//   reads: [{ node, name, line, column }]
//     — identifier reads of state variables that are
//     not write targets (a write after the call is
//     the single-function detector's domain);
//   writes: [{ name, line, column }]
//     — state-variable writes (assignment, update,
//     delete), by name.
function analyzeUnitBody(body, stateVars, paramNames) {
  const sinks = [];
  const reads = [];
  const writes = [];
  const writeTargetNodes = new Set();
  const scopes = [];

  function currentScope() {
    if (scopes.length === 0) scopes.push(new Set());
    return scopes[scopes.length - 1];
  }

  function isStateVar(name) {
    if (scopes.some((scope) => scope.has(name))) return false;
    return stateVars.has(name);
  }

  // Walk one expression, classifying its nodes with the
  // scope stack the statement walker maintains.
  // walkExpression is pre-order, so an assignment /
  // update / delete node is visited before its target
  // identifier — the target is marked before the walk
  // reaches it, and the mark is what keeps a write
  // from being recorded as a read.
  function walkExpr(node) {
    if (!node) return;
    walkExpression(node, (current) => {
      if (current.type === 'AssignmentExpression') {
        const root = rootIdentifier(current.left);
        if (root) {
          writeTargetNodes.add(root);
          if (isStateVar(root.name)) {
            writes.push({ name: root.name, line: root.line, column: root.column });
          }
        }
        return;
      }
      if (current.type === 'UpdateExpression') {
        const root = rootIdentifier(current.argument);
        if (root) {
          writeTargetNodes.add(root);
          if (isStateVar(root.name)) {
            writes.push({ name: root.name, line: root.line, column: root.column });
          }
        }
        return;
      }
      if (current.type === 'UnaryExpression' && current.operator === 'delete') {
        const root = rootIdentifier(current.argument);
        if (root) {
          writeTargetNodes.add(root);
          if (isStateVar(root.name)) {
            writes.push({ name: root.name, line: root.line, column: root.column });
          }
        }
        return;
      }
      if (current.type === 'CallExpression' && isSink(current)) {
        const subtree = new Set();
        walkExpression(current, (inner) => subtree.add(inner));
        sinks.push({
          node: current,
          text: renderExpression(current.callee),
          line: current.line,
          column: current.column,
          subtree,
        });
        return;
      }
      if (current.type === 'Identifier' && !writeTargetNodes.has(current)
        && isStateVar(current.name)) {
        reads.push({
          node: current, name: current.name, line: current.line, column: current.column,
        });
      }
    });
  }

  function walkStatementsList(statements) {
    for (const statement of statements || []) walkStatement(statement);
  }

  function walkStatement(stmt) {
    if (!stmt) return;
    switch (stmt.type) {
      case 'BlockStatement':
        scopes.push(new Set());
        walkStatementsList(stmt.body);
        scopes.pop();
        break;
      case 'EmptyStatement':
        break;
      case 'ExpressionStatement':
        walkExpr(stmt.expression);
        break;
      case 'VariableDeclarationStatement': {
        // Initializers evaluate before the declared
        // names enter scope.
        for (const declaration of stmt.declarations || []) {
          if (declaration.initialValue) walkExpr(declaration.initialValue);
        }
        if (stmt.initialValue) walkExpr(stmt.initialValue);
        for (const declaration of stmt.declarations || []) {
          if (declaration.name) currentScope().add(declaration.name);
        }
        break;
      }
      case 'UncheckedBlock':
        scopes.push(new Set());
        walkStatementsList(stmt.body ? stmt.body.body : []);
        scopes.pop();
        break;
      case 'IfStatement':
        walkExpr(stmt.test);
        scopes.push(new Set());
        walkStatement(stmt.consequent);
        scopes.pop();
        if (stmt.alternate) {
          scopes.push(new Set());
          walkStatement(stmt.alternate);
          scopes.pop();
        }
        break;
      case 'ForStatement':
        scopes.push(new Set());
        if (stmt.init) {
          if (stmt.init.type === 'VariableDeclarationStatement') walkStatement(stmt.init);
          else walkExpr(stmt.init);
        }
        if (stmt.test) walkExpr(stmt.test);
        walkStatement(stmt.body);
        if (stmt.update) walkExpr(stmt.update);
        scopes.pop();
        break;
      case 'WhileStatement':
        if (stmt.test) walkExpr(stmt.test);
        scopes.push(new Set());
        walkStatement(stmt.body);
        scopes.pop();
        break;
      case 'DoWhileStatement':
        scopes.push(new Set());
        walkStatement(stmt.body);
        scopes.pop();
        if (stmt.test) walkExpr(stmt.test);
        break;
      case 'ReturnStatement':
        if (stmt.argument) walkExpr(stmt.argument);
        break;
      case 'EmitStatement':
        walkExpr(stmt.call);
        break;
      case 'RevertStatement':
        if (stmt.argument) walkExpr(stmt.argument);
        break;
      default:
        break;
    }
  }

  if (body) {
    // Parameters shadow state variables for the whole
    // body — seed them in the outermost scope.
    scopes.push(new Set(paramNames || []));
    walkStatement(body);
    scopes.pop();
  }
  return { sinks, reads, writes };
}

// Collect the functions of a contract: its own plus
// those of its bases declared in the same file
// (transitive, cycle-guarded). A base from another file
// is not resolved — same rule as the effective state
// variables.
function effectiveFunctions(contract, byName) {
  const functions = [];
  const seen = new Set();
  const queue = [contract];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || seen.has(current.name)) continue;
    seen.add(current.name);
    for (const fn of current.functions || []) {
      functions.push({ fn, contractName: current.name });
    }
    for (const baseName of current.bases || []) {
      if (byName.has(baseName)) queue.push(byName.get(baseName));
    }
  }
  return functions;
}

// Is this function an externally-callable entry point
// for this analysis: kind 'function' with external or
// public visibility and a body. Constructors are never
// candidates (they cannot be re-entered while
// constructing); receive / fallback are not modeled
// (see the doc); internal / private functions can
// neither be entered from outside nor re-entered.
function isCallable(fn) {
  return fn.kind === 'function'
    && (fn.visibility === 'external' || fn.visibility === 'public')
    && !!fn.body;
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const byName = new Map(contracts.map((contract) => [contract.name, contract]));
  const findings = [];
  for (const contract of contracts) {
    const stateVars = effectiveStateVars(contract, byName);
    const analyzed = effectiveFunctions(contract, byName)
      .filter(({ fn }) => isCallable(fn))
      .map(({ fn, contractName }) => {
        const paramNames = (fn.params || []).map((p) => p.name).filter(Boolean);
        const { sinks, reads, writes } = analyzeUnitBody(fn.body, stateVars, paramNames);
        return {
          fn,
          contractName,
          sinks,
          reads,
          writes,
          nonReentrant: (fn.modifiers || []).includes('nonReentrant'),
        };
      });
    const seen = new Set();
    for (const a of analyzed) {
      for (const sink of a.sinks) {
        for (const read of a.reads) {
          // A post-call read: after the call in source
          // order, and not inside the call's own
          // subtree (receiver / arguments are evaluated
          // before the call executes).
          if (comparePosition(read, sink) <= 0) continue;
          if (sink.subtree.has(read.node)) continue;
          for (const b of analyzed) {
            if (b === a) continue;
            const write = b.writes.find((w) => w.name === read.name);
            if (!write) continue;
            // Shared guard: only when BOTH functions
            // carry nonReentrant is the pair safe (see
            // the header — either modifier alone does
            // not suppress).
            if (a.nonReentrant && b.nonReentrant) continue;
            const key = `${sink.line}:${sink.column}:${read.name}:${b.fn.name}:${b.contractName}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push(makeFinding({
              call: sink,
              read,
              write,
              aName: a.fn.name,
              bName: b.fn.name,
              contractName: contract.name,
            }));
          }
        }
      }
    }
  }
  return findings;
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows the reentrancy / oracle /
// signature-replay pattern (batch / single, content cap,
// finding cap, ids from the record, normalization through
// normalizeRawFinding) but it is its OWN function: those
// envelopes are specific to their detectors' analyses,
// and this detector's scanRecord parses Solidity and runs
// the cross-function reentrancy analysis instead.
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
function solidityCrossFunctionReentrancyDetector(input, defaults) {
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

module.exports = solidityCrossFunctionReentrancyDetector;
module.exports.solidityCrossFunctionReentrancyDetector = solidityCrossFunctionReentrancyDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
