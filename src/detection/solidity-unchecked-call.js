// Solidity unchecked-call detector (Phase 5, round 112):
// flags a low-level external call whose return value is
// NOT checked — the classic SWC-104 pattern. A `.call`,
// `.delegatecall`, `.staticcall`, or `.send` that fails
// returns `false` (or `(false, ...)` for the call family)
// instead of reverting, so a caller that discards the
// result never learns the transfer failed and keeps
// going as if it succeeded.
// CWE-252 (Unchecked Return Value): the return value
// exists precisely to say whether the call worked, and
// discarding it is the flaw. Not CWE-754 (Improper
// Check for Unusual or Exceptional Conditions): the
// condition here is the call's own return value, not
// an unusual state the contract should have checked.
// See docs/detection-solidity-unchecked-call-v1.md for
// the full reasoning.
//
// This is a SEPARATE analysis path like the other
// Solidity detectors: it runs on the Solidity subset AST
// from sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// expression walker + renderer + call-name helper in
// sol-guards.js — all language-neutral.
//
// The rule is syntactic and local, per function or
// modifier body:
//   1. Collect the low-level call nodes (`.call`,
//      `.delegatecall`, `.staticcall`, `.send` on ANY
//      receiver — the member name is distinctive, and
//      the parser carries no type info, so a
//      non-address `.call` method is a false positive
//      by design; see the doc).
//   2. A call is "checked" when its result is used in
//      one of four ways in the same body:
//        - inside a `require(...)` / `assert(...)`
//          argument;
//        - inside an `if` / `while` / `do-while` /
//          `for`-test;
//        - returned directly (`return addr.call(...)`);
//        - assigned to a variable (plain, declaration,
//          or tuple — a tuple binds only its FIRST
//          named element, because `.call` returns
//          `(bool, bytes)` and only the bool says
//          whether it worked) and that variable is
//          mentioned inside a `require` / `assert`
//          argument or an `if` / `while` / `do-while` /
//          `for`-test in the same body.
//   3. Every other low-level call is one finding, at
//      the call site.
//
// NOT modeled (pinned by tests, see the doc):
// `.transfer` (it reverts on failure, so there is
// nothing to check — and an ERC20 `transfer` whose
// return value is unchecked is a separate class, out
// of scope here); a call whose result is used in a
// ternary or in arithmetic (the value must gate
// something or be returned, not merely be used);
// cross-function checks (a variable checked in
// another function does not count); `try` (not in the
// subset parser — the record fails to parse loudly
// instead of being scanned approximately).
// A finding here is a candidate for manual review —
// the same posture as every detector in this repo: a
// precise, evidence-backed signal, not a verdict. A
// call that happens to succeed is still flagged — the
// detector cannot prove the call cannot fail.
'use strict';

const parseSolidity = require('./sol-parser.js');
const { SolParseError } = require('./sol-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');
const { normalizeRawFinding } = require('./normalized-record.js');
const { walkExpression, renderExpression, callName } = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-unchecked-call';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// Low-level call members. `transfer` is deliberately
// absent: it reverts on failure, so there is no return
// value to check.
const LOW_LEVEL_CALLS = new Set(['call', 'delegatecall', 'staticcall', 'send']);

// Calls whose argument counts as a check.
const CHECK_CALLS = new Set(['require', 'assert']);

// --- findings ------------------------------------------------------------

const IMPACT = 'A low-level call that fails returns false instead of reverting, so a caller that discards the result never learns the transfer failed and keeps going as if it succeeded — funds that were supposed to move stay put while the contract records them as moved, or a critical setup step silently does nothing.';
const REMEDIATION = 'Check every low-level call result: wrap the call in `require(...)` (`require(target.call{value: amount}(""), "call failed")`), or assign it to a variable and check that variable (`(bool ok, ) = target.call{value: amount}(""); require(ok);`). Prefer `.transfer` (which reverts on failure) or OpenZeppelin Address.sendValue / functionCall when the call must not fail silently.';

function makeFinding({ call, unitName, unitKind, contractName }) {
  const line = call.line;
  const column = call.column;
  const where = `line ${line}, column ${column}`;
  const notes = `low-level call ${call.text} in ${unitKind} ${unitName} of contract ${contractName} returns a value that is never checked in the same body`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, call.text, line, column, 'unchecked-return'),
    title: `Unchecked low-level call return value in ${unitName}`,
    vulnerability_type: 'unchecked return value',
    description: `${unitKind === 'modifier' ? 'Modifier' : 'Function'} ${unitName} in contract ${contractName} performs a low-level call (${call.text}) whose return value is never checked in the same body — a failed call returns false instead of reverting, so the failure is silent.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-252',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-unchecked-call --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${call.text} at ${where}.`,
      'Verify out of band whether the call can actually fail for reachable inputs — a call to a trusted address that cannot fail makes the finding a false positive, and the detector cannot prove either statically.',
    ],
    proof_of_concept: `Matched ${call.text} at ${where}: low-level call return value unchecked`,
    evidence: [{
      type: 'ast-call',
      kind: 'unchecked-low-level-call',
      sink: call.text,
      function: unitName,
      contract: contractName,
      line,
      column,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Is this call node a low-level call sink?
function isLowLevelCall(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const name = callName(node);
  return !!name && LOW_LEVEL_CALLS.has(name);
}

// Collect, for one function or modifier body: the
// low-level call nodes, and the variable names their
// results are assigned to (each name maps to the call
// nodes that produced it). A tuple binds only its FIRST
// named element — `.call` returns `(bool, bytes)` and
// only the bool says whether it worked; a check on the
// bytes does not check the call.
function collectCallsAndBindings(body) {
  const calls = new Set();
  const assigned = new Map(); // variable name -> call nodes

  walkExpression(body, (node) => {
    if (node.type === 'CallExpression' && isLowLevelCall(node)) calls.add(node);
  });
  if (calls.size === 0) return { calls, assigned };

  // Bindings. A declaration's initial value, or an
  // assignment's right side, that contains a low-level
  // call binds the declared / assigned name(s) to that
  // call. Tuple declarations carry ONE initial value at
  // statement level, binding only the first named slot;
  // plain declarations carry one initial value PER
  // DECLARATOR (`declarations[i].initialValue`,
  // statement-level `initialValue` null) — both shapes
  // must be read (the same two shapes round 111's
  // detectors read).
  function callsIn(node) {
    return [...calls].filter((call) => {
      let found = false;
      walkExpression(node, (current) => {
        if (found) return;
        if (current === call) found = true;
      });
      return found;
    });
  }
  function bind(name, produced) {
    if (!name || produced.length === 0) return;
    if (!assigned.has(name)) assigned.set(name, []);
    assigned.get(name).push(...produced);
  }
  walkExpression(body, (node) => {
    if (node.type === 'VariableDeclarationStatement') {
      if (node.initialValue) {
        // Tuple declaration: only the first NAMED slot
        // is the bool result of the call.
        const produced = callsIn(node.initialValue);
        const firstNamed = (node.declarations || []).find((d) => d && d.name);
        bind(firstNamed ? firstNamed.name : null, produced);
      }
      for (const declaration of node.declarations || []) {
        if (declaration && declaration.name && declaration.initialValue) {
          bind(declaration.name, callsIn(declaration.initialValue));
        }
      }
      return;
    }
    if (node.type === 'AssignmentExpression' && node.operator === '=') {
      if (node.left && node.left.type === 'Identifier') {
        bind(node.left.name, callsIn(node.right));
        return;
      }
      if (node.left && node.left.type === 'TupleExpression') {
        // Tuple assignment: only the first NAMED element
        // is the bool result of the call.
        const produced = callsIn(node.right);
        const firstNamed = (node.left.elements || []).find((e) => e && e.type === 'Identifier');
        bind(firstNamed ? firstNamed.name : null, produced);
      }
    }
  });
  return { calls, assigned };
}

// Is this node a check position — a `require` /
// `assert` call, or a branch / loop test?
function isCheckPosition(node) {
  if (!node) return false;
  if (node.type === 'CallExpression') {
    const name = callName(node);
    return !!name && CHECK_CALLS.has(name);
  }
  return node.type === 'IfStatement' || node.type === 'WhileStatement'
    || node.type === 'DoWhileStatement' || node.type === 'ForStatement';
}

// The subtree that carries the checked value for a
// check position: a require / assert argument, a
// branch / loop test, a return argument.
function checkSubtree(node) {
  if (node.type === 'CallExpression') return (node.arguments || [])[0] || null;
  if (node.type === 'IfStatement' || node.type === 'WhileStatement'
    || node.type === 'DoWhileStatement') return node.test || null;
  if (node.type === 'ForStatement') return node.test || null;
  return null;
}

// Analyze one function or modifier body. Returns the
// unchecked low-level call sites in it.
function analyzeUnit(body) {
  if (!body) return [];
  const { calls, assigned } = collectCallsAndBindings(body);
  if (calls.size === 0) return [];
  const checked = new Set();

  // Direct checks: the call sits inside a require /
  // assert argument, a branch / loop test, or a return
  // argument.
  function markCheckedInSubtree(subtree) {
    if (!subtree) return;
    walkExpression(subtree, (current) => {
      if (current.type === 'CallExpression' && calls.has(current)) checked.add(current);
    });
  }
  walkExpression(body, (node) => {
    if (isCheckPosition(node)) markCheckedInSubtree(checkSubtree(node));
    if (node.type === 'ReturnStatement') markCheckedInSubtree(node.argument);
  });

  // Name-based checks: a variable bound to a call is
  // mentioned inside a check subtree.
  if (assigned.size > 0) {
    const mentioned = new Set();
    walkExpression(body, (node) => {
      if (!isCheckPosition(node)) return;
      const subtree = checkSubtree(node);
      if (!subtree) return;
      walkExpression(subtree, (current) => {
        if (current.type === 'Identifier' && assigned.has(current.name)) {
          mentioned.add(current.name);
        }
      });
    });
    for (const name of mentioned) {
      for (const call of assigned.get(name) || []) checked.add(call);
    }
  }

  return [...calls].filter((call) => !checked.has(call)).map((call) => ({
    call: { text: renderExpression(call), line: call.line, column: call.column },
  }));
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      for (const site of analyzeUnit(fn.body)) {
        findings.push(makeFinding({
          call: site.call,
          unitName: fn.name,
          unitKind: 'function',
          contractName: contract.name,
        }));
      }
    }
    for (const modifier of contract.modifiers || []) {
      for (const site of analyzeUnit(modifier.body)) {
        findings.push(makeFinding({
          call: site.call,
          unitName: modifier.name,
          unitKind: 'modifier',
          contractName: contract.name,
        }));
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
// the unchecked-call analysis instead.
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
function solidityUncheckedCallDetector(input, defaults) {
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

module.exports = solidityUncheckedCallDetector;
module.exports.solidityUncheckedCallDetector = solidityUncheckedCallDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
