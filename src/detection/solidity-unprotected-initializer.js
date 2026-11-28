// Solidity unprotected-initializer detector (Phase 5,
// round 109): flags an external/public `initialize()`
// function that carries neither the `initializer` (or
// `reinitializer`) modifier nor any access control —
// the unprotected-initializer shape (SWC-112's
// initialization half): anyone can call it and
// re-initialize the contract, typically taking
// ownership.
// CWE-862 (Missing Authorization), not CWE-284: the
// flaw is the absence of an authorization check on the
// initialization entry point. CWE-284 (Improper Access
// Control) is the broader parent — it covers a check
// that exists but is wrong or incomplete.
//
// Scope, per the approved round-109 brief: the function
// is flagged only when BOTH are missing — no
// `initializer`/`reinitializer` modifier AND no access
// control (the guard rule lives in sol-guards.js and is
// shared with the access-control detector). An
// initialize() with onlyOwner but no `initializer`
// modifier is NOT flagged: the owner re-initializing is
// a lesser issue, and the modifier is the primary guard
// against re-initialization. An initialize() with the
// `initializer` modifier but no access control is NOT
// flagged either — the modifier itself is the
// protection (it makes the second call revert).
//
// This is a SEPARATE analysis path like the reentrancy
// detector: it runs on the Solidity subset AST from
// sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// guard helpers in sol-guards.js — all language-neutral.
//
// Deliberately NOT modeled (pinned by tests):
//   - whether the contract is actually upgradeable —
//     the detector does not verify inheritance from
//     Initializable / UUPSUpgradeable or the absence
//     of a constructor. A function named `initialize`
//     on a non-upgradeable contract is still flagged
//     when it is unprotected: the name signals
//     initialization semantics, and an unprotected
//     function that (re)initializes state is a
//     missing-authorization finding either way.
//   - `onlyInitializing` on initialize() itself is not
//     counted as protection (it is a lifecycle modifier
//     for functions called DURING initialization, and
//     treating it as a guard here would hide a
//     genuinely unprotected entry point behind an
//     unusual pattern).
//   - constructors on upgradeable contracts (a
//     constructor that sets state in an upgradeable
//     contract is a different class — the constructor
//     runs once at deployment, not through the proxy).
//   - cross-file bases (pin round 108): an initialize()
//     inherited from a base in another file is not
//     analyzed.
// A finding here is a candidate for manual review —
// the same posture as every detector in this repo: a
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
const { hasAccessControl } = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-unprotected-initializer';
const EXTERNAL_VISIBILITY = new Set(['external', 'public']);
const INITIALIZER_MODIFIERS = new Set(['initializer', 'reinitializer']);
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// --- findings ------------------------------------------------------------

const IMPACT = 'Anyone can call initialize() and re-initialize the contract — typically setting themselves as owner, resetting balances, or re-running one-time setup — because the function carries neither the `initializer` modifier (which would make a second call revert) nor any access control. The classic outcome is an ownership takeover of an upgradeable contract.';
const REMEDIATION = 'Add the `initializer` modifier (OpenZeppelin Initializable) to initialize() so it can run exactly once, and restrict who may call it with an access-control modifier (onlyOwner or a role check) or a require(msg.sender == ...) guard. If the contract is not upgradeable, rename the function or protect it anyway — a public function named initialize that anyone may call is a standing invitation.';

function makeFinding({ functionName, contractName, line, column, modifiers }) {
  const where = `line ${line}, column ${column}`;
  const notes = `function ${functionName} in contract ${contractName} at line ${line} has no initializer/reinitializer modifier and no access control (no onlyOwner/role modifier, no require(msg.sender == ...) check, no if-revert guard); modifiers present: ${modifiers.length > 0 ? modifiers.join(', ') : 'none'}`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, functionName, line, column, 'unprotected-initializer'),
    title: `Unprotected initializer ${functionName} in ${contractName}`,
    vulnerability_type: 'broken access control',
    description: `Function ${functionName} in contract ${contractName} is an initializer with neither the \`initializer\` modifier nor any access control. Anyone can call it and re-initialize the contract.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-862',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-unprotected-initializer --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${functionName} at ${where}.`,
      'Verify out of band whether the contract is upgradeable and whether initialize() is meant to be callable more than once — a deliberately re-runnable initializer is a false positive by design, and the detector cannot tell intent.',
    ],
    proof_of_concept: `Matched initialize() at ${where} in contract ${contractName}: no initializer/reinitializer modifier and no access control`,
    evidence: [{
      type: 'ast-function',
      kind: 'unprotected-initializer',
      function: functionName,
      contract: contractName,
      line,
      column,
      modifiers,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      if (fn.kind !== 'function') continue;
      if (fn.name !== 'initialize') continue;
      if (!fn.body) continue;
      if (!EXTERNAL_VISIBILITY.has(fn.visibility)) continue;
      if ((fn.modifiers || []).some((m) => INITIALIZER_MODIFIERS.has(m))) continue;
      const guard = hasAccessControl(fn);
      if (guard.guarded) continue;
      findings.push(makeFinding({
        functionName: fn.name,
        contractName: contract.name,
        line: fn.line,
        column: fn.column,
        modifiers: [...(fn.modifiers || [])],
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
// initializer analysis instead.
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
function solidityUnprotectedInitializerDetector(input, defaults) {
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

module.exports = solidityUnprotectedInitializerDetector;
module.exports.solidityUnprotectedInitializerDetector = solidityUnprotectedInitializerDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
