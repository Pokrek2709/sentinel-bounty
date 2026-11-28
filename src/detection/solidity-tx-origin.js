// Solidity tx.origin detector (Phase 5, round 110):
// flags `tx.origin` used in an authorization comparison
// — `require(tx.origin == owner)`, `if (tx.origin ==
// ...)`, or the same shape inside a modifier body.
// `tx.origin` is the ORIGINATOR of the whole transaction
// (the externally-owned account that started it), not
// the immediate caller: any contract in the middle can
// be tricked into calling the victim on the originator's
// behalf, and the check passes because the originator is
// still the victim. The check must be against
// `msg.sender` — the immediate caller.
// CWE-862 (Missing Authorization), not CWE-477: the flaw
// is that the intended authorization — "only the caller
// may do this" — is missing, because the check validates
// the wrong principal. CWE-477 (Use of Obsolete Function)
// is the wrong family entirely: `tx.origin` is not an
// obsolete or deprecated function, it is a live global
// that is legitimate for other uses (logging, for
// example). CWE-863 (Incorrect Authorization) is the
// closest sibling — the check exists but checks the
// wrong thing — and the repo's convention (round 109)
// uses CWE-862 for authorization failures, so this
// detector reports `cwe_id: CWE-862` and documents the
// CWE-863 reading here. See
// docs/detection-solidity-tx-origin-v1.md for the full
// reasoning.
//
// This closes the pin round 109 left behind: the
// access-control detectors deliberately do NOT treat
// `require(tx.origin == ...)` as a guard, so a function
// guarded ONLY by tx.origin is flagged by
// solidity-access-control (no guard) AND by this detector
// (wrong guard). The two findings are complementary, not
// duplicates — one says "no valid guard", the other says
// "the guard you have checks the wrong principal".
//
// This is a SEPARATE analysis path like the other
// Solidity detectors: it runs on the Solidity subset AST
// from sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// expression renderer in sol-guards.js — all
// language-neutral.
//
// The rule: a `==` / `!=` comparison whose left or right
// subtree contains a `tx.origin` member expression
// (object identifier `tx`, property `origin`). One finding
// per comparison site — a nested comparison inside an
// already-flagged one (`(tx.origin == owner) == true`)
// is flagged once, on the outermost comparison. Function
// bodies AND modifier bodies are scanned (a modifier is
// where an authorization check usually lives — the parser
// keeps ModifierDefinition nodes on the contract since
// this round, precisely so this scan is possible).
//
// NOT modeled (pinned by tests, see the doc):
// `tx.origin` used as a plain value — assigned, logged
// (`emit Log(tx.origin)`), or passed as a call argument
// (`foo(tx.origin)`) — is NOT a finding: it is not an
// authorization comparison. `require(tx.origin !=
// address(0))` IS flagged — it is a comparison using
// tx.origin, and the detector cannot tell a null-check
// from an authorization check; that is a false positive
// by design, a candidate for manual review.
// A finding here is a candidate for manual review — the
// same posture as every detector in this repo: a precise,
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
const { renderExpression } = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-tx-origin';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// --- AST helpers ---------------------------------------------------------

// Is this node a `tx.origin` member expression?
function isTxOrigin(node) {
  return !!node && node.type === 'MemberExpression' && !node.computed
    && node.object && node.object.type === 'Identifier' && node.object.name === 'tx'
    && node.property && node.property.type === 'Identifier' && node.property.name === 'origin';
}

// Does this subtree contain a `tx.origin` member
// expression? A generic recursive check — the AST is a
// tree, so no cycle guard is needed.
function containsTxOrigin(node) {
  if (!node || typeof node !== 'object') return false;
  if (isTxOrigin(node)) return true;
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      if (value.some((item) => containsTxOrigin(item))) return true;
    } else if (value && typeof value === 'object' && value.type) {
      if (containsTxOrigin(value)) return true;
    }
  }
  return false;
}

// --- findings ------------------------------------------------------------

const IMPACT = 'An attacker contract can call this function on the victim\'s behalf: the victim\'s transaction origin is still the victim, so the tx.origin check passes even though the victim never intended this call. A phishing-style contract that tricks the owner into one innocent-looking call can then drain funds, change ownership, or trigger any operation this check was supposed to protect.';
const REMEDIATION = 'Check msg.sender, never tx.origin, for authorization: `require(msg.sender == owner)` or an onlyOwner / role modifier. tx.origin is the transaction originator, not the immediate caller — any contract the originator was tricked into calling inherits the originator\'s identity. Reserve tx.origin for logging or for checks that genuinely mean "the originator", and document why.';

function makeFinding({ comparison, ownerName, contractName }) {
  const line = comparison.line;
  const column = comparison.column;
  const where = `line ${line}, column ${column}`;
  const notes = `${ownerName} in contract ${contractName} compares tx.origin at line ${line} — the check validates the transaction originator, not the immediate caller, so any contract the originator was tricked into calling passes it`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, comparison.text, line, column, 'tx-origin-comparison'),
    title: `Authorization through tx.origin in ${ownerName}`,
    vulnerability_type: 'broken access control',
    description: `${ownerName} in contract ${contractName} authorizes with tx.origin (${comparison.text}): the check validates the transaction originator, not the immediate caller, so a contract the originator was tricked into calling passes the check on the originator's behalf.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-862',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-tx-origin --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${comparison.text} at ${where}.`,
      'Verify out of band whether the comparison guards a sensitive operation — a null-check (`tx.origin != address(0)`) is a false positive by design, and the detector cannot tell it from an authorization check.',
    ],
    proof_of_concept: `Matched ${comparison.text} at ${where}: tx.origin used in an authorization comparison`,
    evidence: [{
      type: 'ast-expression',
      kind: 'tx-origin-comparison',
      function: ownerName,
      contract: contractName,
      line,
      column,
      comparison: comparison.text,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Collect the tx.origin comparisons in one body: every
// `==` / `!=` node whose subtree contains tx.origin,
// outermost only — a comparison nested inside an
// already-flagged comparison is not a second finding.
// The walk carries the `insideFlagged` flag down the
// tree: once a comparison containing tx.origin is
// flagged, its children are walked with the flag set, so
// the inner comparison of `(tx.origin == owner) == true`
// stays silent.
function collectTxOriginSites(body, ownerName, contractName, findings) {
  function walk(node, insideFlagged) {
    if (!node || typeof node !== 'object') return;
    let flagged = insideFlagged;
    if (node.type === 'BinaryExpression'
      && (node.operator === '==' || node.operator === '!=')
      && !insideFlagged && containsTxOrigin(node)) {
      findings.push(makeFinding({
        comparison: { text: renderExpression(node), line: node.line, column: node.column },
        ownerName,
        contractName,
      }));
      flagged = true;
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const item of value) walk(item, flagged);
      } else if (value && typeof value === 'object' && value.type) {
        walk(value, flagged);
      }
    }
  }
  walk(body, false);
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      if (!fn.body) continue;
      collectTxOriginSites(fn.body, fn.name, contract.name, findings);
    }
    // Modifier bodies: an authorization check usually
    // lives in a modifier, so a tx.origin comparison
    // there is the same flaw, attributed to the modifier.
    // The parser keeps ModifierDefinition nodes on the
    // contract since this round (see sol-parser.js
    // parseContract); a contract parsed by an older
    // parser shape simply has no `modifiers` array.
    for (const modifier of contract.modifiers || []) {
      if (!modifier.body) continue;
      collectTxOriginSites(modifier.body, `modifier ${modifier.name}`, contract.name, findings);
    }
  }
  return findings;
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those in
// `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows the reentrancy / access-control
// pattern (batch / single, content cap, finding cap, ids
// from the record, normalization through
// normalizeRawFinding) but it is its OWN function: those
// envelopes are specific to their detectors' analyses,
// and this detector's scanRecord parses Solidity and runs
// the tx.origin analysis instead.
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
function solidityTxOriginDetector(input, defaults) {
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

module.exports = solidityTxOriginDetector;
module.exports.solidityTxOriginDetector = solidityTxOriginDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
