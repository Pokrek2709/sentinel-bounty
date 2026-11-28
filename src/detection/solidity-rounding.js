// Solidity rounding detector (Phase 5, round 110):
// flags integer division BEFORE multiplication — the
// classic precision-loss pattern (`x / y * z`,
// `amount / total * price`). Solidity has no floating
// point: `x / y` truncates toward zero, so dividing
// first throws away the remainder before the
// multiplication can use it, and the result is
// systematically smaller than the exact value.
// CWE-682 (Incorrect Calculation): the arithmetic itself
// is wrong — a truncation the author did not intend —
// not an underflow (CWE-191, wrap-around) and not an
// overflow (CWE-190). See
// docs/detection-solidity-rounding-v1.md for the full
// reasoning.
//
// The safe shape is multiply-first, divide-last
// (`x * y / z` parses as `(x * y) / z` — the division
// is the LAST operation, so the truncation happens once,
// at the end, and is the intended rounding). That shape
// is NOT a finding, and neither is a bare division
// (`x / y` with no following multiplication — the
// truncation is the whole result, not a loss before a
// later operation).
//
// This is a SEPARATE analysis path like the other
// Solidity detectors: it runs on the Solidity subset AST
// from sol-parser.js, NOT on the JavaScript taint engine.
// The only shared code is the finding-id helper
// (findingIdFor), the content / finding caps, the
// finding normalizer (normalizeRawFinding), and the
// expression walker + renderer in sol-guards.js — all
// language-neutral.
//
// The rule is syntactic and local: a `*` BinaryExpression
// whose left or right operand is DIRECTLY a `/`
// BinaryExpression. One finding per multiplication site.
// Parenthesized `(a / b) * c` is the same AST as
// `a / b * c` (the parser has no paren node), so it is
// flagged the same way.
//
// NOT modeled (pinned by tests, see the doc):
// division and multiplication in separate statements
// (`uint q = x / y; ... z = q * w;` — needs data flow,
// not one expression); a division inside a call argument
// of a multiplied value (`foo(a / b) * c` — the `/` is
// not a direct operand of the `*`); exponentiation
// (`(x / y) ** 2` — precision loss of a different shape,
// out of this round's scope); modifier bodies (only
// function bodies are scanned).
// A finding here is a candidate for manual review — the
// same posture as every detector in this repo: a precise,
// evidence-backed signal, not a verdict. A division that
// divides evenly (a constant denominator that always
// divides the numerator) is still flagged — the detector
// cannot prove divisibility statically.
'use strict';

const parseSolidity = require('./sol-parser.js');
const { SolParseError } = require('./sol-parser.js');
const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./taint-engine.js');
const { normalizeRawFinding } = require('./normalized-record.js');
const { walkExpression, renderExpression } = require('./sol-guards.js');

const DETECTOR_NAME = 'solidity-rounding';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// --- findings ------------------------------------------------------------

const IMPACT = 'The division truncates toward zero before the multiplication runs, so the result is systematically smaller than the exact value — a share price, a reward split, or a fee that always rounds against one party. Repeated over many operations the lost remainder compounds into real funds that belong to no one, or to the wrong party.';
const REMEDIATION = 'Multiply first, divide last: rewrite `x / y * z` as `x * z / y` so the truncation happens once, at the end, and is the intended rounding. When the exact value matters more than gas, scale the numerator first (multiply by a precision factor such as 1e18 before dividing) and document the rounding direction.';

function makeFinding({ division, multiplication, functionName, contractName }) {
  const line = multiplication.line;
  const column = multiplication.column;
  const where = `line ${line}, column ${column}`;
  const notes = `function ${functionName} in contract ${contractName} computes ${multiplication.text} — the division ${division.text} truncates before the multiplication runs, so the result loses precision`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, division.text, line, column, 'divide-before-multiply'),
    title: `Rounding loss: division before multiplication in ${functionName}`,
    vulnerability_type: 'integer precision loss',
    description: `Function ${functionName} in contract ${contractName} divides before it multiplies (${multiplication.text}): the division ${division.text} truncates toward zero first, so the multiplied result is systematically smaller than the exact value.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'medium',
    cwe_id: 'CWE-682',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-rounding --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${multiplication.text} at ${where}.`,
      'Verify out of band whether the division can actually truncate for reachable inputs — a denominator that always divides the numerator evenly makes the finding a false positive, and the detector cannot prove divisibility statically.',
    ],
    proof_of_concept: `Matched ${multiplication.text} at ${where}: division ${division.text} truncates before the multiplication`,
    evidence: [{
      type: 'ast-expression',
      kind: 'divide-before-multiply',
      function: functionName,
      contract: contractName,
      line,
      column,
      division: division.text,
      multiplication: multiplication.text,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Collect the divide-before-multiply sites in one
// function body: every `*` node whose left or right
// operand is directly a `/` node. The walk is
// expression-wide (conditions, initializers, return
// arguments, nested calls) because the pattern can sit
// anywhere an expression sits. Each `*` node is visited
// once, so one finding per multiplication site with no
// dedup step.
function collectRoundingSites(fn) {
  const sites = [];
  if (!fn.body) return sites;
  walkExpression(fn.body, (node) => {
    if (node.type !== 'BinaryExpression' || node.operator !== '*') return;
    for (const operand of [node.left, node.right]) {
      if (operand && operand.type === 'BinaryExpression' && operand.operator === '/') {
        sites.push({
          division: { text: renderExpression(operand), line: operand.line, column: operand.column },
          multiplication: { text: renderExpression(node), line: node.line, column: node.column },
        });
        return;
      }
    }
  });
  return sites;
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      if (!fn.body) continue;
      for (const site of collectRoundingSites(fn)) {
        findings.push(makeFinding({
          division: site.division,
          multiplication: site.multiplication,
          functionName: fn.name,
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
// This envelope follows the reentrancy / access-control
// pattern (batch / single, content cap, finding cap, ids
// from the record, normalization through
// normalizeRawFinding) but it is its OWN function: those
// envelopes are specific to their detectors' analyses,
// and this detector's scanRecord parses Solidity and runs
// the rounding analysis instead.
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
function solidityRoundingDetector(input, defaults) {
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

module.exports = solidityRoundingDetector;
module.exports.solidityRoundingDetector = solidityRoundingDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
