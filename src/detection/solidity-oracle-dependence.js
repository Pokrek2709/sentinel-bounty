// Solidity oracle-dependence detector (Phase 5, round 111):
// flags a price taken from ONE on-chain source and used in a
// critical arithmetic computation with no validation — the
// classic single-source oracle pattern (`pair.getReserves()`
// -> `reserve1 * 1e18 / reserve0`, `router.getAmountsOut()`
// -> `amounts[1] * 2`, `feed.latestAnswer()` -> `answer *
// amount / 1e18`). A single DEX pool's spot price is
// manipulable by the caller in the same transaction (a
// flash-loan sandwich moves the reserves, then the
// contract values a mint, a borrow, or a liquidation off
// the moved price), so trusting it without a TWAP, a
// median, or a staleness check is the flaw.
// CWE-829 (Inclusion of Functionality from Untrusted
// Control Sphere): the price is data from an untrusted
// control sphere — a pool anyone can trade against —
// included in the contract's trusted computation. Not
// CWE-20 (Improper Input Validation): the price is not
// "input" in the validation sense, and CWE-20 says
// nothing about trusting the source. See
// docs/detection-solidity-oracle-dependence-v1.md for the
// full reasoning.
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
// The rule is syntactic and local, in three steps per
// function body:
//   1. Collect the single-source price calls
//      (`getReserves`, `getAmountsOut`, `getAmountsIn`,
//      `latestAnswer`, `latestRoundData`) and the variable
//      names their results are assigned to (plain and
//      tuple declarations, plain assignments).
//   2. A price call is "critically used" when it sits
//      inside an arithmetic expression (`*` `/` `+` `-`
//      `%`) directly, or when a variable it was assigned
//      to appears inside an arithmetic expression in the
//      same function. Name-based, no data flow: a variable
//      reassigned to a non-price value later in the
//      function still counts (documented limitation).
//   3. A function is "protected" when it calls a TWAP /
//      median helper (`consult`, `observe`, `getTWAP`,
//      `getAveragePrice`, `getPriceCumulative`,
//      `getCumulativePrice`, `median`, `getMedian`) or
//      when it checks staleness — a comparison, or a
//      `require` argument, whose subtree mentions
//      `updatedAt`, `answeredInRound`, or a `stale*`
//      identifier. Protection is presence, not
//      sufficiency: a TWAP call whose result is ignored
//      still suppresses the finding (the reviewer judges
//      whether the protection actually guards the price).
//
// One finding per critically-used price-call site, only
// in unprotected functions.
//
// NOT modeled (pinned by tests, see the doc):
// comparison-only use (`require(out >= minOut)` — the
// price gates a threshold, it is not computed with);
// price used only for display (emit) or only returned;
// a bare `price()` / `spotPrice()` call (too ambiguous
// to name as a source); cross-function protection (a
// TWAP checked in another function does not protect
// this one); modifier bodies (price computation does
// not live in modifiers).
// A finding here is a candidate for manual review — the
// same posture as every detector in this repo: a precise,
// evidence-backed signal, not a verdict. A spot price
// that happens to be fair at the moment is still
// flagged — the detector cannot prove the pool cannot
// be moved.
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

const DETECTOR_NAME = 'solidity-oracle-dependence';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// Single-source spot-price getters. `getReserves` and
// `getAmountsOut` / `getAmountsIn` read one DEX pool's
// spot price; `latestAnswer` / `latestRoundData` read
// one Chainlink feed (a feed is a single source too
// until its staleness is checked).
const PRICE_CALLS = new Set([
  'getReserves', 'getAmountsOut', 'getAmountsIn',
  'latestAnswer', 'latestRoundData',
]);

// TWAP / median / average helpers: reading one of these
// in the same function counts as protection (presence,
// not sufficiency — see the header).
const TWAP_CALLS = new Set([
  'consult', 'observe', 'getTWAP', 'getAveragePrice',
  'getPriceCumulative', 'getCumulativePrice', 'median', 'getMedian',
]);

const ARITHMETIC = new Set(['*', '/', '+', '-', '%']);
const COMPARISON = new Set(['<', '>', '<=', '>=', '==', '!=']);

// --- findings ------------------------------------------------------------

const IMPACT = 'The price comes from a single on-chain source with no validation, so an attacker who moves that source in the same transaction — a flash-loan sandwich against one DEX pool, or a stale Chainlink round — moves the price the contract values with. A mint, a borrow, a liquidation, or a payout computed off the moved price transfers real funds to the attacker at the protocol\'s expense.';
const REMEDIATION = 'Do not trust a single spot price: read a time-weighted average price (Uniswap V3 TWAP via `consult` / `observe`, or a TWAP library), take the median of several independent sources, or validate the Chainlink feed before use (check `updatedAt` freshness against `block.timestamp` and reject stale or deviating rounds). Document which source the price comes from and what makes it trustworthy.';

function makeFinding({ call, functionName, contractName }) {
  const line = call.line;
  const column = call.column;
  const where = `line ${line}, column ${column}`;
  const notes = `function ${functionName} in contract ${contractName} reads a single-source price at ${call.text} and uses it in arithmetic with no TWAP, median, or staleness check in the same function`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, call.text, line, column, 'single-source-price'),
    title: `Oracle dependence: single-source price used in ${functionName}`,
    vulnerability_type: 'oracle price dependence',
    description: `Function ${functionName} in contract ${contractName} reads a price from a single on-chain source (${call.text}) and computes with it, with no TWAP, median, or staleness check in the same function — the price can be moved by an attacker in the same transaction.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-829',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-oracle-dependence --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${call.text} at ${where}.`,
      'Verify out of band whether the price source can actually be moved for reachable inputs — a pool with deep liquidity or a feed that is checked elsewhere makes the finding a false positive, and the detector cannot prove either statically.',
    ],
    proof_of_concept: `Matched ${call.text} at ${where}: single-source price used in arithmetic with no validation`,
    evidence: [{
      type: 'ast-expression',
      kind: 'single-source-price',
      function: functionName,
      contract: contractName,
      line,
      column,
      source: call.text,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Does this subtree contain any node from `targets`
// (object identity — the walk visits the same node
// objects the collector found)?
function subtreeContains(node, targets) {
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (targets.has(current)) found = true;
  });
  return found;
}

// Does this subtree mention an identifier whose name is
// in `names`?
function subtreeMentions(node, names) {
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type === 'Identifier' && names.has(current.name)) found = true;
  });
  return found;
}

// Is this identifier a staleness marker — `updatedAt`,
// `answeredInRound`, or anything with `stale` in the
// name (`isStale`, `stalePrice`)? Compared
// case-insensitively: the feed's `updatedAt` is the
// canonical spelling, but a local `UpdatedAt` is the
// same check.
function isStalenessName(name) {
  const lower = name.toLowerCase();
  return lower === 'updatedat' || lower === 'answeredinround' || lower.includes('stale');
}

// Collect, for one function body: the price-call nodes,
// the variable names their results are assigned to
// (each name maps to the price calls that produced it),
// whether the function is protected, and which price
// calls are critically used (inside arithmetic, directly
// or through an assigned variable).
function analyzeFunction(fn) {
  if (!fn.body) return [];
  const priceCalls = new Set();
  const assigned = new Map(); // variable name -> price-call nodes

  // Price calls and their assigned names.
  walkExpression(fn.body, (node) => {
    if (node.type === 'CallExpression') {
      const name = callName(node);
      if (name && PRICE_CALLS.has(name)) priceCalls.add(node);
    }
  });
  if (priceCalls.size === 0) return [];

  // A declaration's initial value, or an assignment's
  // right side, that contains a price call binds the
  // declared / assigned name(s) to that call. Tuple
  // declarations carry ONE initial value at statement
  // level, binding every named slot; plain declarations
  // carry one initial value PER DECLARATOR
  // (`declarations[i].initialValue`, statement-level
  // `initialValue` null) — both shapes must be read.
  walkExpression(fn.body, (node) => {
    if (node.type === 'VariableDeclarationStatement') {
      if (node.initialValue) {
        const produced = [...priceCalls].filter((call) => subtreeContains(node.initialValue, new Set([call])));
        if (produced.length > 0) {
          for (const declaration of node.declarations || []) {
            if (declaration && declaration.name) {
              if (!assigned.has(declaration.name)) assigned.set(declaration.name, []);
              assigned.get(declaration.name).push(...produced);
            }
          }
        }
      }
      for (const declaration of node.declarations || []) {
        if (declaration && declaration.name && declaration.initialValue) {
          const produced = [...priceCalls].filter((call) => subtreeContains(declaration.initialValue, new Set([call])));
          if (produced.length > 0) {
            if (!assigned.has(declaration.name)) assigned.set(declaration.name, []);
            assigned.get(declaration.name).push(...produced);
          }
        }
      }
      return;
    }
    if (node.type === 'AssignmentExpression' && node.operator === '='
      && node.left && node.left.type === 'Identifier') {
      const produced = [...priceCalls].filter((call) => subtreeContains(node.right, new Set([call])));
      if (produced.length === 0) return;
      if (!assigned.has(node.left.name)) assigned.set(node.left.name, []);
      assigned.get(node.left.name).push(...produced);
    }
  });

  // Protection: a TWAP / median call anywhere in the
  // function, or a staleness check — a comparison, or a
  // `require` argument, mentioning a staleness marker.
  let protectedFn = false;
  walkExpression(fn.body, (node) => {
    if (protectedFn) return;
    if (node.type === 'CallExpression') {
      const name = callName(node);
      if (name && TWAP_CALLS.has(name)) { protectedFn = true; return; }
      if (name === 'require') {
        const arg = (node.arguments || [])[0];
        if (arg) {
          let mentions = false;
          walkExpression(arg, (inner) => {
            if (mentions) return;
            if (inner.type === 'Identifier' && isStalenessName(inner.name)) mentions = true;
          });
          if (mentions) protectedFn = true;
        }
      }
      return;
    }
    if (node.type === 'BinaryExpression' && COMPARISON.has(node.operator)) {
      let mentions = false;
      walkExpression(node, (inner) => {
        if (mentions) return;
        if (inner.type === 'Identifier' && isStalenessName(inner.name)) mentions = true;
      });
      if (mentions) protectedFn = true;
    }
  });
  if (protectedFn) return [];

  // Critical use: an arithmetic expression whose subtree
  // contains a price call directly, or an identifier
  // bound to one.
  const used = new Set();
  walkExpression(fn.body, (node) => {
    if (node.type !== 'BinaryExpression' || !ARITHMETIC.has(node.operator)) return;
    for (const call of priceCalls) {
      if (subtreeContains(node, new Set([call]))) used.add(call);
    }
    for (const [name, calls] of assigned) {
      if (subtreeMentions(node, new Set([name]))) {
        for (const call of calls) used.add(call);
      }
    }
  });
  return [...used].map((call) => ({
    call: { text: renderExpression(call), line: call.line, column: call.column },
  }));
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      for (const site of analyzeFunction(fn)) {
        findings.push(makeFinding({
          call: site.call,
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
// This envelope follows the reentrancy / access-control /
// rounding pattern (batch / single, content cap, finding
// cap, ids from the record, normalization through
// normalizeRawFinding) but it is its OWN function: those
// envelopes are specific to their detectors' analyses,
// and this detector's scanRecord parses Solidity and runs
// the oracle-dependence analysis instead.
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
function solidityOracleDependenceDetector(input, defaults) {
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

module.exports = solidityOracleDependenceDetector;
module.exports.solidityOracleDependenceDetector = solidityOracleDependenceDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
