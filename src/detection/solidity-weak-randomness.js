// Solidity weak-randomness detector (Phase 5, round 110):
// flags block-derived entropy used as randomness —
// `block.timestamp`, `block.number`, `blockhash(...)`,
// `block.difficulty` / `block.prevrandao`, `block.coinbase`
// feeding a hash, a modulo, or a seed variable. Block
// data is public before the transaction executes and,
// for `block.timestamp` and `block.coinbase`, partly
// chosen by the block producer; `block.prevrandao` is
// the post-merge randomness beacon, but it is known to
// the block proposer in advance — it is NOT secure
// randomness either. Any "random" value derived from
// these sources is predictable, so a lottery, a loot
// box, or a random selection built on them can be gamed.
// CWE-338 (Use of Cryptographically Weak PRNG): the
// randomness source itself is weak and predictable.
// CWE-337 (Predictable Seed in PRNG) is the closest
// sibling — it covers a predictable seed fed into an
// otherwise sound generator — but here the block data
// IS the generator (the hash / modulo of block data is
// the whole "PRNG"), so CWE-338 is the right mapping.
// See docs/detection-solidity-weak-randomness-v1.md for
// the full reasoning.
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
// The rule: a block-entropy source is flagged only when
// it sits in a randomness context —
//   (a) inside the arguments of a hash call
//       (`keccak256(...)`, `sha256(...)`, `sha3(...)`), or
//   (b) as an operand of a `%` (modulo) expression — the
//       classic "random in range" — or
//   (c) as the initializer of a variable (or the right
//       side of an assignment) whose target name matches
//       /seed|random|rand|entropy/i.
// One finding per entropy-source site, with the context
// named in the evidence (hash first, then modulo, then
// seed, when more than one applies).
//
// The context restriction is the whole point: block data
// is legitimate in most code. `require(block.timestamp
// >= start)` is a deadline check, `uint256 deadline =
// block.timestamp + 1 days` is arithmetic, and
// `emit Tick(block.timestamp)` is logging — none of them
// is randomness, and none is flagged. A bare block
// source with no randomness context is never a finding.
//
// NOT modeled (pinned by tests, see the doc):
// a seed variable assigned block data and used LATER
// (`uint256 seed = block.timestamp; ... keccak256(seed)`)
// — the seed assignment is flagged by rule (c), but the
// later use is not traced (no data flow); `block.gaslimit`
// is not a source (not in the brief's list); a hash of
// user input only (`keccak256(abi.encodePacked(
// msg.sender, nonce))`) has no block source and is not
// flagged; modifier bodies are not scanned (randomness
// does not live in modifiers). A finding here is a
// candidate for manual review — the same posture as
// every detector in this repo: a precise,
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

const DETECTOR_NAME = 'solidity-weak-randomness';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);
const ENTROPY_PROPS = new Set(['timestamp', 'number', 'difficulty', 'prevrandao', 'coinbase']);
const HASH_CALLS = new Set(['keccak256', 'sha256', 'sha3']);
const SEED_NAME = /seed|random|rand|entropy/i;

// --- AST helpers ---------------------------------------------------------

// Is this node a block-entropy source — `block.<prop>`
// for a listed property, or a `blockhash(...)` call?
function isBlockEntropy(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'MemberExpression' && !node.computed
    && node.object && node.object.type === 'Identifier' && node.object.name === 'block'
    && node.property && node.property.type === 'Identifier'
    && ENTROPY_PROPS.has(node.property.name)) {
    return true;
  }
  if (node.type === 'CallExpression'
    && node.callee && node.callee.type === 'Identifier'
    && node.callee.name === 'blockhash') {
    return true;
  }
  return false;
}

// --- findings ------------------------------------------------------------

const IMPACT = 'The "random" value is derived from block data that is public before the transaction executes — and, for block.timestamp and block.coinbase, partly chosen by the block producer. An attacker can compute the outcome in advance (or, as a miner/validator, influence it) and only submit the transaction when it wins: a lottery, a loot box, or a random draw built on this source is gameable.';
const REMEDIATION = 'Do not derive randomness from block data. Use a verifiable randomness source (Chainlink VRF or an equivalent commit-reveal scheme) for anything with value at stake, and treat block.timestamp / block.number / blockhash / prevrandao as public scheduling data only — never as entropy.';

function makeFinding({ source, context, functionName, contractName }) {
  const line = source.line;
  const column = source.column;
  const where = `line ${line}, column ${column}`;
  const contextText = context === 'hash'
    ? 'inside a hash call'
    : context === 'modulo' ? 'as an operand of a modulo' : 'as a seed initializer';
  const notes = `function ${functionName} in contract ${contractName} uses block entropy ${source.text} ${contextText} at line ${line} — block data is public before the transaction executes, so the derived "random" value is predictable`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, source.text, line, column, `block-entropy-${context}`),
    title: `Weak randomness: block entropy used as random in ${functionName}`,
    vulnerability_type: 'weak randomness',
    description: `Function ${functionName} in contract ${contractName} uses block entropy (${source.text}) ${contextText}: block data is public before the transaction executes, so the derived "random" value is predictable and gameable.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'medium',
    cwe_id: 'CWE-338',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-weak-randomness --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${source.text} at ${where}.`,
      'Verify out of band whether the value guards anything with value at stake — block data used only for logging or scheduling is not randomness, and the detector only flags hash / modulo / seed contexts, so a finding means the source feeds a randomness-shaped computation.',
    ],
    proof_of_concept: `Matched ${source.text} ${contextText} at ${where}: block entropy used as randomness`,
    evidence: [{
      type: 'ast-expression',
      kind: `block-entropy-${context}`,
      function: functionName,
      contract: contractName,
      line,
      column,
      source: source.text,
      context,
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
}

// --- analysis ------------------------------------------------------------

// Collect the weak-randomness sites in one function body.
// The walk carries three context flags down the tree:
// inHash (inside a keccak256 / sha256 / sha3 call's
// arguments), inModulo (inside an operand of `%`), and
// inSeedInit (initializer / right side of an assignment
// to a seed-named variable). A block-entropy source node
// visited with any flag set is a finding, with the
// context named (hash first, then modulo, then seed).
// Every node is visited exactly once, so one finding
// per source site with no dedup step.
function collectWeakRandomnessSites(fn) {
  const sites = [];

  function contextOf(ctx) {
    if (ctx.inHash) return 'hash';
    if (ctx.inModulo) return 'modulo';
    if (ctx.inSeedInit) return 'seed';
    return null;
  }

  function walk(node, ctx) {
    if (!node || typeof node !== 'object') return;
    if (isBlockEntropy(node)) {
      const context = contextOf(ctx);
      if (context) {
        sites.push({
          source: { text: renderExpression(node), line: node.line, column: node.column },
          context,
        });
      }
      // A blockhash call's arguments can contain another
      // source (`blockhash(block.number - 1)`) — but the
      // argument is a block SELECTOR, not entropy: the
      // blockhash result is the randomness, the number
      // inside it is not. Stop here instead of walking
      // into the arguments.
      if (node.type === 'CallExpression'
        && node.callee && node.callee.type === 'Identifier'
        && node.callee.name === 'blockhash') {
        return;
      }
    }

    // Special shapes that set a context for their
    // children; everything else recurses with the
    // current context.
    if (node.type === 'CallExpression'
      && node.callee && node.callee.type === 'Identifier'
      && HASH_CALLS.has(node.callee.name)) {
      const hashCtx = { ...ctx, inHash: true };
      for (const arg of node.arguments || []) walk(arg, hashCtx);
      return;
    }
    if (node.type === 'BinaryExpression' && node.operator === '%') {
      const modCtx = { ...ctx, inModulo: true };
      walk(node.left, modCtx);
      walk(node.right, modCtx);
      return;
    }
    if (node.type === 'VariableDeclarationStatement') {
      for (const declaration of node.declarations || []) {
        if (!declaration) continue;
        const seed = declaration.name && SEED_NAME.test(declaration.name);
        walk(declaration.initialValue, seed ? { ...ctx, inSeedInit: true } : ctx);
      }
      if (node.initialValue) {
        const seed = (node.declarations || []).some(
          (d) => d && d.name && SEED_NAME.test(d.name),
        );
        walk(node.initialValue, seed ? { ...ctx, inSeedInit: true } : ctx);
      }
      return;
    }
    if (node.type === 'AssignmentExpression') {
      walk(node.left, ctx);
      const seed = node.left && node.left.type === 'Identifier' && SEED_NAME.test(node.left.name);
      walk(node.right, seed ? { ...ctx, inSeedInit: true } : ctx);
      return;
    }

    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const item of value) walk(item, ctx);
      } else if (value && typeof value === 'object' && value.type) {
        walk(value, ctx);
      }
    }
  }

  if (fn.body) walk(fn.body, { inHash: false, inModulo: false, inSeedInit: false });
  return sites;
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    for (const fn of contract.functions || []) {
      if (!fn.body) continue;
      for (const site of collectWeakRandomnessSites(fn)) {
        findings.push(makeFinding({
          source: site.source,
          context: site.context,
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
// the weak-randomness analysis instead.
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
function solidityWeakRandomnessDetector(input, defaults) {
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

module.exports = solidityWeakRandomnessDetector;
module.exports.solidityWeakRandomnessDetector = solidityWeakRandomnessDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
