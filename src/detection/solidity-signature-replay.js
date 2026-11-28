// Solidity signature-replay detector (Phase 5, round 111):
// flags an authorization built on `ecrecover` whose
// signed message carries NO replay protection — no
// nonce, no deadline / expiry, no EIP-712 domain
// separator. A signature is a bearer credential: once
// it is seen on-chain (or in the mempool), anyone can
// resubmit it. Without a nonce the same signature
// authorizes the same action forever; without a
// deadline it authorizes it until the contract dies;
// without a domain separator the same signature
// authorizes the same action on every chain and every
// contract that verifies the same message shape.
// CWE-294 (Authentication Bypass by Capture-replay):
// the signature is captured and replayed — the
// authentication itself is bypassed by reuse, not by
// forging a signature. Not CWE-347 (Improper
// Verification of Cryptographic Signature): the
// signature IS verified correctly here — `ecrecover`
// recovers the signer and the result IS compared —
// what is missing is the message's uniqueness, not
// the verification. A call that never verifies the
// signer at all is CWE-347 territory, not this
// detector's. See
// docs/detection-solidity-signature-replay-v1.md for
// the full reasoning.
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
// The rule is syntactic and local, per function or
// modifier body (authorization checks live in modifiers
// too, and the parser keeps ModifierDefinition nodes on
// the contract since round 110):
//   1. Collect the `ecrecover(...)` calls.
//   2. A call is "compared" when it sits inside a `==`
//      / `!=` comparison directly, or when a variable
//      it was assigned to appears inside such a
//      comparison in the same body. An ecrecover whose
//      result is never compared authorizes nothing, so
//      it is out of this detector's scope (pinned by a
//      test) — the replay question only matters when
//      the recovered address gates something.
//   3. The body is "protected" when ANY ONE of the
//      replay defenses is present: a `nonce*`
//      identifier (a consumed nonce — `nonces[signer]++`,
//      `useNonce`, `_useNonce`), a `deadline` / `expir*`
//      / `validUntil` identifier (an expiry check), or
//      an EIP-712 binding (`DOMAIN_SEPARATOR`,
//      `_hashTypedDataV4`, `hashTypedData`,
//      `toTypedDataHash`). ANY ONE counts — the safe
//      pattern is all three together (the OpenZeppelin
//      ECDSA shape), but a consumed nonce alone already
//      prevents replay entirely, and flagging it would
//      be a false positive an experienced reviewer
//      would reject. Protection is presence, not
//      sufficiency: a deadline with no nonce still
//      allows replay inside the window, and the
//      detector cannot tell — the reviewer judges
//      whether the protection actually binds the
//      signature.
//
// One finding per compared ecrecover site in an
// unprotected body.
//
// NOT modeled (pinned by tests, see the doc):
// cross-function protection (a nonce consumed in
// another function does not protect this one);
// signature malleability (an `s` value above the
// curve order, or a `v` other than 27 / 28, is
// CWE-347 territory); `ECDSA.recover` / `SignatureChecker`
// library wrappers (the call is not a bare `ecrecover`);
// `permit` / `permit2` flows whose nonce lives in a
// base contract in another file (bases are not
// resolved across files).
// A finding here is a candidate for manual review — the
// same posture as every detector in this repo: a precise,
// evidence-backed signal, not a verdict. A signature
// that is only ever seen by its intended signer is
// still flagged — the detector cannot prove the
// signature cannot be captured.
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

const DETECTOR_NAME = 'solidity-signature-replay';
const SOL_LANGUAGES = new Set(['solidity', 'sol']);

// EIP-712 typed-data helpers: calling one of these to
// build the digest binds the signature to a domain
// separator (chain id + verifying contract), which is
// one of the three replay defenses.
const EIP712_CALLS = new Set([
  '_hashTypedDataV4', 'hashTypedData', 'toTypedDataHash', 'hashTypedDataV4',
]);

const COMPARISON = new Set(['==', '!=']);

// --- findings ------------------------------------------------------------

const IMPACT = 'The signed message carries no replay protection — no nonce, no deadline, and no EIP-712 domain separator — so a signature seen once on-chain or in the mempool can be resubmitted by anyone, any number of times, on any chain where the same contract is deployed. An authorization meant for one action becomes a standing authorization for that action, and the signer cannot revoke it without rotating keys or redeploying.';
const REMEDIATION = 'Bind every signed message to one use and one context: consume a nonce per signer (`nonces[signer]++` on use, the OpenZeppelin ECDSA pattern), add a deadline (`require(block.timestamp <= deadline)`) so a leaked signature expires, and hash the message with EIP-712 typed data (`_hashTypedDataV4`) so the domain separator binds the signature to this chain and this contract. All three together is the safe shape; a consumed nonce alone already prevents replay.';

function makeFinding({ call, functionName, contractName, kind }) {
  const line = call.line;
  const column = call.column;
  const where = `line ${line}, column ${column}`;
  const label = kind === 'modifier' ? 'Modifier' : 'Function';
  const notes = `${label} ${functionName} in contract ${contractName} authorizes with ${call.text} and the signed message has no nonce, no deadline, and no EIP-712 domain separator in the same body`;
  return {
    finding_id: findingIdFor(DETECTOR_NAME, call.text, line, column, 'unprotected-signature'),
    title: `Signature replay: ecrecover without replay protection in ${functionName}`,
    vulnerability_type: 'signature replay',
    description: `${label} ${functionName} in contract ${contractName} authorizes with ${call.text}, and the signed message carries no replay protection — no nonce, no deadline, and no EIP-712 domain separator in the same body — so a captured signature can be resubmitted by anyone.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-294',
    steps_to_reproduce: [
      'Run `sentinel detect --detector solidity-signature-replay --input <record.json>` over the record carrying the Solidity source.',
      `Observe the finding for ${call.text} at ${where}.`,
      'Verify out of band whether the signature can actually be captured and replayed for reachable inputs — a signature that is only ever submitted by its signer through a private channel makes the finding a false positive, and the detector cannot prove the channel is private.',
    ],
    proof_of_concept: `Matched ${call.text} at ${where}: ecrecover authorization with no nonce, deadline, or domain separator`,
    evidence: [{
      type: 'ast-expression',
      kind: 'unprotected-signature',
      function: functionName,
      contract: contractName,
      line,
      column,
      call: call.text,
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

// Is this identifier a nonce marker — `nonce`, `nonces`,
// `userNonce`, `_nonce`, `useNonce` (anything with
// `nonce` in the name, compared case-insensitively)?
function isNonceName(name) {
  return name.toLowerCase().includes('nonce');
}

// Is this identifier a deadline / expiry marker —
// `deadline`, `expiry`, `expiresAt`, `validUntil`
// (anything with `deadline`, `expir`, or `validuntil`
// in the name, compared case-insensitively)?
function isDeadlineName(name) {
  const lower = name.toLowerCase();
  return lower.includes('deadline') || lower.includes('expir') || lower.includes('validuntil');
}

// Is this call an EIP-712 typed-data helper?
function isEip712Call(node) {
  if (!node || node.type !== 'CallExpression' || !node.callee) return false;
  if (node.callee.type === 'Identifier') return EIP712_CALLS.has(node.callee.name);
  if (node.callee.type === 'MemberExpression' && !node.callee.computed
    && node.callee.property && node.callee.property.type === 'Identifier') {
    return EIP712_CALLS.has(node.callee.property.name);
  }
  return false;
}

// Collect, for one function or modifier body: the
// ecrecover calls that are compared (directly, or
// through a variable they were assigned to) and that
// sit in a body with no replay protection.
function analyzeBody(body) {
  if (!body) return [];
  const ecrecoverCalls = new Set();
  walkExpression(body, (node) => {
    if (node.type === 'CallExpression'
      && node.callee && node.callee.type === 'Identifier'
      && node.callee.name === 'ecrecover') {
      ecrecoverCalls.add(node);
    }
  });
  if (ecrecoverCalls.size === 0) return [];

  // Variables bound to an ecrecover result (plain and
  // tuple declarations, plain assignments). Tuple
  // declarations carry ONE initial value at statement
  // level, binding every named slot; plain declarations
  // carry one initial value PER DECLARATOR
  // (`declarations[i].initialValue`, statement-level
  // `initialValue` null) — both shapes must be read.
  const assigned = new Map(); // variable name -> ecrecover calls
  walkExpression(body, (node) => {
    if (node.type === 'VariableDeclarationStatement') {
      if (node.initialValue) {
        const produced = [...ecrecoverCalls].filter((call) => subtreeContains(node.initialValue, new Set([call])));
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
          const produced = [...ecrecoverCalls].filter((call) => subtreeContains(declaration.initialValue, new Set([call])));
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
      const produced = [...ecrecoverCalls].filter((call) => subtreeContains(node.right, new Set([call])));
      if (produced.length === 0) return;
      if (!assigned.has(node.left.name)) assigned.set(node.left.name, []);
      assigned.get(node.left.name).push(...produced);
    }
  });

  // Compared: a `==` / `!=` comparison whose subtree
  // contains the call directly, or an identifier bound
  // to it.
  const compared = new Set();
  walkExpression(body, (node) => {
    if (node.type !== 'BinaryExpression' || !COMPARISON.has(node.operator)) return;
    for (const call of ecrecoverCalls) {
      if (subtreeContains(node, new Set([call]))) compared.add(call);
    }
    for (const [name, calls] of assigned) {
      if (subtreeMentions(node, new Set([name]))) {
        for (const call of calls) compared.add(call);
      }
    }
  });

  // Protection: ANY ONE of a nonce marker, a deadline /
  // expiry marker, or an EIP-712 binding (a
  // DOMAIN_SEPARATOR identifier or a typed-data helper
  // call) anywhere in the body. Presence, not
  // sufficiency — see the header.
  let protectedBody = false;
  walkExpression(body, (node) => {
    if (protectedBody) return;
    if (node.type === 'Identifier') {
      if (isNonceName(node.name) || isDeadlineName(node.name)
        || node.name.toLowerCase() === 'domain_separator') {
        protectedBody = true;
      }
      return;
    }
    if (isEip712Call(node)) protectedBody = true;
  });
  if (protectedBody) return [];

  return [...compared].map((call) => ({
    call: { text: renderExpression(call), line: call.line, column: call.column },
  }));
}

function analyzeSolidity(source) {
  const program = parseSolidity(source);
  const contracts = program.body.filter((node) => node.type === 'ContractDefinition');
  const findings = [];
  for (const contract of contracts) {
    // Function bodies and modifier bodies: an
    // authorization check usually lives in a modifier
    // (`modifier onlySigner(...) { ... _; }`), and the
    // parser keeps ModifierDefinition nodes on the
    // contract since round 110 for exactly that scan.
    const bodies = [];
    for (const fn of contract.functions || []) {
      bodies.push({ name: fn.name, body: fn.body, kind: 'function' });
    }
    for (const modifier of contract.modifiers || []) {
      bodies.push({ name: modifier.name, body: modifier.body, kind: 'modifier' });
    }
    for (const { name, body, kind } of bodies) {
      for (const site of analyzeBody(body)) {
        findings.push(makeFinding({
          call: site.call,
          functionName: name,
          contractName: contract.name,
          kind,
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
// the signature-replay analysis instead.
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
function soliditySignatureReplayDetector(input, defaults) {
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

module.exports = soliditySignatureReplayDetector;
module.exports.soliditySignatureReplayDetector = soliditySignatureReplayDetector;
module.exports.analyzeSolidity = analyzeSolidity;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
