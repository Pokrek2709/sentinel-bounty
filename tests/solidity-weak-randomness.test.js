// Round 110 — solidity-weak-randomness detector tests.
//
// The detector flags block-derived entropy
// (block.timestamp, block.number, blockhash(...),
// block.difficulty / block.prevrandao, block.coinbase)
// used as randomness: inside a hash call, as a modulo
// operand, or as a seed initializer. CWE-338 (Use of
// Cryptographically Weak PRNG).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-weak-randomness');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {\n  uint256 public total;\n  uint256 public start;\n  address public owner;\n\n${body}\n}`;
}

function finding(content) {
  const result = detect({ content, language: 'solidity', ...IDS });
  assert.equal(result.skipped, 0, JSON.stringify(result.errors));
  assert.deepEqual(result.errors, []);
  return result.findings[0];
}

function run(source) {
  const result = detect({ content: source, language: 'solidity', ...IDS });
  assert.equal(result.skipped, 0, JSON.stringify(result.errors));
  assert.deepEqual(result.errors, []);
  return result;
}

// --- positives -----------------------------------------------------------

test('weak-randomness: keccak256 of block.timestamp mod n is flagged, hash context first (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    return random;
  }`));
  assert.equal(f.discovery_tool, 'solidity-weak-randomness');
  assert.equal(f.cwe_id, 'CWE-338');
  assert.equal(f.vulnerability_type, 'weak randomness');
  assert.equal(f.severity, 'medium');
  assert.match(f.title, /draw/);
  assert.equal(f.evidence[0].kind, 'block-entropy-hash');
  assert.equal(f.evidence[0].source, 'block.timestamp');
  assert.equal(f.evidence[0].context, 'hash');
  assert.match(f.finding_id, /^solidity-weak-randomness-[0-9a-f]{16}$/);
});

test('weak-randomness: block.timestamp % n is flagged, modulo context (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    return block.timestamp % 100;
  }`));
  assert.equal(f.evidence[0].kind, 'block-entropy-modulo');
  assert.equal(f.evidence[0].source, 'block.timestamp');
  assert.equal(f.evidence[0].context, 'modulo');
});

test('weak-randomness: block.number % n is flagged (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    return block.number % 10;
  }`));
  assert.equal(f.evidence[0].source, 'block.number');
});

test('weak-randomness: block.timestamp as a seed initializer is flagged (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    uint256 seed = block.timestamp;
    return seed;
  }`));
  assert.equal(f.evidence[0].kind, 'block-entropy-seed');
  assert.equal(f.evidence[0].source, 'block.timestamp');
  assert.equal(f.evidence[0].context, 'seed');
});

test('weak-randomness: blockhash as a seed assignment is flagged once — the number inside it is a selector, not entropy (round 110)', () => {
  const result = run(contract(`
  function draw() external returns (uint256) {
    uint256 random;
    random = blockhash(block.number - 1);
    return random;
  }`));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].source, 'blockhash(...)');
  assert.equal(result.findings[0].evidence[0].context, 'seed');
});

test('weak-randomness: blockhash inside a modulo is flagged once, modulo context (round 110)', () => {
  const result = run(contract(`
  function draw() external returns (uint256) {
    uint256 rand = uint256(blockhash(block.number - 1)) % 100;
    return rand;
  }`));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].source, 'blockhash(...)');
  assert.equal(result.findings[0].evidence[0].context, 'modulo');
});

test('weak-randomness: block.prevrandao in a hash is flagged (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.prevrandao, msg.sender)));
  }`));
  assert.equal(f.evidence[0].source, 'block.prevrandao');
  assert.equal(f.evidence[0].context, 'hash');
});

test('weak-randomness: block.coinbase % n is flagged (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    return uint256(uint160(block.coinbase)) % 2;
  }`));
  assert.equal(f.evidence[0].source, 'block.coinbase');
  assert.equal(f.evidence[0].context, 'modulo');
});

test('weak-randomness: block.difficulty in sha256 is flagged (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    return uint256(sha256(abi.encodePacked(block.difficulty)));
  }`));
  assert.equal(f.evidence[0].source, 'block.difficulty');
  assert.equal(f.evidence[0].context, 'hash');
});

test('weak-randomness: two entropy sources in one hash are two findings (round 110)', () => {
  const result = run(contract(`
  function draw() external returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp, block.number)));
  }`));
  assert.equal(result.findings.length, 2);
  assert.deepEqual(
    result.findings.map((f) => f.evidence[0].source),
    ['block.timestamp', 'block.number'],
  );
});

test('weak-randomness: seed name matching is case-insensitive (round 110)', () => {
  const f = finding(contract(`
  function draw() external returns (uint256) {
    uint256 Random = block.timestamp;
    return Random;
  }`));
  assert.equal(f.evidence[0].context, 'seed');
});

// --- negatives -----------------------------------------------------------

test('weak-randomness: block.timestamp in a deadline comparison is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external {
    require(block.timestamp >= start, "not started");
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: block.timestamp arithmetic for a deadline is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external returns (uint256) {
    uint256 deadline = block.timestamp + 1 days;
    return deadline;
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: hash of user input only is not flagged (round 110)', () => {
  const result = run(contract(`
  function f(address who, uint256 nonce) external pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked(who, nonce)));
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: block.timestamp only logged is not flagged (round 110)', () => {
  const result = run(contract(`
  event Tick(uint256 at);
  function f() external {
    emit Tick(block.timestamp);
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: block.number added, not modulo, is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external returns (uint256) {
    uint256 x = block.number + 100;
    return x;
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: block.gaslimit is not a source (round 110)', () => {
  const result = run(contract(`
  function draw() external returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.gaslimit)));
  }`));
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: block.timestamp in a comment is not flagged (round 110)', () => {
  const result = run(contract(`
  // uint256 random = block.timestamp % 100; — removed
  function f() external returns (uint256) {
    return 1;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('weak-randomness: non-Solidity language is skipped (round 110)', () => {
  const result = detect({ content: 'block.timestamp % 100', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: empty content is skipped (round 110)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: unparseable content (assembly) is skipped, never scanned approximately (round 110)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: content over the cap is skipped (round 110)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('weak-randomness: batch input scans each record (round 110)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function draw() external returns (uint256) { return block.timestamp % 100; }'), language: 'solidity', ...IDS },
      { content: contract('  function f() external { require(block.timestamp >= start, "x"); }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('weak-randomness: non-object input throws DETECTOR_INVALID_INPUT (round 110)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
