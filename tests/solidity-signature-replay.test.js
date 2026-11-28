// Round 111 — solidity-signature-replay detector tests.
//
// The detector flags an authorization built on `ecrecover`
// whose signed message carries NO replay protection — no
// nonce, no deadline / expiry, no EIP-712 domain
// separator. CWE-294 (Authentication Bypass by
// Capture-replay).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-signature-replay');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {
  address public owner;
  mapping(address => uint256) public nonces;

${body}
}`;
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

test('signature: ecrecover compared with no protection is flagged (round 111)', () => {
  const f = finding(contract(`
  function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    require(ecrecover(hash, v, r, s) == to);
  }`));
  assert.equal(f.discovery_tool, 'solidity-signature-replay');
  assert.equal(f.cwe_id, 'CWE-294');
  assert.equal(f.vulnerability_type, 'signature replay');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /withdraw/);
  assert.equal(f.evidence[0].kind, 'unprotected-signature');
  assert.match(f.evidence[0].call, /ecrecover/);
  assert.match(f.finding_id, /^solidity-signature-replay-[0-9a-f]{16}$/);
});

test('signature: ecrecover compared through a variable is flagged (round 111)', () => {
  const f = finding(contract(`
  function withdraw(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
    address signer = ecrecover(digest, v, r, s);
    require(signer == owner);
  }`));
  assert.match(f.evidence[0].call, /ecrecover/);
});

test('signature: ecrecover in a modifier without protection is flagged (round 111)', () => {
  const f = finding(contract(`
  modifier onlySigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) {
    require(ecrecover(hash, v, r, s) == msg.sender);
    _;
  }
  function withdraw() external onlySigner(bytes32(0), 0, bytes32(0), bytes32(0)) {
  }`));
  assert.match(f.description, /Modifier onlySigner/);
});

test('signature: two separate ecrecover sites are two findings (round 111)', () => {
  const result = run(contract(`
  function a(bytes32 h1, uint8 v1, bytes32 r1, bytes32 s1) external {
    require(ecrecover(h1, v1, r1, s1) == owner);
  }
  function b(bytes32 h2, uint8 v2, bytes32 r2, bytes32 s2) external {
    require(ecrecover(h2, v2, r2, s2) == owner);
  }`));
  assert.equal(result.findings.length, 2);
});

// --- negatives -----------------------------------------------------------

test('signature: consumed nonce suppresses the finding (round 111)', () => {
  const result = run(contract(`
  function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonces[to]));
    nonces[to]++;
    require(ecrecover(hash, v, r, s) == to);
  }`));
  assert.equal(result.findings.length, 0);
});

test('signature: deadline check suppresses the finding (round 111)', () => {
  const result = run(contract(`
  function withdraw(bytes32 hash, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline);
    require(ecrecover(hash, v, r, s) == owner);
  }`));
  assert.equal(result.findings.length, 0);
});

test('signature: EIP-712 typed-data hash suppresses the finding (round 111)', () => {
  const result = run(contract(`
  function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(to, amount)));
    require(ecrecover(digest, v, r, s) == to);
  }`));
  assert.equal(result.findings.length, 0);
});

test('signature: ecrecover result never compared is out of scope (round 111)', () => {
  const result = run(contract(`
  function getSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
    return ecrecover(hash, v, r, s);
  }`));
  assert.equal(result.findings.length, 0);
});

test('signature: ecrecover inside a comment is not flagged (round 111)', () => {
  const result = run(contract(`
  // require(ecrecover(hash, v, r, s) == owner);
  function f(address x) external pure returns (address) {
    return x;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('signature: non-Solidity language is skipped (round 111)', () => {
  const result = detect({ content: 'ecrecover(h, v, r, s)', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('signature: empty content is skipped (round 111)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('signature: unparseable content (assembly) is skipped, never scanned approximately (round 111)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('signature: content over the cap is skipped (round 111)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('signature: batch input scans each record (round 111)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { require(ecrecover(h, v, r, s) == owner); }'), language: 'solidity', ...IDS },
      { content: contract('  function g(uint256 x) external pure returns (uint256) { return x; }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('signature: non-object input throws DETECTOR_INVALID_INPUT (round 111)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
