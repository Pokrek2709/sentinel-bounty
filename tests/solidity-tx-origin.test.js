// Round 110 — solidity-tx-origin detector tests.
//
// The detector flags `tx.origin` used in an authorization
// comparison — `require(tx.origin == owner)`,
// `if (tx.origin == ...)`, or the same shape inside a
// modifier body. CWE-862 (Missing Authorization), not
// CWE-477 (tx.origin is not an obsolete function).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-tx-origin');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {\n  uint256 public total;\n  address public owner;\n\n${body}\n}`;
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

test('tx-origin: require(tx.origin == owner) is flagged (round 110)', () => {
  const f = finding(contract(`
  function withdraw() external {
    require(tx.origin == owner, "not owner");
    total = 0;
  }`));
  assert.equal(f.discovery_tool, 'solidity-tx-origin');
  assert.equal(f.cwe_id, 'CWE-862');
  assert.equal(f.vulnerability_type, 'broken access control');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /withdraw/);
  assert.equal(f.evidence[0].kind, 'tx-origin-comparison');
  assert.equal(f.evidence[0].comparison, 'tx.origin == owner');
  assert.match(f.finding_id, /^solidity-tx-origin-[0-9a-f]{16}$/);
});

test('tx-origin: reversed comparison owner == tx.origin is flagged (round 110)', () => {
  const f = finding(contract(`
  function withdraw() external {
    require(owner == tx.origin, "not owner");
    total = 0;
  }`));
  assert.equal(f.evidence[0].comparison, 'owner == tx.origin');
});

test('tx-origin: if (tx.origin == ...) is flagged (round 110)', () => {
  const f = finding(contract(`
  function withdraw() external {
    if (tx.origin == owner) {
      total = 0;
    }
  }`));
  assert.equal(f.evidence[0].comparison, 'tx.origin == owner');
});

test('tx-origin: != comparison is flagged (round 110)', () => {
  const f = finding(contract(`
  function withdraw() external {
    if (tx.origin != owner) revert("not owner");
    total = 0;
  }`));
  assert.equal(f.evidence[0].comparison, 'tx.origin != owner');
});

test('tx-origin: comparison inside a modifier body is flagged (round 110)', () => {
  const f = finding(contract(`
  modifier onlyOwner() {
    require(tx.origin == owner, "not owner");
    _;
  }
  function withdraw() external onlyOwner {
    total = 0;
  }`));
  assert.equal(f.evidence[0].function, 'modifier onlyOwner');
  assert.equal(f.evidence[0].comparison, 'tx.origin == owner');
});

test('tx-origin: null-check require(tx.origin != address(0)) is flagged by design (round 110)', () => {
  const f = finding(contract(`
  function f() external {
    require(tx.origin != address(0), "no origin");
  }`));
  assert.equal(f.evidence[0].comparison, 'tx.origin != address(...)');
});

test('tx-origin: two comparisons in one function are two findings (round 110)', () => {
  const result = run(contract(`
  function f() external {
    require(tx.origin == owner, "not owner");
    if (tx.origin != owner) revert("nope");
  }`));
  assert.equal(result.findings.length, 2);
});

test('tx-origin: nested comparison is flagged once, on the outermost (round 110)', () => {
  const result = run(contract(`
  function f() external returns (bool) {
    return (tx.origin == owner) == true;
  }`));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].comparison, '(tx.origin == owner) == true');
});

// --- negatives -----------------------------------------------------------

test('tx-origin: require(msg.sender == owner) is not flagged (round 110)', () => {
  const result = run(contract(`
  function withdraw() external {
    require(msg.sender == owner, "not owner");
    total = 0;
  }`));
  assert.equal(result.findings.length, 0);
});

test('tx-origin: tx.origin only logged is not flagged (round 110)', () => {
  const result = run(contract(`
  event Log(address indexed origin);
  function f() external {
    emit Log(tx.origin);
  }`));
  assert.equal(result.findings.length, 0);
});

test('tx-origin: tx.origin assigned to a variable is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external returns (address) {
    address a = tx.origin;
    return a;
  }`));
  assert.equal(result.findings.length, 0);
});

test('tx-origin: tx.origin passed as a call argument is not flagged (round 110)', () => {
  const result = run(contract(`
  function g(address who) internal pure returns (address) {
    return who;
  }
  function f() external returns (address) {
    return g(tx.origin);
  }`));
  assert.equal(result.findings.length, 0);
});

test('tx-origin: tx.origin in a comment is not flagged (round 110)', () => {
  const result = run(contract(`
  // require(tx.origin == owner) — the old check, removed
  function f() external {
    require(msg.sender == owner, "not owner");
  }`));
  assert.equal(result.findings.length, 0);
});

test('tx-origin: tx.origin in a string literal is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external pure returns (string memory) {
    return "tx.origin == owner";
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('tx-origin: non-Solidity language is skipped (round 110)', () => {
  const result = detect({ content: 'require(tx.origin == owner)', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('tx-origin: empty content is skipped (round 110)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('tx-origin: unparseable content (assembly) is skipped, never scanned approximately (round 110)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('tx-origin: content over the cap is skipped (round 110)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('tx-origin: batch input scans each record (round 110)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function f() external { require(tx.origin == owner, "x"); }'), language: 'solidity', ...IDS },
      { content: contract('  function g() external { require(msg.sender == owner, "x"); }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('tx-origin: non-object input throws DETECTOR_INVALID_INPUT (round 110)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
