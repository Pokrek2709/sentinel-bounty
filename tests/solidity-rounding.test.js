// Round 110 — solidity-rounding detector tests.
//
// The detector flags integer division BEFORE multiplication
// (`x / y * z` — the division truncates before the
// multiplication runs). CWE-682 (Incorrect Calculation).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-rounding');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {\n  uint256 public total;\n\n${body}\n}`;
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

test('rounding: division before multiplication is flagged (round 110)', () => {
  const f = finding(contract(`
  function price(uint256 x, uint256 y, uint256 z) external pure returns (uint256) {
    return x / y * z;
  }`));
  assert.equal(f.discovery_tool, 'solidity-rounding');
  assert.equal(f.cwe_id, 'CWE-682');
  assert.equal(f.vulnerability_type, 'integer precision loss');
  assert.equal(f.severity, 'medium');
  assert.match(f.title, /price/);
  assert.equal(f.evidence[0].kind, 'divide-before-multiply');
  assert.equal(f.evidence[0].division, 'x / y');
  assert.equal(f.evidence[0].multiplication, '(x / y) * z');
  assert.match(f.finding_id, /^solidity-rounding-[0-9a-f]{16}$/);
});

test('rounding: share-price shape amount / total * price is flagged (round 110)', () => {
  const f = finding(contract(`
  function share(uint256 amount, uint256 total, uint256 price) external pure returns (uint256) {
    return amount / total * price;
  }`));
  assert.equal(f.evidence[0].division, 'amount / total');
  assert.equal(f.evidence[0].multiplication, '(amount / total) * price');
});

test('rounding: parenthesized (a / b) * c is the same AST and is flagged (round 110)', () => {
  const f = finding(contract(`
  function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
    return (a / b) * c;
  }`));
  assert.equal(f.evidence[0].division, 'a / b');
});

test('rounding: division on the right of the multiplication is flagged (round 110)', () => {
  const f = finding(contract(`
  function f(uint256 x, uint256 y, uint256 z) external pure returns (uint256) {
    return z * (x / y);
  }`));
  assert.equal(f.evidence[0].division, 'x / y');
  assert.equal(f.evidence[0].multiplication, 'z * (x / y)');
});

test('rounding: pattern inside an if condition is flagged (round 110)', () => {
  const f = finding(contract(`
  function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
    if (a / b * c > 0) {
      return 1;
    }
    return 0;
  }`));
  assert.equal(f.evidence[0].division, 'a / b');
});

test('rounding: two separate sites are two findings (round 110)', () => {
  const result = run(contract(`
  function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
    uint256 x = a / b * c;
    uint256 y = a / c * b;
    return x + y;
  }`));
  assert.equal(result.findings.length, 2);
});

// --- negatives -----------------------------------------------------------

test('rounding: multiply first, divide last is safe and not flagged (round 110)', () => {
  const result = run(contract(`
  function price(uint256 x, uint256 y, uint256 z) external pure returns (uint256) {
    return x * y / z;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: bare division with no following multiplication is not flagged (round 110)', () => {
  const result = run(contract(`
  function f(uint256 x, uint256 y) external pure returns (uint256) {
    return x / y;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: pattern inside a comment is not flagged (round 110)', () => {
  const result = run(contract(`
  // return x / y * z; — the old formula, do not use
  function f(uint256 x) external pure returns (uint256) {
    return x;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: division inside a call argument of a multiplied value is not flagged (round 110)', () => {
  const result = run(contract(`
  function g(uint256 v) internal pure returns (uint256) {
    return v;
  }
  function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
    return g(a / b) * c;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: division before exponentiation is out of scope and not flagged (round 110)', () => {
  const result = run(contract(`
  function f(uint256 x, uint256 y) external pure returns (uint256) {
    return (x / y) ** 2;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: division and multiplication in separate statements are not tracked (round 110)', () => {
  const result = run(contract(`
  function f(uint256 x, uint256 y, uint256 w) external pure returns (uint256) {
    uint256 q = x / y;
    uint256 z = q * w;
    return z;
  }`));
  assert.equal(result.findings.length, 0);
});

test('rounding: pattern in a string literal is not flagged (round 110)', () => {
  const result = run(contract(`
  function f() external pure returns (string memory) {
    return "x / y * z";
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('rounding: non-Solidity language is skipped (round 110)', () => {
  const result = detect({ content: 'x / y * z', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('rounding: empty content is skipped (round 110)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('rounding: unparseable content (assembly) is skipped, never scanned approximately (round 110)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('rounding: content over the cap is skipped (round 110)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('rounding: batch input scans each record (round 110)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a / b * c; }'), language: 'solidity', ...IDS },
      { content: contract('  function g(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { return a * b / c; }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('rounding: non-object input throws DETECTOR_INVALID_INPUT (round 110)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
