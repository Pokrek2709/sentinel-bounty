// Round 111 — solidity-oracle-dependence detector tests.
//
// The detector flags a price taken from ONE on-chain source
// and used in a critical arithmetic computation with no
// TWAP, median, or staleness check in the same function.
// CWE-829 (Inclusion of Functionality from Untrusted
// Control Sphere).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-oracle-dependence');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {
  address public pair;
  address public router;
  address public feed;
  address[] public path;
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

test('oracle: getReserves price used in arithmetic is flagged (round 111)', () => {
  const f = finding(contract(`
  function price() external view returns (uint256) {
    (uint256 r0, uint256 r1,) = IPair(pair).getReserves();
    return r1 * 1e18 / r0;
  }`));
  assert.equal(f.discovery_tool, 'solidity-oracle-dependence');
  assert.equal(f.cwe_id, 'CWE-829');
  assert.equal(f.vulnerability_type, 'oracle price dependence');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /price/);
  assert.equal(f.evidence[0].kind, 'single-source-price');
  assert.match(f.evidence[0].source, /getReserves/);
  assert.match(f.finding_id, /^solidity-oracle-dependence-[0-9a-f]{16}$/);
});

test('oracle: getAmountsOut result used in arithmetic is flagged (round 111)', () => {
  const f = finding(contract(`
  function quote(uint256 amountIn) external view returns (uint256) {
    uint256[] memory amounts = IRouter(router).getAmountsOut(amountIn, path);
    return amounts[1] * 2;
  }`));
  assert.match(f.evidence[0].source, /getAmountsOut/);
});

test('oracle: latestAnswer used in arithmetic is flagged (round 111)', () => {
  const f = finding(contract(`
  function value(uint256 amount) external view returns (uint256) {
    int256 answer = IFeed(feed).latestAnswer();
    return uint256(answer) * amount / 1e18;
  }`));
  assert.match(f.evidence[0].source, /latestAnswer/);
});

test('oracle: latestRoundData answer used in arithmetic is flagged (round 111)', () => {
  const f = finding(contract(`
  function value(uint256 amount) external view returns (uint256) {
    (, int256 answer, , ,) = IFeed(feed).latestRoundData();
    return uint256(answer) * amount;
  }`));
  assert.match(f.evidence[0].source, /latestRoundData/);
});

test('oracle: two separate price sites are two findings (round 111)', () => {
  const result = run(contract(`
  function f(uint256 amount) external view returns (uint256) {
    (uint256 r0, uint256 r1,) = IPair(pair).getReserves();
    uint256[] memory amounts = IRouter(router).getAmountsOut(amount, path);
    return r1 * 1e18 / r0 + amounts[1];
  }`));
  assert.equal(result.findings.length, 2);
});

// --- negatives -----------------------------------------------------------

test('oracle: TWAP consult in the same function suppresses the finding (round 111)', () => {
  const result = run(contract(`
  function price() external view returns (uint256) {
    (uint256 r0, uint256 r1,) = IPair(pair).getReserves();
    uint256 twap = IOracle(router).consult(pair, 3600);
    return r1 * 1e18 / r0 + twap;
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: staleness check on updatedAt suppresses the finding (round 111)', () => {
  const result = run(contract(`
  function value(uint256 amount) external view returns (uint256) {
    (, int256 answer, , uint256 updatedAt,) = IFeed(feed).latestRoundData();
    require(block.timestamp - updatedAt < 3600);
    return uint256(answer) * amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: price used only for an event is not flagged (round 111)', () => {
  const result = run(contract(`
  event Price(uint256 r0, uint256 r1);
  function f() external {
    (uint256 r0, uint256 r1,) = IPair(pair).getReserves();
    emit Price(r0, r1);
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: price only returned, never computed with, is not flagged (round 111)', () => {
  const result = run(contract(`
  function f() external view returns (uint256, uint256) {
    (uint256 r0, uint256 r1,) = IPair(pair).getReserves();
    return (r0, r1);
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: comparison-only use is out of scope and not flagged (round 111)', () => {
  const result = run(contract(`
  function f(uint256 minOut) external view {
    uint256[] memory amounts = IRouter(router).getAmountsOut(1 ether, path);
    require(amounts[1] >= minOut);
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: price call inside a comment is not flagged (round 111)', () => {
  const result = run(contract(`
  // (uint256 r0, uint256 r1,) = IPair(pair).getReserves(); return r1 * 1e18 / r0;
  function f(uint256 x) external pure returns (uint256) {
    return x;
  }`));
  assert.equal(result.findings.length, 0);
});

test('oracle: bare price() call is too ambiguous and not flagged (round 111)', () => {
  const result = run(contract(`
  function f() external view returns (uint256) {
    uint256 p = IFeed(feed).price();
    return p * 2;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('oracle: non-Solidity language is skipped (round 111)', () => {
  const result = detect({ content: 'x = pair.getReserves()', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('oracle: empty content is skipped (round 111)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('oracle: unparseable content (assembly) is skipped, never scanned approximately (round 111)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('oracle: content over the cap is skipped (round 111)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('oracle: batch input scans each record (round 111)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function f() external view returns (uint256) { (uint256 r0, uint256 r1,) = IPair(pair).getReserves(); return r1 * 1e18 / r0; }'), language: 'solidity', ...IDS },
      { content: contract('  function g(uint256 x) external pure returns (uint256) { return x; }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('oracle: non-object input throws DETECTOR_INVALID_INPUT (round 111)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
