// Round 112 — solidity-unchecked-call detector tests.
//
// The detector flags a low-level external call (`.call`,
// `.delegatecall`, `.staticcall`, `.send`) whose return
// value is never checked in the same function or modifier
// body. CWE-252 (Unchecked Return Value).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-unchecked-call');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {
  address public target;
  address public token;
  bool public ok;
  event Log(bool ok);

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

test('unchecked-call: bare .call with value is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    target.call{value: 1 ether}("");
  }`));
  assert.equal(f.discovery_tool, 'solidity-unchecked-call');
  assert.equal(f.cwe_id, 'CWE-252');
  assert.equal(f.vulnerability_type, 'unchecked return value');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /Unchecked/);
  assert.equal(f.evidence[0].kind, 'unchecked-low-level-call');
  assert.match(f.evidence[0].sink, /target\.call/);
  assert.match(f.finding_id, /^solidity-unchecked-call-[0-9a-f]{16}$/);
});

test('unchecked-call: bare .send is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    payable(target).send(1 ether);
  }`));
  assert.match(f.evidence[0].sink, /\.send/);
});

test('unchecked-call: bare .delegatecall is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    target.delegatecall(abi.encodeWithSignature("f()"));
  }`));
  assert.match(f.evidence[0].sink, /\.delegatecall/);
});

test('unchecked-call: bare .staticcall is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    target.staticcall(abi.encodeWithSignature("f()"));
  }`));
  assert.match(f.evidence[0].sink, /\.staticcall/);
});

test('unchecked-call: call assigned and never checked is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    (bool success, ) = target.call{value: 1 ether}("");
  }`));
  assert.match(f.evidence[0].sink, /target\.call/);
});

test('unchecked-call: call result used but not checked is flagged (round 112)', () => {
  const f = finding(contract(`
  function f() external {
    bool success = target.call{value: 1 ether}("");
    emit Log(success);
  }`));
  assert.match(f.evidence[0].sink, /target\.call/);
});

test('unchecked-call: checking only the bytes of a tuple does not check the call (round 112)', () => {
  // A tuple binds only its FIRST named element (the
  // bool) to the call — a check on `ret` does not check
  // whether the call worked.
  const f = finding(contract(`
  function f() external {
    (bool success, bytes memory ret) = target.call{value: 1 ether}("");
    require(ret.length > 0);
  }`));
  assert.match(f.evidence[0].sink, /target\.call/);
});

test('unchecked-call: call result used in a ternary is not a check (round 112)', () => {
  const f = finding(contract(`
  function f() external returns (uint256) {
    bool success = target.call{value: 1 ether}("");
    return success ? 1 : 0;
  }`));
  assert.match(f.evidence[0].sink, /target\.call/);
});

test('unchecked-call: two unchecked calls are two findings (round 112)', () => {
  const result = run(contract(`
  function f() external {
    target.call{value: 1 ether}("");
    target.send(1 ether);
  }`));
  assert.equal(result.findings.length, 2);
});

test('unchecked-call: unchecked call in a modifier body is flagged (round 112)', () => {
  const f = finding(contract(`
  modifier m() {
    target.call{value: 1 ether}("");
    _;
  }
  function f() external m {
  }`));
  assert.equal(f.evidence[0].function, 'm');
});

// --- negatives -----------------------------------------------------------

test('unchecked-call: require around the call is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    require(target.call{value: 1 ether}(""));
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: assert around the call is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    assert(target.call{value: 1 ether}(""));
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: assigned result checked with require is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    bool success = target.call{value: 1 ether}("");
    require(success);
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: assigned result checked with if-revert is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    bool success = target.call{value: 1 ether}("");
    if (!success) revert();
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: call in an if test is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    if (!target.call{value: 1 ether}("")) revert();
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: call result returned is clean (round 112)', () => {
  const result = run(contract(`
  function f() external returns (bool) {
    return target.call{value: 1 ether}("");
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: tuple result checked via the bool is clean (round 112)', () => {
  const result = run(contract(`
  function f() external {
    (bool success, bytes memory ret) = target.call{value: 1 ether}("");
    require(success);
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: plain .transfer is not a sink — it reverts on failure (round 112)', () => {
  const result = run(contract(`
  function f() external {
    payable(target).transfer(1 ether);
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: ERC20 transfer unchecked is a separate class, out of scope (round 112)', () => {
  const result = run(contract(`
  function f(address to, uint256 amount) external {
    token.transfer(to, amount);
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: low-level call inside a comment is not flagged (round 112)', () => {
  const result = run(contract(`
  // target.call{value: 1 ether}("");
  function f(uint256 x) external pure returns (uint256) {
    return x;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: low-level call inside a string is not flagged (round 112)', () => {
  const result = run(contract(`
  function f() external pure returns (string memory) {
    return "target.call{value: 1 ether}(\\"\\")";
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('unchecked-call: non-Solidity language is skipped (round 112)', () => {
  const result = detect({ content: 'x = target.call()', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: empty content is skipped (round 112)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: unparseable content (assembly) is skipped, never scanned approximately (round 112)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: content over the cap is skipped (round 112)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('unchecked-call: batch input scans each record (round 112)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function f() external { target.call{value: 1 ether}(""); }'), language: 'solidity', ...IDS },
      { content: contract('  function g(uint256 x) external pure returns (uint256) { return x; }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('unchecked-call: non-object input throws DETECTOR_INVALID_INPUT (round 112)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
