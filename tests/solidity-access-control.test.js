// Round 109 — solidity-access-control detector tests.
//
// The detector flags an external/public function that
// performs a sensitive operation (state write,
// fund-moving call, selfdestruct, delegatecall) with no
// access control (no onlyOwner/role modifier, no
// require(msg.sender == ...) check, no if-revert guard).
// CWE-862 (Missing Authorization).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-access-control');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body, extraState) {
  return `contract C {
  mapping(address => uint256) public balances;
  uint256 public totalSupply;
  address public owner;
${extraState || ''}

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

test('access-control: external function writing state without a guard is flagged (round 109)', () => {
  const f = finding(contract(`
  function setOwner(address next) external {
    owner = next;
  }`));
  assert.equal(f.discovery_tool, 'solidity-access-control');
  assert.equal(f.cwe_id, 'CWE-862');
  assert.equal(f.vulnerability_type, 'broken access control');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /setOwner/);
  assert.equal(f.evidence[0].kind, 'unprotected-sensitive-function');
  assert.equal(f.evidence[0].operation.type, 'state-write');
  assert.equal(f.evidence[0].operation.variable, 'owner');
  assert.match(f.finding_id, /^solidity-access-control-[0-9a-f]{16}$/);
});

test('access-control: external function calling out funds before a write is flagged on the call (round 109)', () => {
  const f = finding(contract(`
  function withdraw(uint256 amount) external {
    (bool ok, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
  }`));
  assert.equal(f.evidence[0].operation.type, 'fund-call');
  assert.match(f.evidence[0].operation.sink, /msg\.sender\.call/);
});

test('access-control: external function calling selfdestruct is flagged (round 109)', () => {
  const f = finding(contract(`
  function kill() external {
    selfdestruct(payable(msg.sender));
  }`));
  assert.equal(f.evidence[0].operation.type, 'selfdestruct');
  assert.equal(f.evidence[0].operation.sink, 'selfdestruct');
});

test('access-control: external function calling delegatecall is flagged (round 109)', () => {
  const f = finding(contract(`
  function proxy(address target, bytes memory data) external {
    (bool ok, ) = target.delegatecall(data);
  }`));
  assert.equal(f.evidence[0].operation.type, 'delegatecall');
  assert.match(f.evidence[0].operation.sink, /target\.delegatecall/);
});

test('access-control: public function writing state is flagged (round 109)', () => {
  const f = finding(contract(`
  function mint(address to, uint256 amount) public {
    balances[to] += amount;
    totalSupply += amount;
  }`));
  assert.equal(f.evidence[0].operation.type, 'state-write');
  assert.equal(f.evidence[0].operation.variable, 'balances');
});

test('access-control: two unprotected sensitive functions produce two findings, one per function (round 109)', () => {
  const result = run(contract(`
  function setOwner(address next) external {
    owner = next;
  }
  function mint(uint256 amount) external {
    totalSupply += amount;
  }`));
  assert.equal(result.findings.length, 2);
  assert.deepEqual(
    result.findings.map((f) => f.evidence[0].function).sort(),
    ['mint', 'setOwner'],
  );
});

test('access-control: a state write in a nested branch is still flagged (round 109)', () => {
  const f = finding(contract(`
  function adjust(uint256 amount) external {
    if (amount > 0) {
      totalSupply += amount;
    } else {
      totalSupply -= amount;
    }
  }`));
  assert.equal(f.evidence[0].operation.variable, 'totalSupply');
});

test('access-control: a state write in a for-loop body is still flagged (round 109)', () => {
  const f = finding(contract(`
  function bump(uint256 n) external {
    for (uint256 i = 0; i < n; i++) {
      totalSupply += 1;
    }
  }`));
  assert.equal(f.evidence[0].operation.variable, 'totalSupply');
});

test('access-control: an inherited state variable written in the same file is flagged (round 109)', () => {
  const f = finding(`contract Base {
  uint256 public totalSupply;
}

contract C is Base {
  function mint(uint256 amount) external {
    totalSupply += amount;
  }
}`);
  assert.equal(f.evidence[0].operation.variable, 'totalSupply');
  assert.equal(f.evidence[0].contract, 'C');
});

// --- negatives: guards ---------------------------------------------------

test('access-control: onlyOwner is not flagged (round 109)', () => {
  const result = run(contract(`
  function setOwner(address next) external onlyOwner {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: require(msg.sender == owner) is not flagged (round 109)', () => {
  const result = run(contract(`
  function setOwner(address next) external {
    require(msg.sender == owner, "not owner");
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: require(owner == msg.sender) is not flagged (round 109)', () => {
  const result = run(contract(`
  function setOwner(address next) external {
    require(owner == msg.sender);
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: require(hasRole(...msg.sender)) is not flagged (round 109)', () => {
  const result = run(contract(`
  function mint(address to, uint256 amount) external {
    require(hasRole(MINTER_ROLE, msg.sender), "no role");
    balances[to] += amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: require(accessControl.hasRole(...msg.sender)) is not flagged (round 109)', () => {
  const result = run(contract(`
  function mint(address to, uint256 amount) external {
    require(accessControl.hasRole(MINTER_ROLE, msg.sender));
    balances[to] += amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: onlyRole modifier is not flagged (round 109)', () => {
  const result = run(contract(`
  function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    balances[to] += amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: if (msg.sender != owner) revert(...) is not flagged (round 109)', () => {
  const result = run(contract(`
  function setOwner(address next) external {
    if (msg.sender != owner) revert NotOwner();
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: if (msg.sender == owner) revert(...) is not flagged as a guard? — no: it reverts the OWNER, so it IS flagged (round 109)', () => {
  // A guard that reverts on the OWNER passing the check is
  // backwards: it blocks the owner and lets everyone else
  // through, so it is not a guard at all. The detector must
  // still flag the function.
  const f = finding(contract(`
  function setOwner(address next) external {
    if (msg.sender == owner) revert NotOwner();
    owner = next;
  }`));
  assert.equal(f.evidence[0].operation.variable, 'owner');
});

// --- negatives: not externally callable ---------------------------------

test('access-control: internal function writing state is not flagged (round 109)', () => {
  const result = run(contract(`
  function _setOwner(address next) internal {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: function with no visibility qualifier (internal by default) is not flagged (round 109)', () => {
  const result = run(contract(`
  function _setOwner(address next) {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: private function writing state is not flagged (round 109)', () => {
  const result = run(contract(`
  function _setOwner(address next) private {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: constructor writing state is not flagged (round 109)', () => {
  const result = run(contract(`
  constructor() {
    owner = msg.sender;
    totalSupply = 1000;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: interface function without a body is not flagged (round 109)', () => {
  const result = run(`interface IToken {
  function setOwner(address next) external;
}`);
  assert.equal(result.findings.length, 0);
});

// --- negatives: not sensitive -------------------------------------------

test('access-control: external function that only reads state is not flagged (round 109)', () => {
  const result = run(contract(`
  function getBalance(address who) external view returns (uint256) {
    return balances[who];
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: external function with no body statements is not flagged (round 109)', () => {
  const result = run(contract(`
  function noop() external {
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: local variable shadowing a state variable is not flagged (round 109)', () => {
  const result = run(contract(`
  function local(uint256 amount) external {
    uint256 totalSupply = 0;
    totalSupply = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: parameter shadowing a state variable is not flagged (round 109)', () => {
  const result = run(contract(`
  function param(uint256 totalSupply) external {
    totalSupply = 1;
  }`));
  assert.equal(result.findings.length, 0);
});

test('access-control: indexed mapping write is flagged on the root variable name (round 109)', () => {
  const result = run(contract(`
  function indexed(address who, uint256 amount) external {
    balances[who] += amount;
  }`));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].operation.variable, 'balances');
});

// --- pins: patterns that are NOT guards ---------------------------------

test('access-control: a tx.origin-only check is NOT counted as a guard (round 109)', () => {
  // tx.origin authorization is its own class (round 110);
  // here it is pinned as not-a-guard, so the function is
  // still flagged.
  const f = finding(contract(`
  function setOwner(address next) external {
    require(tx.origin == owner);
    owner = next;
  }`));
  assert.equal(f.evidence[0].operation.variable, 'owner');
});

test('access-control: an assert-only check is NOT counted as a guard (round 109)', () => {
  const f = finding(contract(`
  function setOwner(address next) external {
    assert(msg.sender == owner);
    owner = next;
  }`));
  assert.equal(f.evidence[0].operation.variable, 'owner');
});

test('access-control: nonReentrant alone is NOT counted as a guard (round 109)', () => {
  const f = finding(contract(`
  function withdraw(uint256 amount) external nonReentrant {
    (bool ok, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
  }`));
  assert.equal(f.evidence[0].operation.type, 'fund-call');
});

test('access-control: whenNotPaused alone is NOT counted as a guard (round 109)', () => {
  const f = finding(contract(`
  function setOwner(address next) external whenNotPaused {
    owner = next;
  }`));
  assert.equal(f.evidence[0].operation.variable, 'owner');
});

test('access-control: onlyInitializing alone is NOT counted as a guard (round 109)', () => {
  const f = finding(contract(`
  function setOwner(address next) external onlyInitializing {
    owner = next;
  }`));
  assert.equal(f.evidence[0].operation.variable, 'owner');
});

test('access-control: a guard placed AFTER the sensitive operation still counts (no reachability proof, round 109)', () => {
  // The detector does not prove the guard runs before the
  // write (no control-flow analysis); a guard anywhere in
  // the function counts. Pinned as a known limitation, not
  // a false negative.
  const result = run(contract(`
  function setOwner(address next) external {
    owner = next;
    require(msg.sender == owner);
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope / errors ---------------------------------------------------

test('access-control: batch input scans each result and forces the batch tool (round 109)', () => {
  const result = detect({
    tool: 'scanner',
    results: [
      { content: contract(`
  function setOwner(address next) external {
    owner = next;
  }`), language: 'solidity', ...IDS },
      { content: contract(`
  function getBalance(address who) external view returns (uint256) {
    return balances[who];
  }`), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'scanner');
  assert.equal(result.skipped, 0);
});

test('access-control: unparseable Solidity is skipped, not thrown (round 109)', () => {
  const result = detect({ content: 'contract C { function f( }', language: 'solidity', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /failed to parse content as Solidity/);
});

test('access-control: content over the cap is skipped (round 109)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /exceeds the .* character limit/);
});

test('access-control: a non-Solidity language is skipped (round 109)', () => {
  const result = detect({ content: 'const x = 1;', language: 'javascript', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /not Solidity/);
});

test('access-control: a non-object input throws DETECTOR_INVALID_INPUT (round 109)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('contract C {}'), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect([]), /DETECTOR_INVALID_INPUT/);
});
