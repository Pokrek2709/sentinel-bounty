// Round 112 — solidity-cross-function-reentrancy detector
// tests.
//
// The detector flags a function A that performs an
// external call and then READS a state variable, while a
// DIFFERENT external/public function B of the same
// contract WRITES that variable. CWE-841 (Improper
// Enforcement of Behavioral Workflow) — the same CWE as
// the single-function reentrancy detector.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-cross-function-reentrancy');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {
  mapping(address => uint256) public pending;
  mapping(address => uint256) public balances;
  uint256 public totalSettled;
  bool public flag;

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

test('cross-reentrancy: call then read, other function writes — flagged (round 112)', () => {
  const f = finding(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    if (pending[msg.sender] > 0) {
      totalSettled += pending[msg.sender];
    }
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(f.discovery_tool, 'solidity-cross-function-reentrancy');
  assert.equal(f.cwe_id, 'CWE-841');
  assert.equal(f.vulnerability_type, 'cross-function reentrancy');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /settle/);
  assert.equal(f.evidence[0].kind, 'cross-function-reentrancy');
  assert.equal(f.evidence[0].variable, 'pending');
  assert.equal(f.evidence[0].reenteredFunction, 'adjust');
  assert.equal(f.evidence[0].function, 'settle');
  assert.match(f.finding_id, /^solidity-cross-function-reentrancy-[0-9a-f]{16}$/);
});

test('cross-reentrancy: two functions writing the same variable are two findings (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }
  function reset(address user) external {
    pending[user] = 0;
  }`));
  assert.equal(result.findings.length, 2);
});

test('cross-reentrancy: A guarded but B not is still flagged (round 112)', () => {
  const f = finding(contract(`
  function settle() external nonReentrant {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(f.evidence[0].reenteredFunction, 'adjust');
});

test('cross-reentrancy: B guarded but A not is still flagged (round 112)', () => {
  const f = finding(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external nonReentrant {
    pending[user] = amount;
  }`));
  assert.equal(f.evidence[0].reenteredFunction, 'adjust');
});

test('cross-reentrancy: read inside a branch after the call counts (round 112)', () => {
  const f = finding(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    if (flag) {
      totalSettled = pending[msg.sender];
    }
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(f.evidence[0].variable, 'pending');
});

test('cross-reentrancy: writer in a same-file base contract is a B (round 112)', () => {
  const result = run(`contract Base {
  mapping(address => uint256) public pending;
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }
}
contract C is Base {
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
}`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].reenteredFunction, 'adjust');
});

// --- negatives -----------------------------------------------------------

test('cross-reentrancy: both functions nonReentrant is clean — shared guard (round 112)', () => {
  const result = run(contract(`
  function settle() external nonReentrant {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external nonReentrant {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: internal writer is not a B (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) internal {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: internal reader is not an A (round 112)', () => {
  const result = run(contract(`
  function settle() internal {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: read before the call only is clean (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: read inside the call arguments is not a post-call read (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    (bool ok,) = msg.sender.call{value: pending[msg.sender]}("");
    require(ok);
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: A writing the variable after the call is single-function territory (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    pending[msg.sender] = 0;
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: writer of a different variable is clean (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external {
    balances[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: no state read after the call is clean (round 112)', () => {
  const result = run(contract(`
  function settle(uint256 amount) external {
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: constructor writing the variable is not a B (round 112)', () => {
  const result = run(contract(`
  constructor() {
    pending[msg.sender] = 1;
  }
  function settle() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: modifier writing the variable is not a B (round 112)', () => {
  const result = run(contract(`
  modifier bump() {
    pending[msg.sender] += 1;
    _;
  }
  function settle() external bump {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    uint256 x = pending[msg.sender];
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: local shadowing the state variable is not a read of it (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    uint256 pending = 1;
    (bool ok,) = msg.sender.call{value: 1}("");
    require(ok);
    uint256 x = pending;
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: parameter shadowing the state variable is not a read of it (round 112)', () => {
  const result = run(contract(`
  function settle(uint256 totalSettled) external {
    (bool ok,) = msg.sender.call{value: 1}("");
    require(ok);
    uint256 x = totalSettled;
  }
  function adjust(uint256 v) external {
    totalSettled = v;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: this-call is not a sink, so no finding (round 112)', () => {
  const result = run(contract(`
  function settle() external {
    this.withdraw();
    uint256 x = pending[msg.sender];
  }
  function withdraw() external {
    uint256 amount = pending[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: delegatecall in A is not a sink (round 112)', () => {
  const result = run(contract(`
  function settle(address target) external {
    target.delegatecall(abi.encodeWithSignature("f()"));
    uint256 x = pending[msg.sender];
  }
  function adjust(address user, uint256 amount) external {
    pending[user] = amount;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- envelope ------------------------------------------------------------

test('cross-reentrancy: non-Solidity language is skipped (round 112)', () => {
  const result = detect({ content: 'x = pending[msg.sender]', language: 'javascript', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: empty content is skipped (round 112)', () => {
  const result = detect({ content: '   ', language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: unparseable content (assembly) is skipped, never scanned approximately (round 112)', () => {
  const result = detect({
    content: 'contract C { function f() external { assembly { mstore(0, 1) } } }',
    language: 'solidity',
    ...IDS,
  });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: content over the cap is skipped (round 112)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.skipped, 1);
  assert.equal(result.findings.length, 0);
});

test('cross-reentrancy: batch input scans each record (round 112)', () => {
  const result = detect({
    tool: 'batch-tool',
    results: [
      { content: contract('  function settle() external { uint256 amount = pending[msg.sender]; (bool ok,) = msg.sender.call{value: amount}(""); require(ok); uint256 x = pending[msg.sender]; } function adjust(address user, uint256 amount) external { pending[user] = amount; }'), language: 'solidity', ...IDS },
      { content: contract('  function g(uint256 x) external pure returns (uint256) { return x; }'), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
});

test('cross-reentrancy: non-object input throws DETECTOR_INVALID_INPUT (round 112)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('nope'), /DETECTOR_INVALID_INPUT/);
});
