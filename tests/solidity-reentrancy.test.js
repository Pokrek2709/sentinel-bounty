// Tests for the Solidity reentrancy detector
// (src/detection/solidity-reentrancy.js, round 108).
// Positive cases must produce exactly one finding per
// call site with CWE-841 and evidence carrying the call,
// the write, and a non-empty notes string. Negative cases
// must produce zero findings. The detector never reuses
// the JavaScript taint engine — it runs on the Solidity
// subset AST.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detector = require('../src/detection/solidity-reentrancy.js');

const IDS = { session_id: 's1', target_id: 't1', asset_id: 'a1' };

function detect(source) {
  const report = detector({ content: source, ...IDS });
  assert.equal(report.skipped, 0, `expected no skipped records, got errors: ${report.errors.join('; ')}`);
  return report.findings;
}

function contract(body, header = 'contract Vault {') {
  return `
    pragma solidity ^0.8.20;
    ${header}
      mapping(address => uint256) public balances;
      uint256 public totalSupply;
      ${body}
    }
  `;
}

test('detector: classic call-then-write is flagged (CWE-841)', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount, "insufficient");
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok, "call failed");
      balances[msg.sender] -= amount;
      totalSupply -= amount;
    }
  `));
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.discovery_tool, 'solidity-reentrancy');
  assert.equal(finding.vulnerability_type, 'reentrancy');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-841');
  assert.equal(finding.evidence[0].kind, 'call-then-write');
  assert.equal(finding.evidence[0].sink, 'msg.sender.call');
  assert.equal(finding.evidence[0].write.variable, 'balances');
  assert.match(finding.evidence[0].notes, /msg\.sender\.call/);
  assert.match(finding.evidence[0].notes, /balances/);
  assert.equal(typeof finding.finding_id, 'string');
  assert.match(finding.finding_id, /^solidity-reentrancy-[0-9a-f]{16}$/);
});

test('detector: transfer-then-write and send-then-write are flagged', () => {
  const transfer = detect(contract(`
    function payout(address to, uint256 amount) external {
      payable(to).transfer(amount);
      balances[to] -= amount;
    }
  `));
  assert.equal(transfer.length, 1);
  assert.equal(transfer[0].evidence[0].sink, 'payable(...).transfer');

  const send = detect(contract(`
    function payout(address to, uint256 amount) external {
      bool ok = payable(to).send(amount);
      require(ok);
      balances[to] -= amount;
    }
  `));
  assert.equal(send.length, 1);
  assert.equal(send[0].evidence[0].sink, 'payable(...).send');
});

test('detector: a token transfer followed by a state write is flagged', () => {
  const findings = detect(contract(`
    function pay(address token, address to, uint256 amount) external {
      IERC20(token).transfer(to, amount);
      balances[to] -= amount;
    }
  `));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].sink, 'IERC20(...).transfer');
});

test('detector: checks-effects-interactions order is clean', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount, "insufficient");
      balances[msg.sender] -= amount;
      totalSupply -= amount;
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok, "call failed");
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a nonReentrant guard is clean', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external nonReentrant {
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
      balances[msg.sender] -= amount;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: an external call with no state write is clean', () => {
  const findings = detect(contract(`
    function ping(address target) external {
      (bool ok, ) = target.call("");
      require(ok);
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a state write with no external call is clean', () => {
  const findings = detect(contract(`
    function deposit() external payable {
      balances[msg.sender] += msg.value;
      totalSupply += msg.value;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a return after the call ends the segment', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external returns (bool) {
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
      return true;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a write inside a branch after a call is flagged (branch seeds the prefix)', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external {
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
      if (amount > 0) {
        balances[msg.sender] -= amount;
      }
    }
  `));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].write.variable, 'balances');
});

test('detector: a write inside a branch does NOT leak out of it', () => {
  const findings = detect(contract(`
    function f(address target) external {
      if (totalSupply > 0) {
        balances[msg.sender] = 1;
      }
      (bool ok, ) = target.call("");
      require(ok);
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a local variable shadowing a state variable is not a state write', () => {
  const findings = detect(contract(`
    function f(address target) external {
      uint256 balances = 0;
      (bool ok, ) = target.call("");
      require(ok);
      balances = 1;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a parameter shadowing a state variable is not a state write', () => {
  const findings = detect(contract(`
    function f(uint256 totalSupply, address target) external {
      (bool ok, ) = target.call("");
      require(ok);
      totalSupply = 1;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a constructor is not analyzed', () => {
  const findings = detect(contract(`
    constructor(address target) {
      (bool ok, ) = target.call("");
      require(ok);
      totalSupply = 1;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: an inherited state variable written after a call is flagged', () => {
  const source = `
    pragma solidity ^0.8.20;
    contract Base {
      mapping(address => uint256) public balances;
    }
    contract Vault is Base {
      function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
      }
    }
  `;
  const findings = detect(source);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].write.variable, 'balances');
});

test('detector: two call sites produce two findings', () => {
  const findings = detect(contract(`
    function f(address a, address b) external {
      (bool ok1, ) = a.call("");
      require(ok1);
      balances[msg.sender] -= 1;
      (bool ok2, ) = b.call("");
      require(ok2);
      totalSupply -= 1;
    }
  `));
  assert.equal(findings.length, 2);
});

test('detector: one call site with two writes produces one finding', () => {
  const findings = detect(contract(`
    function f(address target) external {
      (bool ok, ) = target.call("");
      require(ok);
      balances[msg.sender] -= 1;
      totalSupply -= 1;
    }
  `));
  assert.equal(findings.length, 1);
});

test('detector: delegatecall is NOT a sink this round (pinned)', () => {
  const findings = detect(contract(`
    function f(address target, bytes memory data) external {
      (bool ok, ) = target.delegatecall(data);
      require(ok);
      balances[msg.sender] = 0;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: cross-function reentrancy is NOT detected this round (pinned)', () => {
  const findings = detect(contract(`
    function withdraw(uint256 amount) external {
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
    }
    function setBalance(address user, uint256 value) external {
      balances[user] = value;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: a write in a loop body after a call in the same body is flagged', () => {
  const findings = detect(contract(`
    function f(address[] memory targets) external {
      for (uint256 i = 0; i < targets.length; i++) {
        (bool ok, ) = targets[i].call("");
        require(ok);
        balances[targets[i]] = 0;
      }
    }
  `));
  assert.equal(findings.length, 1);
});

test('detector: a sink inside a comment or a string is not a call', () => {
  const findings = detect(contract(`
    function f() external {
      // msg.sender.call{value: 1}("");
      string memory s = "transfer send call";
      balances[msg.sender] = 1;
    }
  `));
  assert.equal(findings.length, 0);
});

test('detector: an unparseable contract is skipped, not crashed', () => {
  const report = detector({
    content: 'contract C { function f() external { assembly { } } }',
    ...IDS,
  });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
  assert.match(report.errors[0], /parse error|failed to parse/);
});

test('detector: content over the cap is skipped', () => {
  const report = detector({ content: ' '.repeat(1000001), ...IDS });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
});

test('detector: a non-Solidity language is skipped', () => {
  const report = detector({
    content: 'function f() {}',
    language: 'javascript',
    ...IDS,
  });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
  assert.match(report.errors[0], /not Solidity/);
});

test('detector: batch and single-record shapes match the other detectors', () => {
  const batch = detector({
    tool: 'solidity-reentrancy',
    results: [
      { content: contract(`
        function withdraw(uint256 amount) external {
          (bool ok, ) = msg.sender.call{value: amount}("");
          require(ok);
          balances[msg.sender] -= amount;
        }
      `), ...IDS },
      { content: contract('function f() external {}'), ...IDS },
    ],
  });
  assert.equal(batch.skipped, 0);
  assert.equal(batch.findings.length, 1);
  assert.equal(batch.findings[0].discovery_tool, 'solidity-reentrancy');
  const single = detector({ content: 'contract C {}', ...IDS });
  assert.equal(single.findings.length, 0);
  assert.equal(single.skipped, 0);
  assert.deepEqual(single.errors, []);
});
