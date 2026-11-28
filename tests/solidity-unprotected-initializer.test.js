// Round 109 — solidity-unprotected-initializer detector tests.
//
// The detector flags an external/public `initialize()`
// that carries neither the `initializer` /
// `reinitializer` modifier nor any access control
// (no onlyOwner/role modifier, no require(msg.sender ==
// ...) check, no if-revert guard). CWE-862 (Missing
// Authorization).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detect = require('../src/detection/solidity-unprotected-initializer');
const { MAX_CONTENT_CHARS } = require('../src/detection/taint-engine');

const IDS = { session_id: 'session-1', target_id: 'target-1', asset_id: 'asset-1' };

function contract(body) {
  return `contract C {
  address public owner;
  uint256 public totalSupply;

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

test('unprotected-initializer: external initialize() with no modifier and no guard is flagged (round 109)', () => {
  const f = finding(contract(`
  function initialize(address next) external {
    owner = next;
    totalSupply = 1000;
  }`));
  assert.equal(f.discovery_tool, 'solidity-unprotected-initializer');
  assert.equal(f.cwe_id, 'CWE-862');
  assert.equal(f.vulnerability_type, 'broken access control');
  assert.equal(f.severity, 'high');
  assert.match(f.title, /initialize/);
  assert.equal(f.evidence[0].kind, 'unprotected-initializer');
  assert.equal(f.evidence[0].function, 'initialize');
  assert.equal(f.evidence[0].contract, 'C');
  assert.match(f.finding_id, /^solidity-unprotected-initializer-[0-9a-f]{16}$/);
});

test('unprotected-initializer: public initialize() with no modifier and no guard is flagged (round 109)', () => {
  const f = finding(contract(`
  function initialize(address next) public {
    owner = next;
  }`));
  assert.equal(f.evidence[0].function, 'initialize');
});

test('unprotected-initializer: initialize() with only a non-guard modifier is flagged (round 109)', () => {
  const f = finding(contract(`
  function initialize(address next) external nonReentrant {
    owner = next;
  }`));
  assert.equal(f.evidence[0].function, 'initialize');
  assert.deepEqual(f.evidence[0].modifiers, ['nonReentrant']);
});

// --- negatives: protected ------------------------------------------------

test('unprotected-initializer: initialize() with the initializer modifier is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) external initializer {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: initialize() with the reinitializer modifier is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) external reinitializer(2) {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: initialize() with onlyOwner but no initializer modifier is not flagged (round 109)', () => {
  // Both protections missing is required: onlyOwner alone
  // keeps the function callable only by the owner, so the
  // missing `initializer` modifier is a lesser issue.
  const result = run(contract(`
  function initialize(address next) external onlyOwner {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: initialize() with a require(msg.sender == ...) guard is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) external {
    require(msg.sender == owner, "not owner");
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: initialize() with initializer modifier AND onlyOwner is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) external initializer onlyOwner {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- negatives: not externally callable / not initialize -----------------

test('unprotected-initializer: internal initialize() is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) internal {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: initialize() with no visibility qualifier (internal by default) is not flagged (round 109)', () => {
  const result = run(contract(`
  function initialize(address next) {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: interface initialize() without a body is not flagged (round 109)', () => {
  const result = run(`interface IInit {
  function initialize(address next) external;
}`);
  assert.equal(result.findings.length, 0);
});

test('unprotected-initializer: a function NOT named initialize is not flagged by this detector (round 109)', () => {
  // A setup() that writes state with no guard is the
  // access-control detector's job, not this one's.
  const result = run(contract(`
  function setup(address next) external {
    owner = next;
  }`));
  assert.equal(result.findings.length, 0);
});

// --- pins ----------------------------------------------------------------

test('unprotected-initializer: onlyInitializing alone is NOT counted as protection (round 109)', () => {
  // onlyInitializing is a lifecycle modifier for functions
  // called DURING initialization; treating it as a guard
  // here would hide a genuinely unprotected entry point
  // behind an unusual pattern. Pinned as flagged.
  const f = finding(contract(`
  function initialize(address next) external onlyInitializing {
    owner = next;
  }`));
  assert.equal(f.evidence[0].function, 'initialize');
  assert.deepEqual(f.evidence[0].modifiers, ['onlyInitializing']);
});

// --- envelope / errors ---------------------------------------------------

test('unprotected-initializer: batch input scans each result and forces the batch tool (round 109)', () => {
  const result = detect({
    tool: 'scanner',
    results: [
      { content: contract(`
  function initialize(address next) external {
    owner = next;
  }`), language: 'solidity', ...IDS },
      { content: contract(`
  function initialize(address next) external initializer {
    owner = next;
  }`), language: 'solidity', ...IDS },
    ],
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'scanner');
  assert.equal(result.skipped, 0);
});

test('unprotected-initializer: unparseable Solidity is skipped, not thrown (round 109)', () => {
  const result = detect({ content: 'contract C { function f( }', language: 'solidity', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /failed to parse content as Solidity/);
});

test('unprotected-initializer: content over the cap is skipped (round 109)', () => {
  const result = detect({ content: 'x'.repeat(MAX_CONTENT_CHARS + 1), language: 'solidity', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /exceeds the .* character limit/);
});

test('unprotected-initializer: a non-Solidity language is skipped (round 109)', () => {
  const result = detect({ content: 'const x = 1;', language: 'javascript', ...IDS });
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /not Solidity/);
});

test('unprotected-initializer: a non-object input throws DETECTOR_INVALID_INPUT (round 109)', () => {
  assert.throws(() => detect(null), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect('contract C {}'), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => detect([]), /DETECTOR_INVALID_INPUT/);
});
