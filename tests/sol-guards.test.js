// Round 109 — sol-guards.js unit tests (shared guard
// rule for the access-control and unprotected-initializer
// detectors).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const parseSolidity = require('../src/detection/sol-parser.js');
const { hasAccessControl, effectiveStateVars } = require('../src/detection/sol-guards.js');

function fn(source) {
  const ast = parseSolidity(`contract C {
  address public owner;

${source}
}`);
  return ast.body[0].functions[0];
}

test('sol-guards: hasAccessControl reports the guard kind and the guard source (round 109)', () => {
  const guarded = fn(`
  function f() external onlyOwner {
    owner = msg.sender;
  }`);
  assert.deepEqual(hasAccessControl(guarded), { guarded: true, via: 'modifier:onlyOwner' });

  const required = fn(`
  function f() external {
    require(msg.sender == owner);
  }`);
  assert.deepEqual(hasAccessControl(required), { guarded: true, via: 'require:msg.sender' });

  const roleChecked = fn(`
  function f() external {
    require(hasRole(MINTER_ROLE, msg.sender));
  }`);
  assert.deepEqual(hasAccessControl(roleChecked), { guarded: true, via: 'require:hasRole' });

  const unguarded = fn(`
  function f() external {
    owner = msg.sender;
  }`);
  assert.deepEqual(hasAccessControl(unguarded), { guarded: false, via: null });
});

test('sol-guards: tx.origin, assert, nonReentrant, whenNotPaused, onlyInitializing are not guards (round 109)', () => {
  const cases = [
    'function f() external { require(tx.origin == owner); }',
    'function f() external { assert(msg.sender == owner); }',
    'function f() external nonReentrant {}',
    'function f() external whenNotPaused {}',
    'function f() external onlyInitializing {}',
  ];
  for (const source of cases) {
    assert.deepEqual(hasAccessControl(fn(source)), { guarded: false, via: null }, source);
  }
});

test('sol-guards: if (msg.sender != owner) revert(...) is a guard, the == form is not (round 109)', () => {
  const guard = fn(`
  function f() external {
    if (msg.sender != owner) revert NotOwner();
  }`);
  assert.equal(hasAccessControl(guard).guarded, true);
  assert.equal(hasAccessControl(guard).via, 'if-revert');

  const notGuard = fn(`
  function f() external {
    if (msg.sender == owner) revert NotOwner();
  }`);
  assert.equal(hasAccessControl(notGuard).guarded, false);
});

test('sol-guards: if (msg.sender != owner) revert("...") is a guard too (round 109)', () => {
  const guard = fn(`
  function f() external {
    if (msg.sender != owner) revert("not owner");
  }`);
  assert.deepEqual(hasAccessControl(guard), { guarded: true, via: 'if-revert' });
});

test('sol-guards: effectiveStateVars walks a same-file inheritance chain (round 109)', () => {
  const ast = parseSolidity(`contract Base {
  uint256 public totalSupply;
}
contract Middle is Base {
  address public admin;
}
contract Leaf is Middle {
  uint256 public leafVar;
}`);
  const byName = new Map(ast.body.map((c) => [c.name, c]));
  const leaf = byName.get('Leaf');
  const vars = effectiveStateVars(leaf, byName);
  assert.deepEqual([...vars].sort(), ['admin', 'leafVar', 'totalSupply']);
});

test('sol-guards: effectiveStateVars tolerates a missing base contract (round 109)', () => {
  const ast = parseSolidity(`contract Leaf is MissingBase {
  uint256 public leafVar;
}`);
  const byName = new Map(ast.body.map((c) => [c.name, c]));
  const vars = effectiveStateVars(byName.get('Leaf'), byName);
  assert.deepEqual([...vars], ['leafVar']);
});
