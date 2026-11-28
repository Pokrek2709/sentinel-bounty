// Shared Solidity analysis helpers (Phase 5, round 109):
// the pieces the Solidity detectors share — a generic
// expression walker, the access-control guard check
// (modifiers + body guards), and the effective state
// variables of a contract (own + same-file bases).
//
// This is the Solidity-side analogue of the shared
// JavaScript taint engine: the two round-109 detectors
// both need "is this function guarded?", and duplicating
// that rule in two files would let the two detectors
// drift apart (the exact bug the taint-engine extraction
// fixed in round 101). The reentrancy detector (round
// 108) keeps its own copies — it predates this module
// and its segment walker is specific to call-then-write
// ordering; do not refactor it in this round.
//
// A guard is one of:
//   - a modifier from ACCESS_MODIFIERS (onlyOwner, role
//     modifiers, ...), or
//   - `require(msg.sender == <x>)` (or `<x> == msg.sender`)
//     anywhere in the body, or
//   - `require(<role-call>(..., msg.sender))` — hasRole /
//     isAdmin / isAuthorized / isWhitelisted, or
//   - `if (msg.sender != <x>) revert(...)` (or the revert
//     in the else branch).
//
// Deliberately NOT guards (pinned by tests in the two
// detector files):
//   - `require(tx.origin == ...)` — tx.origin is the
//     wrong check (round 110 territory); a function
//     guarded only by tx.origin is still flagged.
//   - `assert(msg.sender == ...)` — assert is for
//     invariants, not authorization.
//   - `nonReentrant` — a reentrancy guard, not access
//     control.
//   - `whenNotPaused` — a circuit breaker, not access
//     control.
//   - `onlyInitializing` — a lifecycle modifier, not an
//     authorization check (see the initializer doc).
'use strict';

// Modifiers that count as access control. An explicit
// allow-list, not a prefix rule: `only*` would also
// match `onlyAfter` / `onlyDuring` (time locks, not
// authorization), and a time lock is not an access
// check.
const ACCESS_MODIFIERS = new Set([
  'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance',
  'onlyMinter', 'onlyPauser', 'onlyOperator', 'onlyManager',
  'onlyAuthorized', 'onlyWhitelisted', 'onlySelf',
  'authorized', 'requiresAuth',
]);

// Function calls that count as role checks when they
// appear inside a require and mention msg.sender:
// `require(hasRole(MINTER_ROLE, msg.sender))`.
const ROLE_CALLS = new Set([
  'hasRole', 'hasRoleOr', 'isAdmin', 'isAuthorized', 'isWhitelisted',
]);

// --- generic walkers -----------------------------------------------------

// Walk an expression tree, calling `visit(node)` on every
// node (pre-order). Generic: any object with a `type`
// string is a node; arrays and plain objects are recursed
// into. ASTs are trees, so no cycle guard is needed.
function walkExpression(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const item of value) walkExpression(item, visit);
    } else if (value && typeof value === 'object' && value.type) {
      walkExpression(value, visit);
    }
  }
}

// Walk a statement list, calling `visit(statement)` on
// every statement node and recursing into nested blocks,
// branches, and loop bodies. Expression-only positions
// (for-test, for-update, return argument) are NOT
// statements and are not visited — callers that need
// them should walkExpression the statement they came
// from.
function walkStatements(statements, visit) {
  for (const statement of statements || []) {
    if (!statement || typeof statement !== 'object') continue;
    visit(statement);
    switch (statement.type) {
      case 'BlockStatement':
        walkStatements(statement.body, visit);
        break;
      case 'UncheckedBlock':
        // UncheckedBlock wraps a BlockStatement.
        walkStatements(statement.body ? statement.body.body : [], visit);
        break;
      case 'IfStatement':
        walkStatements([statement.consequent], visit);
        if (statement.alternate) walkStatements([statement.alternate], visit);
        break;
      case 'ForStatement':
        if (statement.init) walkStatements([statement.init], visit);
        walkStatements([statement.body], visit);
        break;
      case 'WhileStatement':
      case 'DoWhileStatement':
        walkStatements([statement.body], visit);
        break;
      default:
        break;
    }
  }
}

// --- msg.sender predicates -----------------------------------------------

function isMsgSender(node) {
  return !!node && node.type === 'MemberExpression' && !node.computed
    && node.object && node.object.type === 'Identifier' && node.object.name === 'msg'
    && node.property && node.property.type === 'Identifier' && node.property.name === 'sender';
}

// The name of a call's callee: a plain identifier, or the
// property of a member expression (`x.hasRole` -> 'hasRole').
// Anything else (a call result, an index) has no name.
function callName(call) {
  if (!call || !call.callee) return null;
  if (call.callee.type === 'Identifier') return call.callee.name;
  if (call.callee.type === 'MemberExpression' && !call.callee.computed
    && call.callee.property && call.callee.property.type === 'Identifier') {
    return call.callee.property.name;
  }
  return null;
}

// Does this expression tree contain a `msg.sender == <x>`
// (or `<x> == msg.sender`) comparison?
function containsSenderEquality(node) {
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type !== 'BinaryExpression' || current.operator !== '==') return;
    if (isMsgSender(current.left) || isMsgSender(current.right)) found = true;
  });
  return found;
}

// Does this expression tree contain a `msg.sender != <x>`
// (or `<x> != msg.sender`) comparison?
function containsSenderInequality(node) {
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type !== 'BinaryExpression' || current.operator !== '!=') return;
    if (isMsgSender(current.left) || isMsgSender(current.right)) found = true;
  });
  return found;
}

// Does this expression tree mention msg.sender at all?
function mentionsSender(node) {
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (isMsgSender(current)) found = true;
  });
  return found;
}

// Does this subtree contain a `revert` — a RevertStatement
// (the parser's node for `revert ...;`, added round 109),
// or a `revert(...)` call (kept for robustness: a record
// hand-built outside the parser could carry one)?
function containsRevertCall(node) {
  if (!node) return false;
  let found = false;
  walkExpression(node, (current) => {
    if (found) return;
    if (current.type === 'RevertStatement') { found = true; return; }
    if (current.type === 'CallExpression'
      && current.callee && current.callee.type === 'Identifier'
      && current.callee.name === 'revert') found = true;
  });
  return found;
}

// --- access-control guard ------------------------------------------------

// Is this function guarded by access control? Returns
// { guarded: boolean, via: string|null } — `via` names
// the guard that was found, so a finding can say what it
// looked for and a test can pin which guard matched.
// The check is syntactic: a modifier from the allow-list,
// a require with a msg.sender equality (or a role call
// mentioning msg.sender), or an if-revert guard on
// msg.sender inequality. It does NOT prove the guard is
// sufficient — a require on the wrong address still
// counts; the detector is a candidate generator, and the
// human reviewer judges sufficiency.
function hasAccessControl(fn) {
  for (const modifier of fn.modifiers || []) {
    if (ACCESS_MODIFIERS.has(modifier)) {
      return { guarded: true, via: `modifier:${modifier}` };
    }
  }
  if (!fn.body) return { guarded: false, via: null };
  // require(...) guards anywhere in the body.
  let guard = null;
  walkExpression(fn.body, (node) => {
    if (guard) return;
    if (node.type !== 'CallExpression') return;
    if (!node.callee || node.callee.type !== 'Identifier' || node.callee.name !== 'require') return;
    const arg = (node.arguments || [])[0];
    if (!arg) return;
    if (containsSenderEquality(arg)) {
      guard = { guarded: true, via: 'require:msg.sender' };
      return;
    }
    walkExpression(arg, (inner) => {
      if (guard) return;
      if (inner.type !== 'CallExpression') return;
      const name = callName(inner);
      if (name && ROLE_CALLS.has(name) && mentionsSender(inner)) {
        guard = { guarded: true, via: `require:${name}` };
      }
    });
  });
  if (guard) return guard;
  // if (msg.sender != ...) revert(...) guards.
  walkStatements([fn.body], (statement) => {
    if (guard) return;
    if (statement.type !== 'IfStatement') return;
    if (!containsSenderInequality(statement.test)) return;
    if (containsRevertCall(statement.consequent) || containsRevertCall(statement.alternate)) {
      guard = { guarded: true, via: 'if-revert' };
    }
  });
  return guard || { guarded: false, via: null };
}

// --- state variables -----------------------------------------------------

// Collect the effective state variables of a contract:
// its own declarations plus those of its bases declared
// in the same file (transitive, cycle-guarded). A base
// from another file is not resolved — the caller still
// analyzes the contract with its own variables (a miss
// on an inherited write is a documented limitation, not
// a silent wrong answer about what it did see). Same
// rule as the reentrancy detector.
function effectiveStateVars(contract, byName) {
  const vars = new Set();
  const seen = new Set();
  const queue = [contract];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || seen.has(current.name)) continue;
    seen.add(current.name);
    for (const stateVar of current.stateVars || []) vars.add(stateVar.name);
    for (const baseName of current.bases || []) {
      if (byName.has(baseName)) queue.push(byName.get(baseName));
    }
  }
  return vars;
}

// --- expression rendering --------------------------------------------------

// Render an expression as short readable text for a finding's
// evidence (`amount / total`, `msg.sender.call`, `keccak256(...)`).
// Evidence only — the text is never re-parsed, so a nested
// binary expression is parenthesized to stay unambiguous
// (`(amount / total) * price`, not `amount / total * price`).
// Argument contents are elided as `(...)`: a literal inside
// an argument never lands in a finding. Anything the
// renderer does not know is its node type, never a crash.
function renderExpression(node) {
  if (!node || typeof node !== 'object') return '<unknown>';
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'Literal':
      return String(node.value);
    case 'MemberExpression': {
      const object = renderExpression(node.object);
      if (node.computed) return `${object}[...]`;
      return `${object}.${node.property && node.property.name ? node.property.name : '?'}`;
    }
    case 'CallExpression':
      return `${renderExpression(node.callee)}(...)`;
    case 'NewExpression':
      return `new ${node.callee}(...)`;
    case 'BinaryExpression': {
      const left = node.left && node.left.type === 'BinaryExpression'
        ? `(${renderExpression(node.left)})` : renderExpression(node.left);
      const right = node.right && node.right.type === 'BinaryExpression'
        ? `(${renderExpression(node.right)})` : renderExpression(node.right);
      return `${left} ${node.operator} ${right}`;
    }
    case 'AssignmentExpression': {
      const right = node.right && node.right.type === 'BinaryExpression'
        ? `(${renderExpression(node.right)})` : renderExpression(node.right);
      return `${renderExpression(node.left)} ${node.operator} ${right}`;
    }
    case 'UnaryExpression':
      return `${node.operator}${renderExpression(node.argument)}`;
    case 'UpdateExpression':
      return node.prefix
        ? `${node.operator}${renderExpression(node.argument)}`
        : `${renderExpression(node.argument)}${node.operator}`;
    case 'ConditionalExpression':
      return `${renderExpression(node.test)} ? ${renderExpression(node.consequent)} : ${renderExpression(node.alternate)}`;
    case 'TupleExpression':
      return `(${(node.elements || []).map((e) => (e ? renderExpression(e) : '')).join(', ')})`;
    default:
      return node.type;
  }
}

module.exports = {
  ACCESS_MODIFIERS,
  ROLE_CALLS,
  walkExpression,
  walkStatements,
  isMsgSender,
  callName,
  containsSenderEquality,
  containsSenderInequality,
  mentionsSender,
  containsRevertCall,
  hasAccessControl,
  effectiveStateVars,
  renderExpression,
};
