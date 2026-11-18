const assert = require('node:assert/strict');
const test = require('node:test');
const { ApprovalGate } = require('../src/policy/approval-gate');

const SCOPE_FINGERPRINT = 'a'.repeat(64);

function clockAt(initial = 0) {
  let now = initial;
  return { clock: () => now, advance: (milliseconds) => { now += milliseconds; } };
}

function request(gate, overrides = {}) {
  return gate.request({
    targetId: 'local-lab',
    action: 'active_scanning',
    estimatedRequests: 50,
    scopeFingerprint: SCOPE_FINGERPRINT,
    reason: 'Local authorized lab verification',
    ...overrides,
  });
}

test('fails closed until a human approves the exact binding', () => {
  const gate = new ApprovalGate({ clock: () => 0 });
  const pending = request(gate);
  assert.deepEqual(gate.authorize('unknown', pending.binding), { allowed: false, reason: 'APPROVAL_NOT_FOUND' });
  assert.deepEqual(gate.authorize(pending.approvalId, pending.binding), { allowed: false, reason: 'APPROVAL_NOT_FOUND' });

  const approved = gate.approve(pending.requestId, { approver: 'researcher@example.test' });
  assert.equal(approved.allowed, true);
  assert.deepEqual(gate.authorize(approved.approvalId, { ...pending.binding, estimatedRequests: 51 }), {
    allowed: false,
    reason: 'APPROVAL_BINDING_MISMATCH',
  });
  assert.equal(gate.authorize(approved.approvalId, pending.binding).allowed, true);
});

test('makes an approval single-use', () => {
  const gate = new ApprovalGate({ clock: () => 0 });
  const pending = request(gate);
  const approved = gate.approve(pending.requestId, { approver: 'researcher@example.test' });
  assert.equal(gate.authorize(approved.approvalId, pending.binding).reason, 'APPROVED_AND_CONSUMED');
  assert.deepEqual(gate.authorize(approved.approvalId, pending.binding), { allowed: false, reason: 'APPROVAL_CONSUMED' });
});

test('expires pending and approved requests rather than carrying consent forward', () => {
  const time = clockAt();
  const gate = new ApprovalGate({ clock: time.clock });
  const pending = request(gate, { ttlMs: 1_000 });
  time.advance(1_000);
  assert.deepEqual(gate.approve(pending.requestId, { approver: 'researcher@example.test' }), {
    allowed: false,
    reason: 'APPROVAL_EXPIRED',
  });

  const second = request(gate, { ttlMs: 1_000 });
  const approved = gate.approve(second.requestId, { approver: 'researcher@example.test' });
  time.advance(1_000);
  assert.deepEqual(gate.authorize(approved.approvalId, second.binding), { allowed: false, reason: 'APPROVAL_EXPIRED' });
});

test('rejects oversized, malformed, or long-lived approval requests', () => {
  const gate = new ApprovalGate({ clock: () => 0 });
  assert.throws(() => request(gate, { scopeFingerprint: 'not-a-digest' }), /scopeFingerprint/);
  assert.throws(() => request(gate, { estimatedRequests: 10_001 }), /estimatedRequests/);
  assert.throws(() => request(gate, { ttlMs: 600_001 }), /ttlMs/);
});
