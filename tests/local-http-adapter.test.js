const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { AuditLog } = require('../src/audit/audit-log');
const { ApprovalGate } = require('../src/policy/approval-gate');
const { LocalHttpAdapter } = require('../src/http/local-http-adapter');
const { KillSwitch } = require('../src/policy/kill-switch');
const { RequestGovernor } = require('../src/policy/request-governor');
const { TargetRegistry } = require('../src/scope/target-registry');

function fakeTransport({ statusCode = 200, body = JSON.stringify({ status: 'lab-ok' }), headers = { 'content-type': 'application/json', 'set-cookie': 'session=secret' } } = {}) {
  let requests = 0;
  const requestGet = (url, callback) => {
    requests += 1;
    const request = new EventEmitter();
    request.destroy = () => { request.destroyed = true; request.emit('error', Object.assign(new Error('cancelled'), { code: 'ECONNRESET' })); };
    process.nextTick(() => {
      const response = new EventEmitter();
      response.statusCode = statusCode;
      response.headers = headers;
      response.setEncoding = () => {};
      callback(response);
      process.nextTick(() => { response.emit('data', body); response.emit('end'); });
    });
    return request;
  };
  return { requestGet, get requests() { return requests; } };
}

async function harness(directory, transport = fakeTransport(), killSwitch = new KillSwitch()) {
  const registry = new TargetRegistry();
  registry.register({ target_id: 'local-lab', program_name: 'Local HTTP lab', authorization_reference: 'LOCAL-LAB', allowed_domains: ['localhost'], request_budget: 10 });
  const fingerprint = registry.getScopeFingerprint('local-lab');
  const approvals = new ApprovalGate({ clock: () => Date.now() });
  const pending = approvals.request({ targetId: 'local-lab', action: 'http_probing', estimatedRequests: 1, scopeFingerprint: fingerprint, reason: 'GET-only localhost lab' });
  const approved = approvals.approve(pending.requestId, { approver: 'local-human' });
  const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
  const governor = new RequestGovernor({ requestBudget: 10 });
  const recordedStatuses = [];
  const originalRecordResponse = governor.recordResponse.bind(governor);
  governor.recordResponse = (domain, statusCode) => {
    recordedStatuses.push([domain, statusCode]);
    return originalRecordResponse(domain, statusCode);
  };
  return {
    fingerprint,
    approvalId: approved.approvalId,
    audit,
    governor,
    recordedStatuses,
    transport,
    adapter: new LocalHttpAdapter({ registry, approvalGate: approvals, governor, killSwitch, auditLog: audit, requestGet: transport.requestGet }),
  };
}

// A kill switch whose unregister() is controllable: it is the async
// PersistentKillSwitch.unregisterWorker in production (a state-file
// write under a lock), so a test that gates or rejects it proves
// whether get() waits for it (round 47) instead of resolving early.
function controllableKillSwitch(unregisterBehavior = 'ok') {
  let unregisterCalls = 0;
  let releaseUnregister;
  const unregisterGate = new Promise((resolve) => { releaseUnregister = resolve; });
  return {
    get unregisterCalls() { return unregisterCalls; },
    releaseUnregister,
    assertNotTriggered: async () => ({ allowed: true, reason: 'KILL_SWITCH_INACTIVE' }),
    registerWorker: async () => ({
      registered: true,
      unregister: () => {
        unregisterCalls += 1;
        if (unregisterBehavior === 'reject') return Promise.reject(new Error('ENOSPC'));
        if (unregisterBehavior === 'gate') return unregisterGate;
        return Promise.resolve(true);
      },
    }),
  };
}

test('get() does not resolve before the async unregister() completes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-unregister-gate-');
  try {
    const killSwitch = controllableKillSwitch('gate');
    const context = await harness(directory, fakeTransport(), killSwitch);
    let settled = false;
    const pending = context.adapter.get({ targetId: 'local-lab', url: 'http://localhost/health', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
    pending.then(() => { settled = true; });
    // Wait until the response flow has actually reached cleanup()
    // (unregister called) — a fixed sleep would be load-dependent
    // under the parallel full suite and flaked once (round 47).
    const deadline = Date.now() + 5_000;
    while (killSwitch.unregisterCalls === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(killSwitch.unregisterCalls, 1);
    // Now give the event loop a chance to settle the promise if it
    // were going to (it must not: unregister() is still gated).
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(settled, false, 'get() must not resolve while unregister() is still pending');
    killSwitch.releaseUnregister();
    const response = await pending;
    assert.equal(response.reason, 'HTTP_COMPLETED');
    assert.equal(response.unregisterFailed, undefined);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a failing unregister() surfaces as unregisterFailed, never as an unhandled rejection', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-unregister-fail-');
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const killSwitch = controllableKillSwitch('reject');
    const context = await harness(directory, fakeTransport(), killSwitch);
    const response = await context.adapter.get({ targetId: 'local-lab', url: 'http://localhost/health', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
    // The HTTP request completed; only the bookkeeping failed, so the
    // real result stands and the failure is reported honestly.
    assert.equal(response.reason, 'HTTP_COMPLETED');
    assert.equal(response.unregisterFailed, true);
    assert.equal(killSwitch.unregisterCalls, 1);
    // Let any escaping rejection surface before asserting.
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(unhandled, []);
  } finally {
    process.removeListener('unhandledRejection', onUnhandled);
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('performs a GET to localhost through scope, approval, governor, kill switch, and audit', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ targetId: 'local-lab', url: 'http://localhost/health', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
    assert.equal(response.reason, 'HTTP_COMPLETED');
    assert.equal(response.statusCode, 200);
    assert.deepEqual(JSON.parse(response.body), { status: 'lab-ok' });
    assert.equal(response.headers['set-cookie'], '[REDACTED]');
    const audit = await fs.readFile(path.join(directory, 'state', 'audit.jsonl'), 'utf8');
    assert.equal(audit.split('\n').filter(Boolean).length, 2);
    assert.equal(audit.includes('lab-ok'), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('rejects external hosts and does not follow redirects', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  try {
    const context = await harness(directory);
    const external = await context.adapter.get({ targetId: 'local-lab', url: 'http://example.com/', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
    assert.deepEqual(external, { allowed: false, reason: 'LOCALHOST_ONLY' });

    const redirectTransport = fakeTransport({ statusCode: 302, body: '', headers: { location: '/health' } });
    const second = await harness(directory, redirectTransport);
    const redirected = await second.adapter.get({ targetId: 'local-lab', url: 'http://localhost/redirect', approvalId: second.approvalId, estimatedRequests: 1, scopeFingerprint: second.fingerprint });
    assert.equal(redirected.statusCode, 302);
    assert.equal(redirectTransport.requests, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('passes 429/503 response status to the request governor', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  try {
    const first = await harness(directory, fakeTransport({ statusCode: 429, body: 'busy' }));
    const response = await first.adapter.get({ targetId: 'local-lab', url: 'http://localhost/busy', approvalId: first.approvalId, estimatedRequests: 1, scopeFingerprint: first.fingerprint });
    assert.equal(response.statusCode, 429);
    assert.deepEqual(first.recordedStatuses, [['localhost', 429]]);
    assert.equal(first.governor.acquire('localhost').reason, 'SERVER_BACKOFF');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('requires audit state outside the skill directory', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  try {
    assert.throws(() => new AuditLog({ logFile: path.join(directory, 'skill', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') }), /outside the skill directory/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('recovers a stale audit lock and rotates before the hard limit', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  const skillDirectory = path.join(directory, 'skill');
  const logFile = path.join(directory, 'state', 'audit.jsonl');
  try {
    await fs.mkdir(path.dirname(logFile), { recursive: true });
    const lockFile = `${logFile}.lock`;
    await fs.writeFile(lockFile, 'stale', { mode: 0o600 });
    const old = new Date(Date.now() - 10_000);
    await fs.utimes(lockFile, old, old);
    const audit = new AuditLog({ logFile, skillDirectory, staleLockMs: 100, rotationBytes: 300, retentionCount: 2 });
    await audit.append('FIRST', { value: 'x'.repeat(100) });
    await audit.append('SECOND', { value: 'y'.repeat(100) });
    await audit.append('THIRD', { value: 'z'.repeat(100) });
    assert.equal((await fs.stat(`${logFile}.1`)).isFile(), true);
    assert.equal((await fs.readdir(path.dirname(logFile))).some((name) => name.endsWith('.lock')), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('reports audit health and removes its probe file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  const logFile = path.join(directory, 'state', 'audit.jsonl');
  try {
    const audit = new AuditLog({ logFile, skillDirectory: path.join(directory, 'skill') });
    assert.deepEqual(await audit.healthCheck(), { healthy: true });
    assert.equal((await fs.readdir(path.dirname(logFile))).some((name) => name.endsWith('.health.tmp')), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cleans orphaned audit temporary files before the next locked operation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  const logFile = path.join(directory, 'state', 'audit.jsonl');
  try {
    await fs.mkdir(path.dirname(logFile), { recursive: true });
    const orphan = `${logFile}.1234.123e4567-e89b-12d3-a456-426614174000.tmp`;
    const orphanHealth = `${logFile}.1234.123e4567-e89b-12d3-a456-426614174000.health.tmp`;
    await fs.writeFile(orphan, 'partial', { mode: 0o600 });
    await fs.writeFile(orphanHealth, 'partial', { mode: 0o600 });
    const audit = new AuditLog({ logFile, skillDirectory: path.join(directory, 'skill') });
    await audit.append('CLEANUP_CHECK');
    await assert.rejects(() => fs.stat(orphan), { code: 'ENOENT' });
    await assert.rejects(() => fs.stat(orphanHealth), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health rejects a directory or malformed JSONL log', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-http-');
  const logFile = path.join(directory, 'state', 'audit.jsonl');
  const skillDirectory = path.join(directory, 'skill');
  try {
    await fs.mkdir(logFile, { recursive: true });
    const directoryAudit = new AuditLog({ logFile, skillDirectory });
    assert.deepEqual(await directoryAudit.healthCheck(), { healthy: false, reason: 'AUDIT_LOG_INVALID' });
    await fs.rm(logFile, { recursive: true, force: true });
    await fs.mkdir(path.dirname(logFile), { recursive: true });
    await fs.writeFile(logFile, 'not-json\n', { mode: 0o600 });
    const malformedAudit = new AuditLog({ logFile, skillDirectory });
    assert.deepEqual(await malformedAudit.healthCheck(), { healthy: false, reason: 'AUDIT_LOG_CORRUPT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
