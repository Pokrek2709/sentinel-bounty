const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
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

async function harness(directory, transport = fakeTransport()) {
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
    adapter: new LocalHttpAdapter({ registry, approvalGate: approvals, governor, killSwitch: new KillSwitch(), auditLog: audit, requestGet: transport.requestGet }),
  };
}

test('performs a GET to localhost through scope, approval, governor, kill switch, and audit', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-http-'));
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

test('rejects external hosts and does not follow redirects', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-http-'));
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

test('passes 429/503 response status to the request governor', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-http-'));
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

test('requires audit state outside the skill directory', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-http-'));
  try {
    assert.throws(() => new AuditLog({ logFile: path.join(directory, 'skill', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') }), /outside the skill directory/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
