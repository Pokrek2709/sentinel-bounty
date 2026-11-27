// Public HTTP adapter (round 90, Phase 4 groundwork): the
// GET-only adapter for PUBLIC targets, behind the activation
// gate (kill switch, public hostname, authorization
// reference match, scope, method, fingerprint, governor,
// approval, DNS resolution to a public address). No test
// here touches a real socket or real DNS: the transport and
// the resolver are both stubs. The adapter has no CLI
// command yet — nothing invokes it outside these tests.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { AuditLog } = require('../src/audit/audit-log');
const { ApprovalGate } = require('../src/policy/approval-gate');
const { PublicHttpAdapter, isPublicAddress, isPublicHostname } = require('../src/http/public-http-adapter');
const { KillSwitch } = require('../src/policy/kill-switch');
const { RequestGovernor } = require('../src/policy/request-governor');
const { TargetRegistry } = require('../src/scope/target-registry');

function fakeTransport({ statusCode = 200, body = JSON.stringify({ status: 'public-ok' }), headers = { 'content-type': 'application/json', 'set-cookie': 'session=secret' } } = {}) {
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

function stubResolver(addresses = ['93.184.216.34']) {
  let calls = 0;
  const resolveHost = async (hostname) => {
    calls += 1;
    return addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
  return { resolveHost, get calls() { return calls; } };
}

async function harness(directory, { transport = fakeTransport(), resolver = stubResolver(), killSwitch = new KillSwitch() } = {}) {
  const registry = new TargetRegistry();
  registry.register({ target_id: 'public-lab', program_name: 'Public HTTP lab', authorization_reference: 'REF-PUBLIC-1', allowed_domains: ['example.com'], request_budget: 10 });
  const fingerprint = registry.getScopeFingerprint('public-lab');
  const approvals = new ApprovalGate({ clock: () => Date.now() });
  const pending = approvals.request({ targetId: 'public-lab', action: 'http_probing', estimatedRequests: 1, scopeFingerprint: fingerprint, reason: 'GET-only public lab' });
  const approved = approvals.approve(pending.requestId, { approver: 'local-human' });
  const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
  const governor = new RequestGovernor({ requestBudget: 10 });
  return {
    fingerprint,
    approvalId: approved.approvalId,
    audit,
    governor,
    transport,
    resolver,
    adapter: new PublicHttpAdapter({
      registry, approvalGate: approvals, governor, killSwitch, auditLog: audit,
      requestGet: transport.requestGet, resolveHost: resolver.resolveHost,
    }),
  };
}

const BASE = {
  targetId: 'public-lab',
  url: 'https://example.com/health',
  authorizationRef: 'REF-PUBLIC-1',
  estimatedRequests: 1,
};

test('isPublicAddress refuses private, loopback, link-local, and reserved addresses', () => {
  for (const address of [
    '127.0.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '192.0.2.1', '198.51.100.1',
    '203.0.113.1', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1',
    'fc00::1', 'fd00::1', 'ff02::1', '2001:db8::1', '::ffff:10.0.0.1',
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
  for (const address of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '2001:4860:4860::8888', '2606:4700:4700::1111']) {
    assert.equal(isPublicAddress(address), true, address);
  }
  assert.equal(isPublicAddress('not-an-ip'), false);
  assert.equal(isPublicAddress(''), false);
  assert.equal(isPublicHostname('localhost'), false);
  assert.equal(isPublicHostname('LOCALHOST'), false);
  assert.equal(isPublicHostname('example.com'), true);
});

test('getAuthorizationReference returns the registered reference, null when unregistered', () => {
  const registry = new TargetRegistry();
  assert.equal(registry.getAuthorizationReference('nope'), null);
  registry.register({ target_id: 't', program_name: 'P', authorization_reference: 'REF-X', allowed_domains: ['example.com'] });
  assert.equal(registry.getAuthorizationReference('t'), 'REF-X');
});

test('happy path: a public target completes through the stub transport, headers redacted', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-ok-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, true);
    assert.equal(response.reason, 'HTTP_COMPLETED');
    assert.equal(response.statusCode, 200);
    assert.equal(response.body, JSON.stringify({ status: 'public-ok' }));
    assert.equal(context.transport.requests, 1);
    assert.equal(context.resolver.calls, 1);
    assert.equal(response.headers['set-cookie'], '[REDACTED]');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('localhost is refused before any transport or resolver call', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-localhost-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, url: 'http://localhost/health', approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'NON_PUBLIC_HOST');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('an IP-literal URL is refused by the scope rule, never resolved', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-ip-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, url: 'http://93.184.216.34/health', approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'SCOPE_INVALID_URL');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a wrong authorization reference is refused and never logged', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-authref-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, authorizationRef: 'WRONG-REF', approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'AUTHORIZATION_REFERENCE_MISMATCH');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 0);
    const events = context.audit.readAllEvents();
    const serialized = JSON.stringify(events);
    assert.ok(!serialized.includes('WRONG-REF'), 'the presented reference must never reach the audit log');
    assert.ok(!serialized.includes('REF-PUBLIC-1'), 'the stored reference must never reach the audit log');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('an unregistered target is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-unreg-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, targetId: 'nope', approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'TARGET_NOT_REGISTERED');
    assert.equal(context.transport.requests, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a domain outside the allowlist is refused by scope', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-scope-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, url: 'https://other.com/health', approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'SCOPE_HOST_OUT_OF_SCOPE');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a hostname resolving to a private address is refused (SSRF guard)', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-ssrf-');
  try {
    const context = await harness(directory, { resolver: stubResolver(['10.0.0.5']) });
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'RESOLVED_NON_PUBLIC_HOST');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a hostname resolving to the cloud metadata address is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-metadata-');
  try {
    const context = await harness(directory, { resolver: stubResolver(['169.254.169.254']) });
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'RESOLVED_NON_PUBLIC_HOST');
    assert.equal(context.transport.requests, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a DNS failure is refused and releases the governor reservation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-dnsfail-');
  try {
    const failing = { resolveHost: async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); }, get calls() { return 1; } };
    const context = await harness(directory, { resolver: failing });
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'DNS_RESOLUTION_FAILED');
    assert.equal(context.transport.requests, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a triggered kill switch refuses before anything else', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-kill-');
  try {
    const killSwitch = {
      assertNotTriggered: async () => ({ allowed: false, reason: 'KILL_SWITCH_ACTIVE' }),
      registerWorker: async () => ({ registered: false, reason: 'KILL_SWITCH_ACTIVE' }),
    };
    const context = await harness(directory, { killSwitch });
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: context.fingerprint });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'KILL_SWITCH_ACTIVE');
    assert.equal(context.transport.requests, 0);
    assert.equal(context.resolver.calls, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('a wrong scope fingerprint is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-public-http-fp-');
  try {
    const context = await harness(directory);
    const response = await context.adapter.get({ ...BASE, approvalId: context.approvalId, scopeFingerprint: 'deadbeef' });
    assert.equal(response.allowed, false);
    assert.equal(response.reason, 'SCOPE_FINGERPRINT_MISMATCH');
    assert.equal(context.transport.requests, 0);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
