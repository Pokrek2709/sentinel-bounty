// Public-fetch invocation path (round 93, Phase 4): the CLI-facing
// half of the public HTTP adapter — `sentinel target add/list/remove`
// and `sentinel fetch` (interactive YA confirmation and one-time
// tokens). Module tests use stub transport/resolver only; CLI spawn
// tests cover refusals, minting, and the non-TTY guard — no test
// here (and no CLI invocation in this round) touches a real socket
// or real DNS: the happy-path CLI fetch is exercised at module level
// with stubs, because a local fixture server would be refused by
// the adapter itself (localhost / IP-literal hosts are out of scope
// by design).
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateMode } = require('./helpers/private-mode');
const { AuditLog } = require('../src/audit/audit-log');
const { KillSwitch } = require('../src/policy/kill-switch');
const {
  addPublicTarget,
  removePublicTarget,
  findPublicTarget,
  listPublicTargets,
  scopePrefixMatches,
  storePathFor: publicTargetStorePathFor,
} = require('../src/scope/public-target-store');
const {
  mintPublicFetchApproval,
  consumePublicFetchApproval,
  storePathFor: approvalStorePathFor,
  TOKEN_TTL_MS,
} = require('../src/http/public-fetch-approvals');
const {
  previewPublicFetch,
  mintPublicFetchApprovalFor,
  runPublicFetch,
  renderPreviewText,
} = require('../src/http/public-fetch');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

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
  const resolveHost = async () => {
    calls += 1;
    return addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
  return { resolveHost, get calls() { return calls; } };
}

async function setupTarget(stateDir) {
  const result = await addPublicTarget(publicTargetStorePathFor(stateDir), {
    host: 'example.com',
    scope: '/api',
    purpose: 'Authorized audit program lab',
    authorization_reference: 'REF-PUBLIC-1',
    program_name: 'Public fetch lab',
  });
  assert.equal(result.added, true);
  return result.targetId;
}

function moduleDeps(directory, { transport = fakeTransport(), resolver = stubResolver(), killSwitch = new KillSwitch(), clock } = {}) {
  return {
    requestGet: transport.requestGet,
    resolveHost: resolver.resolveHost,
    killSwitch,
    auditLog: new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') }),
    ...(clock ? { clock } : {}),
    transport,
    resolver,
  };
}

async function invokeCli(args, stateDirectory) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args, '--state-dir', stateDirectory], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// --- store: validation, identity, idempotence -------------------------

test('scopePrefixMatches: / matches all, a prefix matches itself and children only', () => {
  assert.equal(scopePrefixMatches('/', '/anything/at/all'), true);
  assert.equal(scopePrefixMatches('/api', '/api'), true);
  assert.equal(scopePrefixMatches('/api', '/api/users'), true);
  assert.equal(scopePrefixMatches('/api', '/apix'), false);
  assert.equal(scopePrefixMatches('/api', '/apiary'), false);
  assert.equal(scopePrefixMatches('/api', '/other'), false);
  assert.equal(scopePrefixMatches('/api/', '/api/users'), true);
});

test('public-target store: add validates, duplicate identical is a no-op, conflicting re-add is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pubtarget-');
  const stateDir = path.join(directory, 'state');
  const storePath = publicTargetStorePathFor(stateDir);
  const entry = {
    host: 'example.com',
    scope: '/api',
    purpose: 'Authorized audit program lab',
    authorization_reference: 'REF-PUBLIC-1',
  };
  const added = await addPublicTarget(storePath, entry);
  assert.deepEqual(added, { added: true, targetId: 'example.com' });
  await assertPrivateMode(storePath, 0o600);
  const duplicate = await addPublicTarget(storePath, entry);
  assert.deepEqual(duplicate, { added: false, alreadyPresent: true, targetId: 'example.com' });
  await assert.rejects(
    addPublicTarget(storePath, { ...entry, scope: '/other' }),
    /PUBLIC_TARGET_ALREADY_REGISTERED/,
  );
  await assert.rejects(addPublicTarget(storePath, { ...entry, host: '93.184.216.34' }), /PUBLIC_TARGET_INVALID/);
  await assert.rejects(addPublicTarget(storePath, { ...entry, host: '*.example.com' }), /PUBLIC_TARGET_INVALID/);
  await assert.rejects(addPublicTarget(storePath, { ...entry, scope: 'api' }), /PUBLIC_TARGET_INVALID/);
  await assert.rejects(addPublicTarget(storePath, { ...entry, purpose: '' }), /PUBLIC_TARGET_INVALID/);
  const listed = await listPublicTargets(storePath);
  assert.equal(listed.count, 1);
  assert.equal(listed.targets[0].targetId, 'example.com');
  assert.equal(listed.targets[0].scope, '/api');
  // The authorization reference is never listed (text or JSON).
  assert.equal(JSON.stringify(listed).includes('REF-PUBLIC-1'), false);
  const removed = await removePublicTarget(storePath, 'example.com');
  assert.deepEqual(removed, { removed: true, targetId: 'example.com' });
  await assert.rejects(removePublicTarget(storePath, 'example.com'), /PUBLIC_TARGET_NOT_FOUND/);
  assert.equal(await findPublicTarget(storePath, 'example.com'), null);
});

// --- approval tokens: mint, consume, expiry, binding ------------------

test('approval token: mint returns it once, the store holds only its hash', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pftoken-');
  const stateDir = path.join(directory, 'state');
  const storePath = approvalStorePathFor(stateDir);
  const now = Date.now();
  const minted = await mintPublicFetchApproval({
    storePath,
    targetId: 'example.com',
    url: 'https://example.com/api/health',
    scopeFingerprint: 'a'.repeat(64),
    now,
  });
  assert.equal(typeof minted.token, 'string');
  assert.equal(minted.token.length, 48);
  assert.equal(minted.expiresAt, now + TOKEN_TTL_MS);
  const stored = JSON.parse(await fs.readFile(storePath, 'utf8'));
  assert.equal(stored.approvals.length, 1);
  assert.equal(stored.approvals[0].token_hash, crypto.createHash('sha256').update(minted.token).digest('hex'));
  assert.equal(JSON.stringify(stored).includes(minted.token), false);
  await assertPrivateMode(storePath, 0o600);
  const consumed = await consumePublicFetchApproval({
    storePath,
    token: minted.token,
    targetId: 'example.com',
    url: 'https://example.com/api/health',
    scopeFingerprint: 'a'.repeat(64),
    now: now + 1000,
  });
  assert.equal(consumed.consumed, true);
  await assert.rejects(
    consumePublicFetchApproval({ storePath, token: minted.token, targetId: 'example.com', url: 'https://example.com/api/health', scopeFingerprint: 'a'.repeat(64), now: now + 2000 }),
    /PUBLIC_FETCH_TOKEN_CONSUMED/,
  );
  await assert.rejects(
    consumePublicFetchApproval({ storePath, token: 'deadbeef', targetId: 'example.com', url: 'https://example.com/api/health', scopeFingerprint: 'a'.repeat(64), now }),
    /PUBLIC_FETCH_TOKEN_NOT_FOUND/,
  );
});

test('approval token: wrong URL is a binding mismatch, an old token is expired', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pftoken-');
  const stateDir = path.join(directory, 'state');
  const storePath = approvalStorePathFor(stateDir);
  const now = Date.now();
  const minted = await mintPublicFetchApproval({
    storePath,
    targetId: 'example.com',
    url: 'https://example.com/api/health',
    scopeFingerprint: 'a'.repeat(64),
    now,
  });
  await assert.rejects(
    consumePublicFetchApproval({ storePath, token: minted.token, targetId: 'example.com', url: 'https://example.com/api/other', scopeFingerprint: 'a'.repeat(64), now }),
    /PUBLIC_FETCH_TOKEN_BINDING_MISMATCH/,
  );
  await assert.rejects(
    consumePublicFetchApproval({ storePath, token: minted.token, targetId: 'example.com', url: 'https://example.com/api/health', scopeFingerprint: 'a'.repeat(64), now: now + TOKEN_TTL_MS + 1000 }),
    /PUBLIC_FETCH_TOKEN_EXPIRED/,
  );
});

// --- preview ------------------------------------------------------------

test('preview: shows GET-only, timeout, body cap, scope — and touches no network', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfpreview-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory);
  const previewed = await previewPublicFetch({ stateDir, url: 'https://example.com/api/health', ...deps });
  assert.equal(previewed.allowed, true);
  assert.equal(previewed.preview.method, 'GET');
  assert.equal(previewed.preview.url, 'https://example.com/api/health');
  assert.equal(previewed.preview.targetId, 'example.com');
  assert.equal(previewed.preview.scope, '/api');
  assert.equal(previewed.preview.timeoutMs, 5000);
  assert.equal(previewed.preview.maxBodyBytes, 1048576);
  assert.equal(previewed.preview.estimatedRequests, 1);
  const text = renderPreviewText(previewed.preview);
  assert.match(text, /GET \(only\)/);
  assert.match(text, /Timeout: 5000 ms/);
  assert.match(text, /body cap: 1048576 bytes/);
  assert.match(text, /credentials: none/);
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 0);
});

test('preview: unregistered host, out-of-scope path, and armed kill switch are refused before any network', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfpreview-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory);
  const unregistered = await previewPublicFetch({ stateDir, url: 'https://other.com/api/health', ...deps });
  assert.equal(unregistered.allowed, false);
  assert.equal(unregistered.reason, 'PUBLIC_TARGET_NOT_REGISTERED');
  const outOfScope = await previewPublicFetch({ stateDir, url: 'https://example.com/other', ...deps });
  assert.equal(outOfScope.allowed, false);
  assert.equal(outOfScope.reason, 'PUBLIC_HTTP_OUT_OF_SCOPE');
  const armed = new KillSwitch();
  await armed.trigger({ triggeredBy: 'test', reason: 'lab stop' });
  const armedDeps = moduleDeps(directory, { killSwitch: armed });
  const refused = await previewPublicFetch({ stateDir, url: 'https://example.com/api/health', ...armedDeps });
  assert.equal(refused.allowed, false);
  assert.equal(refused.reason, 'KILL_SWITCH_ACTIVE');
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 0);
});

// --- fetch: interactive approval ----------------------------------------

test('fetch with interactive approval: happy path through the stub, body never reaches the audit log', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pffetch-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory);
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => true },
    ...deps,
  });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.reason, 'HTTP_COMPLETED');
  assert.equal(fetched.statusCode, 200);
  assert.equal(fetched.body, JSON.stringify({ status: 'public-ok' }));
  assert.equal(fetched.redirected, false);
  assert.equal(fetched.headers['set-cookie'], '[REDACTED]');
  assert.equal(deps.transport.requests, 1);
  assert.equal(deps.resolver.calls, 1);
  const events = await deps.auditLog.readAllEvents();
  const kinds = events.map((event) => event.event);
  assert.ok(kinds.includes('PUBLIC_HTTP_REQUEST_ALLOWED'));
  assert.ok(kinds.includes('PUBLIC_HTTP_RESPONSE'));
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes('public-ok'), false, 'the response body must never reach the audit log');
  assert.equal(serialized.includes('REF-PUBLIC-1'), false, 'the authorization reference must never reach the audit log');
});

test('fetch with interactive denial: nothing is executed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pffetch-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory);
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => false },
    ...deps,
  });
  assert.equal(fetched.fetched, false);
  assert.equal(fetched.reason, 'PUBLIC_HTTP_APPROVAL_DENIED');
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 0);
  const events = await deps.auditLog.readAllEvents();
  assert.ok(events.some((event) => event.event === 'PUBLIC_FETCH_APPROVAL_DENIED'));
});

// --- fetch: token approval ----------------------------------------------

test('fetch with a token: happy path, then the same token is consumed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pftoken-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  let now = Date.now();
  const deps = moduleDeps(directory, { clock: () => now });
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: 'https://example.com/api/health', ...deps });
  assert.equal(minted.minted, true);
  assert.equal(typeof minted.token, 'string');
  const first = await runPublicFetch({ stateDir, url: 'https://example.com/api/health', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(first.fetched, true);
  assert.equal(first.statusCode, 200);
  assert.equal(deps.transport.requests, 1);
  const second = await runPublicFetch({ stateDir, url: 'https://example.com/api/health', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(second.fetched, false);
  assert.equal(second.reason, 'PUBLIC_FETCH_TOKEN_CONSUMED');
  assert.equal(deps.transport.requests, 1);
  now += 1;
  // A URL outside the scope prefix is refused before the token is
  // even read — the token is not spent on an out-of-scope request.
  const wrongUrl = await runPublicFetch({ stateDir, url: 'https://example.com/other', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(wrongUrl.fetched, false);
  assert.equal(wrongUrl.reason, 'PUBLIC_HTTP_OUT_OF_SCOPE');
  // And the same consumed token presented for a different in-scope
  // URL reports a binding mismatch, not a silent acceptance.
  const wrongBinding = await runPublicFetch({ stateDir, url: 'https://example.com/api/other', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(wrongBinding.fetched, false);
  assert.equal(wrongBinding.reason, 'PUBLIC_FETCH_TOKEN_BINDING_MISMATCH');
});

test('fetch with a token: a DNS failure burns the token', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pftoken-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory);
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: 'https://example.com/api/health', ...deps });
  assert.equal(minted.minted, true);
  const failing = { resolveHost: async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); }, get calls() { return 1; } };
  const failed = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'token', token: minted.token },
    ...moduleDeps(directory, { resolver: failing }),
  });
  assert.equal(failed.fetched, false);
  assert.equal(failed.reason, 'DNS_RESOLUTION_FAILED');
  const retry = await runPublicFetch({ stateDir, url: 'https://example.com/api/health', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(retry.fetched, false);
  assert.equal(retry.reason, 'PUBLIC_FETCH_TOKEN_CONSUMED');
});

test('fetch with a token: an expired token is refused, a missing token is not found', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pftoken-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  let now = Date.now();
  const deps = moduleDeps(directory, { clock: () => now });
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: 'https://example.com/api/health', ...deps });
  assert.equal(minted.minted, true);
  now += TOKEN_TTL_MS + 1000;
  const expired = await runPublicFetch({ stateDir, url: 'https://example.com/api/health', approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(expired.fetched, false);
  assert.equal(expired.reason, 'PUBLIC_FETCH_TOKEN_EXPIRED');
  const missing = await runPublicFetch({ stateDir, url: 'https://example.com/api/health', approval: { kind: 'token', token: 'deadbeef' }, ...deps });
  assert.equal(missing.fetched, false);
  assert.equal(missing.reason, 'PUBLIC_FETCH_TOKEN_NOT_FOUND');
});

// --- fetch: SSRF guard and redirects -------------------------------------

test('fetch: a hostname resolving to a private address is refused before any request', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfssrf-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const deps = moduleDeps(directory, { resolver: stubResolver(['10.0.0.5']) });
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => true },
    ...deps,
  });
  assert.equal(fetched.fetched, false);
  assert.equal(fetched.reason, 'RESOLVED_NON_PUBLIC_HOST');
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 1);
});

test('fetch: a redirect is reported, never followed — even to a private or out-of-scope URL', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfredirect-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);
  const redirect = fakeTransport({ statusCode: 302, body: '', headers: { location: 'http://169.254.169.254/latest/meta-data/' } });
  const deps = moduleDeps(directory, { transport: redirect });
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => true },
    ...deps,
  });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.statusCode, 302);
  assert.equal(fetched.redirected, true);
  assert.equal(redirect.requests, 1, 'the redirect target must never be requested');
  const events = await deps.auditLog.readAllEvents();
  const response = events.find((event) => event.event === 'PUBLIC_HTTP_RESPONSE');
  assert.equal(response.details.redirected, true);
});

// --- CLI spawn: target management ----------------------------------------

test('CLI: target add/list/remove round-trips, and the reference is never printed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfcli-');
  const stateDir = path.join(directory, 'state');
  const added = await invokeCli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'Authorized audit program lab', '--auth-ref', 'REF-PUBLIC-1'], stateDir);
  assert.equal(added.code, 0, added.stderr);
  const addedJson = JSON.parse(added.stdout);
  assert.equal(addedJson.added, true);
  assert.equal(addedJson.targetId, 'example.com');
  assert.equal(addedJson.auditLogged, true);
  const listed = await invokeCli(['target', 'list'], stateDir);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, /example\.com \| scope: \/api/);
  assert.equal(listed.stdout.includes('REF-PUBLIC-1'), false);
  const listedJson = await invokeCli(['target', 'list', '--json'], stateDir);
  assert.equal(listedJson.code, 0, listedJson.stderr);
  assert.equal(JSON.parse(listedJson.stdout).count, 1);
  assert.equal(listedJson.stdout.includes('REF-PUBLIC-1'), false);
  const duplicate = await invokeCli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'Authorized audit program lab', '--auth-ref', 'REF-PUBLIC-1'], stateDir);
  assert.equal(duplicate.code, 0, duplicate.stderr);
  assert.equal(JSON.parse(duplicate.stdout).alreadyPresent, true);
  const conflicting = await invokeCli(['target', 'add', 'example.com', '--scope', '/other', '--purpose', 'Authorized audit program lab', '--auth-ref', 'REF-PUBLIC-1'], stateDir);
  assert.equal(conflicting.code, 1);
  assert.match(conflicting.stderr, /PUBLIC_TARGET_ALREADY_REGISTERED/);
  const removed = await invokeCli(['target', 'remove', 'example.com'], stateDir);
  assert.equal(removed.code, 0, removed.stderr);
  assert.equal(JSON.parse(removed.stdout).removed, true);
  const gone = await invokeCli(['target', 'list'], stateDir);
  assert.match(gone.stdout, /No public targets/);
});

test('CLI: target add is refused while the kill switch is armed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfcli-');
  const stateDir = path.join(directory, 'state');
  const triggered = await invokeCli(['kill-switch', 'trigger', '--actor', 'operator', '--reason', 'lab stop'], stateDir);
  assert.equal(triggered.code, 0, triggered.stderr);
  const refused = await invokeCli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'lab', '--auth-ref', 'REF-1'], stateDir);
  assert.equal(refused.code, 1);
  assert.equal(JSON.parse(refused.stdout).reason, 'PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE');
});

// --- CLI spawn: fetch refusals and mint ----------------------------------

test('CLI: fetch refuses an unregistered host and a missing token without touching the network', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfcli-');
  const stateDir = path.join(directory, 'state');
  const unregistered = await invokeCli(['fetch', '--url', 'https://other.com/api/health'], stateDir);
  assert.equal(unregistered.code, 1);
  assert.equal(JSON.parse(unregistered.stdout).reason, 'PUBLIC_TARGET_NOT_REGISTERED');
  await invokeCli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'lab', '--auth-ref', 'REF-1'], stateDir);
  const badToken = await invokeCli(['fetch', '--url', 'https://example.com/api/health', '--approve-token', 'deadbeef'], stateDir);
  assert.equal(badToken.code, 1);
  assert.equal(JSON.parse(badToken.stdout).reason, 'PUBLIC_FETCH_TOKEN_NOT_FOUND');
  const noTty = await invokeCli(['fetch', '--url', 'https://example.com/api/health'], stateDir);
  assert.equal(noTty.code, 1);
  assert.equal(JSON.parse(noTty.stdout).reason, 'PUBLIC_HTTP_APPROVAL_REQUIRES_TTY');
});

test('CLI: fetch --mint-approval mints a token after the preview, and only once', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfcli-');
  const stateDir = path.join(directory, 'state');
  const unregistered = await invokeCli(['fetch', '--url', 'https://other.com/api/health', '--mint-approval'], stateDir);
  assert.equal(unregistered.code, 1);
  assert.equal(JSON.parse(unregistered.stdout).minted, false);
  await invokeCli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'lab', '--auth-ref', 'REF-1'], stateDir);
  const minted = await invokeCli(['fetch', '--url', 'https://example.com/api/health', '--mint-approval'], stateDir);
  assert.equal(minted.code, 0, minted.stderr);
  const mintedJson = JSON.parse(minted.stdout);
  assert.equal(mintedJson.minted, true);
  assert.equal(typeof mintedJson.token, 'string');
  assert.equal(mintedJson.token.length, 48);
  assert.match(minted.stderr, /Public fetch preview/);
  assert.match(minted.stderr, /Method: GET \(only\)/);
  assert.match(minted.stderr, /Timeout: 5000 ms/);
  // The token survives the round-trip through stdout JSON: the
  // store holds only its hash, never the plaintext.
  const stored = JSON.parse(await fs.readFile(path.join(stateDir, 'public-fetch-approvals.json'), 'utf8'));
  assert.equal(stored.approvals.length, 1);
  assert.equal(stored.approvals[0].token_hash, crypto.createHash('sha256').update(mintedJson.token).digest('hex'));
  assert.equal(JSON.stringify(stored).includes(mintedJson.token), false);
  // Presenting the token is exercised at module level with stub
  // transport/resolver; the CLI spawn path never runs it against a
  // real host in this round.
});
