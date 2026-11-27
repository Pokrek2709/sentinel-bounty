// Public-fetch activation drill (round 94, Phase 4): the end-to-end
// proof that the invocation path built in round 93 actually activates
// — registration, preview, approval, fetch — and that the kill switch
// stops it at every point in the chain, including mid-flight.
//
// This file is the drill, not unit tests for the individual gates
// (those live in tests/public-http-invocation.test.js): each test
// here replays a whole activation scenario in order, with the
// persistent kill switch backed by a real temp state directory and
// stub transport/resolver only. No test here (and no CLI invocation
// in this round) touches a real socket or real DNS: the CLI drill
// mints its token through the CLI, then the actual fetch runs at
// module level with stubs against the same CLI-produced state —
// that cross-boundary step is the proof the CLI-produced stores
// (target, approval, kill-switch state) interoperate with the fetch
// path. The happy-path CLI fetch with a valid token is never
// spawned: it would execute a real request.
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
const { AuditLog } = require('../src/audit/audit-log');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const {
  addPublicTarget,
  storePathFor: publicTargetStorePathFor,
} = require('../src/scope/public-target-store');
const {
  mintPublicFetchApproval,
  loadApprovals,
  storePathFor: approvalStorePathFor,
  TOKEN_TTL_MS,
} = require('../src/http/public-fetch-approvals');
const {
  previewPublicFetch,
  mintPublicFetchApprovalFor,
  runPublicFetch,
} = require('../src/http/public-fetch');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const RESET_TOKEN = 'drill-reset-token-0123456789abcdef';
const URL = 'https://example.com/api/health';
const OTHER_IN_SCOPE_URL = 'https://example.com/api/other';
const OUT_OF_SCOPE_URL = 'https://example.com/other';

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

// A response that never ends: the request hangs until the timeout,
// the operator, or the kill switch ends it. destroy() is SILENT
// (no error event): the adapter's cancel path destroys the request
// and then finishes with PROCESS_FAILED — an error event from
// destroy would race that finish with HTTP_ERROR and make the
// drill outcome nondeterministic.
function hangingTransport() {
  let requests = 0;
  let destroyed = false;
  const requestGet = (url, callback) => {
    requests += 1;
    const request = new EventEmitter();
    request.destroy = () => { destroyed = true; };
    process.nextTick(() => {
      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = {};
      response.setEncoding = () => {};
      callback(response);
      // Never emits data or end: the fetch only finishes by
      // timeout or by kill-switch cancellation.
    });
    return request;
  };
  return { requestGet, get requests() { return requests; }, get destroyed() { return destroyed; } };
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

// A lab whose kill switch is the PERSISTENT one (real state file),
// not the in-memory KillSwitch the round-93 module tests use: the
// drill must prove the state-file path the CLI actually uses. The
// instance carries the drill reset token, so trigger/reset go
// through the same object the fetch path is handed.
function persistentKillSwitch(directory, stateDir) {
  return new PersistentKillSwitch({
    stateFile: path.join(stateDir, 'kill-switch.json'),
    skillDirectory: path.join(directory, 'skill'),
    resetToken: RESET_TOKEN,
  });
}

function drillDeps(directory, { transport = fakeTransport(), resolver = stubResolver(), killSwitch, clock } = {}) {
  const stateDir = path.join(directory, 'state');
  return {
    stateDir,
    requestGet: transport.requestGet,
    resolveHost: resolver.resolveHost,
    killSwitch,
    auditLog: new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') }),
    ...(clock ? { clock } : {}),
    transport,
    resolver,
  };
}

async function invokeCli(args, stateDirectory, extraEnv = {}) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args, '--state-dir', stateDirectory], {
      windowsHide: true,
      env: { ...process.env, ...extraEnv },
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

async function auditEvents(directory) {
  const auditLog = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
  return auditLog.readAllEvents();
}

function eventNames(events) {
  return events.map((event) => event.event);
}

// Asserts `expected` appears in `names` in order (not necessarily
// adjacent): the audit trail of a drill must read as a chain.
function assertOrdered(names, expected) {
  let cursor = -1;
  for (const wanted of expected) {
    const found = names.indexOf(wanted, cursor + 1);
    assert.notEqual(found, -1, `audit trail is missing ${wanted} after position ${cursor}: ${names.join(', ')}`);
    cursor = found;
  }
}

// --- the activation chain ----------------------------------------------

test('drill step 1-4: register → preview → mint → fetch, audit trail in order, no secrets in the audit log', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const deps = drillDeps(directory);
  const { stateDir } = deps;

  // Step 1: register the target (module store; the CLI audit event
  // PUBLIC_TARGET_ADDED is proven in the CLI drill below).
  await setupTarget(stateDir);

  // Step 2: preview — allowed, GET-only, nothing executed yet.
  const previewed = await previewPublicFetch({ stateDir, url: URL, ...deps });
  assert.equal(previewed.allowed, true);
  assert.equal(previewed.preview.method, 'GET');
  assert.equal(previewed.preview.targetId, 'example.com');
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 0);

  // Step 3: mint the one-time approval.
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  assert.equal(minted.minted, true);
  assert.equal(typeof minted.token, 'string');
  assert.equal(minted.token.length, 48);

  // Step 4: fetch with the token through the stub adapter.
  const fetched = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.reason, 'HTTP_COMPLETED');
  assert.equal(fetched.statusCode, 200);
  assert.equal(fetched.body, JSON.stringify({ status: 'public-ok' }));
  assert.equal(fetched.headers['set-cookie'], '[REDACTED]');
  assert.equal(deps.transport.requests, 1);
  assert.equal(deps.resolver.calls, 1);

  // The audit trail reads as the chain: mint, then the adapter's
  // own allow/response pair — and it carries no token, no body,
  // and no authorization reference.
  const names = eventNames(await auditEvents(directory));
  assertOrdered(names, ['PUBLIC_FETCH_APPROVAL_MINTED', 'PUBLIC_HTTP_REQUEST_ALLOWED', 'PUBLIC_HTTP_RESPONSE']);
  const serialized = JSON.stringify(await auditEvents(directory));
  assert.equal(serialized.includes(minted.token), false, 'the token must never reach the audit log');
  assert.equal(serialized.includes('public-ok'), false, 'the response body must never reach the audit log');
  assert.equal(serialized.includes('REF-PUBLIC-1'), false, 'the authorization reference must never reach the audit log');
});

test('drill step 5: refusal matrix — every gate refuses before any network, and a refusal does not burn the token', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const deps = drillDeps(directory);
  const { stateDir } = deps;
  await setupTarget(stateDir);

  const unregistered = await previewPublicFetch({ stateDir, url: 'https://other.com/api/health', ...deps });
  assert.equal(unregistered.allowed, false);
  assert.equal(unregistered.reason, 'PUBLIC_TARGET_NOT_REGISTERED');

  // Mint once, then spend the refusals against it: none of them
  // may consume the token, because every one is decided before
  // the token is read.
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  assert.equal(minted.minted, true);

  const outOfScope = await runPublicFetch({ stateDir, url: OUT_OF_SCOPE_URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(outOfScope.fetched, false);
  assert.equal(outOfScope.reason, 'PUBLIC_HTTP_OUT_OF_SCOPE');

  const noApproval = await runPublicFetch({ stateDir, url: URL, approval: undefined, ...deps });
  assert.equal(noApproval.fetched, false);
  assert.equal(noApproval.reason, 'PUBLIC_HTTP_APPROVAL_REQUIRED');

  const denied = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'interactive', confirm: async () => false }, ...deps });
  assert.equal(denied.fetched, false);
  assert.equal(denied.reason, 'PUBLIC_HTTP_APPROVAL_DENIED');

  const wrongBinding = await runPublicFetch({ stateDir, url: OTHER_IN_SCOPE_URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(wrongBinding.fetched, false);
  assert.equal(wrongBinding.reason, 'PUBLIC_FETCH_TOKEN_BINDING_MISMATCH');

  // The token survived all four refusals: it still fetches.
  const fetched = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(fetched.fetched, true);
  assert.equal(deps.transport.requests, 1, 'only the successful fetch may have touched the network');
  assert.equal(deps.resolver.calls, 1);

  // Replay is consumed; an unknown token is not found.
  const replay = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(replay.fetched, false);
  assert.equal(replay.reason, 'PUBLIC_FETCH_TOKEN_CONSUMED');
  const missing = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: 'deadbeef' }, ...deps });
  assert.equal(missing.fetched, false);
  assert.equal(missing.reason, 'PUBLIC_FETCH_TOKEN_NOT_FOUND');

  // Expiry (injected clock) and DNS failure (which DOES burn the
  // token — the approval is spent by the attempt, not the success).
  let now = Date.now();
  const clockDeps = drillDeps(directory, { clock: () => now });
  const expiring = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...clockDeps });
  now += TOKEN_TTL_MS + 1000;
  const expired = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: expiring.token }, ...clockDeps });
  assert.equal(expired.fetched, false);
  assert.equal(expired.reason, 'PUBLIC_FETCH_TOKEN_EXPIRED');

  const burnable = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  const failingResolver = { resolveHost: async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); } };
  const dnsFailed = await runPublicFetch({
    stateDir, url: URL, approval: { kind: 'token', token: burnable.token },
    ...drillDeps(directory, { resolver: failingResolver }),
  });
  assert.equal(dnsFailed.fetched, false);
  assert.equal(dnsFailed.reason, 'DNS_RESOLUTION_FAILED');
  const burned = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: burnable.token }, ...deps });
  assert.equal(burned.fetched, false);
  assert.equal(burned.reason, 'PUBLIC_FETCH_TOKEN_CONSUMED');
});

// --- the kill-switch drill ----------------------------------------------

test('drill kill-switch 1: trigger before fetch refuses, the token is not spent, mint is refused while armed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  const killSwitch = persistentKillSwitch(directory, stateDir);
  const deps = drillDeps(directory, { killSwitch });
  await setupTarget(stateDir);

  const minted = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  assert.equal(minted.minted, true);

  const triggered = await killSwitch.trigger({ triggeredBy: 'drill', reason: 'activation drill stop' });
  assert.equal(triggered.triggered, true);

  // The fetch is refused before the token is read: zero requests,
  // zero DNS, and the token stays unspent in the store.
  const refused = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(refused.fetched, false);
  assert.equal(refused.reason, 'KILL_SWITCH_ACTIVE');
  assert.equal(deps.transport.requests, 0);
  assert.equal(deps.resolver.calls, 0);
  const stored = await loadApprovals(approvalStorePathFor(stateDir), { now: Date.now(), pruneExpired: false });
  const entry = stored.approvals.find((candidate) => candidate.url === URL);
  assert.ok(entry, 'the minted token must still be in the store');
  assert.equal(entry.consumed_at, null, 'a kill-switch refusal must not consume the token');

  // Minting is refused while armed too, and the refusal is audited.
  const mintRefused = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  assert.equal(mintRefused.minted, false);
  assert.equal(mintRefused.reason, 'KILL_SWITCH_ACTIVE');
  const previewRefused = await previewPublicFetch({ stateDir, url: URL, ...deps });
  assert.equal(previewRefused.allowed, false);
  assert.equal(previewRefused.reason, 'KILL_SWITCH_ACTIVE');
  const names = eventNames(await auditEvents(directory));
  assert.ok(names.includes('PUBLIC_FETCH_BLOCKED'), 'the mint refusal must be audited');
});

test('drill kill-switch 2: reset restores service, and the pre-trigger token still works', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  const killSwitch = persistentKillSwitch(directory, stateDir);
  const deps = drillDeps(directory, { killSwitch });
  await setupTarget(stateDir);

  const minted = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...deps });
  assert.equal(minted.minted, true);
  await killSwitch.trigger({ triggeredBy: 'drill', reason: 'activation drill stop' });
  const refused = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(refused.reason, 'KILL_SWITCH_ACTIVE');

  // Reset is an authorized operator act (reset token); after it the
  // switch is inactive and the service is back.
  const reset = await killSwitch.reset({ resetBy: 'drill', resetToken: RESET_TOKEN });
  assert.equal(reset.reset, true);
  const snapshot = await killSwitch.snapshot();
  assert.equal(snapshot.active, false);

  // Documented semantics (round 94 judgment call): the kill switch
  // blocks USE while armed; it does not revoke approvals. A token
  // minted before the trigger, never spent, still within its TTL,
  // remains valid after an authorized reset — the operator who
  // resets the switch resumes the service deliberately.
  const recovered = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(recovered.fetched, true);
  assert.equal(recovered.statusCode, 200);
  assert.equal(deps.transport.requests, 1);
});

test('drill kill-switch 3: trip between token consume and adapter run — the adapter re-check refuses, the token is burned, zero requests', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  await setupTarget(stateDir);

  // The trip is simulated by a kill switch that allows the first
  // check (the fetch orchestration's pre-check, before the token
  // is consumed) and refuses every later one (the adapter's own
  // re-check): the stand-in for an operator triggering from
  // another process in that window. The adapter never reaches
  // worker registration, so registerWorker must never be called.
  let checks = 0;
  let registrations = 0;
  const trippingSwitch = {
    assertNotTriggered: async () => {
      checks += 1;
      return checks === 1
        ? Object.freeze({ allowed: true, reason: 'KILL_SWITCH_INACTIVE' })
        : Object.freeze({ allowed: false, reason: 'KILL_SWITCH_ACTIVE', trigger: { triggerId: 'drill-trip' } });
    },
    registerWorker: async () => {
      registrations += 1;
      return { registered: true, unregister: async () => {} };
    },
  };
  const deps = drillDeps(directory, { killSwitch: trippingSwitch });

  // Mint with an always-allowed switch so the counting starts at
  // the fetch, not the mint.
  const minted = await mintPublicFetchApprovalFor({ stateDir, url: URL, ...drillDeps(directory) });
  assert.equal(minted.minted, true);
  const fetched = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...deps });
  assert.equal(fetched.fetched, false);
  assert.equal(fetched.reason, 'KILL_SWITCH_ACTIVE');
  assert.equal(checks, 2, 'the adapter must re-check independently of the orchestration pre-check');
  assert.equal(registrations, 0, 'the adapter must refuse before registering a worker');
  assert.equal(deps.transport.requests, 0, 'no request may be sent');
  assert.equal(deps.resolver.calls, 0, 'no DNS may happen');
  // The token was consumed before the adapter ran, so the trip
  // burned it — a replay reports CONSUMED, not a fresh refusal.
  const replay = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: minted.token }, ...drillDeps(directory) });
  assert.equal(replay.fetched, false);
  assert.equal(replay.reason, 'PUBLIC_FETCH_TOKEN_CONSUMED');
});

test('drill kill-switch 4: in-flight cancellation — trigger during a hanging request aborts it (direct cancel)', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  const killSwitch = persistentKillSwitch(directory, stateDir);
  const hanging = hangingTransport();
  const deps = drillDeps(directory, { transport: hanging, killSwitch });
  await setupTarget(stateDir);

  const started = Date.now();
  const pending = runPublicFetch({
    stateDir, url: URL,
    approval: { kind: 'interactive', confirm: async () => true },
    ...deps,
  });
  // Let the request start and the adapter register its worker,
  // then trigger through the same instance: trigger() calls the
  // registered worker's cancel directly.
  await new Promise((resolve) => setTimeout(resolve, 150));
  const triggered = await killSwitch.trigger({ triggeredBy: 'drill', reason: 'mid-flight stop' });
  assert.equal(triggered.triggered, true);
  const aborted = await pending;
  const elapsed = Date.now() - started;
  assert.equal(aborted.fetched, false);
  assert.equal(aborted.reason, 'PROCESS_FAILED');
  assert.equal(aborted.cancellation, 'KILL_SWITCH_ACTIVE');
  assert.equal(hanging.destroyed, true, 'the request must be destroyed');
  assert.ok(elapsed < 4000, `the abort must beat the 5 s timeout (took ${elapsed} ms)`);
  // Cleanup unregistered the worker before the fetch resolved, so
  // the switch can reset cleanly.
  const snapshot = await killSwitch.snapshot();
  assert.equal(snapshot.registeredWorkers, 0);
  const reset = await killSwitch.reset({ resetBy: 'drill', resetToken: RESET_TOKEN });
  assert.equal(reset.reset, true);
});

test('drill kill-switch 5: in-flight cancellation across instances — a trigger from another process is caught by the adapter poller', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  const killSwitch = persistentKillSwitch(directory, stateDir);
  const hanging = hangingTransport();
  const deps = drillDeps(directory, { transport: hanging, killSwitch });
  await setupTarget(stateDir);

  const started = Date.now();
  const pending = runPublicFetch({
    stateDir, url: URL,
    approval: { kind: 'interactive', confirm: async () => true },
    ...deps,
  });
  await new Promise((resolve) => setTimeout(resolve, 150));
  // A SECOND instance over the same state file: its trigger()
  // cannot invoke the first instance's in-process worker cancel,
  // so the abort must come from the adapter's 100 ms kill-switch
  // poller noticing the state change.
  const otherInstance = new PersistentKillSwitch({
    stateFile: path.join(stateDir, 'kill-switch.json'),
    skillDirectory: path.join(directory, 'skill'),
  });
  const triggered = await otherInstance.trigger({ triggeredBy: 'drill-other-process', reason: 'mid-flight stop from another process' });
  assert.equal(triggered.triggered, true);
  const aborted = await pending;
  const elapsed = Date.now() - started;
  assert.equal(aborted.fetched, false);
  assert.equal(aborted.reason, 'PROCESS_FAILED');
  assert.equal(aborted.cancellation, 'KILL_SWITCH_ACTIVE');
  assert.equal(hanging.destroyed, true);
  assert.ok(elapsed < 4000, `the poller abort must beat the 5 s timeout (took ${elapsed} ms)`);
  const reset = await killSwitch.reset({ resetBy: 'drill', resetToken: RESET_TOKEN });
  assert.equal(reset.reset, true);
});

// --- the CLI drill: cross-boundary ---------------------------------------

test('drill CLI: register → mint → trigger → refusals → reset → CLI-minted token fetches at module level (stub)', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-pfdrill-');
  const stateDir = path.join(directory, 'state');
  // The CLI reset reads its token from a digest file (env
  // SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE): JSON metadata,
  // 0600, outside the skill directory, valid until the future.
  const digestFile = path.join(directory, 'reset-token-hash.json');
  const digest = crypto.createHash('sha256').update(RESET_TOKEN).digest('hex');
  await fs.writeFile(digestFile, JSON.stringify({
    version: 1, keyId: 'drill', digest, validUntil: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  }), { mode: 0o600 });
  const env = {
    SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE: digestFile,
    SENTINEL_OPERATOR_RESET_TOKEN: RESET_TOKEN,
  };
  const cli = (args) => invokeCli(args, stateDir, env);

  // Step 1: register through the CLI.
  const added = await cli(['target', 'add', 'example.com', '--scope', '/api', '--purpose', 'Authorized audit program lab', '--auth-ref', 'REF-PUBLIC-1']);
  assert.equal(added.code, 0, added.stderr);
  assert.equal(JSON.parse(added.stdout).added, true);

  // Step 2: mint the approval through the CLI — preview on stderr,
  // the token once on stdout.
  const minted = await cli(['fetch', '--url', URL, '--mint-approval']);
  assert.equal(minted.code, 0, minted.stderr);
  const mintedJson = JSON.parse(minted.stdout);
  assert.equal(mintedJson.minted, true);
  assert.equal(typeof mintedJson.token, 'string');
  assert.equal(mintedJson.token.length, 48);
  assert.match(minted.stderr, /Public fetch preview/);

  // Step 3: trigger the kill switch through the CLI.
  const triggered = await cli(['kill-switch', 'trigger', '--actor', 'drill', '--reason', 'activation drill stop']);
  assert.equal(triggered.code, 0, triggered.stderr);
  assert.equal(JSON.parse(triggered.stdout).triggered, true);
  const statusArmed = await cli(['kill-switch', 'status']);
  assert.equal(JSON.parse(statusArmed.stdout).active, true);

  // Step 4: while armed — add/remove are refused, list still works,
  // mint is refused, and a fetch with the minted token is refused
  // before the token is read.
  const addRefused = await cli(['target', 'add', 'other.com', '--scope', '/api', '--purpose', 'lab', '--auth-ref', 'REF-2']);
  assert.equal(addRefused.code, 1);
  assert.equal(JSON.parse(addRefused.stdout).reason, 'PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE');
  const removeRefused = await cli(['target', 'remove', 'example.com']);
  assert.equal(removeRefused.code, 1);
  assert.equal(JSON.parse(removeRefused.stdout).reason, 'PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE');
  const listed = await cli(['target', 'list']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, /example\.com/);
  const mintRefused = await cli(['fetch', '--url', URL, '--mint-approval']);
  assert.equal(mintRefused.code, 1);
  assert.equal(JSON.parse(mintRefused.stdout).minted, false);
  assert.equal(JSON.parse(mintRefused.stdout).reason, 'KILL_SWITCH_ACTIVE');
  const fetchRefused = await cli(['fetch', '--url', URL, '--approve-token', mintedJson.token]);
  assert.equal(fetchRefused.code, 1);
  assert.equal(JSON.parse(fetchRefused.stdout).reason, 'KILL_SWITCH_ACTIVE');

  // Step 5: reset through the CLI with the operator token.
  const reset = await cli(['kill-switch', 'reset', '--actor', 'drill']);
  assert.equal(reset.code, 0, reset.stderr);
  assert.equal(JSON.parse(reset.stdout).reset, true);
  const statusClear = await cli(['kill-switch', 'status']);
  assert.equal(JSON.parse(statusClear.stdout).active, false);

  // Step 6: the CLI-minted token — minted before the trigger, never
  // spent — fetches at module level with stubs against the SAME
  // CLI-produced state. This is the cross-boundary proof: the CLI
  // stores and the module fetch path interoperate. (The CLI fetch
  // itself is never spawned with a valid token: it would execute a
  // real request.)
  const deps = drillDeps(directory);
  const fetched = await runPublicFetch({ stateDir, url: URL, approval: { kind: 'token', token: mintedJson.token }, ...deps });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.statusCode, 200);
  assert.equal(deps.transport.requests, 1);

  // Step 7: the audit trail reads as the whole drill in order, and
  // carries no token, no body, and no reference.
  const names = eventNames(await auditEvents(directory));
  assertOrdered(names, [
    'PUBLIC_TARGET_ADDED',
    'PUBLIC_FETCH_APPROVAL_MINTED',
    'KILL_SWITCH_TRIGGER',
    'PUBLIC_FETCH_BLOCKED',
    'KILL_SWITCH_RESET',
    'PUBLIC_HTTP_REQUEST_ALLOWED',
    'PUBLIC_HTTP_RESPONSE',
  ]);
  const serialized = JSON.stringify(await auditEvents(directory));
  assert.equal(serialized.includes(mintedJson.token), false);
  assert.equal(serialized.includes('public-ok'), false);
  assert.equal(serialized.includes('REF-PUBLIC-1'), false);
});
