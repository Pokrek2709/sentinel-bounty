// Local operator sessions (round 98, Phase 1): token, heartbeat,
// lease, rotation — all local, hash-only storage. Module tests use
// an injected clock; fetch-binding tests use stub transport/resolver
// only; CLI spawn tests never present a valid token to a real
// socket. No test here touches a real target.
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
  DEFAULT_TTL_MS,
  DEFAULT_LEASE_MS,
  storePathFor,
  hashToken,
  startOperatorSession,
  heartbeatOperatorSession,
  validateOperatorSession,
  revokeOperatorSession,
  rotateOperatorSession,
  listOperatorSessions,
  getOperatorSession,
  deriveSessionStatus,
} = require('../src/policy/operator-sessions');
const { addPublicTarget, storePathFor: publicTargetStorePathFor } = require('../src/scope/public-target-store');
const { runPublicFetch } = require('../src/http/public-fetch');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const NOW = 1_800_000_000_000;

async function invokeCli(args, stateDirectory) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args, '--state-dir', stateDirectory], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function fakeTransport({ statusCode = 200, body = JSON.stringify({ status: 'public-ok' }) } = {}) {
  let requests = 0;
  const requestGet = (url, callback) => {
    requests += 1;
    const request = new EventEmitter();
    request.destroy = () => { request.destroyed = true; };
    process.nextTick(() => {
      const response = new EventEmitter();
      response.statusCode = statusCode;
      response.headers = { 'content-type': 'application/json' };
      response.setEncoding = () => {};
      callback(response);
      process.nextTick(() => { response.emit('data', body); response.emit('end'); });
    });
    return request;
  };
  return { requestGet, get requests() { return requests; } };
}

function stubResolver(addresses = ['93.184.216.34']) {
  const resolveHost = async () => addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  return { resolveHost };
}

async function setupFetchTarget(stateDir) {
  await addPublicTarget(publicTargetStorePathFor(stateDir), {
    host: 'example.com',
    scope: '/api',
    purpose: 'Authorized audit program lab',
    authorization_reference: 'REF-PUBLIC-1',
  });
}

// --- Module: start ---------------------------------------------------------

test('session start returns the token once and stores only its hash', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, label: 'lab shift', now: NOW });
  assert.match(started.token, /^[a-f0-9]{48}$/);
  assert.match(started.sessionId, /^ses-[a-f0-9]{24}$/);
  assert.equal(started.expiresAt, NOW + DEFAULT_TTL_MS);
  assert.equal(started.leaseSeconds, DEFAULT_LEASE_MS / 1_000);
  const stored = await fs.readFile(storePath, 'utf8');
  assert.ok(!stored.includes(started.token), 'plaintext token must never be written to the store');
  assert.ok(stored.includes(hashToken(started.token)), 'store holds the SHA-256 hash');
  assert.ok(!stored.includes('REF-PUBLIC'), 'store holds no authorization reference');
  await assertPrivateMode(storePath, 0o600);
});

test('session start honours custom TTL/lease and rejects out-of-range values', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, ttlMs: 60_000, leaseMs: 60_000, now: NOW });
  assert.equal(started.expiresAt, NOW + 60_000);
  assert.equal(started.leaseSeconds, 60);
  await assert.rejects(
    startOperatorSession({ storePath, ttlMs: 59_000, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_INVALID',
  );
  await assert.rejects(
    startOperatorSession({ storePath, ttlMs: 25 * 60 * 60 * 1_000, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_INVALID',
  );
  await assert.rejects(
    startOperatorSession({ storePath, leaseMs: 59_000, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_INVALID',
  );
  await assert.rejects(
    startOperatorSession({ storePath, leaseMs: 3 * 60 * 60 * 1_000, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_INVALID',
  );
});

test('session start is refused while the kill switch is armed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  await assert.rejects(
    startOperatorSession({ storePath, killSwitchArmed: true, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE',
  );
  const started = await startOperatorSession({ storePath, killSwitchArmed: false, now: NOW });
  assert.match(started.sessionId, /^ses-/);
});

test('two concurrent starts are serialized with distinct ids and tokens', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const [first, second] = await Promise.all([
    startOperatorSession({ storePath, now: NOW }),
    startOperatorSession({ storePath, now: NOW }),
  ]);
  assert.notEqual(first.sessionId, second.sessionId);
  assert.notEqual(first.token, second.token);
});

// --- Module: validate + heartbeat ------------------------------------------

test('validate proves liveness without refreshing anything', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, now: NOW });
  const checked = await validateOperatorSession({ storePath, token: started.token, now: NOW + 60_000 });
  assert.equal(checked.sessionId, started.sessionId);
  assert.equal(checked.expiresAt, NOW + DEFAULT_TTL_MS);
  assert.equal(checked.leaseExpiresAt, NOW + DEFAULT_LEASE_MS);
  // Validation is read-only: the stored heartbeat clock did not move.
  const listed = await listOperatorSessions({ storePath, now: NOW + 60_000 });
  assert.equal(listed.sessions[0].lastHeartbeatAt, NOW);
  assert.equal(listed.sessions[0].heartbeatCount, 0);
  await assert.rejects(
    validateOperatorSession({ storePath, token: '00'.repeat(24), now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_NOT_FOUND',
  );
});

test('heartbeat refreshes the lease and counts, and cannot revive a lapsed lease', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, leaseMs: 60_000, now: NOW });
  const beat = await heartbeatOperatorSession({ storePath, token: started.token, now: NOW + 30_000 });
  assert.equal(beat.heartbeatCount, 1);
  assert.equal(beat.leaseExpiresAt, NOW + 30_000 + 60_000);
  // 30 s later the lease (from the heartbeat) is still live.
  await validateOperatorSession({ storePath, token: started.token, now: NOW + 60_000 });
  // 61 s after the last heartbeat the lease has lapsed: dead.
  await assert.rejects(
    validateOperatorSession({ storePath, token: started.token, now: NOW + 30_000 + 61_000 }),
    (error) => error.code === 'OPERATOR_SESSION_LEASE_LAPSED',
  );
  await assert.rejects(
    heartbeatOperatorSession({ storePath, token: started.token, now: NOW + 30_000 + 61_000 }),
    (error) => error.code === 'OPERATOR_SESSION_LEASE_LAPSED',
  );
  // The lapsed session still reports LEASE_LAPSED, not NOT_FOUND.
  await assert.rejects(
    heartbeatOperatorSession({ storePath, token: started.token, now: NOW + 30_000 + 62_000 }),
    (error) => error.code === 'OPERATOR_SESSION_LEASE_LAPSED',
  );
});

test('heartbeat and validate refuse expired sessions as EXPIRED', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, ttlMs: 60_000, leaseMs: 60_000, now: NOW });
  await assert.rejects(
    validateOperatorSession({ storePath, token: started.token, now: NOW + 60_000 }),
    (error) => error.code === 'OPERATOR_SESSION_EXPIRED',
  );
  await assert.rejects(
    heartbeatOperatorSession({ storePath, token: started.token, now: NOW + 60_000 }),
    (error) => error.code === 'OPERATOR_SESSION_EXPIRED',
  );
});

// --- Module: revoke + rotate ------------------------------------------------

test('revoke ends the session and is idempotent; unknown id is NOT_FOUND', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, now: NOW });
  const first = await revokeOperatorSession({ storePath, sessionId: started.sessionId, now: NOW + 1_000 });
  assert.equal(first.revoked, true);
  const second = await revokeOperatorSession({ storePath, sessionId: started.sessionId, now: NOW + 2_000 });
  assert.equal(second.revoked, false);
  assert.equal(second.alreadyRevoked, true);
  await assert.rejects(
    validateOperatorSession({ storePath, token: started.token, now: NOW + 3_000 }),
    (error) => error.code === 'OPERATOR_SESSION_REVOKED',
  );
  await assert.rejects(
    heartbeatOperatorSession({ storePath, token: started.token, now: NOW + 3_000 }),
    (error) => error.code === 'OPERATOR_SESSION_REVOKED',
  );
  await assert.rejects(
    revokeOperatorSession({ storePath, sessionId: 'ses-000000000000000000000000', now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_NOT_FOUND',
  );
});

test('rotate replaces the token, keeps the TTL, refreshes the heartbeat clock', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, now: NOW });
  const rotated = await rotateOperatorSession({ storePath, sessionId: started.sessionId, now: NOW + 120_000 });
  assert.match(rotated.token, /^[a-f0-9]{48}$/);
  assert.notEqual(rotated.token, started.token);
  assert.equal(rotated.expiresAt, NOW + DEFAULT_TTL_MS, 'rotation never extends the TTL');
  assert.equal(rotated.rotationCount, 1);
  // The old token is dead immediately.
  await assert.rejects(
    validateOperatorSession({ storePath, token: started.token, now: NOW + 121_000 }),
    (error) => error.code === 'OPERATOR_SESSION_NOT_FOUND',
  );
  // The new token validates, and the rotation refreshed the lease clock.
  const checked = await validateOperatorSession({ storePath, token: rotated.token, now: NOW + 121_000 });
  assert.equal(checked.leaseExpiresAt, NOW + 120_000 + DEFAULT_LEASE_MS);
  const listed = await listOperatorSessions({ storePath, now: NOW + 121_000 });
  assert.equal(listed.sessions[0].rotationCount, 1);
  assert.equal(listed.sessions[0].lastHeartbeatAt, NOW + 120_000);
});

test('rotate is refused while armed, and on revoked/expired/lease-lapsed sessions', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, now: NOW });
  await assert.rejects(
    rotateOperatorSession({ storePath, sessionId: started.sessionId, killSwitchArmed: true, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE',
  );
  await revokeOperatorSession({ storePath, sessionId: started.sessionId, now: NOW });
  await assert.rejects(
    rotateOperatorSession({ storePath, sessionId: started.sessionId, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_REVOKED',
  );
  const short = await startOperatorSession({ storePath, ttlMs: 60_000, leaseMs: 60_000, now: NOW });
  await assert.rejects(
    rotateOperatorSession({ storePath, sessionId: short.sessionId, now: NOW + 60_000 }),
    (error) => error.code === 'OPERATOR_SESSION_EXPIRED',
  );
});

// --- Module: list + status + store integrity --------------------------------

test('list is metadata-only and derives lease_lapsed; expired entries are pruned', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const live = await startOperatorSession({ storePath, label: 'live', now: NOW });
  const lapsing = await startOperatorSession({ storePath, label: 'lapsing', leaseMs: 60_000, now: NOW });
  const dying = await startOperatorSession({ storePath, label: 'dying', ttlMs: 60_000, leaseMs: 60_000, now: NOW });
  await revokeOperatorSession({ storePath, sessionId: live.sessionId, now: NOW + 1_000 });
  const listed = await listOperatorSessions({ storePath, now: NOW + 61_000 });
  assert.equal(listed.count, 2, 'the TTL-expired session is pruned');
  assert.ok(!JSON.stringify(listed).includes('token_hash'), 'list never exposes the token hash');
  const byId = new Map(listed.sessions.map((entry) => [entry.sessionId, entry]));
  assert.equal(byId.get(live.sessionId).status, 'revoked');
  assert.equal(byId.get(lapsing.sessionId).status, 'lease_lapsed');
  assert.equal(byId.get(lapsing.sessionId).ttlRemainingMs, NOW + DEFAULT_TTL_MS - (NOW + 61_000));
  assert.equal(byId.get(lapsing.sessionId).leaseRemainingMs, 0);
  // The prune persisted: the file no longer holds the expired entry.
  const stored = JSON.parse(await fs.readFile(storePath, 'utf8'));
  assert.equal(stored.sessions.length, 2);
  assert.ok(!stored.sessions.some((entry) => entry.session_id === dying.sessionId));
});

test('status reports remaining TTL and lease; unknown id is NOT_FOUND', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  const started = await startOperatorSession({ storePath, now: NOW });
  const status = await getOperatorSession({ storePath, sessionId: started.sessionId, now: NOW + 1_000 });
  assert.equal(status.status, 'active');
  assert.equal(status.ttlRemainingMs, DEFAULT_TTL_MS - 1_000);
  assert.equal(status.leaseRemainingMs, DEFAULT_LEASE_MS - 1_000);
  await assert.rejects(
    getOperatorSession({ storePath, sessionId: 'ses-000000000000000000000000', now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_NOT_FOUND',
  );
});

test('deriveSessionStatus orders revoked before expiry before lease', () => {
  const base = {
    token_hash: 'a'.repeat(64),
    session_id: 'ses-000000000000000000000000',
    label: '',
    created_at: NOW,
    expires_at: NOW + 60_000,
    lease_seconds: 60,
    last_heartbeat_at: NOW,
    heartbeat_count: 0,
    rotation_count: 0,
    status: 'active',
    revoked_at: null,
    rotated_at: null,
  };
  assert.equal(deriveSessionStatus(base, NOW), 'active');
  assert.equal(deriveSessionStatus({ ...base, status: 'revoked' }, NOW + 120_000), 'revoked');
  assert.equal(deriveSessionStatus(base, NOW + 60_000), 'expired');
  assert.equal(deriveSessionStatus(base, NOW + 61_000), 'expired', 'expiry wins over a lapsed lease');
  assert.equal(deriveSessionStatus({ ...base, expires_at: NOW + 3_600_000 }, NOW + 61_000), 'lease_lapsed');
});

test('corrupt store shapes fail loudly with named codes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const storePath = storePathFor(directory);
  await fs.writeFile(storePath, '{broken', { mode: 0o600 });
  await assert.rejects(
    listOperatorSessions({ storePath, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_STORE_CORRUPT',
  );
  await fs.writeFile(storePath, JSON.stringify({ schema_version: 99, sessions: [] }), { mode: 0o600 });
  await assert.rejects(
    listOperatorSessions({ storePath, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_STORE_UNSUPPORTED_SCHEMA',
  );
  await fs.writeFile(storePath, JSON.stringify({ schema_version: 1, sessions: [{ token_hash: 'nope' }] }), { mode: 0o600 });
  await assert.rejects(
    listOperatorSessions({ storePath, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_STORE_CORRUPT',
  );
});

test('a symlinked store is refused on read and on write', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const target = path.join(directory, 'real.json');
  await fs.writeFile(target, JSON.stringify({ schema_version: 1, sessions: [] }), { mode: 0o600 });
  const storePath = storePathFor(directory);
  await fs.symlink(target, storePath);
  await assert.rejects(
    listOperatorSessions({ storePath, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_STORE_SYMLINK_REFUSED',
  );
  await assert.rejects(
    startOperatorSession({ storePath, now: NOW }),
    (error) => error.code === 'OPERATOR_SESSION_STORE_SYMLINK_REFUSED',
  );
});

// --- Fetch binding (module level, stubs only) --------------------------------

test('fetch with a live session token binds the session and records it in the audit log', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  await setupFetchTarget(stateDir);
  const started = await startOperatorSession({ storePath: storePathFor(stateDir), now: NOW });
  const transport = fakeTransport();
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => true },
    sessionToken: started.token,
    killSwitch: new KillSwitch(),
    requestGet: transport.requestGet,
    resolveHost: stubResolver().resolveHost,
    clock: () => NOW,
  });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.reason, 'HTTP_COMPLETED');
  assert.equal(fetched.sessionId, started.sessionId);
  assert.equal(transport.requests, 1);
  const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  const events = await audit.readAllEvents();
  const bound = events.find((event) => event.event === 'PUBLIC_FETCH_SESSION_BOUND');
  assert.ok(bound, 'session binding is audited');
  assert.equal(bound.details.sessionId, started.sessionId);
  assert.ok(!JSON.stringify(events).includes(started.token), 'the session token never reaches the audit log');
});

test('fetch with a dead session token refuses before the approval is spent', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  await setupFetchTarget(stateDir);
  const started = await startOperatorSession({ storePath: storePathFor(stateDir), ttlMs: 60_000, leaseMs: 60_000, now: NOW });
  const transport = fakeTransport();
  // The session is expired at the fetch clock: refusal, zero requests,
  // and the interactive confirm callback is never even called.
  let confirms = 0;
  const refused = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => { confirms += 1; return true; } },
    sessionToken: started.token,
    killSwitch: new KillSwitch(),
    requestGet: transport.requestGet,
    resolveHost: stubResolver().resolveHost,
    clock: () => NOW + 61_000,
  });
  assert.equal(refused.fetched, false);
  assert.equal(refused.reason, 'OPERATOR_SESSION_EXPIRED');
  assert.equal(confirms, 0, 'the session refusal precedes the approval step');
  assert.equal(transport.requests, 0);
  const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  const events = await audit.readAllEvents();
  assert.ok(events.some((event) => event.event === 'PUBLIC_FETCH_SESSION_INVALID'), 'the refusal is audited');
});

test('fetch without a session token behaves exactly as before', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  await setupFetchTarget(stateDir);
  const transport = fakeTransport();
  const fetched = await runPublicFetch({
    stateDir,
    url: 'https://example.com/api/health',
    approval: { kind: 'interactive', confirm: async () => true },
    killSwitch: new KillSwitch(),
    requestGet: transport.requestGet,
    resolveHost: stubResolver().resolveHost,
    clock: () => NOW,
  });
  assert.equal(fetched.fetched, true);
  assert.equal(fetched.sessionId, undefined, 'no session was presented, none is recorded');
});

// --- CLI spawn ----------------------------------------------------------------

test('CLI session start/heartbeat/list/status/revoke/rotate round-trip', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  const started = await invokeCli(['session', 'start', '--label', 'cli shift'], stateDir);
  assert.equal(started.code, 0, started.stderr);
  const startJson = JSON.parse(started.stdout);
  assert.equal(startJson.started, true);
  assert.match(startJson.token, /^[a-f0-9]{48}$/);
  assert.equal(startJson.auditLogged, true);
  const heartbeat = await invokeCli(['session', 'heartbeat', '--token', startJson.token], stateDir);
  assert.equal(heartbeat.code, 0, heartbeat.stderr);
  assert.equal(JSON.parse(heartbeat.stdout).heartbeatCount, 1);
  const listed = await invokeCli(['session', 'list', '--json'], stateDir);
  assert.equal(listed.code, 0, listed.stderr);
  const listJson = JSON.parse(listed.stdout);
  assert.equal(listJson.count, 1);
  assert.ok(!listed.stdout.includes(startJson.token), 'list never prints the token');
  const status = await invokeCli(['session', 'status', startJson.sessionId], stateDir);
  assert.equal(status.code, 0, status.stderr);
  assert.match(status.stdout, /active/);
  const rotated = await invokeCli(['session', 'rotate', startJson.sessionId], stateDir);
  assert.equal(rotated.code, 0, rotated.stderr);
  const rotateJson = JSON.parse(rotated.stdout);
  assert.notEqual(rotateJson.token, startJson.token);
  // The old token is dead at the CLI too.
  const stale = await invokeCli(['session', 'heartbeat', '--token', startJson.token], stateDir);
  assert.notEqual(stale.code, 0);
  assert.match(stale.stdout, /OPERATOR_SESSION_NOT_FOUND/);
  const revoked = await invokeCli(['session', 'revoke', startJson.sessionId], stateDir);
  assert.equal(revoked.code, 0, revoked.stderr);
  assert.equal(JSON.parse(revoked.stdout).revoked, true);
  const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  const events = await audit.readAllEvents();
  for (const event of ['OPERATOR_SESSION_STARTED', 'OPERATOR_SESSION_HEARTBEAT', 'OPERATOR_SESSION_ROTATED', 'OPERATOR_SESSION_REVOKED']) {
    assert.ok(events.some((entry) => entry.event === event), `audit carries ${event}`);
  }
  assert.ok(!JSON.stringify(events).includes(startJson.token), 'no session token in the audit log');
});

test('CLI session start/rotate are refused while armed; revoke and heartbeat are not', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  const started = await invokeCli(['session', 'start'], stateDir);
  assert.equal(started.code, 0, started.stderr);
  const startJson = JSON.parse(started.stdout);
  const triggered = await invokeCli(['kill-switch', 'trigger', '--actor', 'operator', '--reason', 'lab stop'], stateDir);
  assert.equal(triggered.code, 0, triggered.stderr);
  const startRefused = await invokeCli(['session', 'start'], stateDir);
  assert.notEqual(startRefused.code, 0);
  assert.match(startRefused.stdout, /OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE/);
  const rotateRefused = await invokeCli(['session', 'rotate', startJson.sessionId], stateDir);
  assert.notEqual(rotateRefused.code, 0);
  assert.match(rotateRefused.stdout, /OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE/);
  // Revoke removes access, so it stays available while armed.
  const revoked = await invokeCli(['session', 'revoke', startJson.sessionId], stateDir);
  assert.equal(revoked.code, 0, revoked.stderr);
  assert.equal(JSON.parse(revoked.stdout).revoked, true);
});

test('CLI session commands refuse unknown ids and tokens with named codes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-opsess-');
  const stateDir = path.join(directory, 'state');
  const status = await invokeCli(['session', 'status', 'ses-000000000000000000000000'], stateDir);
  assert.notEqual(status.code, 0);
  assert.match(status.stdout, /OPERATOR_SESSION_NOT_FOUND/);
  const heartbeat = await invokeCli(['session', 'heartbeat', '--token', '00'.repeat(24)], stateDir);
  assert.notEqual(heartbeat.code, 0);
  assert.match(heartbeat.stdout, /OPERATOR_SESSION_NOT_FOUND/);
  const badTtl = await invokeCli(['session', 'start', '--ttl-seconds', '10'], stateDir);
  assert.notEqual(badTtl.code, 0);
  assert.match(badTtl.stdout, /OPERATOR_SESSION_INVALID/);
});
