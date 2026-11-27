// Local operator sessions (Phase 1, round 98).
//
// An operator session is a bounded, local, file-backed work session
// for the human operator: a token the operator presents to prove
// they are still the same live operator who started the session.
// It is the local half of the F1 session story — token, heartbeat,
// lease, rotation — with no call to any Meta service and no
// credential stored in plaintext anywhere.
//
// A session carries three independent bounds, and ALL THREE must
// hold for the session to be live:
//
//   - TTL: an absolute expiry from start (`expires_at`). Nothing
//     extends it — not a heartbeat, not a rotation. A session ends
//     at most 24 hours after it starts.
//   - Lease: a liveness window (`lease_seconds`). The session stays
//     live only while the operator heartbeats at least once per
//     lease. A lapsed lease ends the session even inside its TTL —
//     a heartbeat cannot revive a dead lease, or the lease would be
//     a soft reminder instead of a liveness proof.
//   - Status: `active` or `revoked`. Revocation is final.
//
// The token is a random 48-hex string, returned ONCE by `start`
// and by `rotate`, and never written to disk, to the audit log, or
// to stdout again: the file holds only its SHA-256 hash (the round
// 93 approval-token precedent). A stolen store file yields hashes,
// not usable tokens — but a live token IS a bearer credential for
// the local lab: anyone holding it while the session is live can
// use it. That is the same trust model as the one-time approval
// tokens, and the same limit: the file's protection is the OS
// permission model (0600 file in a 0700 directory), not a
// hardware-backed secret store. If the user later wants a stronger
// token store, that is a new decision, not a gap in this round.
//
// Placement: `<state-dir>/operator-sessions.json`, the same state
// directory the kill-switch and audit log use. Same file discipline
// as the other state files: parent directory private (0700), file
// 0600, planted symlinks refused, load-modify-save under an
// exclusive lock file (`operator-sessions.json.lock`, `wx` create,
// 5 s timeout, 25 ms retry, 60 s stale reaper).
//
// Revoked entries are kept until their TTL expires so a later
// validation reports REVOKED (informative) instead of NOT_FOUND;
// expired entries are pruned lazily on every load that writes
// (start, list), and judged — not pruned — by the read paths
// (validate, heartbeat, rotate, status), so an expired token
// reports EXPIRED instead of NOT_FOUND.
//
// Kill-switch interaction (documented, not incidental): starting a
// session or rotating its token creates or refreshes access, so
// both are refused while the kill switch is armed
// (OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE). Revoking removes
// access, so it is allowed while armed — the fail-closed
// direction. Heartbeat, list, and status are liveness and
// inspection; they work while armed, and a heartbeat during an
// armed period keeps the lease alive but cannot make a fetch run:
// `sentinel fetch` checks the switch itself.
//
// What a session gates: `sentinel fetch --session-token <token>`
// (round 98) validates the session after the fetch context
// resolves and BEFORE the approval step, so a dead session never
// burns a one-time approval token. The session id is recorded in
// the audit event (metadata only). A fetch without
// --session-token behaves exactly as before — sessions are an
// opt-in layer, not a new requirement on existing commands.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { writeFileRefusingSymlink } = require('./safe-write');
const { ensurePrivateDir } = require('./state-permissions');
const { readJsonFileBounded } = require('./input-limits');
const { closeAndRemoveLock } = require('./lock-file');

const SCHEMA_VERSION = 1;
const STORE_FILE_NAME = 'operator-sessions.json';
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 25;
const STALE_LOCK_MS = 60_000;
const TOKEN_BYTES = 24;
const SESSION_ID_BYTES = 12;
const DEFAULT_TTL_MS = 8 * 60 * 60 * 1_000;
const DEFAULT_LEASE_MS = 30 * 60 * 1_000;
const MIN_TTL_MS = 60 * 1_000;
const MAX_TTL_MS = 24 * 60 * 60 * 1_000;
const MIN_LEASE_MS = 60 * 1_000;
const MAX_LEASE_MS = 2 * 60 * 60 * 1_000;

class OperatorSessionError extends Error {
  constructor(code, message) {
    // The code is part of the message (not only a property): the CLI
    // prints `error.message` to stderr, and operators grep for the code.
    super(`${code}: ${message}`);
    this.name = 'OperatorSessionError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new OperatorSessionError(code, message);
}

function storePathFor(stateDirectory) {
  if (typeof stateDirectory !== 'string' || stateDirectory.trim() === '') {
    fail('OPERATOR_SESSION_STORE_INVALID_PATH', 'stateDirectory must be a non-empty string.');
  }
  return path.join(stateDirectory, STORE_FILE_NAME);
}

function emptyStore() {
  return { schema_version: SCHEMA_VERSION, sessions: [] };
}

function requireString(value, field, maxLength = 200) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    fail('OPERATOR_SESSION_INVALID', `${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

function requireLabel(value) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string' || value.length > 200) {
    fail('OPERATOR_SESSION_INVALID', 'label must be a string no longer than 200 characters.');
  }
  return value;
}

function requireSessionId(value) {
  const id = requireString(value, 'sessionId', 64);
  if (!/^ses-[a-f0-9]{24}$/.test(id)) {
    fail('OPERATOR_SESSION_INVALID', 'sessionId must look like ses-<24 hex>.');
  }
  return id;
}

function requireDuration(value, field, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    fail('OPERATOR_SESSION_INVALID', `${field} must be an integer from ${min} to ${max} milliseconds.`);
  }
  return value;
}

function requireTimestamp(value, field) {
  if (!Number.isInteger(value)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', `Session entry has no valid ${field}.`);
  }
  return value;
}

function validateSessionEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry must be an object.');
  }
  if (typeof entry.token_hash !== 'string' || !/^[a-f0-9]{64}$/.test(entry.token_hash)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid token_hash.');
  }
  if (typeof entry.session_id !== 'string' || !/^ses-[a-f0-9]{24}$/.test(entry.session_id)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid session_id.');
  }
  const sessionId = entry.session_id;
  if (typeof entry.label !== 'string' || entry.label.length > 200) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid label.');
  }
  const createdAt = requireTimestamp(entry.created_at, 'created_at');
  const expiresAt = requireTimestamp(entry.expires_at, 'expires_at');
  const lastHeartbeatAt = requireTimestamp(entry.last_heartbeat_at, 'last_heartbeat_at');
  if (!Number.isInteger(entry.lease_seconds) || entry.lease_seconds < 1) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid lease_seconds.');
  }
  if (!Number.isInteger(entry.heartbeat_count) || entry.heartbeat_count < 0) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid heartbeat_count.');
  }
  if (!Number.isInteger(entry.rotation_count) || entry.rotation_count < 0) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid rotation_count.');
  }
  if (entry.status !== 'active' && entry.status !== 'revoked') {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid status.');
  }
  if (entry.revoked_at !== null && entry.revoked_at !== undefined && !Number.isInteger(entry.revoked_at)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid revoked_at.');
  }
  if (entry.rotated_at !== null && entry.rotated_at !== undefined && !Number.isInteger(entry.rotated_at)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', 'Session entry has no valid rotated_at.');
  }
  return Object.freeze({
    token_hash: entry.token_hash,
    session_id: sessionId,
    label: entry.label,
    created_at: createdAt,
    expires_at: expiresAt,
    lease_seconds: entry.lease_seconds,
    last_heartbeat_at: lastHeartbeatAt,
    heartbeat_count: entry.heartbeat_count,
    rotation_count: entry.rotation_count,
    status: entry.status,
    revoked_at: entry.revoked_at === undefined ? null : entry.revoked_at,
    rotated_at: entry.rotated_at === undefined ? null : entry.rotated_at,
  });
}

function validateStoreShape(parsed, storePath) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', `Session store is not a JSON object: ${storePath}`);
  }
  if (parsed.schema_version !== SCHEMA_VERSION) {
    fail('OPERATOR_SESSION_STORE_UNSUPPORTED_SCHEMA', `Session store schema_version ${JSON.stringify(parsed.schema_version)} is not supported (expected ${SCHEMA_VERSION}): ${storePath}`);
  }
  if (!Array.isArray(parsed.sessions)) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', `Session store has no sessions array: ${storePath}`);
  }
  return { schema_version: SCHEMA_VERSION, sessions: parsed.sessions };
}

async function readStoreJson(storePath) {
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!stat) return null;
  if (stat.isSymbolicLink()) {
    fail('OPERATOR_SESSION_STORE_SYMLINK_REFUSED', `Refusing to read a session store through a symbolic link: ${storePath}`);
  }
  if (!stat.isFile()) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', `Session store is not a regular file: ${storePath}`);
  }
  try {
    return await readJsonFileBounded(storePath);
  } catch (error) {
    fail('OPERATOR_SESSION_STORE_CORRUPT', `Session store cannot be read as JSON: ${error.message}`);
  }
}

// Loads and validates the store. By default prunes entries past
// their TTL — a dead session answers nothing anymore. Callers that
// must distinguish an expired session from a missing one
// (validate, heartbeat, rotate, status) pass `pruneExpired: false`
// and judge expiry themselves.
async function loadSessions(storePath, { now = Date.now(), pruneExpired = true } = {}) {
  const parsed = await readStoreJson(storePath);
  if (!parsed) return emptyStore();
  const shaped = validateStoreShape(parsed, storePath);
  const validated = shaped.sessions.map((entry) => validateSessionEntry(entry));
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const kept = pruneExpired ? validated.filter((entry) => entry.expires_at > now) : validated;
  return { schema_version: SCHEMA_VERSION, sessions: kept };
}

async function saveSessions(storePath, store) {
  await ensurePrivateDir(path.dirname(storePath));
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    fail('OPERATOR_SESSION_STORE_SYMLINK_REFUSED', `Refusing to write a session store through a symbolic link: ${storePath}`);
  }
  await writeFileRefusingSymlink(storePath, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function withStoreLock(storePath, operation) {
  // The lock file lives in the state directory, which may not exist
  // yet on first use: ensure it — private, 0700 — before opening
  // the lock, or the open fails ENOENT and the caller sees a bogus
  // STORE_LOCKED (the round-93 finding, same fix here).
  await ensurePrivateDir(path.dirname(storePath));
  const lockFile = `${storePath}.lock`;
  const started = Date.now();
  let lock = null;
  while (!lock) {
    try {
      lock = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() - started >= LOCK_TIMEOUT_MS) {
        fail('OPERATOR_SESSION_STORE_LOCKED', `Session store is locked by another operation: ${storePath}`);
      }
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs >= STALE_LOCK_MS) await fs.unlink(lockFile);
      } catch (statError) {
        if (statError.code !== 'ENOENT') throw statError;
      }
      await new Promise((resolve) => setTimeout(resolve, LOCK_RETRY_MS));
    }
  }
  try {
    return await operation();
  } finally {
    await closeAndRemoveLock(lock, lockFile);
  }
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Derives the operator-visible status of a stored entry at `now`.
// Stored status is only 'active' or 'revoked'; TTL and lease are
// derived, never stored as a status, so a lapsed lease can never be
// mistaken for a live session by a reader that forgets to check.
function deriveSessionStatus(entry, now) {
  if (entry.status === 'revoked') return 'revoked';
  if (now >= entry.expires_at) return 'expired';
  if (now - entry.last_heartbeat_at >= entry.lease_seconds * 1_000) return 'lease_lapsed';
  return 'active';
}

// The live check, in the order that names the most specific cause:
// revoked first (a revoked session is dead even inside its TTL),
// then TTL, then lease. Throws the OperatorSessionError.
function assertLive(entry, now) {
  const status = deriveSessionStatus(entry, now);
  if (status === 'revoked') fail('OPERATOR_SESSION_REVOKED', 'The operator session has been revoked.');
  if (status === 'expired') fail('OPERATOR_SESSION_EXPIRED', 'The operator session has expired.');
  if (status === 'lease_lapsed') fail('OPERATOR_SESSION_LEASE_LAPSED', 'The operator session lease has lapsed: no heartbeat within the lease window.');
  return status;
}

// Public metadata for one entry: everything the operator may see,
// never the token hash.
function publicSession(entry, now) {
  return Object.freeze({
    sessionId: entry.session_id,
    label: entry.label,
    status: deriveSessionStatus(entry, now),
    createdAt: entry.created_at,
    expiresAt: entry.expires_at,
    leaseSeconds: entry.lease_seconds,
    lastHeartbeatAt: entry.last_heartbeat_at,
    heartbeatCount: entry.heartbeat_count,
    rotationCount: entry.rotation_count,
    ttlRemainingMs: Math.max(0, entry.expires_at - now),
    leaseRemainingMs: Math.max(0, entry.lease_seconds * 1_000 - (now - entry.last_heartbeat_at)),
  });
}

// Starts a session. Returns the plaintext token ONCE — the caller
// prints it to the operator and never stores it; the file holds
// only the hash. `now` is injectable for tests. Refused while the
// kill switch is armed: starting a session creates access.
async function startOperatorSession({ storePath, label, ttlMs = DEFAULT_TTL_MS, leaseMs = DEFAULT_LEASE_MS, killSwitchArmed = false, now = Date.now() }) {
  if (killSwitchArmed) {
    fail('OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE', 'Cannot start an operator session while the kill switch is armed.');
  }
  const cleanLabel = requireLabel(label);
  const ttl = requireDuration(ttlMs, 'ttlMs', MIN_TTL_MS, MAX_TTL_MS);
  const lease = requireDuration(leaseMs, 'leaseMs', MIN_LEASE_MS, MAX_LEASE_MS);
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  const sessionId = `ses-${crypto.randomBytes(SESSION_ID_BYTES).toString('hex')}`;
  const entry = {
    token_hash: hashToken(token),
    session_id: sessionId,
    label: cleanLabel,
    created_at: now,
    expires_at: now + ttl,
    lease_seconds: Math.floor(lease / 1_000),
    last_heartbeat_at: now,
    heartbeat_count: 0,
    rotation_count: 0,
    status: 'active',
    revoked_at: null,
    rotated_at: null,
  };
  await withStoreLock(storePath, async () => {
    const store = await loadSessions(storePath, { now });
    store.sessions.push(entry);
    await saveSessions(storePath, store);
  });
  return Object.freeze({ token, sessionId, expiresAt: entry.expires_at, leaseSeconds: entry.lease_seconds });
}

// Proves liveness: refreshes the lease clock. A heartbeat on a
// revoked, expired, or lease-lapsed session is refused — a dead
// lease cannot be revived, or the lease would be a reminder, not
// a proof. Allowed while the kill switch is armed: liveness is
// inspection, and a heartbeat cannot make a fetch run while the
// switch is armed (fetch checks the switch itself).
async function heartbeatOperatorSession({ storePath, token, now = Date.now() }) {
  if (typeof token !== 'string' || token.trim() === '') {
    fail('OPERATOR_SESSION_NOT_FOUND', 'No session token was presented.');
  }
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const wantedHash = hashToken(token.trim());
  return withStoreLock(storePath, async () => {
    // Load WITHOUT pruning: an expired entry must report EXPIRED,
    // a lease-lapsed entry LEASE_LAPSED, not NOT_FOUND.
    const store = await loadSessions(storePath, { now, pruneExpired: false });
    const entry = store.sessions.find((candidate) => candidate.token_hash === wantedHash);
    if (!entry) {
      fail('OPERATOR_SESSION_NOT_FOUND', 'No operator session matches the presented token.');
    }
    assertLive(entry, now);
    const updated = { ...entry, last_heartbeat_at: now, heartbeat_count: entry.heartbeat_count + 1 };
    store.sessions = store.sessions
      .filter((candidate) => candidate.token_hash === wantedHash || candidate.expires_at > now)
      .map((candidate) => (candidate.token_hash === wantedHash ? updated : candidate));
    await saveSessions(storePath, store);
    return Object.freeze({
      sessionId: entry.session_id,
      expiresAt: entry.expires_at,
      leaseExpiresAt: now + entry.lease_seconds * 1_000,
      heartbeatCount: updated.heartbeat_count,
    });
  });
}

// Read-only liveness check for a presented token: no mutation, no
// refresh — validation proves the session is live, it does not
// extend it. This is what `sentinel fetch --session-token` calls
// before the approval step.
async function validateOperatorSession({ storePath, token, now = Date.now() }) {
  if (typeof token !== 'string' || token.trim() === '') {
    fail('OPERATOR_SESSION_NOT_FOUND', 'No session token was presented.');
  }
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const wantedHash = hashToken(token.trim());
  const store = await loadSessions(storePath, { now, pruneExpired: false });
  const entry = store.sessions.find((candidate) => candidate.token_hash === wantedHash);
  if (!entry) {
    fail('OPERATOR_SESSION_NOT_FOUND', 'No operator session matches the presented token.');
  }
  assertLive(entry, now);
  return Object.freeze({
    sessionId: entry.session_id,
    expiresAt: entry.expires_at,
    leaseExpiresAt: entry.last_heartbeat_at + entry.lease_seconds * 1_000,
    heartbeatCount: entry.heartbeat_count,
  });
}

// Revokes a session by id. Idempotent: revoking an already-revoked
// session succeeds with revoked: false (revocation is a safety
// action; refusing to repeat it adds nothing). Allowed while the
// kill switch is armed: revocation removes access, the fail-closed
// direction.
async function revokeOperatorSession({ storePath, sessionId, now = Date.now() }) {
  const id = requireSessionId(sessionId);
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  return withStoreLock(storePath, async () => {
    const store = await loadSessions(storePath, { now, pruneExpired: false });
    const entry = store.sessions.find((candidate) => candidate.session_id === id);
    if (!entry) {
      fail('OPERATOR_SESSION_NOT_FOUND', `No operator session with id ${id}.`);
    }
    if (entry.status === 'revoked') {
      return Object.freeze({ revoked: false, alreadyRevoked: true, sessionId: id });
    }
    const updated = { ...entry, status: 'revoked', revoked_at: now };
    store.sessions = store.sessions.map((candidate) => (candidate.session_id === id ? updated : candidate));
    await saveSessions(storePath, store);
    return Object.freeze({ revoked: true, alreadyRevoked: false, sessionId: id });
  });
}

// Rotates a session's token: the old token stops working
// immediately, a new one is returned ONCE. The TTL is unchanged —
// rotation refreshes the credential, it never extends the
// session. The heartbeat clock is refreshed (the operator is
// provably present at rotation). Refused while the kill switch is
// armed: rotation creates fresh access.
async function rotateOperatorSession({ storePath, sessionId, killSwitchArmed = false, now = Date.now() }) {
  if (killSwitchArmed) {
    fail('OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE', 'Cannot rotate an operator session while the kill switch is armed.');
  }
  const id = requireSessionId(sessionId);
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  return withStoreLock(storePath, async () => {
    const store = await loadSessions(storePath, { now, pruneExpired: false });
    const entry = store.sessions.find((candidate) => candidate.session_id === id);
    if (!entry) {
      fail('OPERATOR_SESSION_NOT_FOUND', `No operator session with id ${id}.`);
    }
    assertLive(entry, now);
    const updated = {
      ...entry,
      token_hash: hashToken(token),
      last_heartbeat_at: now,
      rotation_count: entry.rotation_count + 1,
      rotated_at: now,
    };
    store.sessions = store.sessions.map((candidate) => (candidate.session_id === id ? updated : candidate));
    await saveSessions(storePath, store);
    return Object.freeze({ token, sessionId: id, expiresAt: entry.expires_at, rotationCount: updated.rotation_count });
  });
}

// Lists live sessions (metadata only, never the token hash).
// Expired entries are pruned on load; revoked entries are kept
// until their TTL passes.
async function listOperatorSessions({ storePath, now = Date.now() }) {
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  return withStoreLock(storePath, async () => {
    // Load pruned and persist the prune in one locked step, so the
    // file does not grow stale entries and the returned list is the
    // stored list.
    const store = await loadSessions(storePath, { now });
    await saveSessions(storePath, store);
    return Object.freeze({
      store: storePath,
      count: store.sessions.length,
      sessions: store.sessions.map((entry) => publicSession(entry, now)),
    });
  });
}

// Status of one session by id (metadata only, never the token
// hash). Expired and lease-lapsed states are derived, not stored.
async function getOperatorSession({ storePath, sessionId, now = Date.now() }) {
  const id = requireSessionId(sessionId);
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const store = await loadSessions(storePath, { now, pruneExpired: false });
  const entry = store.sessions.find((candidate) => candidate.session_id === id);
  if (!entry) {
    fail('OPERATOR_SESSION_NOT_FOUND', `No operator session with id ${id}.`);
  }
  return publicSession(entry, now);
}

module.exports = {
  OperatorSessionError,
  SCHEMA_VERSION,
  STORE_FILE_NAME,
  DEFAULT_TTL_MS,
  DEFAULT_LEASE_MS,
  MIN_TTL_MS,
  MAX_TTL_MS,
  MIN_LEASE_MS,
  MAX_LEASE_MS,
  storePathFor,
  emptyStore,
  hashToken,
  deriveSessionStatus,
  publicSession,
  startOperatorSession,
  heartbeatOperatorSession,
  validateOperatorSession,
  revokeOperatorSession,
  rotateOperatorSession,
  listOperatorSessions,
  getOperatorSession,
  loadSessions,
};
