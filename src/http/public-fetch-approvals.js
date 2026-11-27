// One-time approval tokens for `sentinel fetch` (Phase 4, round 93).
//
// The in-process ApprovalGate is memory-only: an approval minted in
// one CLI invocation does not exist in the next, so a cross-process
// approval needs a durable carrier. This store is that carrier —
// nothing more. A token is a random 48-hex string, minted by
// `fetch --mint-approval` after the operator has seen the preview,
// and spent by `fetch --approve-token <token>`. It is:
//
//   - bound to ONE exact URL, ONE target, ONE scope fingerprint
//     (a token minted for another URL is a binding mismatch, never
//     silently accepted);
//   - single-use: the first presentation consumes it, even when the
//     fetch then fails (a DNS failure burns the approval, exactly
//     like the in-process gate — the round-90 judgment call);
//   - short-lived: 5 minutes from minting, then expired;
//   - stored as a SHA-256 hash only: the plaintext token is returned
//     ONCE by the mint call and never written to disk, to the audit
//     log, or to stdout again. A stolen store file yields hashes,
//     not usable tokens.
//
// Placement: `<state-dir>/public-fetch-approvals.json`, the same
// state directory the kill-switch and audit log use. Same file
// discipline as the other state files: parent directory private
// (0700), file 0600, planted symlinks refused, load-modify-save
// under an exclusive lock file (`public-fetch-approvals.json.lock`,
// `wx` create, 5 s timeout, 25 ms retry, 60 s stale reaper).
//
// Consumed entries are kept until they expire so a replay reports
// PUBLIC_FETCH_TOKEN_CONSUMED (informative) instead of NOT_FOUND;
// expired entries are pruned lazily on every load. The store holds
// no response content and no authorization reference — only the
// binding a token was minted for.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { writeFileRefusingSymlink } = require('../policy/safe-write');
const { ensurePrivateDir } = require('../policy/state-permissions');
const { readJsonFileBounded } = require('../policy/input-limits');
const { closeAndRemoveLock } = require('../policy/lock-file');

const SCHEMA_VERSION = 1;
const STORE_FILE_NAME = 'public-fetch-approvals.json';
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 25;
const STALE_LOCK_MS = 60_000;
const TOKEN_TTL_MS = 5 * 60 * 1_000;
const TOKEN_BYTES = 24;

class PublicFetchApprovalError extends Error {
  constructor(code, message) {
    // The code is part of the message (not only a property): the CLI
    // prints `error.message` to stderr, and operators grep for the code.
    super(`${code}: ${message}`);
    this.name = 'PublicFetchApprovalError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new PublicFetchApprovalError(code, message);
}

function storePathFor(stateDirectory) {
  if (typeof stateDirectory !== 'string' || stateDirectory.trim() === '') {
    fail('PUBLIC_FETCH_APPROVAL_STORE_INVALID_PATH', 'stateDirectory must be a non-empty string.');
  }
  return path.join(stateDirectory, STORE_FILE_NAME);
}

function emptyStore() {
  return { schema_version: SCHEMA_VERSION, approvals: [] };
}

function requireString(value, field, maxLength = 2_000) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    fail('PUBLIC_FETCH_APPROVAL_INVALID', `${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

function requireFingerprint(value) {
  const fingerprint = requireString(value, 'scopeFingerprint', 64).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
    fail('PUBLIC_FETCH_APPROVAL_INVALID', 'scopeFingerprint must be a SHA-256 hexadecimal digest.');
  }
  return fingerprint;
}

function validateApprovalEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', 'Approval entry must be an object.');
  }
  if (typeof entry.token_hash !== 'string' || !/^[a-f0-9]{64}$/.test(entry.token_hash)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', 'Approval entry has no valid token_hash.');
  }
  const targetId = requireString(entry.target_id, 'target_id', 200);
  const url = requireString(entry.url, 'url');
  const scopeFingerprint = requireFingerprint(entry.scope_fingerprint);
  if (!Number.isInteger(entry.created_at) || !Number.isInteger(entry.expires_at)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', 'Approval entry has no valid timestamps.');
  }
  if (entry.consumed_at !== null && entry.consumed_at !== undefined && !Number.isInteger(entry.consumed_at)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', 'Approval entry has no valid consumed_at.');
  }
  return Object.freeze({
    token_hash: entry.token_hash,
    target_id: targetId,
    url,
    scope_fingerprint: scopeFingerprint,
    estimated_requests: 1,
    created_at: entry.created_at,
    expires_at: entry.expires_at,
    consumed_at: entry.consumed_at === undefined ? null : entry.consumed_at,
  });
}

function validateStoreShape(parsed, storePath) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', `Approval store is not a JSON object: ${storePath}`);
  }
  if (parsed.schema_version !== SCHEMA_VERSION) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_UNSUPPORTED_SCHEMA', `Approval store schema_version ${JSON.stringify(parsed.schema_version)} is not supported (expected ${SCHEMA_VERSION}): ${storePath}`);
  }
  if (!Array.isArray(parsed.approvals)) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', `Approval store has no approvals array: ${storePath}`);
  }
  return { schema_version: SCHEMA_VERSION, approvals: parsed.approvals };
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
    fail('PUBLIC_FETCH_APPROVAL_STORE_SYMLINK_REFUSED', `Refusing to read an approval store through a symbolic link: ${storePath}`);
  }
  if (!stat.isFile()) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', `Approval store is not a regular file: ${storePath}`);
  }
  try {
    return await readJsonFileBounded(storePath);
  } catch (error) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_CORRUPT', `Approval store cannot be read as JSON: ${error.message}`);
  }
}

// Loads and validates the store. By default prunes expired entries
// (consumed or not — an expired entry answers nothing anymore).
// Consumed but unexpired entries are KEPT, so a replay reports
// CONSUMED instead of NOT_FOUND. Callers that must distinguish an
// expired token from a missing one (consume) pass
// `pruneExpired: false` and judge expiry themselves.
async function loadApprovals(storePath, { now = Date.now(), pruneExpired = true } = {}) {
  const parsed = await readStoreJson(storePath);
  if (!parsed) return emptyStore();
  const shaped = validateStoreShape(parsed, storePath);
  const validated = shaped.approvals.map((entry) => validateApprovalEntry(entry));
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const kept = pruneExpired ? validated.filter((entry) => entry.expires_at > now) : validated;
  return { schema_version: SCHEMA_VERSION, approvals: kept };
}

async function saveApprovals(storePath, store) {
  await ensurePrivateDir(path.dirname(storePath));
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    fail('PUBLIC_FETCH_APPROVAL_STORE_SYMLINK_REFUSED', `Refusing to write an approval store through a symbolic link: ${storePath}`);
  }
  await writeFileRefusingSymlink(storePath, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function withStoreLock(storePath, operation) {
  // The lock file lives in the state directory, which may not exist
  // yet on first use (a direct store call, without the CLI's
  // kill-switch guard creating it first): ensure it — private,
  // 0700 — before opening the lock, or the open fails ENOENT and
  // the caller sees a bogus STORE_LOCKED.
  await ensurePrivateDir(path.dirname(storePath));
  const lockFile = `${storePath}.lock`;
  const started = Date.now();
  let lock = null;
  while (!lock) {
    try {
      lock = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() - started >= LOCK_TIMEOUT_MS) {
        fail('PUBLIC_FETCH_APPROVAL_STORE_LOCKED', `Approval store is locked by another operation: ${storePath}`);
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

// Mints a one-time approval token bound to one exact URL, target,
// and scope fingerprint. Returns the plaintext token ONCE — the
// caller prints it to the operator and never stores it; the file
// holds only the hash. `now` is injectable for tests.
async function mintPublicFetchApproval({ storePath, targetId, url, scopeFingerprint, now = Date.now() }) {
  const binding = {
    target_id: requireString(targetId, 'targetId', 200),
    url: requireString(url, 'url'),
    scope_fingerprint: requireFingerprint(scopeFingerprint),
  };
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  const entry = {
    token_hash: hashToken(token),
    target_id: binding.target_id,
    url: binding.url,
    scope_fingerprint: binding.scope_fingerprint,
    estimated_requests: 1,
    created_at: now,
    expires_at: now + TOKEN_TTL_MS,
    consumed_at: null,
  };
  await withStoreLock(storePath, async () => {
    const store = await loadApprovals(storePath, { now });
    store.approvals.push(entry);
    await saveApprovals(storePath, store);
  });
  return Object.freeze({ token, targetId: binding.target_id, url: binding.url, expiresAt: entry.expires_at });
}

// Consumes a presented token: finds the entry by hash, then checks
// binding, expiry, and single-use — in that order, so a token for
// another URL reports a binding mismatch, not a generic failure.
// The entry is marked consumed and the store rewritten BEFORE the
// caller runs the fetch: a crash after consume cannot revive the
// token, and a fetch that then fails (DNS included) still burns it.
async function consumePublicFetchApproval({ storePath, token, targetId, url, scopeFingerprint, now = Date.now() }) {
  if (typeof token !== 'string' || token.trim() === '') {
    fail('PUBLIC_FETCH_TOKEN_NOT_FOUND', 'No approval token was presented.');
  }
  const presented = token.trim();
  const binding = {
    target_id: requireString(targetId, 'targetId', 200),
    url: requireString(url, 'url'),
    scope_fingerprint: requireFingerprint(scopeFingerprint),
  };
  if (!Number.isInteger(now)) throw new TypeError('now must be an integer millisecond timestamp.');
  const wantedHash = hashToken(presented);
  return withStoreLock(storePath, async () => {
    // Load WITHOUT pruning: an expired entry must report EXPIRED,
    // not NOT_FOUND, and a consumed entry must report CONSUMED.
    const store = await loadApprovals(storePath, { now, pruneExpired: false });
    const entry = store.approvals.find((candidate) => candidate.token_hash === wantedHash);
    if (!entry) {
      fail('PUBLIC_FETCH_TOKEN_NOT_FOUND', 'No approval token matches the presented token.');
    }
    if (entry.target_id !== binding.target_id || entry.url !== binding.url || entry.scope_fingerprint !== binding.scope_fingerprint) {
      fail('PUBLIC_FETCH_TOKEN_BINDING_MISMATCH', 'The approval token was minted for a different target, URL, or scope.');
    }
    if (now >= entry.expires_at) {
      fail('PUBLIC_FETCH_TOKEN_EXPIRED', 'The approval token has expired.');
    }
    if (entry.consumed_at !== null) {
      fail('PUBLIC_FETCH_TOKEN_CONSUMED', 'The approval token has already been used.');
    }
    const consumed = { ...entry, consumed_at: now };
    // Rewrite with the entry consumed — and prune the other expired
    // entries at the same time, so the store never grows stale.
    store.approvals = store.approvals
      .filter((candidate) => candidate.token_hash === wantedHash || candidate.expires_at > now)
      .map((candidate) => (candidate.token_hash === wantedHash ? consumed : candidate));
    await saveApprovals(storePath, store);
    return Object.freeze({ consumed: true, targetId: entry.target_id, url: entry.url, expiresAt: entry.expires_at });
  });
}

module.exports = {
  PublicFetchApprovalError,
  SCHEMA_VERSION,
  STORE_FILE_NAME,
  TOKEN_TTL_MS,
  storePathFor,
  emptyStore,
  hashToken,
  mintPublicFetchApproval,
  consumePublicFetchApproval,
  loadApprovals,
};
