// Persistent scope-target store (Phase 3, round 53).
//
// Baseline (verified 2026-11-26): there is NO persistent registry file
// and NO CLI management. `check-scope --target <file>` registers exactly
// one target per invocation from the file the operator passes; nothing
// on disk remembers it afterwards, and `sentinel scope add` prints the
// usage text with exit 1. docs/scope-explain-v1.md says the same.
//
// This module is the store that closes that gap: a versioned JSON file
// holding the operator's scope targets, one entry per registered target
// (the raw target object exactly as the operator supplied it — the
// canonical target shape is the one `normalizeTarget` validates, so the
// stored object is re-validated on every load and a damaged entry fails
// loudly instead of silently changing scope).
//
// Placement: `<state-dir>/scope-targets.json`, the same state directory
// the kill-switch and audit log use (default
// `~/workspace/sentinel-bounty/state`). It is deliberately NOT inside
// the skill directory: a skill reinstall (fresh clone + rsync --delete)
// would wipe operator-managed files there, while the state directory
// survives reinstalls. The parent directory is created private (0700)
// and the file is written 0600 with planted symlinks refused, matching
// the round-34/45 state-file rules.
//
// Concurrency: add/remove run load-modify-save under an exclusive lock
// file (`scope-targets.json.lock`, `wx` create, 5 s timeout, 25 ms
// retry, 60 s stale reaper — the same shape as the audit log's lock),
// so two concurrent CLI invocations cannot silently lose each other's
// target. A lock that cannot be acquired in time fails with
// SCOPE_STORE_LOCKED and writes nothing.
//
// The store never changes scope decisions: it only remembers targets.
// `check-scope --store <path> --target-id <id>` resolves a target from
// the store and evaluates it with the unchanged `evaluate()` logic.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { writeFileRefusingSymlink } = require('../policy/safe-write');
const { ensurePrivateDir } = require('../policy/state-permissions');
const { readJsonFileBounded } = require('../policy/input-limits');
const { closeAndRemoveLock } = require('../policy/lock-file');
const { normalizeTarget } = require('./target-registry');

const SCHEMA_VERSION = 1;
const STORE_FILE_NAME = 'scope-targets.json';
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 25;
const STALE_LOCK_MS = 60_000;

class ScopeStoreError extends Error {
  constructor(code, message) {
    // The code is part of the message (not only a property): the CLI
    // prints `error.message` to stderr, and operators grep for the code.
    super(`${code}: ${message}`);
    this.name = 'ScopeStoreError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new ScopeStoreError(code, message);
}

function storePathFor(stateDirectory) {
  if (typeof stateDirectory !== 'string' || stateDirectory.trim() === '') {
    fail('SCOPE_STORE_INVALID_PATH', 'stateDirectory must be a non-empty string.');
  }
  return path.join(stateDirectory, STORE_FILE_NAME);
}

function emptyStore() {
  return { schema_version: SCHEMA_VERSION, targets: [] };
}

function validateTargetEntry(entry, index) {
  try {
    normalizeTarget(entry);
  } catch (error) {
    fail('SCOPE_TARGET_INVALID', `targets[${index}] is not a valid target: ${error.message}`);
  }
}

function validateStoreShape(parsed, storePath) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail('SCOPE_STORE_CORRUPT', `Scope store is not a JSON object: ${storePath}`);
  }
  if (parsed.schema_version !== SCHEMA_VERSION) {
    fail('SCOPE_STORE_UNSUPPORTED_SCHEMA', `Scope store schema_version ${JSON.stringify(parsed.schema_version)} is not supported (expected ${SCHEMA_VERSION}): ${storePath}`);
  }
  if (!Array.isArray(parsed.targets)) {
    fail('SCOPE_STORE_CORRUPT', `Scope store has no targets array: ${storePath}`);
  }
  parsed.targets.forEach((entry, index) => validateTargetEntry(entry, index));
  return { schema_version: SCHEMA_VERSION, targets: parsed.targets };
}

async function loadScopeTargets(storePath) {
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!stat) return emptyStore();
  if (stat.isSymbolicLink()) {
    fail('SCOPE_STORE_SYMLINK_REFUSED', `Refusing to read a scope store through a symbolic link: ${storePath}`);
  }
  if (!stat.isFile()) {
    fail('SCOPE_STORE_CORRUPT', `Scope store is not a regular file: ${storePath}`);
  }
  let parsed;
  try {
    parsed = await readJsonFileBounded(storePath);
  } catch (error) {
    fail('SCOPE_STORE_CORRUPT', `Scope store cannot be read as JSON: ${error.message}`);
  }
  return validateStoreShape(parsed, storePath);
}

async function saveScopeTargets(storePath, store) {
  await ensurePrivateDir(path.dirname(storePath));
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    fail('SCOPE_STORE_SYMLINK_REFUSED', `Refusing to write a scope store through a symbolic link: ${storePath}`);
  }
  await writeFileRefusingSymlink(storePath, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function withStoreLock(storePath, operation) {
  const lockFile = `${storePath}.lock`;
  const started = Date.now();
  let lock = null;
  while (!lock) {
    try {
      lock = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() - started >= LOCK_TIMEOUT_MS) {
        fail('SCOPE_STORE_LOCKED', `Scope store is locked by another operation: ${storePath}`);
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

// Adds a target object to the store. The target is validated with the
// same `normalizeTarget` the scope manager uses; an invalid target fails
// with SCOPE_TARGET_INVALID and nothing is written. Adding a target_id
// that is already present is an idempotent no-op: exit path reports
// `added: false, alreadyPresent: true`, the file is not rewritten and
// no audit record is written for it.
async function addScopeTarget(storePath, targetObject) {
  let normalized;
  try {
    normalized = normalizeTarget(targetObject);
  } catch (error) {
    fail('SCOPE_TARGET_INVALID', `Target is not valid: ${error.message}`);
  }
  return withStoreLock(storePath, async () => {
    const store = await loadScopeTargets(storePath);
    if (store.targets.some((entry) => {
      try {
        return normalizeTarget(entry).targetId === normalized.targetId;
      } catch {
        return false;
      }
    })) {
      return Object.freeze({ added: false, alreadyPresent: true, targetId: normalized.targetId });
    }
    store.targets.push(targetObject);
    await saveScopeTargets(storePath, store);
    return Object.freeze({ added: true, targetId: normalized.targetId });
  });
}

// Removes a target by target_id. A target_id that is not in the store
// fails with SCOPE_TARGET_NOT_FOUND and nothing is written.
async function removeScopeTarget(storePath, targetId) {
  if (typeof targetId !== 'string' || targetId.trim() === '') {
    fail('SCOPE_TARGET_INVALID', 'targetId must be a non-empty string.');
  }
  const wanted = targetId.trim();
  return withStoreLock(storePath, async () => {
    const store = await loadScopeTargets(storePath);
    const index = store.targets.findIndex((entry) => {
      try {
        return normalizeTarget(entry).targetId === wanted;
      } catch {
        return false;
      }
    });
    if (index === -1) {
      fail('SCOPE_TARGET_NOT_FOUND', `No scope target with target_id "${wanted}" in ${storePath}`);
    }
    store.targets.splice(index, 1);
    await saveScopeTargets(storePath, store);
    return Object.freeze({ removed: true, targetId: wanted });
  });
}

// Resolves one target from the store by target_id. Returns the raw
// target object, or null when it is not present. Load failures (corrupt
// store, symlink, unsupported schema) still throw.
async function findScopeTarget(storePath, targetId) {
  if (typeof targetId !== 'string' || targetId.trim() === '') {
    fail('SCOPE_TARGET_INVALID', 'targetId must be a non-empty string.');
  }
  const wanted = targetId.trim();
  const store = await loadScopeTargets(storePath);
  const found = store.targets.find((entry) => {
    try {
      return normalizeTarget(entry).targetId === wanted;
    } catch {
      return false;
    }
  });
  return found || null;
}

module.exports = {
  ScopeStoreError,
  SCHEMA_VERSION,
  STORE_FILE_NAME,
  storePathFor,
  emptyStore,
  loadScopeTargets,
  saveScopeTargets,
  addScopeTarget,
  removeScopeTarget,
  findScopeTarget,
};
