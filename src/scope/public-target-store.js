// Persistent public-target store (Phase 4, round 93).
//
// `sentinel target add` registers a PUBLIC target for the invocation
// path (`sentinel fetch`): one host, one path-prefix scope, one
// purpose, one authorization reference. This store is SEPARATE from
// the scope-target store (`<state-dir>/scope-targets.json`) on
// purpose: the scope schema cannot express a path-prefix allowlist —
// `allowed_urls` is validated at registration but never enforced in
// scope evaluation (TargetRegistry only enforces allowed domains,
// excluded domains, and excluded paths) — so a public target's
// `--scope /path` lives here, next to the host it restricts, and the
// fetch path enforces it before the adapter runs.
//
// Placement: `<state-dir>/public-targets.json`, the same state
// directory the kill-switch and audit log use (default
// `~/workspace/sentinel-bounty/state`). It is deliberately NOT inside
// the skill directory: a skill reinstall (fresh clone + rsync
// --delete) would wipe operator-managed files there, while the state
// directory survives reinstalls. The parent directory is created
// private (0700) and the file is written 0600 with planted symlinks
// refused, matching the round-34/45 state-file rules.
//
// Concurrency: add/remove run load-modify-save under an exclusive
// lock file (`public-targets.json.lock`, `wx` create, 5 s timeout,
// 25 ms retry, 60 s stale reaper — the same shape as the scope
// store's lock), so two concurrent CLI invocations cannot silently
// lose each other's target. A lock that cannot be acquired in time
// fails with PUBLIC_TARGET_STORE_LOCKED and writes nothing.
//
// The authorization reference is a reference string (for example a
// program ticket id), not a secret — but it is still never printed
// by `target list` (neither text nor JSON): the operator does not
// need to see it to manage targets, and the fetch command reads it
// from the store directly. The audit events for add/remove carry
// targetId, host, and scope only.
//
// Identity: target_id IS the host (lowercased, canonical). One
// registration per host, exact host only — no wildcards (a wildcard
// would widen the fetch surface beyond the single host the operator
// named). Adding the same host with identical fields is an
// idempotent no-op; adding it with DIFFERENT fields is refused with
// PUBLIC_TARGET_ALREADY_REGISTERED — the operator must `target
// remove` first, then re-add, so a changed scope or reference is an
// explicit, auditable act, never a silent overwrite.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { writeFileRefusingSymlink } = require('../policy/safe-write');
const { ensurePrivateDir } = require('../policy/state-permissions');
const { readJsonFileBounded } = require('../policy/input-limits');
const { closeAndRemoveLock } = require('../policy/lock-file');
const { normalizeTarget } = require('./target-registry');

const SCHEMA_VERSION = 1;
const STORE_FILE_NAME = 'public-targets.json';
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 25;
const STALE_LOCK_MS = 60_000;
const DEFAULT_PROGRAM_NAME = 'Public HTTP target';
const DEFAULT_REQUEST_BUDGET = 1_000;
const MAX_REQUEST_BUDGET = 10_000;
const MAX_STRING_LENGTH = 500;

class PublicTargetStoreError extends Error {
  constructor(code, message) {
    // The code is part of the message (not only a property): the CLI
    // prints `error.message` to stderr, and operators grep for the code.
    super(`${code}: ${message}`);
    this.name = 'PublicTargetStoreError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new PublicTargetStoreError(code, message);
}

function storePathFor(stateDirectory) {
  if (typeof stateDirectory !== 'string' || stateDirectory.trim() === '') {
    fail('PUBLIC_TARGET_STORE_INVALID_PATH', 'stateDirectory must be a non-empty string.');
  }
  return path.join(stateDirectory, STORE_FILE_NAME);
}

function emptyStore() {
  return { schema_version: SCHEMA_VERSION, targets: [] };
}

function requireBoundedString(value, field, maxLength = MAX_STRING_LENGTH) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    fail('PUBLIC_TARGET_INVALID', `${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

function normalizeScopePrefix(value) {
  const raw = requireBoundedString(value, 'scope');
  if (!raw.startsWith('/') || raw.includes('?') || raw.includes('#')) {
    fail('PUBLIC_TARGET_INVALID', 'scope must be an absolute path without query or fragment.');
  }
  return raw.length > 1 ? raw.replace(/\/+$/, '') : raw;
}

// The host is validated by the same normalizer the scope manager
// uses: build the target object the adapter will register and let
// normalizeTarget judge the hostname (canonical DNS hostname, no IP
// literal, no credentials). Wildcards are refused here even though
// the normalizer accepts a leading `*.`: a public-target
// registration names exactly one host.
function normalizeHost(value) {
  const host = requireBoundedString(value, 'host').toLowerCase().replace(/\.$/, '');
  if (host.startsWith('*.')) {
    fail('PUBLIC_TARGET_INVALID', 'host must be a single hostname, not a wildcard.');
  }
  try {
    normalizeTarget({
      target_id: host,
      program_name: DEFAULT_PROGRAM_NAME,
      authorization_reference: 'placeholder-reference',
      allowed_domains: [host],
      allowed_methods: ['http_probing'],
    });
  } catch (error) {
    fail('PUBLIC_TARGET_INVALID', `host is not a canonical DNS hostname: ${error.message}`);
  }
  return host;
}

function normalizeRequestBudget(value) {
  if (value === undefined) return DEFAULT_REQUEST_BUDGET;
  if (!Number.isInteger(value) || value < 1 || value > MAX_REQUEST_BUDGET) {
    fail('PUBLIC_TARGET_INVALID', `request_budget must be an integer from 1 to ${MAX_REQUEST_BUDGET}.`);
  }
  return value;
}

function validatePublicTargetEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    fail('PUBLIC_TARGET_INVALID', 'target entry must be an object.');
  }
  const host = normalizeHost(entry.host);
  // target_id IS the host: callers may omit it (it is derived), but
  // a supplied value must equal the host — the store invariant is
  // one registration per host, and a divergent id would split it.
  const targetId = entry.target_id === undefined ? host : entry.target_id.trim();
  if (targetId !== host) {
    fail('PUBLIC_TARGET_INVALID', 'target_id must equal the host.');
  }
  const scope = normalizeScopePrefix(entry.scope);
  const purpose = requireBoundedString(entry.purpose, 'purpose');
  const authorizationReference = requireBoundedString(entry.authorization_reference, 'authorization_reference');
  const programName = entry.program_name === undefined
    ? DEFAULT_PROGRAM_NAME
    : requireBoundedString(entry.program_name, 'program_name', 200);
  const requestBudget = normalizeRequestBudget(entry.request_budget);
  const registeredAt = entry.registered_at === undefined
    ? null
    : requireBoundedString(entry.registered_at, 'registered_at', 100);
  return Object.freeze({
    target_id: targetId,
    host,
    scope,
    purpose,
    authorization_reference: authorizationReference,
    program_name: programName,
    request_budget: requestBudget,
    registered_at: registeredAt,
  });
}

function validateStoreShape(parsed, storePath) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail('PUBLIC_TARGET_STORE_CORRUPT', `Public-target store is not a JSON object: ${storePath}`);
  }
  if (parsed.schema_version !== SCHEMA_VERSION) {
    fail('PUBLIC_TARGET_STORE_UNSUPPORTED_SCHEMA', `Public-target store schema_version ${JSON.stringify(parsed.schema_version)} is not supported (expected ${SCHEMA_VERSION}): ${storePath}`);
  }
  if (!Array.isArray(parsed.targets)) {
    fail('PUBLIC_TARGET_STORE_CORRUPT', `Public-target store has no targets array: ${storePath}`);
  }
  return { schema_version: SCHEMA_VERSION, targets: parsed.targets };
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
    fail('PUBLIC_TARGET_STORE_SYMLINK_REFUSED', `Refusing to read a public-target store through a symbolic link: ${storePath}`);
  }
  if (!stat.isFile()) {
    fail('PUBLIC_TARGET_STORE_CORRUPT', `Public-target store is not a regular file: ${storePath}`);
  }
  try {
    return await readJsonFileBounded(storePath);
  } catch (error) {
    fail('PUBLIC_TARGET_STORE_CORRUPT', `Public-target store cannot be read as JSON: ${error.message}`);
  }
}

async function loadPublicTargets(storePath) {
  const parsed = await readStoreJson(storePath);
  if (!parsed) return emptyStore();
  const shaped = validateStoreShape(parsed, storePath);
  shaped.targets.forEach((entry) => validatePublicTargetEntry(entry));
  return shaped;
}

async function savePublicTargets(storePath, store) {
  await ensurePrivateDir(path.dirname(storePath));
  let stat = null;
  try {
    stat = await fs.lstat(storePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    fail('PUBLIC_TARGET_STORE_SYMLINK_REFUSED', `Refusing to write a public-target store through a symbolic link: ${storePath}`);
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
        fail('PUBLIC_TARGET_STORE_LOCKED', `Public-target store is locked by another operation: ${storePath}`);
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

// Adds a public-target entry to the store. The entry is validated
// (host, scope, purpose, reference); an invalid entry fails with
// PUBLIC_TARGET_INVALID and nothing is written. Adding a host that
// is already present with IDENTICAL fields is an idempotent no-op
// (exit path reports `added: false, alreadyPresent: true`, the file
// is not rewritten); adding it with different fields is refused
// with PUBLIC_TARGET_ALREADY_REGISTERED — remove first, then re-add.
async function addPublicTarget(storePath, entry) {
  const normalized = validatePublicTargetEntry(entry);
  const stamped = Object.freeze({
    ...normalized,
    registered_at: normalized.registered_at || new Date().toISOString(),
  });
  return withStoreLock(storePath, async () => {
    const store = await loadPublicTargets(storePath);
    const existing = store.targets.find((candidate) => {
      try {
        return validatePublicTargetEntry(candidate).target_id === stamped.target_id;
      } catch {
        return false;
      }
    });
    if (existing) {
      const same = ['scope', 'purpose', 'authorization_reference', 'program_name', 'request_budget']
        .every((field) => existing[field] === stamped[field]);
      if (same) return Object.freeze({ added: false, alreadyPresent: true, targetId: stamped.target_id });
      fail('PUBLIC_TARGET_ALREADY_REGISTERED', `A public target for host "${stamped.target_id}" is already registered with different fields; remove it first, then re-add.`);
    }
    store.targets.push(stamped);
    await savePublicTargets(storePath, store);
    return Object.freeze({ added: true, targetId: stamped.target_id });
  });
}

// Removes a public target by host. A host that is not in the store
// fails with PUBLIC_TARGET_NOT_FOUND and nothing is written.
async function removePublicTarget(storePath, host) {
  const wanted = normalizeHost(host);
  return withStoreLock(storePath, async () => {
    const store = await loadPublicTargets(storePath);
    const index = store.targets.findIndex((entry) => {
      try {
        return validatePublicTargetEntry(entry).target_id === wanted;
      } catch {
        return false;
      }
    });
    if (index === -1) {
      fail('PUBLIC_TARGET_NOT_FOUND', `No public target for host "${wanted}" in ${storePath}`);
    }
    store.targets.splice(index, 1);
    await savePublicTargets(storePath, store);
    return Object.freeze({ removed: true, targetId: wanted });
  });
}

// Resolves one public target from the store by host. Returns the
// validated entry, or null when it is not present. Load failures
// (corrupt store, symlink, unsupported schema) still throw.
async function findPublicTarget(storePath, host) {
  const wanted = normalizeHost(host);
  const store = await loadPublicTargets(storePath);
  const found = store.targets.find((entry) => {
    try {
      return validatePublicTargetEntry(entry).target_id === wanted;
    } catch {
      return false;
    }
  });
  return found ? validatePublicTargetEntry(found) : null;
}

// Lists every public target in the store, sorted by target_id. The
// authorization reference is deliberately NOT included: the operator
// manages targets without seeing it, and the fetch command reads it
// from the store directly.
async function listPublicTargets(storePath) {
  const store = await loadPublicTargets(storePath);
  const entries = store.targets.map((entry) => {
    const normalized = validatePublicTargetEntry(entry);
    return Object.freeze({
      targetId: normalized.target_id,
      host: normalized.host,
      scope: normalized.scope,
      purpose: normalized.purpose,
      programName: normalized.program_name,
      requestBudget: normalized.request_budget,
      registeredAt: normalized.registered_at,
    });
  });
  entries.sort((a, b) => (a.targetId < b.targetId ? -1 : a.targetId > b.targetId ? 1 : 0));
  return Object.freeze({ store: storePath, count: entries.length, targets: Object.freeze(entries) });
}

// Builds the TargetRegistry target object for a stored public-target
// entry: the adapter's gate runs on this object (allowed domain =
// the host, the only allowed method is http_probing).
function buildTargetForAdapter(entry) {
  const normalized = validatePublicTargetEntry(entry);
  return {
    target_id: normalized.target_id,
    program_name: normalized.program_name,
    authorization_reference: normalized.authorization_reference,
    allowed_domains: [normalized.host],
    allowed_methods: ['http_probing'],
    request_budget: normalized.request_budget,
  };
}

// Does a normalized request path fall inside a scope prefix? The
// scope `/` matches every path; any other scope matches itself and
// its children (`/api` matches `/api` and `/api/users`, never
// `/apix` or `/apiary`). The caller passes the path the scope rule
// already normalized (decode + posix.normalize), so `//` and `/../`
// tricks cannot escape the prefix.
function scopePrefixMatches(scope, requestPath) {
  const prefix = normalizeScopePrefix(scope);
  if (prefix === '/') return true;
  return requestPath === prefix || requestPath.startsWith(`${prefix}/`);
}

module.exports = {
  PublicTargetStoreError,
  SCHEMA_VERSION,
  STORE_FILE_NAME,
  DEFAULT_PROGRAM_NAME,
  DEFAULT_REQUEST_BUDGET,
  storePathFor,
  emptyStore,
  validatePublicTargetEntry,
  loadPublicTargets,
  savePublicTargets,
  addPublicTarget,
  removePublicTarget,
  findPublicTarget,
  listPublicTargets,
  buildTargetForAdapter,
  scopePrefixMatches,
  normalizeScopePrefix,
  normalizeHost,
};
