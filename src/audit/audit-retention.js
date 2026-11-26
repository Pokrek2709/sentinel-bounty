// Audit-log retention policy (Phase 8, round 62).
//
// Background: round 37 proved audit-log rotation with bounded
// archives (retentionCount, default 3), and round 43 added the SHA-256
// hash chain — honestly documenting that deleting a leading prefix is
// NOT detected, because rotation retention legitimately drops the
// oldest records. Until now there was no operator-configurable
// retention: archives accumulated to the constructor's fixed bound and
// the oldest archive fell off silently at every rotation.
//
// This module is the policy that closes that gap: a versioned JSON
// file holding the operator's retention limits, one entry point for
// both the CLI and the audit log's rotation path.
//
// Placement: `<state-dir>/audit-retention.json`, the same state
// directory the kill-switch, audit log and scope store use (default
// `~/workspace/sentinel-bounty/state`). It is deliberately NOT inside
// the skill directory: a skill reinstall (fresh clone + rsync --delete)
// would wipe operator-managed files there, while the state directory
// survives reinstalls. The parent directory is created private (0700)
// and the file is written 0600 with planted symlinks refused, matching
// the round-34/45 state-file rules.
//
// Shape: `{ schema_version: 1, max_archives?: <n>, max_records?: <n> }`.
// Both limits are optional; absent means "no limit from this policy"
// (current behavior, no pruning). Values must be integers >= 1; zero,
// negative, non-integer and non-numeric values are invalid, as are
// unknown keys and a schema_version other than 1. An invalid file
// fails loudly (AUDIT_RETENTION_INVALID) instead of silently changing
// retention — except on the audit log's rotation path, which reads the
// policy leniently (see readRetentionPolicyLenient): a corrupt policy
// must never block audit appends (round 43's rule that the writer
// never refuses to append), so rotation skips pruning for that one
// rotation and the operator discovers the damage via
// `sentinel audit retention --show`, which reads strictly.
//
// Enforcement (in AuditLog.append, rotation branch only): when
// rotation runs and a policy is set, the oldest archives/records are
// pruned down to the limits, and the prune is RECORDED, not silent —
// an AUDIT_LOG_PRUNED anchor record is appended before the prune,
// chained from the current tail, stating what left the retained set
// (count, first/last timestamps, hash of the last pruned record).
// Pruning is lazy: it is evaluated when rotation runs; setting a
// policy does not prune retroactively until the next rotation. See
// docs/audit-retention-v1.md for the full semantics, including what
// `audit verify` and `audit export` report for a pruned log.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { writeFileRefusingSymlink } = require('../policy/safe-write');
const { ensurePrivateDir } = require('../policy/state-permissions');
const { readJsonFileBounded } = require('../policy/input-limits');

const SCHEMA_VERSION = 1;
const RETENTION_FILE_NAME = 'audit-retention.json';

class AuditRetentionError extends Error {
  constructor(code, message) {
    // The code is part of the message (not only a property): the CLI
    // prints `error.message` to stderr, and operators grep for the code.
    super(`${code}: ${message}`);
    this.name = 'AuditRetentionError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditRetentionError(code, message);
}

function retentionPathFor(stateDirectory) {
  if (typeof stateDirectory !== 'string' || stateDirectory.trim() === '') {
    fail('AUDIT_RETENTION_INVALID_PATH', 'stateDirectory must be a non-empty string.');
  }
  return path.join(stateDirectory, RETENTION_FILE_NAME);
}

// Pure validation. Returns a frozen normalized policy
// `{ schema_version: 1, max_archives: <n|null>, max_records: <n|null> }`
// (absent limits normalize to null, so callers never have to probe for
// undefined). Throws AUDIT_RETENTION_INVALID on any shape violation.
function validateRetentionPolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    fail('AUDIT_RETENTION_INVALID', 'Retention policy must be a JSON object.');
  }
  if (policy.schema_version !== SCHEMA_VERSION) {
    fail('AUDIT_RETENTION_INVALID', `Retention policy schema_version ${JSON.stringify(policy.schema_version)} is not supported (expected ${SCHEMA_VERSION}).`);
  }
  for (const key of Object.keys(policy)) {
    if (!['schema_version', 'max_archives', 'max_records'].includes(key)) {
      fail('AUDIT_RETENTION_INVALID', `Retention policy has an unknown key: ${key}`);
    }
  }
  const normalized = { schema_version: SCHEMA_VERSION, max_archives: null, max_records: null };
  for (const key of ['max_archives', 'max_records']) {
    if (policy[key] === undefined || policy[key] === null) continue;
    if (!Number.isInteger(policy[key]) || policy[key] < 1) {
      fail('AUDIT_RETENTION_INVALID', `${key} must be an integer >= 1, got ${JSON.stringify(policy[key])}.`);
    }
    normalized[key] = policy[key];
  }
  return Object.freeze(normalized);
}

async function readRetentionPolicy(stateDirectory) {
  const retentionPath = retentionPathFor(stateDirectory);
  let stat = null;
  try {
    stat = await fs.lstat(retentionPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!stat) return null;
  if (stat.isSymbolicLink()) {
    fail('AUDIT_RETENTION_SYMLINK_REFUSED', `Refusing to read a retention policy through a symbolic link: ${retentionPath}`);
  }
  if (!stat.isFile()) {
    fail('AUDIT_RETENTION_INVALID', `Retention policy is not a regular file: ${retentionPath}`);
  }
  let parsed;
  try {
    parsed = await readJsonFileBounded(retentionPath);
  } catch (error) {
    fail('AUDIT_RETENTION_INVALID', `Retention policy cannot be read as JSON: ${error.message}`);
  }
  return validateRetentionPolicy(parsed);
}

// Lenient read for the audit log's rotation path: any failure (absent,
// corrupt, symlink, unreadable) returns null, i.e. "no policy", so a
// damaged policy file can never block audit appends. The damage stays
// discoverable: `sentinel audit retention --show` reads strictly and
// reports it.
async function readRetentionPolicyLenient(stateDirectory) {
  try {
    return await readRetentionPolicy(stateDirectory);
  } catch {
    return null;
  }
}

async function writeRetentionPolicy(stateDirectory, policy) {
  const normalized = validateRetentionPolicy(policy);
  const retentionPath = retentionPathFor(stateDirectory);
  await ensurePrivateDir(path.dirname(retentionPath));
  let stat = null;
  try {
    stat = await fs.lstat(retentionPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    fail('AUDIT_RETENTION_SYMLINK_REFUSED', `Refusing to write a retention policy through a symbolic link: ${retentionPath}`);
  }
  await writeFileRefusingSymlink(retentionPath, `${JSON.stringify(normalized, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  return normalized;
}

module.exports = {
  AuditRetentionError,
  SCHEMA_VERSION,
  RETENTION_FILE_NAME,
  retentionPathFor,
  validateRetentionPolicy,
  readRetentionPolicy,
  readRetentionPolicyLenient,
  writeRetentionPolicy,
};
