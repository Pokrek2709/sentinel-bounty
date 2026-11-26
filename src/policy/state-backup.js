// State backup and restore (Phase 8, round 37).
//
// Backup captures ONLY the kill-switch state file (`kill-switch.json`).
// The audit log is deliberately NOT included: it is append-only evidence,
// and restoring an old copy would silently erase intervening audit events
// (an audit-integrity incident). Operators who need the audit trail copy
// `audit.jsonl` and its `.N` archives separately, as plain files, and
// never restore them over a live log. See docs/backup-restore-v1.md.
//
// Envelope format (schema version 1):
//   { "schemaVersion": 1, "createdAt": "<ISO-8601>", "sha256": "<hex>",
//     "state": { "version": 2, "active": false, "trigger": null, "workers": [] } }
// The hash covers the canonical form `JSON.stringify(state)` — the parsed
// state object re-serialized with insertion order preserved through the
// JSON round-trip — so backup and restore compute the same digest.
//
// Restore verifies, in order, BEFORE writing anything: the input is a
// regular file (never a symlink), it parses, the schema version is
// supported, the hash matches, and the enclosed state has the v2 shape.
// Any failure refuses with a named error and writes nothing.
//
// Armed-with-leased-workers rule (the one rule this version picks):
// REFUSE. A backup whose state is active AND holds any worker lease that
// has not yet expired is refused (`BACKUP_ARMED_WITH_LEASED_WORKERS`).
// Those leases belong to processes that are gone (the state was wiped or
// moved); restoring them would plant phantom live workers that block a
// later reset. An armed state with no live leases (empty or all expired)
// restores normally — the armed flag itself is preserved, so a restore
// can never silently disarm the switch.
//
// Symlinks are never followed, for output or input: the backup output
// goes through `writeFileRefusingSymlink`, the restore input is
// lstat-checked, and the restored state file is written through the same
// helper. Restore also refuses while a fresh state lock
// (`kill-switch.json.lock`, younger than 60 s) exists, so it cannot race
// a live writer; a stale lock does not block a restore.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { ensurePrivateDir } = require('./state-permissions');
const { writeFileRefusingSymlink } = require('./safe-write');
const { hasNonDirectoryAncestor } = require('./storage-errors');

const BACKUP_SCHEMA_VERSION = 1;
const MAX_BACKUP_BYTES = 1024 * 1024;
const STALE_LOCK_MS = 60_000;

// Integrity refusals (exit 3 in the CLI): the backup cannot be trusted.
const INTEGRITY_REASONS = new Set([
  'BACKUP_CORRUPT',
  'BACKUP_HASH_MISMATCH',
  'BACKUP_UNSUPPORTED_SCHEMA',
  'BACKUP_STATE_INVALID',
  'BACKUP_ARMED_WITH_LEASED_WORKERS',
  'BACKUP_SYMLINK_REFUSED',
]);

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function isValidState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
  if (state.version !== 2 || typeof state.active !== 'boolean') return false;
  if (state.trigger !== null && (typeof state.trigger !== 'object' || Array.isArray(state.trigger))) return false;
  if (!Array.isArray(state.workers)) return false;
  return state.workers.every((worker) => worker
    && typeof worker === 'object'
    && !Array.isArray(worker)
    && typeof worker.workerId === 'string'
    && worker.workerId.trim() !== ''
    && Number.isFinite(worker.leaseExpiresAt));
}

function hasLiveLease(state, now = Date.now()) {
  return state.active && state.workers.some((worker) => worker.leaseExpiresAt > now);
}

async function backupState({ stateDir, outPath }) {
  const stateFile = path.join(stateDir, 'kill-switch.json');
  let stat;
  try {
    stat = await fs.lstat(stateFile);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Windows reports a path through a file as ENOENT, not ENOTDIR:
      // a file parent means the state file is unusable, not missing.
      if (await hasNonDirectoryAncestor(stateFile)) throw new Error('BACKUP_STATE_INVALID');
      throw new Error('BACKUP_STATE_MISSING');
    }
    throw error;
  }
  if (stat.isSymbolicLink()) throw new Error('BACKUP_SYMLINK_REFUSED');
  if (!stat.isFile()) throw new Error('BACKUP_STATE_INVALID');
  let state;
  try {
    state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
  } catch {
    throw new Error('BACKUP_STATE_INVALID');
  }
  if (!isValidState(state)) throw new Error('BACKUP_STATE_INVALID');
  const createdAt = new Date().toISOString();
  const envelope = {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    createdAt,
    sha256: sha256Hex(JSON.stringify(state)),
    state,
  };
  const output = path.resolve(outPath);
  // The output directory is operator-chosen (it may be anywhere), so
  // only a newly created directory gets 0700 — an existing directory
  // is never chmodded. The backup FILE itself is written 0600
  // through writeFileRefusingSymlink below.
  await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
  try {
    await writeFileRefusingSymlink(output, `${JSON.stringify(envelope, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (error) {
    if (/symbolic link/i.test(error.message)) throw new Error('BACKUP_SYMLINK_REFUSED');
    throw error;
  }
  return Object.freeze({
    backedUp: true,
    schemaVersion: BACKUP_SCHEMA_VERSION,
    sha256: envelope.sha256,
    createdAt,
    active: state.active,
    workers: state.workers.length,
  });
}

async function restoreState({ stateDir, fromPath }) {
  const input = path.resolve(fromPath);
  let stat;
  try {
    stat = await fs.lstat(input);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Windows reports a path through a file as ENOENT, not ENOTDIR:
      // a file parent means the input is unusable as a backup, not absent.
      if (await hasNonDirectoryAncestor(input)) throw new Error('BACKUP_CORRUPT');
      throw new Error('BACKUP_NOT_FOUND');
    }
    throw error;
  }
  if (stat.isSymbolicLink()) throw new Error('BACKUP_SYMLINK_REFUSED');
  if (!stat.isFile()) throw new Error('BACKUP_CORRUPT');
  if (stat.size > MAX_BACKUP_BYTES) throw new Error('BACKUP_TOO_LARGE');
  let envelope;
  try {
    envelope = JSON.parse(await fs.readFile(input, 'utf8'));
  } catch {
    throw new Error('BACKUP_CORRUPT');
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('BACKUP_CORRUPT');
  if (typeof envelope.schemaVersion !== 'number' || !Number.isInteger(envelope.schemaVersion)) throw new Error('BACKUP_CORRUPT');
  if (envelope.schemaVersion !== BACKUP_SCHEMA_VERSION) throw new Error('BACKUP_UNSUPPORTED_SCHEMA');
  if (typeof envelope.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(envelope.sha256)) throw new Error('BACKUP_CORRUPT');
  if (!envelope.state || typeof envelope.state !== 'object' || Array.isArray(envelope.state)) throw new Error('BACKUP_CORRUPT');
  const recomputed = sha256Hex(JSON.stringify(envelope.state));
  if (!crypto.timingSafeEqual(Buffer.from(recomputed), Buffer.from(envelope.sha256))) throw new Error('BACKUP_HASH_MISMATCH');
  if (!isValidState(envelope.state)) throw new Error('BACKUP_STATE_INVALID');
  if (hasLiveLease(envelope.state)) throw new Error('BACKUP_ARMED_WITH_LEASED_WORKERS');
  // A fresh state lock means a live writer holds the state; refuse rather
  // than racing it. A stale lock (older than 60 s) does not block a
  // restore — the writer is gone, and the lock file itself is not state.
  const stateFile = path.join(stateDir, 'kill-switch.json');
  const lockFile = `${stateFile}.lock`;
  try {
    const lockStat = await fs.lstat(lockFile);
    if (!lockStat.isSymbolicLink() && lockStat.isFile() && Date.now() - lockStat.mtimeMs < STALE_LOCK_MS) {
      throw new Error('BACKUP_STATE_LOCKED');
    }
  } catch (error) {
    if (error.message === 'BACKUP_STATE_LOCKED') throw error;
    if (error.code !== 'ENOENT') throw error;
  }
  // The restore target IS a state directory: guarantee 0700 even if
  // it already exists (round 45, ensurePrivateDir).
  await ensurePrivateDir(stateDir);
  try {
    await writeFileRefusingSymlink(stateFile, `${JSON.stringify(envelope.state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (error) {
    if (/symbolic link/i.test(error.message)) throw new Error('BACKUP_SYMLINK_REFUSED');
    throw error;
  }
  return Object.freeze({
    restored: true,
    schemaVersion: BACKUP_SCHEMA_VERSION,
    sha256: envelope.sha256,
    active: envelope.state.active,
    workers: envelope.state.workers.length,
  });
}

module.exports = { backupState, restoreState, BACKUP_SCHEMA_VERSION, MAX_BACKUP_BYTES, INTEGRITY_REASONS, isValidState };
