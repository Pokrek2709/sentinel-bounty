// Portable state export (Phase 8, round 58).
//
// `sentinel state export` produces ONE portable document of the whole
// operator state — kill-switch state + scope targets + audit summary —
// for migration or off-machine inspection. EXPORT ONLY: there is no
// matching `state import` in this round. Importing foreign state would
// need a trust decision (whose state, verified how, what it may
// overwrite), and that decision stays with the user. See
// docs/state-export-v1.md.
//
// Envelope (schema version 1):
//   { "exportVersion": 1, "exportedAt": "<ISO-8601>",
//     "contents": {
//       "killSwitchState": { "version": 2, "active": false,
//         "trigger": null, "workers": [] },
//       "scopeTargets": [ ...raw target objects as stored... ],
//       "auditSummary": { "totalRecords": n, "verifiedRecords": n,
//         "legacyRecords": n, "brokenRecords": n,
//         "chainVerified": true, "anchorHash": "<hex|null>",
//         "firstRecordedAt": "<ISO|null>",
//         "lastRecordedAt": "<ISO|null>" }
//     },
//     "contentHash": "<sha256 of JSON.stringify(contents)>" }
//
// What is included, exactly:
// - killSwitchState: the state file as stored (`kill-switch.json`),
//   validated with the same `isValidState` the backup uses. The state
//   file carries NO token value and NO reset-token digest — the reset
//   token hash lives only in the kill-switch process memory, never on
//   disk — so there is nothing credential-like to strip. The exported
//   fields are exactly { version, active, trigger, workers }; trigger
//   is { triggerId, triggeredBy, reason, triggeredAt }; a worker is
//   { workerId, pid, leaseExpiresAt }. A test asserts by construction
//   that no exported key matches /token|secret|password|api[-_]?key/i.
// - scopeTargets: the raw target objects from the round-53 store.
//   A missing store file exports as an empty list, not an error. A
//   DAMAGED store fails the whole export with the store's own named
//   error (never silently dropping a target): an export is a
//   migration artifact, and silently omitting a target would change
//   scope on the destination. This differs deliberately from the
//   audit export (round 56), which lists broken records as error
//   entries — audit records are evidence of tampering, while a
//   damaged scope target cannot be migrated faithfully.
// - auditSummary: counts and timestamps from round 56's
//   verifyChainPerRecord(), NOT the full audit log — the full trail
//   already has its own export (`sentinel audit export`).
//
// What is NOT included: token values, reset-token digests (none exist
// on disk), the full audit log, and any file outside the three named
// sources. The export is read-only: it never writes to the state dir,
// never arms or disarms the switch, and works while the switch is
// armed. One side effect is inherited from the audit reader: asking
// for the chain summary creates the state directory (0700) when it
// does not exist yet, exactly as `audit export` does.
//
// The content hash covers the canonical `contents` ONLY (the
// timestamp is excluded), so the same state always yields the same
// hash — two exports at different times are comparable by hash. The
// hash is computed over `JSON.stringify(contents)` with insertion
// order preserved through the JSON round-trip, the same convention
// as the round-37 backup hash.
//
// A missing kill-switch state file exports as the default inactive
// state ({ version: 2, active: false, trigger: null, workers: [] }),
// matching the kill-switch's own ENOENT semantics. A CORRUPT state
// file fails with STATE_EXPORT_STATE_INVALID, and a symlinked state
// file with STATE_EXPORT_SYMLINK_REFUSED — no half-written export
// is ever produced, because the envelope is rendered fully in
// memory first and the CLI writes it only after collection
// succeeds. A legacy-shaped (v1) state file fails as invalid: run
// any kill-switch command first (its locked reader migrates the
// file to v2) and export again.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { AuditLog } = require('../audit/audit-log');
const { loadScopeTargets, storePathFor } = require('../scope/target-store');
const { isValidState } = require('./state-backup');
const { hasNonDirectoryAncestor } = require('./storage-errors');

const EXPORT_VERSION = 1;
const STATE_FILE_NAME = 'kill-switch.json';

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function computeStateExportHash(contents) {
  return sha256Hex(JSON.stringify(contents));
}

function defaultKillSwitchState() {
  return { version: 2, active: false, trigger: null, workers: [] };
}

async function readKillSwitchState(stateDir) {
  const stateFile = path.join(stateDir, STATE_FILE_NAME);
  let stat;
  try {
    stat = await fs.lstat(stateFile);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Windows reports a path through a file as ENOENT, not ENOTDIR:
      // a file parent means the state is unusable, not "no state yet".
      if (await hasNonDirectoryAncestor(stateFile)) throw new Error('STATE_EXPORT_STATE_INVALID');
      return defaultKillSwitchState();
    }
    throw error;
  }
  if (stat.isSymbolicLink()) throw new Error('STATE_EXPORT_SYMLINK_REFUSED');
  if (!stat.isFile()) throw new Error('STATE_EXPORT_STATE_INVALID');
  let state;
  try {
    state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
  } catch {
    throw new Error('STATE_EXPORT_STATE_INVALID');
  }
  if (!isValidState(state)) throw new Error('STATE_EXPORT_STATE_INVALID');
  return state;
}

async function collectStateExport({ stateDir, skillDirectory }) {
  if (typeof stateDir !== 'string' || stateDir.trim() === '') {
    throw new Error('STATE_EXPORT_INVALID_STATE_DIR');
  }
  if (typeof skillDirectory !== 'string' || skillDirectory.trim() === '') {
    throw new Error('STATE_EXPORT_INVALID_SKILL_DIR');
  }
  const killSwitchState = await readKillSwitchState(stateDir);
  // A missing scope store is an empty target list, not an error; a
  // damaged store throws the store's own named error (see the header
  // note) and the whole export fails rather than dropping a target.
  const store = await loadScopeTargets(storePathFor(stateDir));
  const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory });
  const chain = await audit.verifyChainPerRecord();
  const auditSummary = {
    totalRecords: chain.summary.totalRecords,
    verifiedRecords: chain.summary.verifiedRecords,
    legacyRecords: chain.summary.legacyRecords,
    brokenRecords: chain.summary.brokenRecords,
    chainVerified: chain.verified,
    anchorHash: chain.summary.anchorHash,
    firstRecordedAt: chain.summary.firstRecordedAt,
    lastRecordedAt: chain.summary.lastRecordedAt,
  };
  return Object.freeze({
    killSwitchState,
    scopeTargets: store.targets,
    auditSummary: Object.freeze(auditSummary),
  });
}

function renderStateExport(contents, exportedAt = new Date().toISOString()) {
  if (!contents || typeof contents !== 'object' || Array.isArray(contents)) {
    throw new TypeError('renderStateExport expects a collectStateExport() result.');
  }
  if (!contents.killSwitchState || !Array.isArray(contents.scopeTargets) || !contents.auditSummary) {
    throw new TypeError('renderStateExport expects a collectStateExport() result.');
  }
  if (typeof exportedAt !== 'string' || exportedAt.trim() === '') {
    throw new TypeError('renderStateExport expects an ISO-8601 exportedAt string.');
  }
  const envelope = {
    exportVersion: EXPORT_VERSION,
    exportedAt,
    contents,
    contentHash: computeStateExportHash(contents),
  };
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

module.exports = {
  collectStateExport,
  renderStateExport,
  computeStateExportHash,
  defaultKillSwitchState,
  EXPORT_VERSION,
  STATE_FILE_NAME,
};
