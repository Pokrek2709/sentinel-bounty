// Operator status overview (Phase 8, round 63).
//
// `sentinel status` is ONE read-only view of the whole operator
// state — kill-switch, audit chain, scope targets, retention policy,
// verify-install, and tool availability — for an operator who today
// must run six commands to see the same picture. It aggregates
// existing read paths and reuses their code; it implements no new
// check of its own except the aggregation itself.
//
// STRICTLY READ-ONLY. Every read below is lockless and creates
// nothing: the kill-switch is read with snapshotLockless() (no lock
// file, no mkdir, no lease pruning — unlike `kill-switch status`,
// which takes the lock to prune expired leases and can therefore
// create a lock file and fail on storage exhaustion); the audit log
// is read with plain readFile (no AuditLog lock, no temp-file
// cleanup, no state-dir creation); the scope store, retention
// policy, verify-install checks, and tool probes are all reads or
// local version-command spawns. `status` never writes, arms,
// rotates, prunes, or repairs anything. A test proves it: the state
// files' contents AND mtimes, and the state directory's own mtime,
// are identical before and after a status run. One inherited
// non-read: checkTool spawns the tool's version command (e.g.
// `docker --version`) — a local probe, never a network request and
// never a write to the state dir.
//
// What is reported, exactly:
// - killSwitch: active/inactive, live-worker count (leases only,
//   same counting as the lockless snapshot), the trigger object
//   when active ({triggerId, triggeredBy, reason, triggeredAt} —
//   the same fields `kill-switch status` already prints), and
//   resetTokenConfigured — whether the env-configured digest FILE
//   exists as a regular file (lstat only, never read). The state
//   file carries no token value and no digest (the reset-token hash
//   lives only in process memory, round 58), so there is nothing
//   credential-like to strip; the digest itself is never read or
//   reported, only its file's presence.
// - audit: per-record chain counts from a LOCKLESS replay of the
//   round-43/56 rules (same entry order — archives .3..1 oldest
//   first, then the active log — same legacy/chained/broken rules,
//   same summary fields), plus pruneAnchors (count of
//   AUDIT_LOG_PRUNED anchor records, round 62) and firstBrokenReason
//   (the AUDIT_CHAIN_* code of the first broken record, or null).
//   The walk is a deliberate duplication of
//   AuditLog.verifyChainPerRecord's rules WITHOUT its lock, because
//   the locked path creates the state dir and a lock file; a test
//   cross-checks the lockless summary against verifyChainPerRecord
//   on the same fixture so the two can never silently diverge.
// - scope: target count + invalid-entry count from
//   listScopeTargets (per-entry validation, so one bad entry never
//   hides the rest).
// - retention: the round-62 policy, or unset, or its error code
//   when the policy file is damaged (reported, not fatal — a
//   corrupt policy must never block operations).
// - verifyInstall: pass/fail counts + overall from runVerifyInstall
//   (counts only, per the round brief — the per-check reasons stay
//   with `verify-install` itself).
// - tools: available/missing counts + missing tool names from the
//   checker's loadToolNames + checkTool (the same probing
//   `check-env` uses, without check-env's storage-probe write).
//
// Failure semantics (fail-closed where it matters, reporting where
// it does not):
// - Corrupt/unreadable KILL-SWITCH state (KILL_SWITCH_STATE_*)
//   → the whole command fails with OperatorStatusError
//   (component 'killSwitch', exit 1). The switch is the
//   fail-closed component: a damaged switch must never be
//   reported as "inactive".
// - Audit-log STORAGE failure (permission/path/quota, the
//   AUDIT_LOG_* codes) → the whole command fails (component
//   'audit', exit 1). An unreadable log is not an empty log.
// - Scope-store SHAPE/symlink failure (SCOPE_STORE_*) → the
//   whole command fails (component 'scope', exit 1), same rule:
//   a damaged store must never be reported as "0 targets".
// - Audit-log CONTENT breaks (unparseable line, legacy after
//   chained, prev/hash mismatch) → reported INSIDE the audit
//   section as broken records with the AUDIT_CHAIN_* reason;
//   the command still exits 0 (the export's job is to show the
//   break, round 56's rule, applied here too).
// - Damaged retention policy → reported inside the retention
//   section as its error code; the command still exits 0.
// - A missing state directory is the EMPTY view (inactive, 0
//   records, 0 targets, retention unset), not an error — the
//   same defaults rounds 56/58 use. No directory is created.
//
// Determinism: the status object carries NO wall-clock timestamp
// (first/lastRecordedAt are audit-log data). The same state always
// renders the same JSON and the same text.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { PersistentKillSwitch } = require('./persistent-kill-switch');
const { hasNonDirectoryAncestor } = require('./storage-errors');
const { computeAuditRecordHash } = require('../audit/audit-log');
const { readRetentionPolicy } = require('../audit/audit-retention');
const { listScopeTargets, storePathFor } = require('../scope/target-store');
const { runVerifyInstall } = require('../install/verifier');
const { loadToolNames, checkTool } = require('../environment/checker');

const STATUS_VERSION = 1;
// Must match AuditLog's DEFAULT_RETENTION_COUNT (src/audit/audit-log.js):
// the lockless chain reader reads exactly the archives verifyChain()
// reads (.3..1, oldest first, then the active log). A test cross-checks
// the lockless summary against verifyChainPerRecord() on the same
// fixture, so a drift in either side fails loudly.
const AUDIT_ARCHIVE_COUNT = 3;
const AUDIT_LOG_FILE = 'audit.jsonl';
const KILL_SWITCH_FILE = 'kill-switch.json';

class OperatorStatusError extends Error {
  constructor(component, reason) {
    super(`${component}: ${reason}`);
    this.name = 'OperatorStatusError';
    this.component = component;
    this.reason = reason;
  }
}

function fail(component, reason) {
  throw new OperatorStatusError(component, reason);
}

// Same mapping as the verifier's checkAuditLog (src/install/verifier.js):
// storage failures get the classified AUDIT_LOG_* code, never a raw
// errno. Content breaks are NOT errors here — the walk reports them
// as broken records instead (see collectAudit).
function classifyAuditReadError(error) {
  if (['EACCES', 'EPERM'].includes(error.code)) return 'AUDIT_LOG_PERMISSION_DENIED';
  if (error.code === 'ENOTDIR') return 'AUDIT_LOG_PATH_INVALID';
  if (['ENOSPC', 'EDQUOT'].includes(error.code)) return 'AUDIT_LOG_STORAGE_UNAVAILABLE';
  return 'AUDIT_LOG_UNAVAILABLE';
}

// Presence only, never a read: the env-configured digest file must
// exist as a regular file. A symlink is NOT configured —
// readExpectedResetTokenHash refuses symlinks, so a linked file is
// unusable as a digest and must not be reported as configured. An
// unset env var is not configured. The digest VALUE is never read.
async function resetTokenConfigured() {
  const configured = process.env.SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE;
  if (!configured || typeof configured !== 'string' || configured.trim() === '') return false;
  try {
    const stat = await fs.lstat(configured);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function collectKillSwitch(stateDir, skillDirectory) {
  const killSwitch = new PersistentKillSwitch({
    stateFile: path.join(stateDir, KILL_SWITCH_FILE),
    skillDirectory,
  });
  let snapshot;
  try {
    // Lockless read: no lock file, no mkdir, no writes. A missing
    // state file returns the default inactive snapshot (ENOENT
    // semantics shared with the kill-switch itself).
    snapshot = await killSwitch.snapshotLockless();
  } catch (error) {
    if (typeof error.message === 'string' && error.message.startsWith('KILL_SWITCH_')) {
      fail('killSwitch', error.message);
    }
    throw error;
  }
  return Object.freeze({
    state: snapshot.active ? 'active' : 'inactive',
    workers: snapshot.registeredWorkers,
    trigger: snapshot.trigger
      ? Object.freeze({
        triggerId: snapshot.trigger.triggerId,
        triggeredBy: snapshot.trigger.triggeredBy,
        reason: snapshot.trigger.reason,
        triggeredAt: snapshot.trigger.triggeredAt,
      })
      : null,
    resetTokenConfigured: await resetTokenConfigured(),
  });
}

// Lockless replay of AuditLog.verifyChainPerRecord's rules (round 56),
// without its lock: plain readFile per file, ENOENT skipped (a missing
// archive or a missing log is an empty set, not an error). Storage
// failures are fail-closed (component 'audit'); content breaks are
// counted as broken records with the AUDIT_CHAIN_* reason, exactly
// as verifyChainPerRecord counts them.
async function collectAudit(stateDir) {
  const files = [];
  for (let index = AUDIT_ARCHIVE_COUNT; index >= 1; index -= 1) files.push(`${AUDIT_LOG_FILE}.${index}`);
  files.push(AUDIT_LOG_FILE);
  const entries = [];
  for (const file of files) {
    let text;
    try {
      text = await fs.readFile(path.join(stateDir, file), 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Windows reports a path through a file as ENOENT, not
        // ENOTDIR: a file parent is a path failure, not a missing file
        // to skip — fail closed instead of reporting zero records.
        if (await hasNonDirectoryAncestor(path.join(stateDir, file))) fail('audit', 'AUDIT_LOG_PATH_INVALID');
        continue;
      }
      fail('audit', classifyAuditReadError(error));
    }
    text.split('\n').filter(Boolean).forEach((line, index) => {
      entries.push({ file, line: index + 1, text: line });
    });
  }
  const summary = {
    totalRecords: entries.length,
    verifiedRecords: 0,
    legacyRecords: 0,
    brokenRecords: 0,
    anchorHash: null,
    firstRecordedAt: null,
    lastRecordedAt: null,
  };
  let seenChained = false;
  let expectedPrev = null;
  let firstBrokenReason = null;
  let pruneAnchors = 0;
  const broken = (reason) => {
    summary.brokenRecords += 1;
    if (firstBrokenReason === null) firstBrokenReason = reason;
  };
  for (const entry of entries) {
    let parsed;
    try {
      parsed = JSON.parse(entry.text);
    } catch {
      broken('AUDIT_CHAIN_UNPARSEABLE');
      continue;
    }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') {
      broken('AUDIT_CHAIN_UNPARSEABLE');
      continue;
    }
    if (typeof parsed.recordedAt === 'string') {
      if (summary.firstRecordedAt === null) summary.firstRecordedAt = parsed.recordedAt;
      summary.lastRecordedAt = parsed.recordedAt;
    }
    if (parsed.event === 'AUDIT_LOG_PRUNED') pruneAnchors += 1;
    if (typeof parsed.hash !== 'string') {
      if (seenChained) broken('AUDIT_CHAIN_LEGACY_AFTER_CHAINED');
      else summary.legacyRecords += 1;
      continue;
    }
    if (!seenChained) {
      seenChained = true;
      summary.anchorHash = typeof parsed.prevHash === 'string' ? parsed.prevHash : null;
      expectedPrev = parsed.prevHash;
    }
    let reason = null;
    if (typeof parsed.prevHash !== 'string' || parsed.prevHash !== expectedPrev) {
      reason = 'AUDIT_CHAIN_PREV_MISMATCH';
    } else if (!/^[a-f0-9]{64}$/.test(parsed.hash) || computeAuditRecordHash(parsed) !== parsed.hash) {
      reason = 'AUDIT_CHAIN_HASH_MISMATCH';
    }
    if (reason) broken(reason);
    else summary.verifiedRecords += 1;
    expectedPrev = parsed.hash;
  }
  return Object.freeze({
    ...summary,
    chainVerified: summary.brokenRecords === 0,
    pruneAnchors,
    firstBrokenReason,
  });
}

async function collectScope(stateDir) {
  let result;
  try {
    result = await listScopeTargets(storePathFor(stateDir));
  } catch (error) {
    // A damaged store shape (or a symlinked store) is fail-closed:
    // a damaged store must never be reported as "0 targets".
    // Per-entry invalidity is NOT an error — listScopeTargets
    // reports those as valid: false and they are counted below.
    fail('scope', error.message);
  }
  return Object.freeze({
    targets: result.count,
    invalidTargets: result.targets.filter((entry) => !entry.valid).length,
  });
}

async function collectRetention(stateDir) {
  try {
    const policy = await readRetentionPolicy(stateDir);
    if (policy === null) return Object.freeze({ set: false, maxArchives: null, maxRecords: null, error: null });
    return Object.freeze({ set: true, maxArchives: policy.max_archives, maxRecords: policy.max_records, error: null });
  } catch (error) {
    // A damaged policy is reported, not fatal (round 62's rule: a
    // corrupt policy must never block operations).
    return Object.freeze({ set: false, maxArchives: null, maxRecords: null, error: error.message });
  }
}

async function collectVerifyInstall(stateDir, skillDirectory, nodeVersion) {
  const result = await runVerifyInstall({ skillDirectory, stateDirectory: stateDir, nodeVersion });
  return Object.freeze({ passed: result.passed, failed: result.failed, overall: result.overall });
}

// Default tool prober: the checker's own loadToolNames + checkTool
// (the same probing `check-env` uses), without check-env's
// storage-probe write. Injectable for tests: pass probeTools to
// collectOperatorStatus to pin the tool counts deterministically.
async function probeTools(skillDirectory) {
  const toolList = await loadToolNames(path.join(skillDirectory, 'config', 'environment-tools.json'));
  const results = await Promise.all(toolList.names.map((name) => checkTool(name)));
  const missingTools = toolList.names.filter((_, index) => results[index].status !== 'verified');
  return Object.freeze({
    total: results.length,
    available: results.length - missingTools.length,
    missing: missingTools.length,
    missingTools: Object.freeze(missingTools),
  });
}

async function collectOperatorStatus({ stateDir, skillDirectory, nodeVersion = process.version, probeTools: probeToolsFn = probeTools } = {}) {
  if (typeof stateDir !== 'string' || stateDir.trim() === '') throw new TypeError('stateDir must be a non-empty string.');
  if (typeof skillDirectory !== 'string' || skillDirectory.trim() === '') throw new TypeError('skillDirectory must be a non-empty string.');
  if (typeof probeToolsFn !== 'function') throw new TypeError('probeTools must be a function.');
  const stateDirectory = path.resolve(stateDir);
  const skillDir = path.resolve(skillDirectory);
  // Fail-closed components first, in security order: a damaged
  // kill-switch must fail before anything else is reported.
  const killSwitch = await collectKillSwitch(stateDirectory, skillDir);
  const audit = await collectAudit(stateDirectory);
  const scope = await collectScope(stateDirectory);
  const retention = await collectRetention(stateDirectory);
  const verifyInstall = await collectVerifyInstall(stateDirectory, skillDir, nodeVersion);
  const tools = await probeToolsFn(skillDir);
  if (!tools || typeof tools !== 'object' || !Number.isInteger(tools.total) || !Number.isInteger(tools.available)
    || !Number.isInteger(tools.missing) || !Array.isArray(tools.missingTools)) {
    throw new TypeError('probeTools must resolve to { total, available, missing, missingTools }.');
  }
  return Object.freeze({
    version: STATUS_VERSION,
    stateDir: stateDirectory,
    skillDir,
    killSwitch,
    audit,
    scope,
    retention,
    verifyInstall,
    tools: Object.freeze({ ...tools, missingTools: Object.freeze([...tools.missingTools]) }),
  });
}

function plural(count, singular, pluralForm = `${singular}s`) {
  return count === 1 ? singular : pluralForm;
}

function renderOperatorStatusText(status) {
  if (!status || typeof status !== 'object') throw new TypeError('renderOperatorStatusText expects a collectOperatorStatus() result.');
  const lines = [`sentinel status — ${status.stateDir}`];
  const killSwitch = status.killSwitch;
  const triggerDetail = killSwitch.trigger
    ? ` (triggered by ${killSwitch.trigger.triggeredBy || 'unknown'}: ${killSwitch.trigger.reason || ''})`
    : '';
  lines.push(`kill-switch: ${killSwitch.state}${triggerDetail} (${killSwitch.workers} ${plural(killSwitch.workers, 'worker')}, reset token: ${killSwitch.resetTokenConfigured ? 'configured' : 'not configured'})`);
  const audit = status.audit;
  const chain = audit.chainVerified
    ? 'chain verified'
    : `chain NOT verified (first break: ${audit.firstBrokenReason})`;
  const last = audit.lastRecordedAt ? `, last: ${audit.lastRecordedAt}` : '';
  const prunes = audit.pruneAnchors > 0 ? `, ${audit.pruneAnchors} prune ${plural(audit.pruneAnchors, 'anchor')}` : '';
  lines.push(`audit: ${audit.totalRecords} ${plural(audit.totalRecords, 'record')} (${audit.verifiedRecords} verified, ${audit.legacyRecords} legacy, ${audit.brokenRecords} broken), ${chain}${last}${prunes}`);
  lines.push(`scope: ${status.scope.targets} ${plural(status.scope.targets, 'target')} (${status.scope.invalidTargets} invalid)`);
  const retention = status.retention;
  if (retention.error) lines.push(`retention: error ${retention.error}`);
  else if (retention.set) lines.push(`retention: max_archives=${retention.maxArchives ?? 'unset'}, max_records=${retention.maxRecords ?? 'unset'}`);
  else lines.push('retention: unset');
  lines.push(`verify-install: ${status.verifyInstall.passed} passed, ${status.verifyInstall.failed} failed — ${status.verifyInstall.overall}`);
  const tools = status.tools;
  lines.push(`tools: ${tools.available} available, ${tools.missing} missing${tools.missing > 0 ? ` (${tools.missingTools.join(', ')})` : ''}`);
  return lines.join('\n');
}

module.exports = {
  OperatorStatusError,
  STATUS_VERSION,
  AUDIT_ARCHIVE_COUNT,
  collectOperatorStatus,
  renderOperatorStatusText,
  probeTools,
};
