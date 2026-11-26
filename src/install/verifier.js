'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { PersistentKillSwitch } = require('../policy/persistent-kill-switch');
const { classifyStateReadError, hasNonDirectoryAncestor } = require('../policy/storage-errors');
const { auditStatePermissions } = require('../policy/state-permissions');

const MIN_NODE_MAJOR = 18;
// Repo layout keeps the skill doc under skills/, an installed copy keeps it
// at the skill root. Either location counts as present.
const SKILL_FILE_CANDIDATES = ['skills/sentinel-bounty/SKILL.md', 'SKILL.md'];
const SCOPE_CONFIG_RELATIVE = path.join('config', 'environment-tools.json');

function pass(id, reason) {
  return { id, status: 'PASS', reason };
}

function fail(id, reason) {
  return { id, status: 'FAIL', reason };
}

function parseNodeMajor(nodeVersion) {
  const match = /^v(\d+)\./.exec(typeof nodeVersion === 'string' ? nodeVersion : '');
  return match ? Number.parseInt(match[1], 10) : NaN;
}

async function checkNodeVersion(nodeVersion) {
  const major = parseNodeMajor(nodeVersion);
  if (Number.isFinite(major) && major >= MIN_NODE_MAJOR) {
    return pass('node-version', `Node ${nodeVersion} meets the >= ${MIN_NODE_MAJOR} requirement.`);
  }
  return fail('node-version', `Node ${nodeVersion} is below the >= ${MIN_NODE_MAJOR} requirement.`);
}

async function checkCliReachable(skillDirectory) {
  const entrypoint = path.join(skillDirectory, 'bin', 'sentinel.js');
  try {
    const stat = await fs.stat(entrypoint);
    if (!stat.isFile()) return fail('cli-reachable', 'CLI entrypoint bin/sentinel.js exists but is not a file.');
    return pass('cli-reachable', 'CLI entrypoint bin/sentinel.js resolves.');
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (await hasNonDirectoryAncestor(entrypoint)) return fail('cli-reachable', 'CLI entrypoint path is invalid (a path component is not a directory).');
      return fail('cli-reachable', 'CLI entrypoint bin/sentinel.js is missing.');
    }
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('cli-reachable', 'CLI entrypoint bin/sentinel.js is not readable (permission denied).');
    if (error.code === 'ENOTDIR') return fail('cli-reachable', 'CLI entrypoint path is invalid (a path component is not a directory).');
    return fail('cli-reachable', 'CLI entrypoint bin/sentinel.js could not be read.');
  }
}

async function checkKillSwitch(stateDirectory, skillDirectory) {
  const stateFile = path.join(stateDirectory, 'kill-switch.json');
  try {
    await fs.stat(stateFile);
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (await hasNonDirectoryAncestor(stateFile)) return fail('kill-switch', 'Kill-switch state could not be read (KILL_SWITCH_STATE_PATH_INVALID).');
      return pass('kill-switch', 'No kill-switch state file exists yet; kill-switch is inactive.');
    }
    return fail('kill-switch', `Kill-switch state could not be read (${classifyStateReadError(error) || 'KILL_SWITCH_STATE_UNAVAILABLE'}).`);
  }
  let snapshot;
  try {
    // snapshotLockless() is the read-only reader: no lock file, no mkdir,
    // no writes. It throws KILL_SWITCH_STATE_CORRUPT for unparseable or
    // wrong-shape state and the classified KILL_SWITCH_STATE_* codes for
    // permission/path failures, so a damaged state can never look
    // inactive here.
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory });
    snapshot = await killSwitch.snapshotLockless();
  } catch (error) {
    const code = /^KILL_SWITCH_[A-Z_]+$/.test(error.message) ? error.message : 'KILL_SWITCH_STATE_UNAVAILABLE';
    return fail('kill-switch', `Kill-switch state is not readable (${code}).`);
  }
  if (snapshot.active) {
    const trigger = snapshot.trigger;
    const detail = trigger && typeof trigger.reason === 'string' && trigger.reason
      ? ` (triggered by ${typeof trigger.triggeredBy === 'string' && trigger.triggeredBy ? trigger.triggeredBy : 'unknown'}: ${trigger.reason})`
      : '';
    return fail('kill-switch', `Kill-switch is ACTIVE${detail}. The armed state exists and must be reviewed before use; verify-install does not pass while the kill-switch is armed.`);
  }
  return pass('kill-switch', 'Kill-switch state is readable and inactive.');
}

async function checkAuditLog(stateDirectory) {
  const logFile = path.join(stateDirectory, 'audit.jsonl');
  let content;
  try {
    // Read-only parse, mirroring AuditLog.healthCheck's record validation
    // without its lock, mkdir, or probe-file writes: verify-install must
    // not write anything.
    content = await fs.readFile(logFile, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (await hasNonDirectoryAncestor(logFile)) return fail('audit-log', 'Audit log path is invalid (AUDIT_LOG_PATH_INVALID).');
      return pass('audit-log', 'No audit log exists yet; nothing to verify.');
    }
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('audit-log', 'Audit log is not readable (AUDIT_LOG_PERMISSION_DENIED).');
    if (error.code === 'ENOTDIR') return fail('audit-log', 'Audit log path is invalid (AUDIT_LOG_PATH_INVALID).');
    if (['ENOSPC', 'EDQUOT'].includes(error.code)) return fail('audit-log', 'Audit log storage is unavailable (AUDIT_LOG_STORAGE_UNAVAILABLE).');
    return fail('audit-log', 'Audit log could not be read (AUDIT_LOG_UNAVAILABLE).');
  }
  for (const line of content.split('\n').filter(Boolean)) {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      return fail('audit-log', 'Audit log is corrupt (AUDIT_LOG_CORRUPT): a line is not valid JSON.');
    }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') {
      return fail('audit-log', 'Audit log is corrupt (AUDIT_LOG_CORRUPT): a record has no event.');
    }
  }
  return pass('audit-log', 'Audit log is readable and every record parses.');
}

async function checkStatePermissions(stateDirectory) {
  let audit;
  try {
    audit = await auditStatePermissions(stateDirectory);
  } catch (error) {
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('state-permissions', 'State directory is not readable (STATE_PERMISSION_DENIED).');
    if (error.code === 'ENOTDIR' || error.message === 'STATE_PERMISSION_PATH_INVALID') return fail('state-permissions', 'State directory path is invalid (STATE_PERMISSION_PATH_INVALID).');
    return fail('state-permissions', 'State directory permissions could not be checked (STATE_PERMISSION_UNAVAILABLE).');
  }
  if (!audit.exists) return pass('state-permissions', 'No state directory exists yet; nothing to verify.');
  if (audit.violations.length === 0) {
    // Round 81: on Windows POSIX mode bits do not exist, so the
    // audit checks symlinks and special files only — the PASS
    // message must not claim 0600/0700 were verified there.
    if (audit.posixModes === false) {
      return pass('state-permissions', `State directory permissions checked (${audit.checked} entr${audit.checked === 1 ? 'y' : 'ies'} checked: POSIX modes do not apply on Windows; no symlinks or special files).`);
    }
    return pass('state-permissions', `State directory permissions are private (${audit.checked} entr${audit.checked === 1 ? 'y' : 'ies'} checked: files 0600, directories 0700, no symlinks).`);
  }
  const detail = audit.violations.map((violation) => {
    if (violation.kind === 'symlink') return `${violation.path} is a symlink (expected: no symlink)`;
    if (violation.kind === 'other') return `${violation.path} is an unexpected special file (${violation.actualMode})`;
    return `${violation.path} is ${violation.actualMode} (expected ${violation.expectedMode})`;
  }).join('; ');
  return fail('state-permissions', `${audit.violations.length} permission violation${audit.violations.length === 1 ? '' : 's'} (STATE_PERMISSION_VIOLATION): ${detail}. Run verify-install --fix to tighten them.`);
}

async function checkScopeConfig(skillDirectory) {
  const configFile = path.join(skillDirectory, SCOPE_CONFIG_RELATIVE);
  let content;
  try {
    content = await fs.readFile(configFile, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (await hasNonDirectoryAncestor(configFile)) return fail('scope-config', 'Scope config path is invalid (a path component is not a directory).');
      return fail('scope-config', 'Scope config config/environment-tools.json is missing.');
    }
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('scope-config', 'Scope config config/environment-tools.json is not readable (permission denied).');
    if (error.code === 'ENOTDIR') return fail('scope-config', 'Scope config path is invalid (a path component is not a directory).');
    return fail('scope-config', 'Scope config config/environment-tools.json could not be read.');
  }
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return fail('scope-config', 'Scope config config/environment-tools.json is not valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.tools)) {
    return fail('scope-config', 'Scope config config/environment-tools.json has an unexpected shape (expected a tools list).');
  }
  return pass('scope-config', 'Scope config config/environment-tools.json is present and parses.');
}

async function checkSkillFiles(skillDirectory) {
  let blocked;
  for (const candidate of SKILL_FILE_CANDIDATES) {
    try {
      const stat = await fs.stat(path.join(skillDirectory, candidate));
      if (stat.isFile()) return pass('skill-files', `Skill file ${candidate} is present.`);
    } catch (error) {
      if (error.code !== 'ENOENT' && !blocked) blocked = error;
    }
  }
  if (blocked) return fail('skill-files', 'Skill file SKILL.md could not be read (permission denied).');
  return fail('skill-files', 'Skill file SKILL.md is missing (checked skills/sentinel-bounty/SKILL.md and SKILL.md).');
}

// Read-only install verification: every check is a local read (stat /
// readFile) only. No writes, no network requests, no security tools.
// Returns a frozen { checks, passed, failed, overall } summary; callers
// decide the exit code from `failed`. checkStatePermissions is also
// exported for the CLI --fix path, which re-runs just that check after
// a repair instead of re-running the whole suite.
async function runVerifyInstall({ skillDirectory, stateDirectory, nodeVersion = process.version } = {}) {
  if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path.');
  if (typeof stateDirectory !== 'string' || !path.isAbsolute(stateDirectory)) throw new TypeError('stateDirectory must be an absolute path.');
  const checks = [
    await checkNodeVersion(nodeVersion),
    await checkCliReachable(skillDirectory),
    await checkKillSwitch(stateDirectory, skillDirectory),
    await checkAuditLog(stateDirectory),
    await checkStatePermissions(stateDirectory),
    await checkScopeConfig(skillDirectory),
    await checkSkillFiles(skillDirectory),
  ];
  const passed = checks.filter((check) => check.status === 'PASS').length;
  const failed = checks.length - passed;
  return Object.freeze({
    checks: Object.freeze(checks),
    passed,
    failed,
    overall: failed === 0 ? 'PASS' : 'FAIL',
  });
}

module.exports = { runVerifyInstall, checkStatePermissions, MIN_NODE_MAJOR };
