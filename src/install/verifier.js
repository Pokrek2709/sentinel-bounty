'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { PersistentKillSwitch } = require('../policy/persistent-kill-switch');
const { classifyStateReadError, hasNonDirectoryAncestor } = require('../policy/storage-errors');
const { auditStatePermissions } = require('../policy/state-permissions');
const { loadSessions } = require('../policy/operator-sessions');

const execFileAsync = promisify(execFile);

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

async function checkCliSyntax(skillDirectory) {
  // Round 98: `cli-reachable` only stats the entrypoint — a
  // half-written bin/sentinel.js (interrupted write) would pass it
  // and fail at first use. This check runs `node --check` on it:
  // a syntax check, never an execution, and it writes nothing.
  // Absence or unreadability is cli-reachable's job, so this check
  // passes vacuously there instead of double-counting the failure.
  const entrypoint = path.join(skillDirectory, 'bin', 'sentinel.js');
  let stat;
  try {
    stat = await fs.stat(entrypoint);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return pass('cli-syntax', 'No CLI entrypoint to check; cli-reachable reports it.');
    if (['EACCES', 'EPERM'].includes(error.code)) return pass('cli-syntax', 'CLI entrypoint is not readable; cli-reachable reports it.');
    return fail('cli-syntax', 'CLI entrypoint could not be checked.');
  }
  if (!stat.isFile()) return pass('cli-syntax', 'CLI entrypoint is not a file; cli-reachable reports it.');
  try {
    await execFileAsync(process.execPath, ['--check', entrypoint], { timeout: 10_000, windowsHide: true });
  } catch (error) {
    if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' || error.killed) return fail('cli-syntax', 'CLI entrypoint could not be syntax-checked (timed out).');
    return fail('cli-syntax', 'CLI entrypoint bin/sentinel.js does not parse as JavaScript (node --check failed).');
  }
  return pass('cli-syntax', 'CLI entrypoint bin/sentinel.js parses as JavaScript (node --check).');
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

async function checkSkillCopiesIdentical(skillDirectory) {
  // Round 98: the repo layout keeps two copies of the skill
  // contract (root and skills/sentinel-bounty/) that must stay
  // byte-identical; the docs-crossref guard test pins the same
  // property, and this is the runtime half of it. An installed
  // single-copy layout has nothing to compare, so it passes
  // vacuously — presence itself is skill-files' job.
  const copies = [];
  for (const candidate of SKILL_FILE_CANDIDATES) {
    try {
      copies.push(await fs.readFile(path.join(skillDirectory, candidate)));
    } catch {
      // Missing or unreadable: nothing to compare; skill-files
      // reports presence and readability.
    }
  }
  if (copies.length < 2) return pass('skill-copies-identical', 'Fewer than two readable SKILL.md copies; nothing to compare.');
  if (copies[0].equals(copies[1])) return pass('skill-copies-identical', 'Both SKILL.md copies (root and skills/sentinel-bounty/) are byte-identical.');
  return fail('skill-copies-identical', 'The two SKILL.md copies differ (root vs skills/sentinel-bounty/); they must be byte-identical.');
}

async function checkOperatorSessions(stateDirectory) {
  // Round 98: the operator-session store is a new state file, so
  // the installer validates it like the audit log — a corrupt
  // store must fail loudly instead of passing as "no sessions".
  // A missing file means no sessions yet, which passes.
  const storePath = path.join(stateDirectory, 'operator-sessions.json');
  try {
    await fs.lstat(storePath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (await hasNonDirectoryAncestor(storePath)) return fail('operator-sessions', 'Operator sessions path is invalid (a path component is not a directory).');
      return pass('operator-sessions', 'No operator sessions file exists yet; nothing to verify.');
    }
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('operator-sessions', 'Operator sessions store is not readable (permission denied).');
    if (error.code === 'ENOTDIR') return fail('operator-sessions', 'Operator sessions path is invalid (a path component is not a directory).');
    return fail('operator-sessions', 'Operator sessions store could not be read.');
  }
  try {
    await loadSessions(storePath, { now: Date.now(), pruneExpired: false });
  } catch (error) {
    const code = typeof error.code === 'string' ? error.code : 'OPERATOR_SESSION_STORE_CORRUPT';
    return fail('operator-sessions', `Operator sessions store is not valid (${code}).`);
  }
  return pass('operator-sessions', 'Operator sessions store is readable and valid.');
}

async function readGuardFile(filePath) {
  // Returns the file content, or null when absent (a missing guard
  // file is not this check's failure — see checkCiGuards). Any other
  // read failure is reported, because an unreadable guard file is a
  // proven problem, not an absence.
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null;
    throw error;
  }
}

async function checkCiGuards(skillDirectory) {
  // Round 99: consistency of the CI guard files, when present. This
  // is a consistency check, not a presence check — an installed
  // single-copy layout may ship without .github/ or scripts/, so a
  // skill with none of the four files passes vacuously (presence of
  // the CI job itself is pinned by tests/ci-guards.test.js, not
  // here). What fails here is inconsistency: a workflow that runs
  // the Windows simulation through /tmp (wiped on every VM restart
  // — the round-95 lesson), a preload that does not actually
  // override process.platform, or a guard script that does not
  // parse. The workflow must name the committed preload; a workflow
  // that never runs the simulation fails the same way.
  const workflowPath = path.join(skillDirectory, '.github', 'workflows', 'ci-guards.yml');
  const preloadPath = path.join(skillDirectory, 'scripts', 'fake-win32.cjs');
  const scriptPaths = [
    path.join(skillDirectory, 'scripts', 'pre-push-check.cjs'),
    path.join(skillDirectory, 'scripts', 'fetch-windows-logs.cjs'),
  ];
  let workflow;
  let preload;
  let scripts;
  try {
    workflow = await readGuardFile(workflowPath);
    preload = await readGuardFile(preloadPath);
    scripts = [];
    for (const scriptPath of scriptPaths) scripts.push(await readGuardFile(scriptPath));
  } catch (error) {
    if (['EACCES', 'EPERM'].includes(error.code)) return fail('ci-guards', 'CI guard files could not be read (permission denied).');
    return fail('ci-guards', 'CI guard files could not be read.');
  }
  if (workflow === null && preload === null && scripts.every((content) => content === null)) {
    return pass('ci-guards', 'No CI guard files present; nothing to verify.');
  }
  if (workflow !== null) {
    if (workflow.includes('/tmp/fake-win32.cjs')) return fail('ci-guards', 'CI workflow references /tmp/fake-win32.cjs, which the VM wipes on restart; it must reference scripts/fake-win32.cjs.');
    if (!workflow.includes('scripts/fake-win32.cjs')) return fail('ci-guards', 'CI workflow does not run the Windows simulation through the committed preload scripts/fake-win32.cjs.');
  }
  if (preload !== null && (!preload.includes("Object.defineProperty(process, 'platform'") || !preload.includes("'win32'"))) {
    return fail('ci-guards', 'Committed Windows simulation preload scripts/fake-win32.cjs does not override process.platform to win32.');
  }
  for (let i = 0; i < scriptPaths.length; i += 1) {
    if (scripts[i] === null) continue;
    try {
      await execFileAsync(process.execPath, ['--check', scriptPaths[i]], { timeout: 10_000, windowsHide: true });
    } catch (error) {
      if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' || error.killed) return fail('ci-guards', `CI guard script ${path.basename(scriptPaths[i])} could not be syntax-checked (timed out).`);
      return fail('ci-guards', `CI guard script ${path.basename(scriptPaths[i])} does not parse as JavaScript (node --check failed).`);
    }
  }
  return pass('ci-guards', 'CI guard files are consistent (workflow uses the committed preload; guard scripts parse).');
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
    await checkCliSyntax(skillDirectory),
    await checkKillSwitch(stateDirectory, skillDirectory),
    await checkAuditLog(stateDirectory),
    await checkStatePermissions(stateDirectory),
    await checkScopeConfig(skillDirectory),
    await checkSkillFiles(skillDirectory),
    await checkSkillCopiesIdentical(skillDirectory),
    await checkOperatorSessions(stateDirectory),
    await checkCiGuards(skillDirectory),
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
