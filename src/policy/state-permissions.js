'use strict';

// State-file permission standard (round 45, Phase 8).
//
// The state directory holds sensitive material: kill-switch state with
// token digests, audit records, worker records, backups. The standard
// is simple and strict:
//   - every regular file inside the state directory: 0600
//   - every directory inside the state directory: 0700
//   - no symlinks anywhere inside the state directory
//
// Why a module for this: several writers already set 0600/0700 at
// creation time (persistent-kill-switch, audit-log, safe-write,
// state-backup), but `fs.mkdir({ recursive: true, mode: 0o700 })`
// does NOT chmod a directory that already exists — so a state
// directory created earlier under a permissive umask stayed loose
// forever (the live install's state dir was 2770, and two legacy
// files were 0660). Nothing verified permissions at all. This module
// is the single place that audits, repairs, and enforces the
// standard.
//
// Honest limits (see docs/state-permissions-v1.md): permissions are
// a local-OS control. They do not protect against root, against a
// user who deliberately loosens them afterwards, or against an
// attacker who can rewrite the whole state directory — the audit
// hash chain (round 43) is the tamper-evidence layer for that.
//
// Windows (round 81): POSIX mode bits do not exist on Windows.
// Node reports every regular file as 0666 and every directory as
// 0777 there, and `fs.chmod` is a no-op except for the read-only
// bit — so a 0600/0700 standard is unstatable AND unenforceable
// on that platform. `posixModesApply()` is the single place that
// knows this: the audit skips mode checks on Windows (symlink and
// special-file checks still apply), repair therefore has no mode
// violation to "fix" (it must never report a repair it did not
// perform), and `verify-install` passes the state-permissions
// check for a normal Windows state directory instead of failing
// it forever. The privacy guarantee on Windows is the OS ACL,
// which Node cannot observe — documented, not hidden.

const fs = require('node:fs/promises');
const path = require('node:path');

const REQUIRED_FILE_MODE = 0o600;
const REQUIRED_DIR_MODE = 0o700;

// POSIX mode bits apply on every platform except Windows, where
// they do not exist (see the header comment). Pure function of a
// platform string so tests can pin the branching without a
// Windows machine: posixModesApply('win32') is false,
// posixModesApply('linux') and posixModesApply('darwin') are true.
function posixModesApply(platform = process.platform) {
  return platform !== 'win32';
}

// Modes are compared on the permission bits only (0o7777 keeps the
// setuid/setgid/sticky bits visible in reports: a 2770 directory is
// a violation, not just "not 0700").
const MODE_MASK = 0o7777;

function formatMode(mode) {
  return `0o${(mode & MODE_MASK).toString(8).padStart(4, '0')}`;
}

function isTooPermissive(actualMode, requiredMode) {
  // Any permission bit outside the required set is a violation.
  // 0600 vs 0660 differs by group bits; 0700 vs 2770 differs by
  // setgid + group bits. A mode MORE restrictive than required
  // (e.g. 0400 file, 0500 dir) is not a violation — it is still
  // private — but repair never loosens, so it leaves it alone.
  return (actualMode & ~requiredMode) !== 0;
}

async function walkStateDirectory(stateDirectory, onEntry) {
  const names = await fs.readdir(stateDirectory);
  names.sort();
  for (const name of names) {
    const full = path.join(stateDirectory, name);
    const stat = await fs.lstat(full);
    await onEntry(full, stat);
    if (stat.isDirectory()) await walkStateDirectory(full, onEntry);
  }
}

// Read-only audit. Returns { stateDirectory, exists, checked,
// violations, posixModes }. A violation is { path, kind,
// actualMode, expectedMode }: kind 'file' | 'directory' |
// 'symlink'. For a symlink expectedMode is null — the expectation
// is "not a symlink". `posixModes` records whether POSIX mode
// bits were even checked: false on Windows, where mode checks are
// skipped (round 81 — files report 0666 and directories 0777
// there, so every entry would otherwise be a permanent false
// violation). Symlink and special-file checks still apply on
// every platform. Never follows a symlink. Throws on unreadable
// directories other than a missing state directory.
async function auditStatePermissions(stateDirectory) {
  if (typeof stateDirectory !== 'string' || !path.isAbsolute(stateDirectory)) {
    throw new TypeError('stateDirectory must be an absolute path.');
  }
  const posixModes = posixModesApply();
  let names;
  try {
    names = await fs.readdir(stateDirectory);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { stateDirectory, exists: false, checked: 0, violations: [], posixModes };
    }
    throw error;
  }
  const violations = [];
  let checked = 0;
  const checkEntry = async (full, stat) => {
    checked += 1;
    if (stat.isSymbolicLink()) {
      violations.push({
        path: full,
        kind: 'symlink',
        actualMode: formatMode(stat.mode),
        expectedMode: null,
      });
      return;
    }
    if (stat.isDirectory()) {
      if (posixModes && isTooPermissive(stat.mode & MODE_MASK, REQUIRED_DIR_MODE)) {
        violations.push({
          path: full,
          kind: 'directory',
          actualMode: formatMode(stat.mode),
          expectedMode: formatMode(REQUIRED_DIR_MODE),
        });
      }
      return;
    }
    if (stat.isFile()) {
      if (posixModes && isTooPermissive(stat.mode & MODE_MASK, REQUIRED_FILE_MODE)) {
        violations.push({
          path: full,
          kind: 'file',
          actualMode: formatMode(stat.mode),
          expectedMode: formatMode(REQUIRED_FILE_MODE),
        });
      }
      return;
    }
    // Sockets, FIFOs, devices inside the state directory are not
    // expected at all: report them as violations, never touch them.
    violations.push({
      path: full,
      kind: 'other',
      actualMode: formatMode(stat.mode),
      expectedMode: null,
    });
  };
  // The state directory itself is entry zero: the live install's
  // state dir was 2770, and checking only its contents would have
  // missed exactly that.
  await checkEntry(stateDirectory, await fs.lstat(stateDirectory));
  names.sort();
  for (const name of names) {
    const full = path.join(stateDirectory, name);
    const stat = await fs.lstat(full);
    await checkEntry(full, stat);
    if (stat.isDirectory() && !stat.isSymbolicLink()) await walkStateDirectory(full, checkEntry);
  }
  return { stateDirectory, exists: true, checked, violations, posixModes };
}

// Repair: tighten every violating file to 0600 and every violating
// directory to 0700. Only touches entries inside the state
// directory, never follows a symlink (symlinks and other special
// files are reported in `refused`, never chmodded — chmod through
// a symlink would change the target). Returns { repaired, refused }.
// On Windows the audit reports no mode violations (round 81), so
// repair has no mode to tighten and never claims one — a chmod
// there would be a no-op, and reporting it as repaired would be
// a lie.
async function repairStatePermissions(stateDirectory) {
  const audit = await auditStatePermissions(stateDirectory);
  const repaired = [];
  const refused = [];
  for (const violation of audit.violations) {
    if (violation.kind === 'file') {
      await fs.chmod(violation.path, REQUIRED_FILE_MODE);
      repaired.push({ ...violation, fromMode: violation.actualMode, toMode: formatMode(REQUIRED_FILE_MODE) });
    } else if (violation.kind === 'directory') {
      await fs.chmod(violation.path, REQUIRED_DIR_MODE);
      repaired.push({ ...violation, fromMode: violation.actualMode, toMode: formatMode(REQUIRED_DIR_MODE) });
    } else {
      refused.push({ path: violation.path, kind: violation.kind, reason: 'STATE_PERMISSION_SYMLINK_REFUSED' });
    }
  }
  return { repaired, refused };
}

// Create a directory (parents included) and guarantee the target
// directory itself ends at 0700. `fs.mkdir({ recursive: true,
// mode: 0o700 })` alone does NOT chmod a directory that already
// exists, which is exactly how the live state dir stayed 2770.
// Only the target directory is chmodded — parents are left alone,
// because they may belong to the operator, not to the skill.
//
// A chmod that fails with EACCES/EPERM is swallowed, not thrown:
// it means we do not own the directory, and the caller's next
// filesystem operation (lock open, write) will fail with the
// properly classified permission error (EACCES) instead. Throwing
// the raw EPERM here would mask that classification — the
// round-27 EACCES probes regressed exactly this way. Any other
// chmod failure still propagates.
async function ensurePrivateDir(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    throw new TypeError('directory must be an absolute path.');
  }
  await fs.mkdir(directory, { recursive: true, mode: REQUIRED_DIR_MODE });
  try {
    await fs.chmod(directory, REQUIRED_DIR_MODE);
  } catch (error) {
    if (['EACCES', 'EPERM'].includes(error.code)) return;
    throw error;
  }
}

module.exports = {
  REQUIRED_FILE_MODE,
  REQUIRED_DIR_MODE,
  formatMode,
  posixModesApply,
  auditStatePermissions,
  repairStatePermissions,
  ensurePrivateDir,
};
