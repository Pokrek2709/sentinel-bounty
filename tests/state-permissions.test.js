'use strict';

// State-file permissions (round 45, Phase 8): audit, repair, writer
// hardening under a permissive umask, verify-install integration,
// and the CLI --fix path. All local, temp dirs only.

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const REPO = path.resolve(__dirname, '..');
const CLI = path.join(REPO, 'bin', 'sentinel.js');
const {
  auditStatePermissions,
  repairStatePermissions,
  ensurePrivateDir,
  REQUIRED_FILE_MODE,
  REQUIRED_DIR_MODE,
} = require('../src/policy/state-permissions');
const { runVerifyInstall, checkStatePermissions } = require('../src/install/verifier');

async function modeOf(target) {
  return (await fs.lstat(target)).mode & 0o7777;
}

async function invokeCli(args) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// Round 81 (Windows): the tests skipped below assert POSIX permission
// bits end to end (audit reports 0644/0755, repair 0660 -> 0600,
// verify-install FAIL -> PASS). On Windows those bits do not exist —
// Node reports files 0666 and directories 0777, chmod is a no-op —
// so the audit skips mode checks there by design and these tests
// cannot pass on that platform. They still run on POSIX, where the
// standard is enforced. Windows behavior is covered instead by
// tests/windows-platform.test.js (audit/repair/verify-install on
// win32, skipped here on POSIX).
async function makeSkillRoot(directory) {
  await fs.mkdir(path.join(directory, 'bin'), { recursive: true });
  await fs.mkdir(path.join(directory, 'config'), { recursive: true });
  await fs.mkdir(path.join(directory, 'skills', 'sentinel-bounty'), { recursive: true });
  await fs.writeFile(path.join(directory, 'bin', 'sentinel.js'), '#!/usr/bin/env node\n', { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'config', 'environment-tools.json'), JSON.stringify({ version: '1.0.0', tools: ['docker'] }), { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'skills', 'sentinel-bounty', 'SKILL.md'), '# Sentinel Bounty\n', { mode: 0o600 });
}

test('audit reports a loose file with its actual mode', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const loose = path.join(dir, 'kill-switch.json');
  await fs.writeFile(loose, '{}');
  // writeFile's mode option is masked by the umask (0007 here turns
  // 0644 into 0640), so set the loose mode explicitly.
  await fs.chmod(loose, 0o644);
  const audit = await auditStatePermissions(dir);
  assert.equal(audit.exists, true);
  // The state directory itself is entry zero, plus the one file.
  assert.equal(audit.checked, 2);
  assert.equal(audit.violations.length, 1);
  assert.equal(audit.violations[0].path, loose);
  assert.equal(audit.violations[0].kind, 'file');
  assert.equal(audit.violations[0].actualMode, '0o0644');
  assert.equal(audit.violations[0].expectedMode, '0o0600');
});

test('audit reports a loose directory, including a nested one', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  await fs.chmod(dir, 0o755);
  const sub = path.join(dir, 'drill');
  await fs.mkdir(sub);
  await fs.chmod(sub, 0o755);
  await fs.writeFile(path.join(sub, 'audit.jsonl'), '', { mode: 0o600 });
  const audit = await auditStatePermissions(dir);
  // Root dir + subdir + one file.
  assert.equal(audit.checked, 3);
  const kinds = audit.violations.map((v) => v.kind).sort();
  assert.deepEqual(kinds, ['directory', 'directory']);
  assert.ok(audit.violations.some((v) => v.path === dir && v.actualMode === '0o0755'));
  assert.ok(audit.violations.some((v) => v.path === sub && v.actualMode === '0o0755'));
});

test('audit passes clean modes and reports a missing directory', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  await fs.chmod(dir, 0o700);
  await fs.writeFile(path.join(dir, 'kill-switch.json'), '{}', { mode: 0o600 });
  const clean = await auditStatePermissions(dir);
  assert.deepEqual(clean.violations, []);
  // Root dir + one file.
  assert.equal(clean.checked, 2);
  const missing = await auditStatePermissions(path.join(dir, 'nope'));
  assert.equal(missing.exists, false);
  assert.deepEqual(missing.violations, []);
});

test('audit flags a symlink and never follows it', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const outside = await makeTempDir(t, 'r45-perms-');
  const target = path.join(outside, 'secret.txt');
  await fs.writeFile(target, 'x');
  await fs.chmod(target, 0o644);
  const link = path.join(dir, 'audit.jsonl');
  await fs.symlink(target, link);
  const audit = await auditStatePermissions(dir);
  assert.equal(audit.violations.length, 1);
  assert.equal(audit.violations[0].kind, 'symlink');
  assert.equal(audit.violations[0].expectedMode, null);
  // The target was never touched: still 0644.
  assert.equal(await modeOf(target), 0o644);
});

test('repair tightens files and directories and reports from/to modes', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  await fs.chmod(dir, 0o755);
  const loose = path.join(dir, 'budget.json');
  await fs.writeFile(loose, '{}');
  await fs.chmod(loose, 0o660);
  const repair = await repairStatePermissions(dir);
  assert.equal(repair.refused.length, 0);
  assert.equal(repair.repaired.length, 2);
  assert.ok(repair.repaired.some((r) => r.path === loose && r.fromMode === '0o0660' && r.toMode === '0o0600'));
  assert.ok(repair.repaired.some((r) => r.path === dir && r.fromMode === '0o0755' && r.toMode === '0o0700'));
  assert.equal(await modeOf(loose), 0o600);
  assert.equal(await modeOf(dir), 0o700);
  // Idempotent: a second repair finds nothing to do.
  const again = await repairStatePermissions(dir);
  assert.deepEqual(again.repaired, []);
  assert.deepEqual(again.refused, []);
});

test('repair refuses a symlink and leaves its target alone', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const outside = await makeTempDir(t, 'r45-perms-');
  const target = path.join(outside, 'secret.txt');
  await fs.writeFile(target, 'x');
  await fs.chmod(target, 0o644);
  const link = path.join(dir, 'audit.jsonl');
  await fs.symlink(target, link);
  const repair = await repairStatePermissions(dir);
  assert.equal(repair.repaired.length, 0);
  assert.equal(repair.refused.length, 1);
  assert.equal(repair.refused[0].path, link);
  assert.equal(repair.refused[0].reason, 'STATE_PERMISSION_SYMLINK_REFUSED');
  assert.equal(await modeOf(target), 0o644);
  assert.equal((await fs.lstat(link)).isSymbolicLink(), true);
});

test('ensurePrivateDir chmods a directory that already exists', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  await fs.chmod(dir, 0o755);
  const sub = path.join(dir, 'state');
  await fs.mkdir(sub);
  await fs.chmod(sub, 0o755);
  await ensurePrivateDir(sub);
  assert.equal(await modeOf(sub), 0o700);
  // Parents are left alone.
  assert.equal(await modeOf(dir), 0o755);
});

test('fresh writes are 0600/0700 even under umask 022', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const stateDir = path.join(dir, 'state');
  const script = `
    const fs = require('node:fs/promises');
    const path = require('node:path');
    const repo = process.argv[2];
    const { PersistentKillSwitch } = require(path.join(repo, 'src/policy/persistent-kill-switch'));
    const { AuditLog } = require(path.join(repo, 'src/audit/audit-log'));
    (async () => {
      process.umask(0o022);
      const stateDir = process.argv[1];
      const ks = new PersistentKillSwitch({ stateFile: path.join(stateDir, 'kill-switch.json'), skillDirectory: repo });
      await ks.trigger({ triggeredBy: 'umask-probe', reason: 'fresh write under umask 022' });
      const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: repo });
      await audit.append('UMASK_PROBE', {});
      const out = {};
      for (const name of ['kill-switch.json', 'audit.jsonl']) {
        out[name] = ((await fs.stat(path.join(stateDir, name))).mode & 0o7777).toString(8);
      }
      out['.'] = ((await fs.stat(stateDir)).mode & 0o7777).toString(8);
      process.stdout.write(JSON.stringify(out));
    })().catch((e) => { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
  `;
  const result = await execFileAsync(process.execPath, ['-e', script, stateDir, REPO], { windowsHide: true });
  const modes = JSON.parse(result.stdout);
  assert.equal(modes['kill-switch.json'], '600');
  assert.equal(modes['audit.jsonl'], '600');
  assert.equal(modes['.'], '700');
});

test('verify-install state-permissions check fails loose, passes after repair', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const skill = path.join(dir, 'skill');
  const state = path.join(dir, 'state');
  await makeSkillRoot(skill);
  await fs.mkdir(state, { recursive: true });
  const stateFile = path.join(state, 'kill-switch.json');
  await fs.writeFile(stateFile, JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }));
  await fs.chmod(stateFile, 0o644);
  const before = await runVerifyInstall({ skillDirectory: skill, stateDirectory: state });
  const check = before.checks.find((c) => c.id === 'state-permissions');
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /0o0644/);
  assert.match(check.reason, /STATE_PERMISSION_VIOLATION/);
  await repairStatePermissions(state);
  const after = await checkStatePermissions(state);
  assert.equal(after.status, 'PASS');
  const rerun = await runVerifyInstall({ skillDirectory: skill, stateDirectory: state });
  assert.equal(rerun.checks.find((c) => c.id === 'state-permissions').status, 'PASS');
});

test('CLI verify-install --fix tightens loose state and exits 0; without --fix it exits 1', { skip: process.platform === 'win32' }, async (t) => {
  const dir = await makeTempDir(t, 'r45-perms-');
  const skill = path.join(dir, 'skill');
  const state = path.join(dir, 'state');
  await makeSkillRoot(skill);
  await fs.mkdir(state, { recursive: true });
  const loose = path.join(state, 'kill-switch.json');
  await fs.writeFile(loose, JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }));
  await fs.chmod(loose, 0o644);
  const plain = await invokeCli(['verify-install', '--state-dir', state, '--skill-dir', skill]);
  assert.equal(plain.code, 1);
  assert.match(plain.stdout, /FAIL state-permissions/);
  assert.equal(await modeOf(loose), 0o644);
  const fixed = await invokeCli(['verify-install', '--state-dir', state, '--skill-dir', skill, '--fix']);
  assert.equal(fixed.code, 0);
  assert.match(fixed.stdout, new RegExp(`fixed ${loose.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: 0o0644 -> 0o0600`));
  assert.match(fixed.stdout, /PASS state-permissions/);
  assert.match(fixed.stdout, /verify-install: 11 passed, 0 failed — PASS/);
  assert.equal(await modeOf(loose), 0o600);
});

test('required modes are the documented standard', () => {
  assert.equal(REQUIRED_FILE_MODE, 0o600);
  assert.equal(REQUIRED_DIR_MODE, 0o700);
});
