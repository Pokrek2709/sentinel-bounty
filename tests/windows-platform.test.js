'use strict';

// Windows platform behavior (round 81).
//
// The `windows-test` workflow failed on all 53 runs since round 28
// because the suite asserted POSIX permission bits that do not exist
// on Windows: Node reports every regular file as 0666 and every
// directory as 0777 there, and `fs.chmod` is a no-op except for
// the read-only bit. This file pins the platform branching that
// fixes it, so a future edit cannot silently reintroduce a
// POSIX-only assertion.
//
// Tests in this file fall in two groups:
//  - platform-independent (run everywhere): `posixModesApply`
//    and the private-mode helper's POSIX enforcement.
//  - win32-only (skipped on POSIX): the audit/repair/
//    verify-install behavior on Windows. They cannot run on the
//    Linux lab — they are verified by the Windows CI run itself,
//    which is exactly the run this round fixes.

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateMode, assertPrivateModeSync } = require('./helpers/private-mode');
const {
  posixModesApply,
  auditStatePermissions,
  repairStatePermissions,
} = require('../src/policy/state-permissions');
const { runVerifyInstall, checkStatePermissions } = require('../src/install/verifier');

const IS_WIN32 = process.platform === 'win32';

test('posixModesApply: false on win32, true on POSIX platforms', () => {
  assert.equal(posixModesApply('win32'), false);
  assert.equal(posixModesApply('linux'), true);
  assert.equal(posixModesApply('darwin'), true);
  assert.equal(posixModesApply('freebsd'), true);
  assert.equal(posixModesApply(), process.platform !== 'win32');
});

test('audit result carries posixModes matching the current platform', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-posixmodes-');
  const audit = await auditStatePermissions(dir);
  assert.equal(audit.posixModes, process.platform !== 'win32');
  assert.deepEqual(audit.violations, []);
});

test('private-mode helper enforces exact modes on POSIX', { skip: IS_WIN32 }, async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-helper-');
  const loose = path.join(dir, 'loose.txt');
  await fs.writeFile(loose, 'x');
  await fs.chmod(loose, 0o644);
  // The strict-equal message prints decimal modes (420 !== 384),
  // so match the error type, not an octal literal in the text.
  const isAssertion = (error) => error && error.code === 'ERR_ASSERTION';
  await assert.rejects(assertPrivateMode(loose, 0o600), isAssertion);
  assert.throws(() => assertPrivateModeSync(loose, 0o600), isAssertion);
  await fs.chmod(loose, 0o600);
  await assertPrivateMode(loose, 0o600);
  assertPrivateModeSync(loose, 0o600);
  const sub = path.join(dir, 'sub');
  await fs.mkdir(sub);
  await fs.chmod(sub, 0o700);
  await assertPrivateMode(sub, 0o700);
  assertPrivateModeSync(sub, 0o700);
  // makeTempDir itself creates 0700, so the negative directory
  // case needs its own loose directory.
  const looseDir = path.join(dir, 'loose-dir');
  await fs.mkdir(looseDir);
  await fs.chmod(looseDir, 0o755);
  await assert.rejects(assertPrivateMode(looseDir, 0o700), isAssertion);
});

test('private-mode helper accepts a normal file on Windows', { skip: !IS_WIN32 }, async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-helper-');
  const file = path.join(dir, 'normal.txt');
  await fs.writeFile(file, 'x');
  // Node reports this file as 0666 on Windows; the helper must not
  // fail it for not being 0600 — there is no 0600 on Windows.
  await assertPrivateMode(file, 0o600);
  assertPrivateModeSync(file, 0o600);
  await assertPrivateMode(dir, 0o700);
  assertPrivateModeSync(dir, 0o700);
});

test('audit on Windows reports no POSIX mode violations for a normal state dir', { skip: !IS_WIN32 }, async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-audit-');
  const stateDir = path.join(dir, 'state');
  await fs.mkdir(stateDir, { recursive: true });
  await fs.writeFile(path.join(stateDir, 'kill-switch.json'), '{}');
  const audit = await auditStatePermissions(stateDir);
  assert.equal(audit.posixModes, false);
  assert.deepEqual(audit.violations, []);
});

test('repair on Windows has no mode to tighten and reports nothing repaired', { skip: !IS_WIN32 }, async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-repair-');
  const stateDir = path.join(dir, 'state');
  await fs.mkdir(stateDir, { recursive: true });
  await fs.writeFile(path.join(stateDir, 'kill-switch.json'), '{}');
  const repair = await repairStatePermissions(stateDir);
  assert.deepEqual(repair.repaired, []);
  assert.deepEqual(repair.refused, []);
});

test('verify-install state-permissions passes on Windows for a normal state dir', { skip: !IS_WIN32 }, async (t) => {
  const dir = await makeTempDir(t, 'sentinel-win32-verify-');
  const skill = path.join(dir, 'skill');
  const state = path.join(dir, 'state');
  await fs.mkdir(path.join(skill, 'bin'), { recursive: true });
  await fs.mkdir(path.join(skill, 'config'), { recursive: true });
  await fs.mkdir(path.join(skill, 'skills', 'sentinel-bounty'), { recursive: true });
  await fs.writeFile(path.join(skill, 'bin', 'sentinel.js'), '#!/usr/bin/env node\n');
  await fs.writeFile(path.join(skill, 'config', 'environment-tools.json'), JSON.stringify({ version: '1.0.0', tools: ['docker'] }));
  await fs.writeFile(path.join(skill, 'skills', 'sentinel-bounty', 'SKILL.md'), '# Sentinel Bounty\n');
  await fs.mkdir(state, { recursive: true });
  await fs.writeFile(path.join(state, 'kill-switch.json'), JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }));
  const check = await checkStatePermissions(state);
  assert.equal(check.status, 'PASS');
  const rerun = await runVerifyInstall({ skillDirectory: skill, stateDirectory: state });
  assert.equal(rerun.checks.find((c) => c.id === 'state-permissions').status, 'PASS');
});
