const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const { runVerifyInstall } = require('../src/install/verifier');

async function invoke(args, env = {}) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, 'verify-install', ...args], {
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// A minimal well-formed skill root: entrypoint, scope config, skill doc.
async function makeSkillRoot(directory) {
  await fs.mkdir(path.join(directory, 'bin'), { recursive: true });
  await fs.mkdir(path.join(directory, 'config'), { recursive: true });
  await fs.mkdir(path.join(directory, 'skills', 'sentinel-bounty'), { recursive: true });
  await fs.writeFile(path.join(directory, 'bin', 'sentinel.js'), '#!/usr/bin/env node\n', { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'config', 'environment-tools.json'), JSON.stringify({ version: '1.0.0', tools: ['docker'] }), { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'skills', 'sentinel-bounty', 'SKILL.md'), '# Sentinel Bounty\n', { mode: 0o600 });
}

async function makeStateDirectory(directory, { killSwitch, audit } = {}) {
  await fs.mkdir(directory, { recursive: true });
  // Fixtures comply with the round-45 permission standard (state
  // directory 0700); mkdir alone would leave 0770 under umask 0007.
  await fs.chmod(directory, 0o700);
  if (killSwitch !== undefined) {
    await fs.writeFile(path.join(directory, 'kill-switch.json'), typeof killSwitch === 'string' ? killSwitch : JSON.stringify(killSwitch), { mode: 0o600 });
  }
  if (audit !== undefined) {
    await fs.writeFile(path.join(directory, 'audit.jsonl'), audit, { mode: 0o600 });
  }
}

async function snapshotTree(directory) {
  const entries = [];
  async function walk(current) {
    let names;
    try {
      names = await fs.readdir(current);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const name of names.sort()) {
      const full = path.join(current, name);
      const stat = await fs.stat(full);
      entries.push(stat.isDirectory() ? `${path.relative(directory, full)}/` : path.relative(directory, full));
      if (stat.isDirectory()) await walk(full);
    }
  }
  await walk(directory);
  return entries;
}

test('verify-install passes on a well-formed install with inactive kill-switch', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
    audit: `${JSON.stringify({ version: 1, event: 'KILL_SWITCH_RESET', eventId: 'x', recordedAt: new Date().toISOString(), details: {} })}\n`,
  });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.overall, 'PASS');
  assert.equal(result.passed, 7);
  assert.equal(result.failed, 0);
  assert.deepEqual(result.checks.map((check) => check.id), ['node-version', 'cli-reachable', 'kill-switch', 'audit-log', 'state-permissions', 'scope-config', 'skill-files']);
  assert.ok(result.checks.every((check) => check.status === 'PASS' && typeof check.reason === 'string' && check.reason.length > 0));
});

test('verify-install passes with no state files yet', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await fs.mkdir(stateDirectory, { recursive: true });
  await fs.chmod(stateDirectory, 0o700);
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.overall, 'PASS');
  assert.equal(result.checks.find((check) => check.id === 'kill-switch').reason, 'No kill-switch state file exists yet; kill-switch is inactive.');
  assert.equal(result.checks.find((check) => check.id === 'audit-log').reason, 'No audit log exists yet; nothing to verify.');
});

test('verify-install fails the node check below version 18', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory);
  const result = await runVerifyInstall({ skillDirectory, stateDirectory, nodeVersion: 'v16.20.2' });
  assert.equal(result.overall, 'FAIL');
  assert.equal(result.failed, 1);
  assert.match(result.checks.find((check) => check.id === 'node-version').reason, /below the >= 18 requirement/);
});

test('verify-install fails an armed kill-switch and explains it must be reviewed', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, {
    killSwitch: { version: 2, active: true, trigger: { triggeredBy: 'operator', reason: 'lab stop' }, workers: [] },
  });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.overall, 'FAIL');
  const check = result.checks.find((item) => item.id === 'kill-switch');
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /Kill-switch is ACTIVE/);
  assert.match(check.reason, /lab stop/);
  assert.match(check.reason, /must be reviewed/);
});

test('verify-install fails a corrupt kill-switch state instead of passing it as inactive', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, { killSwitch: '{not json' });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  const check = result.checks.find((item) => item.id === 'kill-switch');
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /KILL_SWITCH_STATE_CORRUPT/);
});

test('verify-install fails a corrupt audit log', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, { audit: '{"event": "OK"}\n{broken\n' });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  const check = result.checks.find((item) => item.id === 'audit-log');
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /AUDIT_LOG_CORRUPT/);
});

test('verify-install fails a missing entrypoint, scope config, and skill file', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory);
  await fs.unlink(path.join(skillDirectory, 'bin', 'sentinel.js'));
  await fs.unlink(path.join(skillDirectory, 'config', 'environment-tools.json'));
  await fs.unlink(path.join(skillDirectory, 'skills', 'sentinel-bounty', 'SKILL.md'));
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.overall, 'FAIL');
  assert.equal(result.failed, 3);
  assert.match(result.checks.find((check) => check.id === 'cli-reachable').reason, /missing/);
  assert.match(result.checks.find((check) => check.id === 'scope-config').reason, /missing/);
  assert.match(result.checks.find((check) => check.id === 'skill-files').reason, /missing/);
});

test('verify-install accepts SKILL.md at the installed-copy root', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory);
  await fs.rm(path.join(skillDirectory, 'skills'), { recursive: true, force: true });
  await fs.writeFile(path.join(skillDirectory, 'SKILL.md'), '# Sentinel Bounty\n', { mode: 0o600 });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.checks.find((check) => check.id === 'skill-files').status, 'PASS');
  assert.match(result.checks.find((check) => check.id === 'skill-files').reason, /SKILL\.md is present/);
});

test('verify-install fails invalid scope-config JSON', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory);
  await fs.writeFile(path.join(skillDirectory, 'config', 'environment-tools.json'), '{broken', { mode: 0o600 });
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.checks.find((check) => check.id === 'scope-config').status, 'FAIL');
  assert.match(result.checks.find((check) => check.id === 'scope-config').reason, /not valid JSON/);
});

test('verify-install writes nothing to the skill or state directories', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
    audit: `${JSON.stringify({ version: 1, event: 'OK', eventId: 'x', recordedAt: new Date().toISOString(), details: {} })}\n`,
  });
  const beforeSkill = await snapshotTree(skillDirectory);
  const beforeState = await snapshotTree(stateDirectory);
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  assert.equal(result.overall, 'PASS');
  assert.deepEqual(await snapshotTree(skillDirectory), beforeSkill);
  assert.deepEqual(await snapshotTree(stateDirectory), beforeState);
});

test('CLI verify-install exits 0 with one PASS line per check on a good install', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
  });
  const beforeState = await snapshotTree(stateDirectory);
  const result = await invoke(['--skill-dir', skillDirectory, '--state-dir', stateDirectory]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /^PASS node-version: /m);
  assert.match(result.stdout, /^PASS cli-reachable: /m);
  assert.match(result.stdout, /^PASS kill-switch: /m);
  assert.match(result.stdout, /^PASS audit-log: /m);
  assert.match(result.stdout, /^PASS state-permissions: /m);
  assert.match(result.stdout, /^PASS scope-config: /m);
  assert.match(result.stdout, /^PASS skill-files: /m);
  assert.match(result.stdout, /verify-install: 7 passed, 0 failed — PASS/);
  assert.deepEqual(await snapshotTree(stateDirectory), beforeState);
});

test('CLI verify-install exits non-zero with FAIL lines on a broken install', async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-verify-'));
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory, {
    killSwitch: { version: 2, active: true, trigger: { triggeredBy: 'operator', reason: 'lab stop' }, workers: [] },
    audit: '{broken\n',
  });
  await fs.unlink(path.join(skillDirectory, 'skills', 'sentinel-bounty', 'SKILL.md'));
  const result = await invoke(['--skill-dir', skillDirectory, '--state-dir', stateDirectory]);
  assert.notEqual(result.code, 0);
  assert.match(result.stdout, /^FAIL kill-switch: Kill-switch is ACTIVE/m);
  assert.match(result.stdout, /^FAIL audit-log: /m);
  assert.match(result.stdout, /^FAIL skill-files: /m);
  assert.match(result.stdout, /verify-install: 4 passed, 3 failed — FAIL/);
});
