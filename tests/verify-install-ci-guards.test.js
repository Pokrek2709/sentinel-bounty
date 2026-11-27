// verify-install ci-guards check tests (round 99).
//
// The ci-guards check is a consistency check, not a presence check:
// a skill with none of the guard files passes vacuously (an installed
// single-copy layout may ship without .github/ or scripts/), and what
// fails is inconsistency — a workflow pointing at the /tmp preload,
// a workflow that never runs the simulation, a preload that does not
// override the platform, or a guard script that does not parse.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');

const { makeTempDir } = require('./helpers/temp-dir');
const { runVerifyInstall } = require('../src/install/verifier');

const REPO_ROOT = path.resolve(__dirname, '..');

async function makeSkillRoot(directory) {
  await fs.mkdir(path.join(directory, 'bin'), { recursive: true });
  await fs.mkdir(path.join(directory, 'config'), { recursive: true });
  await fs.mkdir(path.join(directory, 'skills', 'sentinel-bounty'), { recursive: true });
  await fs.writeFile(path.join(directory, 'bin', 'sentinel.js'), '#!/usr/bin/env node\n', { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'config', 'environment-tools.json'), JSON.stringify({ version: '1.0.0', tools: ['docker'] }), { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'skills', 'sentinel-bounty', 'SKILL.md'), '# Sentinel Bounty\n', { mode: 0o600 });
}

async function makeStateDirectory(directory) {
  await fs.mkdir(directory, { recursive: true });
  await fs.chmod(directory, 0o700);
}

async function writeGuardFiles(skillDirectory, { workflow, preload, prePush, fetchLogs } = {}) {
  if (workflow !== undefined) {
    await fs.mkdir(path.join(skillDirectory, '.github', 'workflows'), { recursive: true });
    await fs.writeFile(path.join(skillDirectory, '.github', 'workflows', 'ci-guards.yml'), workflow);
  }
  if (preload !== undefined) {
    await fs.mkdir(path.join(skillDirectory, 'scripts'), { recursive: true });
    await fs.writeFile(path.join(skillDirectory, 'scripts', 'fake-win32.cjs'), preload);
  }
  if (prePush !== undefined) {
    await fs.mkdir(path.join(skillDirectory, 'scripts'), { recursive: true });
    await fs.writeFile(path.join(skillDirectory, 'scripts', 'pre-push-check.cjs'), prePush);
  }
  if (fetchLogs !== undefined) {
    await fs.mkdir(path.join(skillDirectory, 'scripts'), { recursive: true });
    await fs.writeFile(path.join(skillDirectory, 'scripts', 'fetch-windows-logs.cjs'), fetchLogs);
  }
}

const GOOD_WORKFLOW = 'name: ci-guards\njobs:\n  ci-guards:\n    runs-on: ubuntu-latest\n    steps:\n      - run: node --test --require ./scripts/fake-win32.cjs\n';
const GOOD_PRELOAD = "'use strict';\nObject.defineProperty(process, 'platform', { value: 'win32' });\n";
const GOOD_SCRIPT = "'use strict';\nmodule.exports = {};\n";

async function ciGuardsCheck(t, guardFiles) {
  const base = await makeTempDir(t, 'sentinel-ci-guards-');
  const skillDirectory = path.join(base, 'skill');
  const stateDirectory = path.join(base, 'state');
  await makeSkillRoot(skillDirectory);
  await makeStateDirectory(stateDirectory);
  await writeGuardFiles(skillDirectory, guardFiles);
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  return result.checks.find((check) => check.id === 'ci-guards');
}

test('ci-guards check passes vacuously when no guard files are present', async (t) => {
  const check = await ciGuardsCheck(t, {});
  assert.equal(check.status, 'PASS');
  assert.match(check.reason, /nothing to verify/);
});

test('ci-guards check passes when all guard files are present and consistent', async (t) => {
  const check = await ciGuardsCheck(t, {
    workflow: GOOD_WORKFLOW, preload: GOOD_PRELOAD, prePush: GOOD_SCRIPT, fetchLogs: GOOD_SCRIPT,
  });
  assert.equal(check.status, 'PASS');
});

test('ci-guards check fails when the workflow references the /tmp preload', async (t) => {
  const check = await ciGuardsCheck(t, {
    workflow: GOOD_WORKFLOW.replace('./scripts/fake-win32.cjs', '/tmp/fake-win32.cjs'),
    preload: GOOD_PRELOAD,
  });
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /\/tmp\/fake-win32\.cjs/);
});

test('ci-guards check fails when the workflow never runs the simulation', async (t) => {
  const check = await ciGuardsCheck(t, {
    workflow: 'name: ci-guards\njobs:\n  ci-guards:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n',
    preload: GOOD_PRELOAD,
  });
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /does not run the Windows simulation/);
});

test('ci-guards check fails when the preload does not override the platform', async (t) => {
  const check = await ciGuardsCheck(t, {
    workflow: GOOD_WORKFLOW,
    preload: "'use strict';\n// no override here\n",
  });
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /does not override process\.platform/);
});

test('ci-guards check fails when a guard script does not parse', async (t) => {
  const check = await ciGuardsCheck(t, {
    workflow: GOOD_WORKFLOW, preload: GOOD_PRELOAD, prePush: "'use strict';\nconst broken = ;\n",
  });
  assert.equal(check.status, 'FAIL');
  assert.match(check.reason, /pre-push-check\.cjs does not parse/);
});

test('ci-guards check passes on the real repo guard files', async (t) => {
  const base = await makeTempDir(t, 'sentinel-ci-guards-');
  const stateDirectory = path.join(base, 'state');
  await makeStateDirectory(stateDirectory);
  const result = await runVerifyInstall({ skillDirectory: REPO_ROOT, stateDirectory });
  const check = result.checks.find((c) => c.id === 'ci-guards');
  assert.equal(check.status, 'PASS', check.reason);
});
