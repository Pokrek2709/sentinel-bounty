const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const {
  checkCommand,
  checkFirstAvailableCommand,
  checkNodeVersion,
  checkProcessTermination,
  checkStorage,
  checkTool,
  loadToolNames,
  runEnvironmentCheck,
  MIN_NODE_VERSION,
  TOOL_DEFINITIONS,
} = require('../src/environment/checker');

const REPO_CONFIG_PATH = path.resolve(__dirname, '..', 'config', 'environment-tools.json');

test('reports unavailable when a command cannot be found', async () => {
  const result = await checkCommand('missing', 'missing', [], async () => {
    const error = new Error('not found');
    error.code = 'ENOENT';
    throw error;
  });
  assert.equal(result.status, 'unavailable');
});

test('Node.js below the documented minimum is not_verified with the floor named', async () => {
  const result = checkNodeVersion('v16.20.2');
  assert.equal(result.status, 'not_verified');
  assert.equal(result.detail.minimumVersion, MIN_NODE_VERSION);
  assert.match(result.detail.reason, /18\.0\.0 or later is required/);
  assert.equal(checkNodeVersion('v18.0.0').status, 'verified');
  assert.equal(checkNodeVersion('v24.22.1').status, 'verified');
  assert.equal(checkNodeVersion('not-a-version').status, 'not_verified');
});

test('runEnvironmentCheck enforces the Node minimum through the runtime capability', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const report = await runEnvironmentCheck({
      probeDirectory: directory,
      environment: {},
      commandRunner: async () => 'test-version',
      now: new Date('2026-01-01T00:00:00.000Z'),
      nodeVersion: 'v16.0.0',
    });
    assert.equal(report.capabilities.runtime.status, 'not_verified');
    assert.equal(report.capabilities.runtime.detail.minimumVersion, MIN_NODE_VERSION);
    assert.equal(report.capabilities.runtime.detail.platform, process.platform);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('unavailable tools carry a purpose and an install hint', async () => {
  const result = await checkTool('docker', async () => {
    const error = new Error('not found');
    error.code = 'ENOENT';
    throw error;
  });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.detail.purpose, TOOL_DEFINITIONS.docker.purpose);
  assert.equal(result.detail.installHint, TOOL_DEFINITIONS.docker.installHint);
  assert.equal(result.detail.caveat, TOOL_DEFINITIONS.docker.caveat);
});

test('checkTool without a runner still probes the real command (default runner)', async () => {
  // Round 83, Windows run 54: operator-status's probeTools called
  // checkTool(name) with no runner, so every tool silently reported
  // not_verified ("commandRunner is not a function") and `sentinel
  // status` always showed 0 tools available. A real probe either
  // verifies the tool or fails with ENOENT (unavailable) — it never
  // fails for a missing runner.
  const result = await checkTool('docker');
  assert.notEqual(result.detail?.reason, 'commandRunner is not a function');
  assert.ok(['verified', 'unavailable'].includes(result.status), `unexpected status ${result.status}: ${JSON.stringify(result.detail)}`);
});

test('a tool listed in the config without a checker definition is not_verified, never skipped', async () => {
  const result = await checkTool('definitely-not-a-tool', async () => 'x');
  assert.equal(result.status, 'not_verified');
  assert.match(result.detail.reason, /No version command is defined/);
});

test('tool list is loaded from the config file; a missing config falls back to built-ins', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const configPath = path.join(directory, 'environment-tools.json');
    await fs.writeFile(configPath, JSON.stringify({ version: '1.0.0', tools: ['docker'] }));
    const fromConfig = await loadToolNames(configPath);
    assert.equal(fromConfig.source, 'config');
    assert.deepEqual(fromConfig.names, ['docker']);

    const missing = await loadToolNames(path.join(directory, 'no-such-file.json'));
    assert.equal(missing.source, 'fallback');
    assert.deepEqual(missing.names, Object.keys(TOOL_DEFINITIONS));
    assert.match(missing.reason, /not found/);

    await fs.writeFile(configPath, '{broken');
    const broken = await loadToolNames(configPath);
    assert.equal(broken.source, 'fallback');
    assert.match(broken.reason, /not valid JSON/);

    await fs.writeFile(configPath, JSON.stringify({ version: '1.0.0', tools: 'docker' }));
    const badShape = await loadToolNames(configPath);
    assert.equal(badShape.source, 'fallback');
    assert.match(badShape.reason, /unexpected shape/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('runEnvironmentCheck reports the tool-config source and checks only the configured tools', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const configPath = path.join(directory, 'environment-tools.json');
    await fs.writeFile(configPath, JSON.stringify({ version: '1.0.0', tools: ['docker', 'katana'] }));
    const report = await runEnvironmentCheck({
      probeDirectory: directory,
      environment: {},
      commandRunner: async () => { const error = new Error('not found'); error.code = 'ENOENT'; throw error; },
      now: new Date('2026-01-01T00:00:00.000Z'),
      configPath,
    });
    assert.deepEqual(Object.keys(report.capabilities.tools), ['docker', 'katana']);
    assert.equal(report.capabilities.toolConfiguration.status, 'verified');
    assert.equal(report.capabilities.toolConfiguration.detail.source, 'config');
    assert.equal(report.capabilities.tools.docker.detail.installHint, TOOL_DEFINITIONS.docker.installHint);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('built-in tool definitions match the documented config tool list (drift guard)', async () => {
  const loaded = await loadToolNames(REPO_CONFIG_PATH);
  assert.equal(loaded.source, 'config');
  assert.deepEqual([...loaded.names].sort(), Object.keys(TOOL_DEFINITIONS).sort());
});

test('process-termination probe verifies the kill-switch machinery in an isolated directory', async () => {
  const result = await checkProcessTermination({ skillDirectory: path.resolve(__dirname, '..') });
  assert.equal(result.status, 'verified');
  assert.equal(result.detail.mechanism, 'persistent-kill-switch');
  assert.equal(result.detail.active, false);
  assert.equal(result.detail.registeredWorkers, 0);
  assert.equal(result.detail.endToEndProof, 'sentinel drill');
});

test('process-termination probe fails closed when the probe state cannot sit outside the skill directory', async () => {
  // The probe state lives under os.tmpdir(); a skill directory of the
  // filesystem root contains it, so the constructor must refuse.
  const result = await checkProcessTermination({ skillDirectory: path.parse(os.tmpdir()).root });
  assert.equal(result.status, 'not_verified');
  assert.match(result.detail.reason, /outside the skill directory/);
});

test('uses python3 when python is unavailable', async () => {
  const result = await checkFirstAvailableCommand('Python', [['python', ['--version']], ['python3', ['--version']]], async (command) => {
    if (command === 'python') {
      const error = new Error('not found');
      error.code = 'ENOENT';
      throw error;
    }
    return 'Python 3.12.3';
  });
  assert.equal(result.status, 'verified');
  assert.equal(result.detail.command, 'python3');
  assert.deepEqual(result.detail.attempts, [
    { command: 'python', status: 'unavailable', reason: 'Command was not found on PATH.' },
    { command: 'python3', status: 'verified' },
  ]);
});

test('verifies local storage and verifies persistence on a subsequent invocation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const first = await checkStorage(directory, new Date('2026-01-01T00:00:00.000Z'));
    const second = await checkStorage(directory, new Date('2026-01-02T00:00:00.000Z'));
    assert.equal(first.status, 'verified');
    assert.equal(first.detail.persistence.status, 'not_verified');
    assert.equal(second.detail.persistence.status, 'verified');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('environment report is explicitly non-networked and does not assert Muse verification', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const report = await runEnvironmentCheck({
      probeDirectory: directory,
      environment: {},
      commandRunner: async () => 'test-version',
      now: new Date('2026-01-01T00:00:00.000Z'),
    });
    assert.equal(report.safety.networkRequestsMade, 0);
    assert.equal(report.capabilities.network.status, 'not_tested');
    assert.equal(report.capabilities.museSecureVm.status, 'not_verified');
    assert.match(report.decision, /not verified/i);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
