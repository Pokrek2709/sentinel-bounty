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
  // Round 91, Windows run for c4c9060 (log logs_124580440327,
  // supplied by the user): docker IS present on the
  // windows-2025-vs2026 runner but `docker --version` exits
  // non-zero, so a real probe reports not_verified ("Command failed:
  // docker --version"). That is a legitimate probe outcome — the
  // command was executed and its failure reported — not the
  // missing-runner error. The regression detector is the reason
  // guard below, not the status whitelist: any of the three probe
  // outcomes proves the default runner executed.
  const result = await checkTool('docker');
  assert.notEqual(result.detail?.reason, 'commandRunner is not a function');
  assert.ok(['verified', 'unavailable', 'not_verified'].includes(result.status), `unexpected status ${result.status}: ${JSON.stringify(result.detail)}`);
});

test('a command that runs but exits non-zero is not_verified, never unavailable', async () => {
  // Round 91: the c4c9060 Windows run failed because `docker
  // --version` spawns and exits non-zero on the runner. That must
  // stay not_verified (the command exists; its version probe failed),
  // not unavailable (which means "not found on PATH"). Pinning this
  // so no future change mislabels a present-but-broken tool as absent.
  const result = await checkCommand('docker', 'docker', ['--version'], async () => {
    const error = new Error('Command failed: docker --version\n');
    error.code = 1;
    throw error;
  });
  assert.equal(result.status, 'not_verified');
  assert.match(result.detail.reason, /Command failed: docker --version/);
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

test('Node floor constant matches package.json engines (drift guard)', async () => {
  // Round 97: the check-env audit (round 41) says the floor constant
  // "mirrors package.json engines and is covered by a test" — but no
  // test ever read package.json, so bumping engines without the
  // constant (or vice versa) would drift silently. Pin it.
  const pkg = JSON.parse(await fs.readFile(path.resolve(__dirname, '..', 'package.json'), 'utf8'));
  const match = /^>=(\d+)\.(\d+)\.(\d+)$/.exec(pkg.engines.node);
  assert.ok(match, `unexpected engines.node: ${pkg.engines.node}`);
  assert.equal(MIN_NODE_VERSION, `${match[1]}.${match[2]}.${match[3]}`);
  assert.equal(checkNodeVersion(`v${MIN_NODE_VERSION}`).status, 'verified');
});

test('Muse-like environment markers are reported, never treated as proof', async (t) => {
  // Round 97: detectMuseEnvironment's marker branch had no test —
  // the only coverage was the no-marker path (environment: {}).
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const withMarker = await runEnvironmentCheck({
      probeDirectory: directory,
      environment: { MUSE_TEST_MARKER: '1', PATH: process.env.PATH },
      commandRunner: async () => 'test-version',
      now: new Date('2026-01-01T00:00:00.000Z'),
      nodeVersion: 'v24.22.1',
    });
    assert.equal(withMarker.capabilities.museSecureVm.status, 'not_verified');
    assert.deepEqual(withMarker.capabilities.museSecureVm.detail.markers, ['MUSE_TEST_MARKER']);
    assert.match(withMarker.decision, /not verified/i);

    const withoutMarker = await runEnvironmentCheck({
      probeDirectory: directory,
      environment: {},
      commandRunner: async () => 'test-version',
      now: new Date('2026-01-01T00:00:00.000Z'),
      nodeVersion: 'v24.22.1',
    });
    assert.equal(withoutMarker.capabilities.museSecureVm.status, 'not_verified');
    assert.equal(withoutMarker.capabilities.museSecureVm.detail, undefined);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('checkFirstAvailableCommand fails closed when every candidate fails', async () => {
  // Round 97: only the success path (second candidate verifies) was
  // tested. The all-fail branches — all ENOENT means unavailable, a
  // mixed failure means not_verified — had no test.
  const allMissing = await checkFirstAvailableCommand('Missing', [['a', []], ['b', []]], async () => {
    const error = new Error('not found');
    error.code = 'ENOENT';
    throw error;
  });
  assert.equal(allMissing.status, 'unavailable');
  assert.equal(allMissing.detail.attempts.length, 2);

  const mixed = await checkFirstAvailableCommand('Mixed', [['a', []], ['b', []]], async (command) => {
    if (command === 'a') throw new Error('Command failed: a --version');
    const error = new Error('not found');
    error.code = 'ENOENT';
    throw error;
  });
  assert.equal(mixed.status, 'not_verified');
  assert.equal(mixed.detail.attempts[0].status, 'not_verified');
  assert.equal(mixed.detail.attempts[1].status, 'unavailable');
});

test('checkCommand treats NOT_FOUND like ENOENT (unavailable, never not_verified)', async () => {
  // Round 97: only the ENOENT code was tested; the NOT_FOUND code
  // takes the same branch and had no test.
  const result = await checkCommand('missing', 'missing', [], async () => {
    const error = new Error('not found');
    error.code = 'NOT_FOUND';
    throw error;
  });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.detail.reason, 'Command was not found on PATH.');
});

test('storage probe fails closed when the probe directory cannot be created', async (t) => {
  // Round 97: only the success path (write, read back, persistence
  // on a second call) was tested. A probe directory through a file
  // must report unavailable with the reason, not throw.
  const directory = await makeTempDir(t, 'sentinel-env-');
  try {
    const blocker = path.join(directory, 'blocker');
    await fs.writeFile(blocker, 'not a directory');
    const result = await checkStorage(path.join(blocker, 'sub'), new Date('2026-01-01T00:00:00.000Z'));
    assert.equal(result.status, 'unavailable');
    assert.match(result.detail.reason, /ENOTDIR/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
