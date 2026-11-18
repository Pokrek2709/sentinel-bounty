const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { checkCommand, checkFirstAvailableCommand, checkStorage, runEnvironmentCheck } = require('../src/environment/checker');

test('reports unavailable when a command cannot be found', async () => {
  const result = await checkCommand('missing', 'missing', [], async () => {
    const error = new Error('not found');
    error.code = 'ENOENT';
    throw error;
  });
  assert.equal(result.status, 'unavailable');
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

test('verifies local storage and verifies persistence on a subsequent invocation', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-env-'));
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

test('environment report is explicitly non-networked and does not assert Muse verification', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-env-'));
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
