const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

async function invoke(args, stateDirectory, token) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, 'kill-switch', ...args, '--state-dir', stateDirectory], {
      env: { ...process.env, ...(token === undefined ? { SENTINEL_OPERATOR_RESET_TOKEN: undefined } : { SENTINEL_OPERATOR_RESET_TOKEN: token }) },
      windowsHide: true,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function parse(stdout) {
  return JSON.parse(stdout);
}

test('operator CLI exposes status, trigger, and token-gated reset without printing the token', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-'));
  const token = 'operator-token-for-local-lab-1234';
  try {
    const initial = await invoke(['status'], directory);
    assert.equal(initial.code, 0);
    assert.deepEqual(parse(initial.stdout), { active: false, trigger: null, registeredWorkers: 0, version: 2 });

    const triggered = await invoke(['trigger', '--actor', 'operator', '--reason', 'lab stop'], directory);
    assert.equal(triggered.code, 0);
    assert.equal(parse(triggered.stdout).triggered, true);

    const unauthorized = await invoke(['reset', '--actor', 'operator'], directory);
    assert.equal(unauthorized.code, 3);
    assert.equal(parse(unauthorized.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');
    assert.equal(unauthorized.stdout.includes(token), false);
    assert.equal(unauthorized.stderr.includes(token), false);

    const reset = await invoke(['reset', '--actor', 'operator'], directory, token);
    assert.equal(reset.code, 0);
    assert.deepEqual(parse(reset.stdout), { reset: true });
    assert.equal(parse((await invoke(['status'], directory)).stdout).active, false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('operator CLI rejects a state directory inside the installed skill', async () => {
  const inside = path.resolve(__dirname, '..', 'state-cli-test');
  const result = await invoke(['status'], inside);
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /outside the skill directory/);
  await fs.rm(inside, { recursive: true, force: true });
});
