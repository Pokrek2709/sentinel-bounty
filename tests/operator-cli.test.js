const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

async function invoke(args, stateDirectory, token, hashFile, newToken) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, 'kill-switch', ...args, '--state-dir', stateDirectory], {
      env: {
        ...process.env,
        SENTINEL_OPERATOR_RESET_TOKEN: token,
        SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE: hashFile,
        SENTINEL_OPERATOR_NEW_RESET_TOKEN: newToken,
      },
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
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, `${crypto.createHash('sha256').update(token).digest('hex')}\n`, { mode: 0o600 });
    const initial = await invoke(['status'], directory);
    assert.equal(initial.code, 0);
    assert.deepEqual(parse(initial.stdout), { active: false, trigger: null, registeredWorkers: 0, workers: [], version: 2 });
    const health = await invoke(['audit-health'], directory);
    assert.equal(health.code, 0);
    assert.deepEqual(parse(health.stdout), { healthy: true, reservedStateBytes: 4096 });

    const triggered = await invoke(['trigger', '--actor', 'operator', '--reason', 'lab stop'], directory);
    assert.equal(triggered.code, 0);
    assert.equal(parse(triggered.stdout).triggered, true);

    const nextToken = 'operator-token-rotated-local-5678';
    const rotated = await invoke(['rotate-token', '--actor', 'operator'], directory, token, hashFile, nextToken);
    assert.equal(rotated.code, 0);
    assert.equal(parse(rotated.stdout).rotated, true);
    assert.equal(parse(rotated.stdout).auditLogged, true);
    const metadata = JSON.parse(await fs.readFile(hashFile, 'utf8'));
    assert.equal(metadata.version, 1);
    assert.equal(metadata.digest, crypto.createHash('sha256').update(nextToken).digest('hex'));
    assert.ok(Date.parse(metadata.validUntil) > Date.now());
    assert.equal(parse(rotated.stdout).validUntil, metadata.validUntil);

    const unauthorized = await invoke(['reset', '--actor', 'operator'], directory);
    assert.equal(unauthorized.code, 3);
    assert.equal(parse(unauthorized.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');
    assert.equal(unauthorized.stdout.includes(token), false);
    assert.equal(unauthorized.stderr.includes(token), false);

    const wrongToken = await invoke(['reset', '--actor', 'operator'], directory, 'wrong-token-that-is-long-enough-1234', hashFile);
    assert.equal(wrongToken.code, 3);
    assert.equal(parse(wrongToken.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');
    assert.equal(wrongToken.stdout.includes(token), false);

    const oldToken = await invoke(['reset', '--actor', 'operator'], directory, token, hashFile);
    assert.equal(oldToken.code, 3);
    assert.equal(parse(oldToken.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');

    const reset = await invoke(['reset', '--actor', 'operator'], directory, nextToken, hashFile);
    assert.equal(reset.code, 0);
    assert.equal(parse(reset.stdout).reset, true);
    assert.equal(parse(reset.stdout).auditLogged, true);
    const audit = await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8');
    assert.match(audit, /KILL_SWITCH_TRIGGER/);
    assert.match(audit, /KILL_SWITCH_TOKEN_ROTATED/);
    assert.match(audit, new RegExp(metadata.validUntil));
    assert.match(audit, /KILL_SWITCH_RESET/);
    assert.equal(audit.includes(token), false);
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

test('operator CLI rejects a symlinked reset-token digest file', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-link-'));
  const token = 'operator-token-for-local-lab-1234';
  const target = path.join(directory, 'real-token.sha256');
  const link = path.join(directory, 'linked-token.sha256');
  try {
    await fs.writeFile(target, `${crypto.createHash('sha256').update(token).digest('hex')}\n`, { mode: 0o600 });
    try {
      await fs.symlink(target, link, 'file');
    } catch (error) {
      t.skip(`symlink unavailable: ${error.code || error.message}`);
      return;
    }
    assert.equal((await invoke(['trigger', '--actor', 'operator', '--reason', 'lab stop'], directory)).code, 0);
    const reset = await invoke(['reset', '--actor', 'operator'], directory, token, link);
    assert.equal(reset.code, 3);
    assert.equal(parse(reset.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('operator CLI rejects an expired token metadata file', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-expired-'));
  const token = 'operator-token-for-local-lab-1234';
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, JSON.stringify({ version: 1, keyId: 'expired-key', digest: crypto.createHash('sha256').update(token).digest('hex'), validUntil: new Date(Date.now() - 1).toISOString() }), { mode: 0o600 });
    assert.equal((await invoke(['trigger', '--actor', 'operator', '--reason', 'lab stop'], directory)).code, 0);
    const reset = await invoke(['reset', '--actor', 'operator'], directory, token, hashFile);
    assert.equal(reset.code, 3);
    assert.equal(parse(reset.stdout).reason, 'RESET_OPERATOR_UNAUTHORIZED');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('serializes concurrent token rotations so exactly one writer wins', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-rotate-race-'));
  const token = 'operator-token-for-local-lab-1234';
  const nextA = 'operator-token-rotation-a-5678';
  const nextB = 'operator-token-rotation-b-9012';
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, `${crypto.createHash('sha256').update(token).digest('hex')}\n`, { mode: 0o600 });
    const results = await Promise.all([
      invoke(['rotate-token', '--actor', 'operator'], directory, token, hashFile, nextA),
      invoke(['rotate-token', '--actor', 'operator'], directory, token, hashFile, nextB),
    ]);
    assert.equal(results.filter((item) => item.code === 0).length, 1);
    assert.equal(results.filter((item) => item.code === 3).length, 1);
    const winner = results.find((item) => item.code === 0);
    const winnerToken = parse(winner.stdout).keyId ? (await fs.readFile(hashFile, 'utf8')).includes(crypto.createHash('sha256').update(nextA).digest('hex')) ? nextA : nextB : null;
    assert.ok(winnerToken);
    const audit = await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8');
    assert.equal((audit.match(/KILL_SWITCH_TOKEN_ROTATED/g) || []).length, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('revokes a token only after recording an audit event', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-revoke-'));
  const token = 'operator-token-for-local-lab-1234';
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, `${crypto.createHash('sha256').update(token).digest('hex')}\n`, { mode: 0o600 });
    const revoked = await invoke(['revoke-token', '--actor', 'operator'], directory, token, hashFile);
    assert.equal(revoked.code, 0);
    assert.equal(parse(revoked.stdout).revoked, true);
    assert.equal(parse(revoked.stdout).auditLogged, true);
    await assert.rejects(() => fs.stat(hashFile), { code: 'ENOENT' });
    const audit = await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8');
    assert.match(audit, /KILL_SWITCH_TOKEN_REVOKE_PENDING/);
    assert.match(audit, /KILL_SWITCH_TOKEN_REVOKED/);
    assert.equal(audit.includes(token), false);

    const second = await invoke(['revoke-token', '--actor', 'operator'], directory, token, hashFile);
    assert.equal(second.code, 3);
    assert.equal(parse(second.stdout).reason, 'RESET_TOKEN_ALREADY_REVOKED');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('revoke-token recovers an interrupted pending revocation idempotently', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-revoke-recovery-'));
  const token = 'operator-token-for-local-lab-1234';
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, `${crypto.createHash('sha256').update(token).digest('hex')}\n`, { mode: 0o600 });
    await fs.mkdir(directory, { recursive: true });
    await fs.writeFile(path.join(directory, 'audit.jsonl'), `${JSON.stringify({ version: 1, event: 'KILL_SWITCH_TOKEN_REVOKE_PENDING', eventId: 'pending-1', recordedAt: new Date().toISOString(), details: { actor: 'operator', keyId: 'legacy', requestedAt: new Date().toISOString() } })}\n`, { mode: 0o600 });
    const recovered = await invoke(['revoke-token', '--actor', 'operator'], directory, token, hashFile);
    assert.equal(recovered.code, 0);
    assert.equal(parse(recovered.stdout).revoked, true);
    assert.equal(parse(recovered.stdout).recovered, true);
    assert.equal((await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8')).match(/KILL_SWITCH_TOKEN_REVOKED/g).length, 1);
    await assert.rejects(() => fs.stat(hashFile), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
