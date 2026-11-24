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
    assert.equal(parse(revoked.stdout).recovered, false);
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

test('revoke-token allows a newly provisioned key after an older key was revoked', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-revoke-sequential-'));
  const tokenA = 'operator-token-first-generation-1234';
  const tokenB = 'operator-token-second-generation-5678';
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  try {
    await fs.writeFile(hashFile, JSON.stringify({
      version: 1,
      keyId: 'key-a',
      digest: crypto.createHash('sha256').update(tokenA).digest('hex'),
      validUntil: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    }) + '\n', { mode: 0o600 });
    const revokedA = await invoke(['revoke-token', '--actor', 'operator'], directory, tokenA, hashFile);
    assert.equal(revokedA.code, 0);
    assert.equal(parse(revokedA.stdout).keyId, 'key-a');

    await fs.writeFile(hashFile, JSON.stringify({
      version: 1,
      keyId: 'key-b',
      digest: crypto.createHash('sha256').update(tokenB).digest('hex'),
      validUntil: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    }) + '\n', { mode: 0o600 });
    const revokedB = await invoke(['revoke-token', '--actor', 'operator'], directory, tokenB, hashFile);
    assert.equal(revokedB.code, 0);
    assert.equal(parse(revokedB.stdout).keyId, 'key-b');
    assert.equal(parse(revokedB.stdout).revoked, true);
    await assert.rejects(() => fs.stat(hashFile), { code: 'ENOENT' });

    const events = (await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8'))
      .trim().split('\n').map((line) => JSON.parse(line));
    const revokedEvents = events.filter((event) => event.event === 'KILL_SWITCH_TOKEN_REVOKED');
    assert.deepEqual(revokedEvents.map((event) => event.details.keyId), ['key-a', 'key-b']);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('revoke-token recovers an older pending marker hidden by a newer completed marker', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-revoke-shadowed-'));
  const hashFile = path.join(directory, 'operator-reset-token.sha256');
  const recordedAt = new Date().toISOString();
  const event = (eventId, name, keyId) => JSON.stringify({ version: 1, event: name, eventId, recordedAt, details: { actor: 'operator', keyId, requestedAt: recordedAt } });
  try {
    await fs.mkdir(directory, { recursive: true });
    await fs.writeFile(path.join(directory, 'audit.jsonl'), [
      event('pending-b', 'KILL_SWITCH_TOKEN_REVOKE_PENDING', 'key-b'),
      event('pending-a', 'KILL_SWITCH_TOKEN_REVOKE_PENDING', 'key-a'),
      event('revoked-a', 'KILL_SWITCH_TOKEN_REVOKED', 'key-a'),
    ].join('\n') + '\n', { mode: 0o600 });
    const recovered = await invoke(['revoke-token', '--actor', 'operator'], directory, 'not-used-for-recovery', hashFile);
    assert.equal(recovered.code, 0);
    assert.equal(parse(recovered.stdout).keyId, 'key-b');
    assert.equal(parse(recovered.stdout).recovered, true);
    const events = (await fs.readFile(path.join(directory, 'audit.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(events.filter((item) => item.event === 'KILL_SWITCH_TOKEN_REVOKED' && item.details.keyId === 'key-b').length, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('status falls back to a lockless read on a full disk', async (t) => {
  const mountPoint = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-cli-full-disk-'));
  const mount = async () => execFileAsync('mount', ['-t', 'tmpfs', '-o', 'size=64k', 'tmpfs', mountPoint]);
  const unmount = async () => execFileAsync('umount', [mountPoint]).catch(() => {});
  try {
    try {
      await mount();
    } catch (error) {
      t.skip(`tmpfs mount unavailable: ${error.code || error.message}`);
      return;
    }
    const directory = path.join(mountPoint, 'state');
    await fs.mkdir(directory, { recursive: true });
    const now = Date.now();
    await fs.writeFile(path.join(directory, 'kill-switch.json'), JSON.stringify({
      version: 2,
      active: true,
      trigger: { triggerId: 'full-disk-lab', triggeredBy: 'operator', reason: 'lab stop', triggeredAt: now - 60000 },
      workers: [
        { workerId: 'live-worker', pid: 1111, leaseExpiresAt: now + 60000 },
        { workerId: 'expired-worker', pid: 2222, leaseExpiresAt: now - 60000 },
      ],
    }), { mode: 0o600 });
    const chunk = Buffer.alloc(4096, 0x61);
    let filler = 0;
    try {
      for (;;) {
        await fs.writeFile(path.join(mountPoint, `filler-${filler}.bin`), chunk, { flag: 'wx' });
        filler += 1;
      }
    } catch (error) {
      assert.equal(error.code, 'ENOSPC');
    }
    const result = await invoke(['status'], directory);
    assert.equal(result.code, 0);
    const status = parse(result.stdout);
    assert.equal(status.active, true);
<<<<<<< HEAD
=======
    // Canonical lockless shape (ronde 24): one fallback path inside
    // snapshot(), so the CLI no longer adds fallbackReason.
>>>>>>> b4c6fa68713854a411c9307660be6d1254534ee4
    assert.equal(status.readMode, 'LOCKLESS_FALLBACK');
    assert.equal(status.lockless, true);
    assert.equal(status.pruned, false);
    assert.equal(status.fallbackReason, undefined);
    assert.equal(status.registeredWorkers, 1);
    assert.equal(status.workers.find((worker) => worker.workerId === 'live-worker').leaseExpired, false);
    assert.equal(status.workers.find((worker) => worker.workerId === 'expired-worker').leaseExpired, true);
    assert.deepEqual((await fs.readdir(directory)).sort(), ['kill-switch.json']);
  } finally {
    await unmount();
    await fs.rm(mountPoint, { recursive: true, force: true });
  }
});

test('skill and v1 docs carry no merge-conflict markers and document the canonical lockless shape', async () => {
  for (const relative of ['skills/sentinel-bounty/SKILL.md', 'docs/persistent-kill-switch-v1.md']) {
    const text = await fs.readFile(path.resolve(__dirname, '..', relative), 'utf8');
    for (const line of text.split('\n')) {
      assert.ok(!line.startsWith('<<<<<<<') && !line.startsWith('>>>>>>>') && line !== '=======', `${relative} still contains a merge-conflict marker: ${line}`);
    }
    assert.ok(text.includes('readMode: LOCKLESS_FALLBACK'), `${relative} must document readMode: LOCKLESS_FALLBACK`);
    assert.ok(text.includes('KILL_SWITCH_STATE_LOCKED'), `${relative} must document the live-lock refusal`);
  }
});
