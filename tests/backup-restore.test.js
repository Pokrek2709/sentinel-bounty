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

async function invoke(args) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function parse(stdout) {
  return JSON.parse(stdout);
}

async function triggerState(directory) {
  const triggered = await invoke(['kill-switch', 'trigger', '--actor', 'operator', '--reason', 'lab stop', '--state-dir', directory]);
  assert.equal(triggered.code, 0, `trigger must succeed: ${triggered.stdout} ${triggered.stderr}`);
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

test('backup round-trips an armed state: wipe then restore leaves identical state', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-roundtrip-'));
  const stateDir = path.join(directory, 'state');
  const backupFile = path.join(directory, 'backup.json');
  try {
    await triggerState(stateDir);
    const before = JSON.parse(await fs.readFile(path.join(stateDir, 'kill-switch.json'), 'utf8'));
    const backup = await invoke(['backup', '--out', backupFile, '--state-dir', stateDir]);
    assert.equal(backup.code, 0, backup.stderr);
    const body = parse(backup.stdout);
    assert.equal(body.backedUp, true);
    assert.equal(body.schemaVersion, 1);
    assert.equal(body.active, true);
    assert.equal(body.workers, 0);
    // The envelope carries a SHA-256 that matches the captured state.
    const envelope = JSON.parse(await fs.readFile(backupFile, 'utf8'));
    assert.equal(envelope.schemaVersion, 1);
    assert.equal(envelope.sha256, sha256Hex(JSON.stringify(envelope.state)));
    assert.deepEqual(envelope.state, before);
    // The audit log is deliberately NOT part of the backup.
    assert.equal('audit' in envelope, false);
    assert.equal(JSON.stringify(envelope).includes('KILL_SWITCH_TRIGGER'), false);

    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    const restore = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(restore.code, 0, restore.stderr);
    assert.equal(parse(restore.stdout).restored, true);
    assert.deepEqual(JSON.parse(await fs.readFile(path.join(stateDir, 'kill-switch.json'), 'utf8')), before);
    assert.equal(parse((await invoke(['kill-switch', 'status', '--state-dir', stateDir])).stdout).active, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('restore refuses a tampered backup (hash mismatch) and writes nothing', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-tamper-'));
  const stateDir = path.join(directory, 'state');
  const backupFile = path.join(directory, 'backup.json');
  try {
    await triggerState(stateDir);
    assert.equal((await invoke(['backup', '--out', backupFile, '--state-dir', stateDir])).code, 0);
    const envelope = JSON.parse(await fs.readFile(backupFile, 'utf8'));
    envelope.state.trigger.reason = 'tampered reason';
    await fs.writeFile(backupFile, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    const restore = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(restore.code, 3);
    assert.equal(parse(restore.stdout).restored, false);
    assert.equal(parse(restore.stdout).reason, 'BACKUP_HASH_MISMATCH');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('restore refuses corrupt JSON, an unsupported schema, and a wrong-shape state', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-refusals-'));
  const stateDir = path.join(directory, 'state');
  try {
    await fs.mkdir(stateDir, { recursive: true });
    const cases = [
      { label: 'unparseable JSON', contents: '{"schemaVersion": 1, "state": ', reason: 'BACKUP_CORRUPT' },
      { label: 'not an object', contents: '[1, 2, 3]', reason: 'BACKUP_CORRUPT' },
      { label: 'missing schema version', contents: JSON.stringify({ sha256: '0'.repeat(64), state: { version: 2, active: false, trigger: null, workers: [] } }), reason: 'BACKUP_CORRUPT' },
      { label: 'bad hash format', contents: JSON.stringify({ schemaVersion: 1, sha256: 'not-a-hash', state: { version: 2, active: false, trigger: null, workers: [] } }), reason: 'BACKUP_CORRUPT' },
    ];
    for (const { label, contents, reason } of cases) {
      const file = path.join(directory, 'backup.json');
      await fs.writeFile(file, contents, { mode: 0o600 });
      const restore = await invoke(['restore', '--from', file, '--state-dir', stateDir]);
      assert.equal(restore.code, 3, `${label} exit`);
      assert.equal(parse(restore.stdout).reason, reason, `${label} reason`);
      await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' }, `${label} must write nothing`);
    }
    // Unsupported schema: envelope is well-formed and the hash is correct
    // for its state — only the version is unknown.
    const state = { version: 2, active: false, trigger: null, workers: [] };
    const future = path.join(directory, 'future.json');
    await fs.writeFile(future, JSON.stringify({ schemaVersion: 99, createdAt: new Date().toISOString(), sha256: sha256Hex(JSON.stringify(state)), state }), { mode: 0o600 });
    const unsupported = await invoke(['restore', '--from', future, '--state-dir', stateDir]);
    assert.equal(unsupported.code, 3);
    assert.equal(parse(unsupported.stdout).reason, 'BACKUP_UNSUPPORTED_SCHEMA');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });
    // Wrong-shape state with a correct hash over that shape.
    const badState = { version: 99, active: 'yes' };
    const badShape = path.join(directory, 'badshape.json');
    await fs.writeFile(badShape, JSON.stringify({ schemaVersion: 1, createdAt: new Date().toISOString(), sha256: sha256Hex(JSON.stringify(badState)), state: badState }), { mode: 0o600 });
    const invalid = await invoke(['restore', '--from', badShape, '--state-dir', stateDir]);
    assert.equal(invalid.code, 3);
    assert.equal(parse(invalid.stdout).reason, 'BACKUP_STATE_INVALID');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('restore refuses an armed state with live leased workers, but accepts one with only expired leases', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-leased-'));
  const stateDir = path.join(directory, 'state');
  const backupFile = path.join(directory, 'backup.json');
  try {
    await fs.mkdir(stateDir, { recursive: true });
    const now = Date.now();
    const armedLive = {
      version: 2,
      active: true,
      trigger: { triggerId: 'leased-lab', triggeredBy: 'operator', reason: 'lab stop', triggeredAt: now - 60000 },
      workers: [{ workerId: 'ghost-worker', pid: 99999, leaseExpiresAt: now + 60000 }],
    };
    await fs.writeFile(path.join(stateDir, 'kill-switch.json'), JSON.stringify(armedLive, null, 2), { mode: 0o600 });
    // Backup itself succeeds — it only captures; the refusal is a
    // restore-time rule, so the backup must exist to test it.
    assert.equal((await invoke(['backup', '--out', backupFile, '--state-dir', stateDir])).code, 0);
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    const refused = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(refused.code, 3);
    assert.equal(parse(refused.stdout).reason, 'BACKUP_ARMED_WITH_LEASED_WORKERS');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });

    // Same armed state, but every lease already expired: the armed flag
    // itself is preserved, no phantom worker is planted.
    const armedExpired = { ...armedLive, workers: [{ workerId: 'dead-worker', pid: 99999, leaseExpiresAt: now - 60000 }] };
    await fs.writeFile(path.join(stateDir, 'kill-switch.json'), JSON.stringify(armedExpired, null, 2), { mode: 0o600 });
    assert.equal((await invoke(['backup', '--out', backupFile, '--state-dir', stateDir])).code, 0);
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    const restored = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(restored.code, 0, restored.stderr);
    assert.equal(parse(restored.stdout).restored, true);
    assert.equal(parse((await invoke(['kill-switch', 'status', '--state-dir', stateDir])).stdout).active, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('backup and restore never follow symlinks for output or input', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-symlink-'));
  const stateDir = path.join(directory, 'state');
  try {
    await triggerState(stateDir);
    const target = path.join(directory, 'target.json');
    await fs.writeFile(target, 'do not overwrite\n', { mode: 0o600 });
    const linkOut = path.join(directory, 'link-out.json');
    try {
      await fs.symlink(target, linkOut, 'file');
    } catch (error) {
      t.skip(`symlink unavailable: ${error.code || error.message}`);
      return;
    }
    const backup = await invoke(['backup', '--out', linkOut, '--state-dir', stateDir]);
    assert.equal(backup.code, 3);
    assert.equal(parse(backup.stdout).reason, 'BACKUP_SYMLINK_REFUSED');
    assert.equal(await fs.readFile(target, 'utf8'), 'do not overwrite\n');

    const backupFile = path.join(directory, 'backup.json');
    assert.equal((await invoke(['backup', '--out', backupFile, '--state-dir', stateDir])).code, 0);
    const linkIn = path.join(directory, 'link-in.json');
    await fs.symlink(backupFile, linkIn, 'file');
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    const restore = await invoke(['restore', '--from', linkIn, '--state-dir', stateDir]);
    assert.equal(restore.code, 3);
    assert.equal(parse(restore.stdout).reason, 'BACKUP_SYMLINK_REFUSED');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });

    // A symlinked state file itself is refused as a backup source, and a
    // symlinked state target is refused on restore.
    const realState = path.join(directory, 'real-state.json');
    await fs.writeFile(realState, JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }), { mode: 0o600 });
    await fs.symlink(realState, path.join(stateDir, 'kill-switch.json'), 'file');
    const linkedBackup = await invoke(['backup', '--out', path.join(directory, 'linked-backup.json'), '--state-dir', stateDir]);
    assert.equal(linkedBackup.code, 3);
    assert.equal(parse(linkedBackup.stdout).reason, 'BACKUP_SYMLINK_REFUSED');
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    await fs.symlink(realState, path.join(stateDir, 'kill-switch.json'), 'file');
    const linkedRestore = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(linkedRestore.code, 3);
    assert.equal(parse(linkedRestore.stdout).reason, 'BACKUP_SYMLINK_REFUSED');
    assert.equal(JSON.parse(await fs.readFile(realState, 'utf8')).active, false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('backup refuses a missing state file and restore refuses a missing backup file', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-missing-'));
  const stateDir = path.join(directory, 'state');
  try {
    await fs.mkdir(stateDir, { recursive: true });
    const backup = await invoke(['backup', '--out', path.join(directory, 'backup.json'), '--state-dir', stateDir]);
    assert.equal(backup.code, 1);
    assert.equal(parse(backup.stdout).reason, 'BACKUP_STATE_MISSING');
    const restore = await invoke(['restore', '--from', path.join(directory, 'no-such-backup.json'), '--state-dir', stateDir]);
    assert.equal(restore.code, 1);
    assert.equal(parse(restore.stdout).reason, 'BACKUP_NOT_FOUND');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('restore refuses while a fresh state lock is held and writes nothing', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-backup-locked-'));
  const stateDir = path.join(directory, 'state');
  const backupFile = path.join(directory, 'backup.json');
  try {
    await triggerState(stateDir);
    assert.equal((await invoke(['backup', '--out', backupFile, '--state-dir', stateDir])).code, 0);
    await fs.rm(path.join(stateDir, 'kill-switch.json'));
    await fs.writeFile(path.join(stateDir, 'kill-switch.json.lock'), JSON.stringify({ pid: 99999, acquiredAt: Date.now() }), { mode: 0o600 });
    const restore = await invoke(['restore', '--from', backupFile, '--state-dir', stateDir]);
    assert.equal(restore.code, 1);
    assert.equal(parse(restore.stdout).reason, 'BACKUP_STATE_LOCKED');
    await assert.rejects(() => fs.stat(path.join(stateDir, 'kill-switch.json')), { code: 'ENOENT' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('docs document the backup commands, the hash, and the leased-workers rule', async () => {
  for (const relative of ['skills/sentinel-bounty/SKILL.md', 'docs/backup-restore-v1.md']) {
    const text = await fs.readFile(path.resolve(__dirname, '..', relative), 'utf8');
    assert.ok(text.includes('BACKUP_HASH_MISMATCH'), `${relative} must document BACKUP_HASH_MISMATCH`);
    assert.ok(text.includes('BACKUP_ARMED_WITH_LEASED_WORKERS'), `${relative} must document the leased-workers refusal`);
  }
  const skill = await fs.readFile(path.resolve(__dirname, '..', 'skills', 'sentinel-bounty', 'SKILL.md'), 'utf8');
  assert.ok(skill.includes('sentinel backup --out'), 'SKILL.md must list the backup command');
  assert.ok(skill.includes('sentinel restore --from'), 'SKILL.md must list the restore command');
});
