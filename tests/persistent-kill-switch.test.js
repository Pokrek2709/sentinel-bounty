const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');

test('persists activation across fresh instances with private atomic state', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    const skillDirectory = path.join(directory, 'skill');
    const first = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const second = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    assert.equal((await first.assertNotTriggered()).allowed, true);
    assert.equal((await first.trigger({ triggeredBy: 'local-human', reason: 'lab stop' })).triggered, true);
    assert.deepEqual(await second.assertNotTriggered().then((value) => value.reason), 'KILL_SWITCH_ACTIVE');
    const stat = await fs.stat(stateFile);
    if (process.platform !== 'win32') assert.equal(stat.mode & 0o777, 0o600);
    assert.equal((await second.reset({ resetBy: 'local-human', resetToken: 'local-reset-token-1234' })).reset, true);
    assert.equal((await first.assertNotTriggered()).allowed, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cancels local workers and refuses registration after activation', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  try {
    const killSwitch = new PersistentKillSwitch({ stateFile: path.join(directory, 'state', 'kill.json'), skillDirectory: path.join(directory, 'skill'), resetToken: 'local-reset-token-1234' });
    let cancelled = false;
    const registration = await killSwitch.registerWorker({ workerId: 'worker-a', cancel: async () => { cancelled = true; } });
    assert.equal(registration.registered, true);
    await killSwitch.trigger({ triggeredBy: 'local-human', reason: 'lab stop' });
    assert.equal(cancelled, true);
    assert.deepEqual(await killSwitch.registerWorker({ workerId: 'worker-b', cancel: async () => {} }), { registered: false, reason: 'KILL_SWITCH_ACTIVE' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('protects reset against workers registered by another process and requires the operator token', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  const stateFile = path.join(directory, 'state', 'kill.json');
  const skillDirectory = path.join(directory, 'skill');
  const token = 'local-reset-token-1234';
  try {
    const first = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: token });
    const second = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: token });
    const registration = await first.registerWorker({ workerId: 'worker-from-process-a', cancel: async () => {} });
    const workerSnapshot = await second.snapshot();
    assert.equal(workerSnapshot.registeredWorkers, 1);
    assert.equal(workerSnapshot.workers[0].workerId, 'worker-from-process-a');
    assert.equal(workerSnapshot.workers[0].pid, process.pid);
    assert.ok(workerSnapshot.workers[0].leaseExpiresAt > Date.now());
    await first.trigger({ triggeredBy: 'local-human', reason: 'lab stop' });
    assert.deepEqual(await second.reset({ resetBy: 'mallory', resetToken: 'wrong-token-000000' }), { reset: false, reason: 'RESET_OPERATOR_UNAUTHORIZED' });
    assert.deepEqual(await second.reset({ resetBy: 'operator', resetToken: token }), { reset: false, reason: 'WORKERS_STILL_REGISTERED', registeredWorkers: 1 });
    await registration.unregister();
    assert.deepEqual(await second.reset({ resetBy: 'operator', resetToken: token }), { reset: true });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('status remains fail-closed when a live state lock is held', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-status-lock-'));
  const stateFile = path.join(directory, 'state', 'kill.json');
  const skillDirectory = path.join(directory, 'skill');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(`${stateFile}.lock`, JSON.stringify({ pid: process.pid, acquiredAt: Date.now() }), { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, lockTimeoutMs: 20, lockRetryMs: 5 });
    await assert.rejects(() => killSwitch.snapshot(), /KILL_SWITCH_STATE_LOCKED/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('matches a presented token against an independently provisioned digest', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  const token = 'independent-reset-token-1234';
  try {
    const digest = require('node:crypto').createHash('sha256').update(token).digest('hex');
    const killSwitch = new PersistentKillSwitch({ stateFile: path.join(directory, 'state', 'kill.json'), skillDirectory: path.join(directory, 'skill'), resetTokenHash: digest });
    await killSwitch.trigger({ triggeredBy: 'operator', reason: 'lab stop' });
    assert.deepEqual(await killSwitch.reset({ resetBy: 'operator', resetToken: 'wrong-token-that-is-long-enough-1234' }), { reset: false, reason: 'RESET_OPERATOR_UNAUTHORIZED' });
    assert.deepEqual(await killSwitch.reset({ resetBy: 'operator', resetToken: token }), { reset: true });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('rejects state inside the reinstall-replaced skill directory', () => {
  assert.throws(() => new PersistentKillSwitch({
    stateFile: path.join(os.tmpdir(), 'skill', 'state.json'),
    skillDirectory: path.join(os.tmpdir(), 'skill'),
    resetToken: 'local-reset-token-1234',
  }), /outside the skill directory/);
});

test('snapshotLockless reads stored state without pruning and marks expired leases', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-lockless-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    const now = Date.now();
    const stored = {
      version: 2,
      active: true,
      trigger: { triggerId: 'lockless-lab', triggeredBy: 'operator', reason: 'lab stop', triggeredAt: now - 60000 },
      workers: [
        { workerId: 'live-worker', pid: 1111, leaseExpiresAt: now + 60000 },
        { workerId: 'expired-worker', pid: 2222, leaseExpiresAt: now - 60000 },
      ],
    };
    await fs.writeFile(stateFile, JSON.stringify(stored), { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const snapshot = await killSwitch.snapshotLockless();
    assert.equal(snapshot.active, true);
    assert.equal(snapshot.readMode, 'LOCKLESS_FALLBACK');
    assert.equal(snapshot.lockless, true);
    assert.equal(snapshot.pruned, false);
    assert.equal(snapshot.registeredWorkers, 1);
    assert.equal(snapshot.workers.find((worker) => worker.workerId === 'live-worker').leaseExpired, false);
    assert.equal(snapshot.workers.find((worker) => worker.workerId === 'expired-worker').leaseExpired, true);
    const after = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    assert.equal(after.workers.length, 2);
    assert.equal((await fs.readdir(path.dirname(stateFile))).some((name) => name.endsWith('.lock') || name.endsWith('.tmp')), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless returns the inactive default when the state file is missing', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-lockless-missing-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    assert.deepEqual(await killSwitch.snapshotLockless(), { active: false, trigger: null, registeredWorkers: 0, workers: [], version: 2, readMode: 'LOCKLESS_FALLBACK', lockless: true, pruned: false });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless migrates a v1 state in memory without writing', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-lockless-v1-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    const v1 = JSON.stringify({ version: 1, active: true, trigger: { triggerId: 't1', triggeredBy: 'op', reason: 'v1 reason', triggeredAt: Date.now() - 1000 } });
    await fs.writeFile(stateFile, v1, { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const snapshot = await killSwitch.snapshotLockless();
    assert.equal(snapshot.version, 2);
    assert.equal(snapshot.active, true);
    assert.equal(snapshot.trigger.reason, 'v1 reason');
    assert.equal(snapshot.readMode, 'LOCKLESS_FALLBACK');
    assert.equal(snapshot.lockless, true);
    assert.equal(await fs.readFile(stateFile, 'utf8'), v1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless rejects corrupt state with the same error as the locked read', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-lockless-corrupt-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(stateFile, '{not json', { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const locklessError = await killSwitch.snapshotLockless().then(() => null, (error) => error);
    const lockedError = await killSwitch.snapshot().then(() => null, (error) => error);
    assert.ok(locklessError instanceof SyntaxError);
    assert.ok(lockedError instanceof SyntaxError);
    assert.equal(locklessError.message, lockedError.message);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless marks without pruning while the locked snapshot prunes', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-lockless-vs-locked-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    const now = Date.now();
    const stored = {
      version: 2,
      active: true,
      trigger: { triggerId: 'lockless-lab', triggeredBy: 'operator', reason: 'lab stop', triggeredAt: now - 60000 },
      workers: [
        { workerId: 'live-worker', pid: 1111, leaseExpiresAt: now + 60000 },
        { workerId: 'expired-worker', pid: 2222, leaseExpiresAt: now - 60000 },
      ],
    };
    await fs.writeFile(stateFile, JSON.stringify(stored), { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const lockless = await killSwitch.snapshotLockless();
    assert.equal(lockless.readMode, 'LOCKLESS_FALLBACK');
    assert.equal(lockless.workers.length, 2);
    assert.equal(lockless.registeredWorkers, 1);
    assert.equal(lockless.workers.find((worker) => worker.workerId === 'expired-worker').leaseExpired, true);
    // The locked path prunes the expired lease and persists the pruned state.
    const locked = await killSwitch.snapshot();
    assert.equal(locked.readMode, undefined);
    assert.equal(locked.workers.length, 1);
    assert.equal(locked.registeredWorkers, 1);
    assert.equal(JSON.parse(await fs.readFile(stateFile, 'utf8')).workers.length, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('migrates the legacy enabled schema atomically without reviving approvals', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(stateFile, JSON.stringify({ enabled: true, reason: 'legacy lab stop', updated_at: '2026-11-20T00:00:00.000Z' }), { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const status = await killSwitch.assertNotTriggered();
    assert.equal(status.reason, 'KILL_SWITCH_ACTIVE');
    const migrated = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    assert.equal(migrated.version, 2);
    assert.equal(migrated.active, true);
    assert.equal(migrated.trigger.reason, 'legacy lab stop');
    assert.equal(migrated.trigger.triggeredAt, Date.parse('2026-11-20T00:00:00.000Z'));
    assert.equal((await fs.readdir(path.dirname(stateFile))).some((name) => name.endsWith('.tmp')), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
