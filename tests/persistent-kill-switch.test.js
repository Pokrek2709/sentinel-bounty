const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');

const execFileAsync = promisify(execFile);

// EACCES can only be produced by an unprivileged process: root ignores
// permission bits. These tests run a probe as user nobody and are skipped
// anywhere that cannot do that (non-root, Windows).
const canRunAsNobody = process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0;

test('persists activation across fresh instances with private atomic state', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-');
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

test('cancels local workers and refuses registration after activation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-');
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

test('protects reset against workers registered by another process and requires the operator token', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-');
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

test('status remains fail-closed when a live state lock is held', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-status-lock-');
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

test('matches a presented token against an independently provisioned digest', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-');
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

test('snapshotLockless reads stored state without pruning and marks expired leases', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-lockless-');
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

test('snapshotLockless returns the inactive default when the state file is missing', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-lockless-missing-');
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    assert.deepEqual(await killSwitch.snapshotLockless(), { active: false, trigger: null, registeredWorkers: 0, workers: [], version: 2, readMode: 'LOCKLESS_FALLBACK', lockless: true, pruned: false });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless migrates a v1 state in memory without writing', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-lockless-v1-');
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

test('snapshotLockless rejects corrupt state with the same error as the locked read', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-lockless-corrupt-');
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(stateFile, '{not json', { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const locklessError = await killSwitch.snapshotLockless().then(() => null, (error) => error);
    const lockedError = await killSwitch.snapshot().then(() => null, (error) => error);
    assert.equal(locklessError.message, 'KILL_SWITCH_STATE_CORRUPT');
    assert.equal(lockedError.message, 'KILL_SWITCH_STATE_CORRUPT');
    assert.equal(locklessError.message, lockedError.message);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('snapshotLockless marks without pruning while the locked snapshot prunes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-lockless-vs-locked-');
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

test('lockless and locked snapshots drop non-object workers instead of spreading them', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-nonobject-');
  const skillDirectory = path.join(directory, 'skill');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    const now = Date.now();
    const stored = {
      version: 2,
      active: false,
      trigger: null,
      workers: [
        'x',
        42,
        null,
        ['array-worker'],
        { workerId: 'live-worker', pid: 1111, leaseExpiresAt: now + 60000 },
        { workerId: 'expired-worker', pid: 2222, leaseExpiresAt: now - 60000 },
      ],
    };
    await fs.writeFile(stateFile, JSON.stringify(stored), { mode: 0o600 });
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    // Lockless: non-objects are dropped (no phantom {"0": "x"} worker);
    // expired object leases are reported, not pruned.
    const lockless = await killSwitch.snapshotLockless();
    assert.equal(lockless.workers.length, 2);
    assert.deepEqual(lockless.workers.map((worker) => worker.workerId).sort(), ['expired-worker', 'live-worker']);
    assert.equal(lockless.registeredWorkers, 1);
    // Locked: the same malformed entries are pruned (and a null worker
    // no longer throws TypeError), leaving only the live lease.
    const locked = await killSwitch.snapshot();
    assert.equal(locked.workers.length, 1);
    assert.equal(locked.workers[0].workerId, 'live-worker');
    assert.equal(JSON.parse(await fs.readFile(stateFile, 'utf8')).workers.length, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('locked and lockless migration agree on v1 and legacy shapes', async (t) => {
  const cases = [
    { name: 'v1', state: { version: 1, active: true, trigger: { triggerId: 't1', triggeredBy: 'op', reason: 'v1 reason', triggeredAt: Date.now() - 1000 } } },
    { name: 'legacy-enabled', state: { enabled: true, reason: 'old stop', updatedAt: new Date(Date.now() - 5000).toISOString() } },
    { name: 'legacy-disabled', state: { enabled: false } },
  ];
  for (const { name, state } of cases) {
    const directory = await makeTempDir(t, 'sentinel-kill-migrate-parity-');
    const skillDirectory = path.join(directory, 'skill');
    const stateFile = path.join(directory, 'state', 'kill-switch.json');
    try {
      await fs.mkdir(path.dirname(stateFile), { recursive: true });
      const before = JSON.stringify(state);
      await fs.writeFile(stateFile, before, { mode: 0o600 });
      const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
      const lockless = await killSwitch.snapshotLockless();
      assert.equal(await fs.readFile(stateFile, 'utf8'), before, `${name} lockless must not write`);
      const locked = await killSwitch.snapshot();
      const persisted = JSON.parse(await fs.readFile(stateFile, 'utf8'));
      assert.equal(locked.version, 2, name);
      assert.equal(locked.active, lockless.active, `${name} active parity`);
      assert.deepEqual(locked.trigger, lockless.trigger, `${name} trigger parity`);
      assert.equal(persisted.version, 2, `${name} persisted v2`);
      assert.equal(persisted.active, lockless.active, `${name} persisted active parity`);
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  }
});

test('migrates the legacy enabled schema atomically without reviving approvals', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-');
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

test('classifies ENOTDIR as KILL_SWITCH_STATE_PATH_INVALID on every locked operation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-enotdir-');
  const token = 'local-reset-token-1234';
  try {
    const notADir = path.join(directory, 'notadir');
    await fs.writeFile(notADir, 'I am a regular file, not a directory');
    const stateFile = path.join(notADir, 'state', 'kill-switch.json');
    const skillDirectory = path.join(directory, 'skill');
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: token });
    await assert.rejects(() => killSwitch.snapshot(), /KILL_SWITCH_STATE_PATH_INVALID/);
    await assert.rejects(() => killSwitch.trigger({ triggeredBy: 'operator', reason: 'lab stop' }), /KILL_SWITCH_STATE_PATH_INVALID/);
    await assert.rejects(() => killSwitch.reset({ resetBy: 'operator', resetToken: token }), /KILL_SWITCH_STATE_PATH_INVALID/);
    await assert.rejects(() => killSwitch.registerWorker({ workerId: 'worker-a', cancel: async () => {} }), /KILL_SWITCH_STATE_PATH_INVALID/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('recovers a stale state lock and succeeds without leaving a lock file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-stale-');
  const stateFile = path.join(directory, 'state', 'kill-switch.json');
  const skillDirectory = path.join(directory, 'skill');
  try {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    const stored = JSON.stringify({ version: 2, active: false, trigger: null, workers: [] });
    await fs.writeFile(stateFile, stored, { mode: 0o600 });
    const lockFile = `${stateFile}.lock`;
    await fs.writeFile(lockFile, JSON.stringify({ pid: 99999, acquiredAt: Date.now() - 61000 }), { mode: 0o600 });
    const staleDate = new Date(Date.now() - 61000);
    require('node:fs').utimesSync(lockFile, staleDate, staleDate);
    const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory, resetToken: 'local-reset-token-1234' });
    const snapshot = await killSwitch.snapshot();
    assert.equal(snapshot.active, false);
    assert.equal(require('node:fs').existsSync(lockFile), false);
    assert.equal(await fs.readFile(stateFile, 'utf8'), stored);
    assert.equal((await fs.readdir(path.dirname(stateFile))).some((name) => name.endsWith('.tmp')), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('classifies EACCES as KILL_SWITCH_STATE_PERMISSION_DENIED, not STATE_LOCKED', { skip: !canRunAsNobody }, async (t) => {
  const directory = await makeTempDir(t, 'sentinel-kill-eacces-');
  try {
    await fs.chmod(directory, 0o755);
    const stateDir = path.join(directory, 'state-ro');
    await fs.mkdir(stateDir, { mode: 0o555 });
    const stateFile = path.join(stateDir, 'kill-switch.json');
    await fs.writeFile(stateFile, JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }), { mode: 0o644 });
    const skillDirectory = path.join(directory, 'skill');
    await fs.mkdir(skillDirectory, { mode: 0o755 });
    // The probe runs as nobody, so it cannot read the repo checkout itself
    // (checkout files are group-only readable). Copy the module plus its
    // dependencies into the scratch directory, world-readable, mirroring
    // the repo layout (policy/): the module depends on
    // ./storage-errors and ./state-permissions (round 45), so a flat
    // single-file copy no longer loads.
    await fs.mkdir(path.join(directory, 'policy'));
    // mkdir's mode is masked by the umask (0007 turns 0755 into
    // 0750): set world-traversal explicitly for the nobody probe.
    await fs.chmod(path.join(directory, 'policy'), 0o755);
    const probeModule = path.join(directory, 'policy', 'persistent-kill-switch.js');
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'policy', 'persistent-kill-switch.js'), probeModule);
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'policy', 'storage-errors.js'), path.join(directory, 'policy', 'storage-errors.js'));
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'policy', 'state-permissions.js'), path.join(directory, 'policy', 'state-permissions.js'));
    await fs.chmod(probeModule, 0o644);
    await fs.chmod(path.join(directory, 'policy', 'storage-errors.js'), 0o644);
    await fs.chmod(path.join(directory, 'policy', 'state-permissions.js'), 0o644);
    const probe = `
      const { PersistentKillSwitch } = require(process.env.PROBE_MODULE);
      (async () => {
        const ks = new PersistentKillSwitch({ stateFile: process.env.PROBE_STATE_FILE, skillDirectory: process.env.PROBE_SKILL_DIR, resetToken: 'local-reset-token-1234' });
        try {
          const out = process.env.PROBE_OP === 'register'
            ? await ks.registerWorker({ workerId: 'probe-worker', cancel: async () => {} })
            : await ks.snapshot();
          console.log('OK:' + JSON.stringify(out));
        } catch (error) { console.log('ERROR:' + error.message); }
      })();
    `;
    for (const operation of ['snapshot', 'register']) {
      const { stdout } = await execFileAsync(process.execPath, ['-e', probe], {
        uid: 65534,
        gid: 65534,
        // cwd must be world-readable: node resolves the -e module's
        // self-reference against cwd's package.json, and the repo checkout
        // is not readable by nobody.
        cwd: directory,
        env: {
          ...process.env,
          PROBE_MODULE: probeModule,
          PROBE_STATE_FILE: stateFile,
          PROBE_SKILL_DIR: skillDirectory,
          PROBE_OP: operation,
        },
      });
      assert.ok(stdout.includes('ERROR:KILL_SWITCH_STATE_PERMISSION_DENIED'), `${operation} as nobody must report PERMISSION_DENIED, got: ${stdout}`);
      assert.ok(!stdout.includes('KILL_SWITCH_STATE_LOCKED'), `${operation} must not be mislabeled STATE_LOCKED, got: ${stdout}`);
    }
    assert.equal(require('node:fs').existsSync(`${stateFile}.lock`), false);
  } finally {
    await fs.chmod(directory, 0o700).catch(() => {});
    await fs.rm(directory, { recursive: true, force: true });
  }
});
