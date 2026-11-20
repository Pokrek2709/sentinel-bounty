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
    const first = new PersistentKillSwitch({ stateFile, skillDirectory });
    const second = new PersistentKillSwitch({ stateFile, skillDirectory });
    assert.equal((await first.assertNotTriggered()).allowed, true);
    assert.equal((await first.trigger({ triggeredBy: 'local-human', reason: 'lab stop' })).triggered, true);
    assert.deepEqual(await second.assertNotTriggered().then((value) => value.reason), 'KILL_SWITCH_ACTIVE');
    const stat = await fs.stat(stateFile);
    if (process.platform !== 'win32') assert.equal(stat.mode & 0o777, 0o600);
    assert.equal((await second.reset({ resetBy: 'local-human' })).reset, true);
    assert.equal((await first.assertNotTriggered()).allowed, true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cancels local workers and refuses registration after activation', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-'));
  try {
    const killSwitch = new PersistentKillSwitch({ stateFile: path.join(directory, 'state', 'kill.json'), skillDirectory: path.join(directory, 'skill') });
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

test('rejects state inside the reinstall-replaced skill directory', () => {
  assert.throws(() => new PersistentKillSwitch({
    stateFile: path.join(os.tmpdir(), 'skill', 'state.json'),
    skillDirectory: path.join(os.tmpdir(), 'skill'),
  }), /outside the skill directory/);
});
