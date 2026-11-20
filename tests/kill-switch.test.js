const assert = require('node:assert/strict');
const test = require('node:test');
const { KillSwitch } = require('../src/policy/kill-switch');

test('fails closed after trigger and dispatches cancellation to every registered worker', async () => {
  const cancelled = [];
  const killSwitch = new KillSwitch({ clock: () => 0 });
  killSwitch.registerWorker({ workerId: 'worker-a', cancel: async (context) => { cancelled.push(['a', context.reason]); } });
  killSwitch.registerWorker({ workerId: 'worker-b', cancel: async (context) => { cancelled.push(['b', context.reason]); } });

  const triggered = await killSwitch.trigger({ triggeredBy: 'researcher@example.test', reason: 'Local lab stop' });
  assert.equal(triggered.triggered, true);
  assert.deepEqual(cancelled, [['a', 'KILL_SWITCH_ACTIVE'], ['b', 'KILL_SWITCH_ACTIVE']]);
  assert.deepEqual(triggered.cancellations.map((entry) => entry.cancelled), [true, true]);
  assert.equal(killSwitch.assertNotTriggered().reason, 'KILL_SWITCH_ACTIVE');
  assert.deepEqual(killSwitch.registerWorker({ workerId: 'worker-c', cancel: async () => {} }), {
    registered: false,
    reason: 'KILL_SWITCH_ACTIVE',
  });
});

test('records cancellation failures but keeps the switch active', async () => {
  const killSwitch = new KillSwitch({ clock: () => 0 });
  killSwitch.registerWorker({ workerId: 'worker-a', cancel: async () => { throw new Error('termination failed'); } });
  const result = await killSwitch.trigger({ triggeredBy: 'researcher@example.test', reason: 'Local lab stop' });
  assert.deepEqual(result.cancellations, [{ workerId: 'worker-a', cancelled: false, error: 'termination failed' }]);
  assert.equal(killSwitch.snapshot().active, true);
});

test('requires registered workers to be removed before an explicit reset', async () => {
  const killSwitch = new KillSwitch({ clock: () => 0 });
  const registration = killSwitch.registerWorker({ workerId: 'worker-a', cancel: async () => {} });
  await killSwitch.trigger({ triggeredBy: 'researcher@example.test', reason: 'Local lab stop' });
  assert.deepEqual(killSwitch.reset({ resetBy: 'researcher@example.test' }), {
    reset: false,
    reason: 'WORKERS_STILL_REGISTERED',
    registeredWorkers: 1,
  });
  assert.equal(registration.unregister(), true);
  assert.deepEqual(killSwitch.reset({ resetBy: 'researcher@example.test' }), { reset: true });
  assert.equal(killSwitch.assertNotTriggered().allowed, true);
});

test('does not re-trigger or accept malformed worker and trigger inputs', async () => {
  const killSwitch = new KillSwitch({ clock: () => 0 });
  assert.throws(() => killSwitch.registerWorker({ workerId: '', cancel: async () => {} }), /workerId/);
  await killSwitch.trigger({ triggeredBy: 'researcher@example.test', reason: 'Local lab stop' });
  const repeat = await killSwitch.trigger({ triggeredBy: 'researcher@example.test', reason: 'again' });
  assert.equal(repeat.reason, 'KILL_SWITCH_ALREADY_ACTIVE');
});
