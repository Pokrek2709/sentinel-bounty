const assert = require('node:assert/strict');
const { execFile, spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { runDrill } = require('../src/policy/incident-drill');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { AuditLog } = require('../src/audit/audit-log');

const SKILL_DIR = path.resolve(__dirname, '..');
const CLI = path.join(SKILL_DIR, 'bin', 'sentinel.js');
// Fast timeouts for the suite: the cooperative worker dies on SIGTERM
// immediately, the stubborn one after one short grace period.
const FAST = { sigtermGraceMs: 100, cancelTimeoutMs: 2000 };

async function tempStateDir(t, prefix) {
  return makeTempDir(t, prefix);
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

async function readAuditEvents(stateDir) {
  const audit = new AuditLog({ logFile: path.join(stateDir, 'drill', 'audit.jsonl'), skillDirectory: SKILL_DIR });
  return audit.readEvents();
}

// A dead pid, guaranteed: spawn a process that exits immediately and
// reuse its pid after it is gone.
async function deadPid() {
  const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await new Promise((resolve) => child.once('exit', resolve));
  return child.pid;
}

function armDrillState(stateDir, { workerPid, workerId = 'drill-old-run-cooperative' } = {}) {
  const drillDir = path.join(stateDir, 'drill');
  return fs.mkdir(drillDir, { recursive: true, mode: 0o700 }).then(() => fs.writeFile(
    path.join(drillDir, 'kill-switch.json'),
    JSON.stringify({
      version: 2,
      active: true,
      trigger: { triggerId: 'abandoned-trigger', triggeredBy: 'drill', reason: 'abandoned run', triggeredAt: Date.now() },
      workers: workerPid ? [{ workerId, pid: workerPid, leaseExpiresAt: Date.now() + 60_000 }] : [],
    }, null, 2),
    { encoding: 'utf8', mode: 0o600 },
  ));
}

async function appendDrillStart(stateDir, runId) {
  const audit = new AuditLog({ logFile: path.join(stateDir, 'drill', 'audit.jsonl'), skillDirectory: SKILL_DIR });
  await audit.append('DRILL_START', { runId });
}

test('drill passes end-to-end: cooperative cancel, stubborn escalation, clean reset, complete audit', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-happy-');
  const result = await runDrill({ stateDir, skillDirectory: SKILL_DIR, ...FAST });

  assert.equal(result.verdict, 'PASS');
  assert.equal(result.steps.length, 11);
  assert.ok(result.steps.every((step) => step.status === 'PASS'), JSON.stringify(result.steps));
  assert.match(result.steps.find((step) => step.id === 'trigger-stubborn').detail, /escalated to SIGKILL: true/);
  assert.match(result.steps.find((step) => step.id === 'trigger-cooperative').detail, /escalated to SIGKILL: false/);

  // Drill state is clean afterwards.
  const drillState = await readJson(path.join(stateDir, 'drill', 'kill-switch.json'));
  assert.equal(drillState.active, false);
  assert.deepEqual(drillState.workers, []);

  // The audit log records both triggers and both cancellations.
  const events = await readAuditEvents(stateDir);
  const names = events.map((event) => event.event);
  assert.equal(events.filter((event) => event.event === 'KILL_SWITCH_TRIGGER').length, 2);
  assert.equal(events.filter((event) => event.event === 'DRILL_WORKER_CANCELLED' && event.details.cancelled).length, 2);
  assert.equal(events.filter((event) => event.event === 'DRILL_WORKER_CANCELLED' && event.details.escalated).length, 1);
  assert.ok(names.includes('DRILL_COMPLETE'));

  // The real state files were never touched: no kill-switch.json and
  // no audit.jsonl exist outside the drill directory.
  await assert.rejects(fs.stat(path.join(stateDir, 'kill-switch.json')), /ENOENT/);
  await assert.rejects(fs.stat(path.join(stateDir, 'audit.jsonl')), /ENOENT/);
});

test('drill refuses while the real kill-switch is armed and while a real worker is registered', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-real-');
  const realSwitch = new PersistentKillSwitch({
    stateFile: path.join(stateDir, 'kill-switch.json'),
    skillDirectory: SKILL_DIR,
    resetToken: '0123456789abcdef0123456789abcdef',
  });

  // Armed real switch: refuse with DRILL_REAL_SWITCH_ACTIVE.
  await realSwitch.trigger({ triggeredBy: 'operator', reason: 'lab stop' });
  const armed = await runDrill({ stateDir, skillDirectory: SKILL_DIR, ...FAST });
  assert.equal(armed.verdict, 'FAIL');
  assert.equal(armed.steps.find((step) => step.id === 'precheck-real-state').reason, 'DRILL_REAL_SWITCH_ACTIVE');
  await realSwitch.reset({ resetBy: 'operator', resetToken: '0123456789abcdef0123456789abcdef' });

  // Registered real worker: refuse with DRILL_REAL_WORKERS_PRESENT,
  // and the real worker's process must still be alive afterwards —
  // the drill only ever cancels workers it started itself.
  const realChild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });
  const registration = await realSwitch.registerWorker({
    workerId: 'real-worker',
    cancel: async () => { realChild.kill('SIGKILL'); },
  });
  assert.equal(registration.registered, true);
  try {
    const refused = await runDrill({ stateDir, skillDirectory: SKILL_DIR, ...FAST });
    assert.equal(refused.verdict, 'FAIL');
    assert.equal(refused.steps.find((step) => step.id === 'precheck-real-state').reason, 'DRILL_REAL_WORKERS_PRESENT');
    assert.equal(realChild.exitCode, null, 'drill must not kill a real worker');
    assert.equal(realChild.signalCode, null, 'drill must not kill a real worker');
  } finally {
    // Awaited: unregister() writes the state file asynchronously, and
    // the test's t.after temp-dir removal runs right after this block —
    // an un-awaited write raced the removal (ENOTEMPTY) once the
    // round-46 helper started removing the dir.
    await registration.unregister();
    realChild.kill('SIGKILL');
  }
});

test('drill refuses a double-arm and recovers an abandoned armed state only with --recover', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-armed-');
  const pid = await deadPid();
  await armDrillState(stateDir, { workerPid: pid });
  await appendDrillStart(stateDir, 'drill-abandoned-run');

  const refused = await runDrill({ stateDir, skillDirectory: SKILL_DIR, ...FAST });
  assert.equal(refused.verdict, 'FAIL');
  assert.equal(refused.steps.find((step) => step.id === 'precheck-drill-state').reason, 'DRILL_ALREADY_ARMED');
  // The armed state is still there after the refusal.
  assert.equal((await readJson(path.join(stateDir, 'drill', 'kill-switch.json'))).active, true);

  const recovered = await runDrill({ stateDir, skillDirectory: SKILL_DIR, recover: true, ...FAST });
  assert.equal(recovered.verdict, 'PASS');
  assert.match(recovered.steps.find((step) => step.id === 'precheck-drill-state').detail, /Recovered abandoned armed drill state/);
  const events = await readAuditEvents(stateDir);
  const recoveredEvent = events.find((event) => event.event === 'DRILL_RECOVERED');
  assert.ok(recoveredEvent, 'interruption stays on the audit record');
  assert.equal(recoveredEvent.details.abandonedRunId, 'drill-abandoned-run');
  assert.equal(recoveredEvent.details.triggerId, 'abandoned-trigger');
  assert.equal((await readJson(path.join(stateDir, 'drill', 'kill-switch.json'))).active, false);
});

test('recovery refuses while a drill worker process is still alive', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-alive-');
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });
  try {
    await armDrillState(stateDir, { workerPid: child.pid });
    await appendDrillStart(stateDir, 'drill-alive-run');
    const result = await runDrill({ stateDir, skillDirectory: SKILL_DIR, recover: true, ...FAST });
    assert.equal(result.verdict, 'FAIL');
    assert.equal(result.steps.find((step) => step.id === 'precheck-drill-state').reason, 'DRILL_WORKER_STILL_ALIVE');
    assert.equal(child.exitCode, null, 'recovery must not kill the live worker itself');
    assert.equal(child.signalCode, null, 'recovery must not kill the live worker itself');
  } finally {
    child.kill('SIGKILL');
  }
});

test('recovery refuses an armed drill state with no DRILL_START on record', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-inconsistent-');
  await armDrillState(stateDir, { workerPid: await deadPid() });
  const result = await runDrill({ stateDir, skillDirectory: SKILL_DIR, recover: true, ...FAST });
  assert.equal(result.verdict, 'FAIL');
  assert.equal(result.steps.find((step) => step.id === 'precheck-drill-state').reason, 'DRILL_STATE_INCONSISTENT');
});

test('CLI: drill prints per-step PASS/FAIL plus a verdict and exits 0 on PASS', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-cli-');
  const output = await new Promise((resolve, reject) => {
    execFile(process.execPath, [CLI, 'drill', '--state-dir', stateDir], (error, stdout, stderr) => {
      if (error && error.code !== 0) reject(new Error(`exit ${error.code}: ${stderr}`));
      else resolve(stdout);
    });
  });
  assert.match(output, /PASS precheck-real-state/);
  assert.match(output, /PASS trigger-stubborn/);
  assert.match(output, /drill: PASS/);
  const summary = JSON.parse(output.slice(output.indexOf('{\n  "verdict"')));
  assert.equal(summary.verdict, 'PASS');
  assert.equal(summary.steps.length, 11);
});

test('CLI: drill --recover recovers an abandoned armed state; a second plain drill refuses', async (t) => {
  const stateDir = await tempStateDir(t, 'sentinel-drill-cli-recover-');
  await armDrillState(stateDir, { workerPid: await deadPid() });
  await appendDrillStart(stateDir, 'drill-cli-abandoned');

  const refused = await new Promise((resolve) => {
    execFile(process.execPath, [CLI, 'drill', '--state-dir', stateDir], (error, stdout) => resolve({ code: error?.code ?? 0, stdout }));
  });
  assert.equal(refused.code, 1);
  assert.match(refused.stdout, /FAIL precheck-drill-state/);
  assert.match(refused.stdout, /drill: FAIL/);

  const recovered = await new Promise((resolve, reject) => {
    execFile(process.execPath, [CLI, 'drill', '--state-dir', stateDir, '--recover'], (error, stdout, stderr) => {
      if (error && error.code !== 0) reject(new Error(`exit ${error.code}: ${stderr}`));
      else resolve(stdout);
    });
  });
  assert.match(recovered, /drill: PASS/);
});
