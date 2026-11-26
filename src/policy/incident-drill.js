// Incident-response drill (Phase 8 hardening, round 39).
//
// `sentinel drill` exercises the kill-switch end-to-end in the lab
// against a fake worker — a local child process that only sleeps, never
// a real target and never a network call. Two phases run in one drill:
// a cooperative worker (exits on the polite cancel) and a stubborn
// worker (ignores the polite cancel, so the drill must escalate to
// SIGKILL and report it honestly).
//
// Polite cancel is platform-aware (round 83): on POSIX it is SIGTERM,
// which a handler can swallow. On Windows there is no SIGTERM delivery
// to a handler — the OS terminates the process outright (TerminateProcess)
// — so a "stubborn" worker cannot be stubborn against SIGTERM at all:
// it would die on the polite step and the escalation check would fail
// (Windows run 54: all four drill tests). On win32 the polite step is
// therefore an IPC `cancel` message over the child's IPC channel, which
// the stubborn worker ignores like it ignores SIGTERM on POSIX. The
// forceful step is SIGKILL on both platforms (TerminateProcess on
// Windows), and the `escalated` verdict keeps the same meaning: the
// worker only died on the forceful step.
//
// Safety model, in one paragraph: the drill NEVER touches the real
// kill-switch state. It uses a drill-scoped state directory
// `<state-dir>/drill/` (its own kill-switch.json + audit.jsonl) and a
// separate PersistentKillSwitch instance with an ephemeral, in-memory
// reset token that dies with the process. The only contact with real
// state is a read-only pre-check (snapshotLockless: no lock, no writes)
// that REFUSES the drill while the real switch is armed or any real
// worker is registered. Drill workers are tagged by workerId prefix
// `drill-<runId>-` and their cancel function closes over the exact
// child process the drill spawned, so a drill can only ever cancel its
// own workers.
//
// Recovery: a drill interrupted after arming leaves an armed drill
// state behind. `sentinel drill --recover` recovers it — but ONLY
// because drill state is scoped and disposable by design: it verifies
// no drill worker process is still alive (PID liveness check), appends
// a DRILL_RECOVERED record to the drill audit log (the interruption
// stays on the record), and replaces the drill kill-switch file with
// a clean state. The same trick must NEVER be applied to the real
// state directory. Without --recover, an armed drill state makes the
// drill refuse cleanly (DRILL_ALREADY_ARMED) instead of double-arming.

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { PersistentKillSwitch } = require('./persistent-kill-switch');
const { AuditLog } = require('../audit/audit-log');
const { ensurePrivateDir } = require('./state-permissions');

const DRILL_DIR_NAME = 'drill';
const DRILL_ACTOR = 'drill';
const DEFAULT_SIGTERM_GRACE_MS = 1_000;
const DEFAULT_CANCEL_TIMEOUT_MS = 5_000;
const DEFAULT_WORKER_LEASE_MS = 30_000;
const EXIT_POLL_MS = 25;

// A sleep loop: the fake lab worker does nothing but stay alive until
// cancelled. No target, no network, no work of any kind. The worker
// prints `ready` once it is running — the drill waits for that line
// before arming, so a polite cancel can never land before the handler
// is installed (a freshly spawned child cancelled in that window would
// die with the default disposition and fake the result).
//
// Both scripts install both polite-cancel handlers, so the same script
// works on either platform: the cooperative worker exits on the IPC
// `cancel` message and dies on SIGTERM by default disposition; the
// stubborn worker swallows both. Which channel the drill actually uses
// is decided by cancelChild (SIGTERM on POSIX, IPC on win32).
const COOPERATIVE_WORKER_SCRIPT = "process.on('message', (m) => { if (m === 'cancel') process.exit(0); }); console.log('ready'); setInterval(() => {}, 1000);";
// Same sleep loop, but the polite cancel is swallowed: proves the drill
// escalates to SIGKILL instead of reporting a success it did not
// achieve.
const STUBBORN_WORKER_SCRIPT = "process.on('message', () => {}); process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000);";

const READY_TIMEOUT_MS = 5_000;

function waitForReady(child, timeoutMs) {
  return new Promise((resolve) => {
    let buffer = '';
    const timer = setTimeout(() => {
      cleanup();
      resolve(false);
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.includes('ready')) {
        cleanup();
        resolve(true);
      }
    };
    const onExit = () => {
      cleanup();
      resolve(false);
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout?.removeListener('data', onData);
      child.removeListener('exit', onExit);
    };
    child.stdout?.on('data', onData);
    child.once('exit', onExit);
  });
}

function isExited(child) {
  // A process killed by a signal has exitCode null and signalCode set:
  // checking exitCode alone wrongly reports a signal-killed worker as
  // still alive.
  return child.exitCode !== null || child.signalCode !== null;
}

function waitForExit(child, timeoutMs) {
  if (isExited(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.removeListener('exit', onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once('exit', onExit);
  });
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // ESRCH: no such process. EPERM: a process exists but this user
    // may not signal it — alive is the safe answer.
    return error.code !== 'ESRCH';
  }
}

// Send the polite cancel to one drill child: SIGTERM on POSIX, an IPC
// `cancel` message on win32 (Windows cannot deliver SIGTERM to a
// handler — see the module header). A failed send means the channel is
// already closed, i.e. the child is exiting; waitForExit settles that.
function sendPoliteCancel(child) {
  if (process.platform === 'win32') {
    try {
      return child.send('cancel');
    } catch {
      return false;
    }
  }
  return child.kill('SIGTERM');
}

// Cancel one drill child: polite cancel, a grace period, then SIGKILL.
// The outcome is reported honestly — `escalated` is true exactly when
// the worker ignored the polite cancel and only died on SIGKILL.
async function cancelChild(child, { sigtermGraceMs, cancelTimeoutMs }) {
  const started = Date.now();
  if (isExited(child)) return { cancelled: true, escalated: false, ms: 0 };
  sendPoliteCancel(child);
  if (await waitForExit(child, sigtermGraceMs)) {
    return { cancelled: true, escalated: false, ms: Date.now() - started };
  }
  child.kill('SIGKILL');
  const remaining = Math.max(0, cancelTimeoutMs - (Date.now() - started));
  if (await waitForExit(child, remaining)) {
    return { cancelled: true, escalated: true, ms: Date.now() - started };
  }
  return { cancelled: false, escalated: true, ms: Date.now() - started };
}

async function writeCleanDrillState(stateFile) {
  const temporary = `${stateFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let renamed = false;
  try {
    await fs.writeFile(temporary, JSON.stringify({ version: 2, active: false, trigger: null, workers: [] }, null, 2), { encoding: 'utf8', mode: 0o600 });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, stateFile);
    renamed = true;
    await fs.chmod(stateFile, 0o600);
  } finally {
    if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function runDrill({
  stateDir,
  skillDirectory,
  recover = false,
  sigtermGraceMs = DEFAULT_SIGTERM_GRACE_MS,
  cancelTimeoutMs = DEFAULT_CANCEL_TIMEOUT_MS,
  clock = () => Date.now(),
} = {}) {
  if (typeof stateDir !== 'string' || !path.isAbsolute(stateDir)) throw new TypeError('stateDir must be an absolute path.');
  if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path.');
  if (!Number.isInteger(sigtermGraceMs) || sigtermGraceMs < 0) throw new TypeError('sigtermGraceMs must be a non-negative integer.');
  if (!Number.isInteger(cancelTimeoutMs) || cancelTimeoutMs <= sigtermGraceMs) throw new TypeError('cancelTimeoutMs must be an integer greater than sigtermGraceMs.');

  const startedAt = Date.now();
  const runId = `drill-${crypto.randomUUID()}`;
  const drillDir = path.join(stateDir, DRILL_DIR_NAME);
  const drillStateFile = path.join(drillDir, 'kill-switch.json');
  const drillAuditFile = path.join(drillDir, 'audit.jsonl');
  const steps = [];
  const children = [];
  let audit = null;
  let killSwitch = null;

  const record = (id, status, detail, reason) => {
    const step = { id, status, detail };
    if (reason) step.reason = reason;
    steps.push(step);
    return status === 'PASS';
  };
  const fail = (id, detail, reason) => record(id, 'FAIL', detail, reason);

  try {
    // ensurePrivateDir (round 45): mkdir({ recursive, mode }) alone
    // never chmods a directory that already exists.
    await ensurePrivateDir(drillDir);
    audit = new AuditLog({ logFile: drillAuditFile, skillDirectory, clock });
    // Ephemeral reset token, in memory only: the drill can reset its
    // own scoped switch, and a dead drill leaves no usable token behind.
    const ephemeralToken = crypto.randomBytes(16).toString('hex');
    killSwitch = new PersistentKillSwitch({
      stateFile: drillStateFile,
      skillDirectory,
      clock,
      workerLeaseMs: DEFAULT_WORKER_LEASE_MS,
      resetToken: ephemeralToken,
    });
    const ephemeralReset = () => killSwitch.reset({ resetBy: DRILL_ACTOR, resetToken: ephemeralToken });

    // DRILL_START is recorded only AFTER the pre-checks pass: a refused
    // drill must not leave a DRILL_START behind, or recovery would
    // mistake the refusal itself for the abandoned run.
    // Step 1 — real state pre-check (read-only): refuse while the real
    // switch is armed or any real worker is registered. A corrupt real
    // state file is also a refusal, not a crash.
    const realSwitch = new PersistentKillSwitch({ stateFile: path.join(stateDir, 'kill-switch.json'), skillDirectory, clock });
    let realSnapshot;
    try {
      realSnapshot = await realSwitch.snapshotLockless();
    } catch (error) {
      await audit.append('DRILL_REFUSED', { runId, reason: 'DRILL_REAL_STATE_UNREADABLE', error: error.message }).catch(() => {});
      fail('precheck-real-state', 'Real kill-switch state could not be read; drill refused.', 'DRILL_REAL_STATE_UNREADABLE');
      return finish();
    }
    if (realSnapshot.active) {
      await audit.append('DRILL_REFUSED', { runId, reason: 'DRILL_REAL_SWITCH_ACTIVE' }).catch(() => {});
      fail('precheck-real-state', 'Real kill-switch is armed; drill refused.', 'DRILL_REAL_SWITCH_ACTIVE');
      return finish();
    }
    if (realSnapshot.registeredWorkers > 0) {
      await audit.append('DRILL_REFUSED', { runId, reason: 'DRILL_REAL_WORKERS_PRESENT', registeredWorkers: realSnapshot.registeredWorkers }).catch(() => {});
      fail('precheck-real-state', `${realSnapshot.registeredWorkers} real worker(s) registered; drill refused.`, 'DRILL_REAL_WORKERS_PRESENT');
      return finish();
    }
    record('precheck-real-state', 'PASS', 'Real kill-switch inactive, no real workers registered.');

    // Step 2 — drill state pre-check: refuse a double-arm; recover only
    // with --recover, and only from an abandoned drill run.
    let drillSnapshot;
    try {
      drillSnapshot = await killSwitch.snapshotLockless();
    } catch (error) {
      fail('precheck-drill-state', 'Drill kill-switch state could not be read.', 'DRILL_STATE_UNREADABLE');
      return finish();
    }
    if (drillSnapshot.active) {
      if (!recover) {
        await audit.append('DRILL_REFUSED', { runId, reason: 'DRILL_ALREADY_ARMED', triggerId: drillSnapshot.trigger?.triggerId }).catch(() => {});
        fail('precheck-drill-state', 'Drill kill-switch is already armed (previous drill interrupted?). Re-run with --recover.', 'DRILL_ALREADY_ARMED');
        return finish();
      }
      const recovered = await recoverStaleDrillState({ killSwitch, audit, drillStateFile, runId });
      if (!recovered.ok) {
        fail('precheck-drill-state', `Recovery of the abandoned armed drill state failed: ${recovered.detail}`, recovered.reason);
        return finish();
      }
      record('precheck-drill-state', 'PASS', `Recovered abandoned armed drill state (${recovered.detail}).`);
    } else {
      record('precheck-drill-state', 'PASS', recover ? 'Drill state clean; nothing to recover.' : 'Drill state clean.');
    }
    await audit.append('DRILL_START', { runId, stateDir: drillDir });

    // Phases: cooperative worker, then stubborn worker. Each phase arms,
    // cancels, verifies the audit record, and resets to clean.
    for (const phase of [
      { kind: 'cooperative', script: COOPERATIVE_WORKER_SCRIPT, expectEscalated: false },
      { kind: 'stubborn', script: STUBBORN_WORKER_SCRIPT, expectEscalated: true },
    ]) {
      const workerId = `${runId}-${phase.kind}`;
      const startId = `start-${phase.kind}-worker`;
      const triggerId = `trigger-${phase.kind}`;
      const auditId = `verify-audit-${phase.kind}`;
      const resetId = `reset-after-${phase.kind}`;

      // The fourth stdio entry opens the IPC channel the win32 polite
      // cancel uses; on POSIX it is unused (the polite step is SIGTERM).
      const child = spawn(process.execPath, ['-e', phase.script], { stdio: ['ignore', 'pipe', 'ignore', 'ipc'] });
      children.push(child);
      if (!(await waitForReady(child, READY_TIMEOUT_MS))) {
        fail(startId, `Worker did not signal ready within ${READY_TIMEOUT_MS}ms.`, 'DRILL_WORKER_NOT_READY');
        return finish();
      }
      const cancelOutcome = { value: null };
      const cancel = async () => {
        const outcome = await cancelChild(child, { sigtermGraceMs, cancelTimeoutMs });
        cancelOutcome.value = outcome;
        if (!outcome.cancelled) throw new Error('DRILL_WORKER_CANCEL_FAILED');
      };
      let registration;
      try {
        registration = await killSwitch.registerWorker({ workerId, cancel });
      } catch (error) {
        fail(startId, `Worker registration failed: ${error.message}`, 'DRILL_WORKER_REGISTER_FAILED');
        return finish();
      }
      if (!registration.registered) {
        fail(startId, `Worker registration refused: ${registration.reason}`, registration.reason);
        return finish();
      }
      await audit.append('DRILL_WORKER_STARTED', { runId, workerId, kind: phase.kind, pid: child.pid });
      const registered = await killSwitch.snapshot();
      if (registered.registeredWorkers !== 1 || !registered.workers.some((worker) => worker.workerId === workerId)) {
        fail(startId, 'Worker not visible in the drill kill-switch snapshot after registration.', 'DRILL_WORKER_NOT_REGISTERED');
        return finish();
      }
      record(startId, 'PASS', `${phase.kind} worker started (pid ${child.pid}) and registered as ${workerId}.`);

      const triggerStarted = Date.now();
      const trigger = await killSwitch.trigger({ triggeredBy: DRILL_ACTOR, reason: `drill ${phase.kind} phase` });
      await audit.append('KILL_SWITCH_TRIGGER', { runId, workerId, kind: phase.kind, triggerId: trigger.trigger?.triggerId, reason: trigger.reason || 'TRIGGERED' });
      if (!trigger.triggered) {
        fail(triggerId, `Kill-switch did not trigger: ${trigger.reason}`, trigger.reason);
        return finish();
      }
      const cancellation = trigger.cancellations.find((entry) => entry.workerId === workerId);
      const outcome = cancelOutcome.value;
      if (!cancellation?.cancelled || !outcome?.cancelled) {
        fail(triggerId, `Worker was not cancelled within ${cancelTimeoutMs}ms (escalated: ${outcome?.escalated ?? 'unknown'}).`, 'DRILL_WORKER_CANCEL_FAILED');
        return finish();
      }
      if (outcome.escalated !== phase.expectEscalated) {
        fail(triggerId, `Escalation mismatch: escalated=${outcome.escalated}, expected ${phase.expectEscalated}.`, 'DRILL_ESCALATION_MISMATCH');
        return finish();
      }
      if (!isExited(child)) {
        fail(triggerId, 'Cancel reported success but the worker process is still alive.', 'DRILL_WORKER_STILL_ALIVE');
        return finish();
      }
      await audit.append('DRILL_WORKER_CANCELLED', { runId, workerId, kind: phase.kind, cancelled: true, escalated: outcome.escalated, ms: outcome.ms });
      record(triggerId, 'PASS', `Worker cancelled in ${outcome.ms}ms (escalated to SIGKILL: ${outcome.escalated}; trigger took ${Date.now() - triggerStarted}ms).`);

      let events;
      try {
        events = await audit.readEvents();
      } catch (error) {
        fail(auditId, `Drill audit log could not be read: ${error.message}`, 'DRILL_AUDIT_UNREADABLE');
        return finish();
      }
      const runEvents = events.filter((event) => event.details?.runId === runId && event.details?.kind === phase.kind);
      const hasTrigger = runEvents.some((event) => event.event === 'KILL_SWITCH_TRIGGER');
      const hasCancellation = runEvents.some((event) => event.event === 'DRILL_WORKER_CANCELLED' && event.details?.cancelled === true);
      if (!hasTrigger || !hasCancellation) {
        fail(auditId, `Audit log is missing the ${phase.kind} trigger/cancellation record (trigger: ${hasTrigger}, cancellation: ${hasCancellation}).`, 'DRILL_AUDIT_INCOMPLETE');
        return finish();
      }
      record(auditId, 'PASS', `Audit log records the ${phase.kind} trigger and cancellation.`);

      // unregister() is async: awaiting it matters. The first version
      // called it fire-and-forget, so reset() raced the unregister's
      // state-file write and flaked with WORKERS_STILL_REGISTERED
      // under parallel load (caught by the suite, run 3 of 3).
      const unregistered = await registration.unregister();
      if (!unregistered) {
        fail(resetId, 'Worker could not be unregistered before reset.', 'DRILL_WORKER_UNREGISTER_FAILED');
        return finish();
      }
      const reset = await ephemeralReset();
      if (!reset.reset) {
        fail(resetId, `Kill-switch reset refused: ${reset.reason}`, reset.reason);
        return finish();
      }
      const afterReset = await killSwitch.snapshot();
      if (afterReset.active || afterReset.registeredWorkers !== 0) {
        fail(resetId, 'State is not clean after reset.', 'DRILL_STATE_NOT_CLEAN');
        return finish();
      }
      await audit.append('DRILL_RESET', { runId, workerId, kind: phase.kind });
      record(resetId, 'PASS', `Kill-switch reset; state clean after the ${phase.kind} phase.`);
    }

    await audit.append('DRILL_COMPLETE', { runId, verdict: 'PASS' });
    record('complete', 'PASS', 'Both phases passed; drill audit log complete.');
    return finish();

    function finish() {
      const verdict = steps.every((step) => step.status === 'PASS') ? 'PASS' : 'FAIL';
      return Object.freeze({
        verdict,
        runId,
        stateDir,
        drillStateDir: drillDir,
        steps: Object.freeze(steps),
        durationMs: Date.now() - startedAt,
      });
    }
  } catch (error) {
    // A drill failure must never leave a drill child running: SIGKILL
    // anything this run spawned that is still alive, best-effort.
    for (const child of children) {
      if (!isExited(child)) {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
      }
    }
    if (audit) {
      await audit.append('DRILL_FAILED', { runId, error: error.message }).catch(() => {});
    }
    steps.push({ id: 'drill-error', status: 'FAIL', detail: `Drill aborted: ${error.message}`, reason: 'DRILL_ERROR' });
    return Object.freeze({
      verdict: 'FAIL',
      runId,
      stateDir,
      drillStateDir: drillDir,
      steps: Object.freeze(steps),
      durationMs: Date.now() - startedAt,
    });
  }
}

// Recover an armed drill state left by an interrupted run. Valid ONLY
// for drill-scoped state: the state file is disposable by design, the
// audit log survives (the interruption stays on the record), and no
// live drill worker may exist. Refuses when a drill worker process is
// still alive, when the audit log cannot be read, or when the armed
// state contradicts the audit record (a DRILL_COMPLETE after the last
// DRILL_START means the state is inconsistent, not merely abandoned).
async function recoverStaleDrillState({ killSwitch, audit, drillStateFile, runId }) {
  let snapshot;
  try {
    snapshot = await killSwitch.snapshotLockless();
  } catch (error) {
    return { ok: false, reason: 'DRILL_STATE_UNREADABLE', detail: error.message };
  }
  if (!snapshot.active) return { ok: true, detail: 'state already clean' };
  let events;
  try {
    events = await audit.readEvents();
  } catch (error) {
    return { ok: false, reason: 'DRILL_AUDIT_UNREADABLE', detail: error.message };
  }
  const starts = events.map((event, index) => ({ event, index })).filter(({ event }) => event.event === 'DRILL_START');
  if (starts.length === 0) return { ok: false, reason: 'DRILL_STATE_INCONSISTENT', detail: 'armed drill state with no DRILL_START on record' };
  const lastStart = starts[starts.length - 1];
  const completedAfterStart = events.slice(lastStart.index + 1).some((event) => event.event === 'DRILL_COMPLETE');
  if (completedAfterStart) return { ok: false, reason: 'DRILL_STATE_INCONSISTENT', detail: 'DRILL_COMPLETE on record but drill state is still armed' };
  for (const worker of snapshot.workers) {
    if (isPidAlive(worker.pid)) {
      return { ok: false, reason: 'DRILL_WORKER_STILL_ALIVE', detail: `drill worker ${worker.workerId} (pid ${worker.pid}) is still alive; kill it by hand first` };
    }
  }
  await audit.append('DRILL_RECOVERED', {
    runId,
    abandonedRunId: lastStart.event.details?.runId,
    triggerId: snapshot.trigger?.triggerId,
    triggeredAt: snapshot.trigger?.triggeredAt,
  });
  await writeCleanDrillState(drillStateFile);
  const after = await killSwitch.snapshotLockless();
  if (after.active || after.registeredWorkers !== 0) {
    return { ok: false, reason: 'DRILL_STATE_NOT_CLEAN', detail: 'state still armed after recovery write' };
  }
  return { ok: true, detail: `abandoned run ${lastStart.event.details?.runId || 'unknown'} recovered; interruption recorded as DRILL_RECOVERED` };
}

module.exports = {
  runDrill,
  recoverStaleDrillState,
  DRILL_DIR_NAME,
  DEFAULT_SIGTERM_GRACE_MS,
  DEFAULT_CANCEL_TIMEOUT_MS,
  // Exported for tests: the IPC-cancel mechanism the win32 polite step
  // relies on is verified by spawning these scripts directly.
  COOPERATIVE_WORKER_SCRIPT,
  STUBBORN_WORKER_SCRIPT,
};
