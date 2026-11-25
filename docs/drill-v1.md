# Incident-response drill (v1, round 39)

## What it is

```text
sentinel drill [--state-dir <path>] [--recover]
```

`sentinel drill` exercises the kill-switch end-to-end in the lab
against a fake worker — a local child process that only sleeps, never
a real target and never a network call. One drill run covers two
phases: a cooperative worker (exits on SIGTERM) and a stubborn worker
(ignores SIGTERM, so the drill must escalate to SIGKILL and report
it honestly). Each phase arms the kill-switch, cancels the worker,
verifies the audit record, and resets to clean. The drill prints a
PASS/FAIL line per step plus an overall verdict, and exits non-zero
if any step fails.

## Steps (11 per run)

| # | Step | What it proves |
|---|------|----------------|
| 1 | `precheck-real-state` | Real kill-switch inactive, no real workers registered (read-only check). |
| 2 | `precheck-drill-state` | Drill state clean (or recovered, see below). |
| 3 | `start-cooperative-worker` | Fake worker spawned and registered in the drill state. |
| 4 | `trigger-cooperative` | Trigger cancels the worker within the bound, without escalation. |
| 5 | `verify-audit-cooperative` | Audit log records the trigger and the cancellation. |
| 6 | `reset-after-cooperative` | Kill-switch resets; state is clean. |
| 7 | `start-stubborn-worker` | SIGTERM-ignoring fake worker spawned and registered. |
| 8 | `trigger-stubborn` | Trigger cancels the worker, escalating to SIGKILL. |
| 9 | `verify-audit-stubborn` | Audit log records the trigger and the escalation. |
| 10 | `reset-after-stubborn` | Kill-switch resets; state is clean. |
| 11 | `complete` | `DRILL_COMPLETE` written; overall verdict PASS. |

Defaults: SIGTERM grace 1,000 ms, cancel bound 5,000 ms, worker
lease 30,000 ms (longer than the default 5,000 ms so a slow machine
cannot expire a drill lease mid-run).

## Safety rules

1. **The drill never touches real kill-switch state.** It uses a
   drill-scoped directory `<state-dir>/drill/` with its own
   `kill-switch.json` + `audit.jsonl` and a separate
   `PersistentKillSwitch` instance. The only contact with real state
   is step 1, a read-only `snapshotLockless()` (no lock, no writes).
2. **Refuse while real work exists.** If the real switch is armed
   (`DRILL_REAL_SWITCH_ACTIVE`) or any real worker is registered
   (`DRILL_REAL_WORKERS_PRESENT`), the drill refuses and exits 1. A
   corrupt real state file is also a refusal
   (`DRILL_REAL_STATE_UNREADABLE`), not a crash.
3. **Only its own workers.** Drill workers are tagged by workerId
   prefix `drill-<runId>-` and their cancel function closes over the
   exact child process the drill spawned, so a drill can only ever
   cancel its own workers. The drill reset uses an ephemeral,
   in-memory token generated per run — a dead drill leaves no usable
   token behind.
4. **Readiness before arming.** The fake worker prints `ready` once
   it is running; the drill waits for that line (5 s timeout) before
   arming. Without this, a SIGTERM landing before the child has
   executed its script would kill it with the default disposition
   and fake the stubborn-worker's result. (Found the hard way: the
   first implementation failed the stubborn phase exactly like this.)
5. **Signal-killed is dead.** A process killed by a signal has
   `exitCode === null` and `signalCode` set. Aliveness is checked
   with `exitCode !== null || signalCode !== null`, never with
   `exitCode` alone. (Also found the hard way: the first
   implementation reported a successfully cancelled worker as still
   alive.)

## Failure behaviors

- **Worker ignores SIGTERM:** the cancel path waits the grace
  period, then escalates to SIGKILL and reports `escalated: true`
  with the elapsed milliseconds. Escalation is a recorded outcome,
  not a failure — the step fails only if the worker is still alive
  after SIGKILL (`DRILL_WORKER_CANCEL_FAILED`) or if the escalation
  flag does not match the phase (`DRILL_ESCALATION_MISMATCH`).
- **Already armed drill state:** the drill refuses cleanly with
  `DRILL_ALREADY_ARMED` and exits 1. It never double-arms. The
  refusal is recorded as `DRILL_REFUSED` in the drill audit log.
  A refusal leaves no `DRILL_START` behind, so a later recovery
  cannot mistake the refusal for the abandoned run.
- **Interrupted mid-run:** a drill interrupted after arming leaves
  an armed drill state behind. `sentinel drill --recover` recovers
  it — valid ONLY because drill state is scoped and disposable by
  design: it verifies no drill worker process is still alive (PID
  liveness check; a live worker refuses recovery with
  `DRILL_WORKER_STILL_ALIVE`), appends a `DRILL_RECOVERED` record
  to the drill audit log (the interruption stays on the record),
  and replaces the drill kill-switch file with a clean state. The
  same trick must NEVER be applied to the real state directory.
  Recovery also refuses when the audit log cannot be read
  (`DRILL_AUDIT_UNREADABLE`) or when the armed state contradicts
  the audit record — an armed state with a `DRILL_COMPLETE` after
  the last `DRILL_START`, or with no `DRILL_START` at all
  (`DRILL_STATE_INCONSISTENT`).
- **A failed drill** appends `DRILL_FAILED` to the audit log and
  SIGKILLs any drill child it spawned that is still alive
  (best-effort) before returning.

## Audit events (drill audit log only)

`DRILL_START`, `DRILL_WORKER_STARTED`, `KILL_SWITCH_TRIGGER`,
`DRILL_WORKER_CANCELLED` (with `cancelled`, `escalated`, `ms`),
`DRILL_RESET`, `DRILL_COMPLETE`, `DRILL_REFUSED`,
`DRILL_RECOVERED`, `DRILL_FAILED`. All carry `runId` so one run's
record can be followed through the log.

## What it does NOT prove

The drill proves the kill-switch machinery (arm → cancel → audit →
reset) works against a local sleep loop. It does not prove
cancellation of a real tool, a networked worker, or a worker that
catches SIGKILL (impossible), and it says nothing about detection,
scoring, or reporting quality. It is a Phase 8 hardening exercise,
not a substitute for a live-fire test against a real workload.
