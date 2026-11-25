# Pending-promise audit (Phase 8 hardening, round 47)

## Why this exists

There is no `unhandledRejection` handler anywhere in `src/` or
`bin/` — and `bin/sentinel.js` only catches rejections from the
top-level `main()` promise. Any other promise that rejects without
a handler crashes the process (Node's default), and any `await`
that is missing from a cleanup path can leave a run unsettled or a
state write stranded. Two earlier rounds already hit this shape:
round 39's drill caught a readiness race, and round 46's test
migration exposed an un-awaited `unregister()` racing a directory
removal (`ENOTEMPTY`). This round audited every unawaited async
call in `src/` and `bin/` and fixed the ones that were real.

## Method

Enumerate every `async` function in `src/` and `bin/`, then check
each call site for `await` / `return` / `.catch()` / a both-handled
`.then()`. Also checked: `fs` promise calls without `await`, `new
Promise(async ...)` executors, async `setTimeout`/`setInterval`
callbacks, async event-emitter handlers, and every
`unregister()`/`finishRun()` call site. The audit is recorded in
`capability-report-2026-11-26-pending-promise-audit.md` (F1);
the findings below are the fixes.

## The four real fixes

### A. Adapter `unregister()` was fire-and-forget (the headline)

`src/http/local-http-adapter.js` `cleanup()` called the async
`PersistentKillSwitch.unregisterWorker` without awaiting it.
Consequences, both real: (1) a process exiting right after `get()`
resolved could strand the worker record until lease expiry (the
default lease is 5 s), blocking `reset()` with
`WORKERS_STILL_REGISTERED` in that window; (2) a write rejection
(ENOSPC, EPERM) became an unhandled rejection — a process crash.

Fix: `cleanup()` is async and `finishRun` awaits it before
resolving. `finishRun` never rejects by construction: a cleanup
failure resolves with the real HTTP result plus
`unregisterFailed: true`, so the outcome stays honest instead of
masking a completed request as a policy error. The two synchronous
call sites (the `error` handler, the timeout) call it as `void
finishRun(...)`; the guard test enforces that every other call
site awaits it.

### B. Wrapper timeout: a throwing `terminate()` hung the run and crashed the process

`src/execution/controlled-wrapper.js` `setTimeout(async () => {
await terminate(); finish(...); })` — if `terminate()` threw
(signalling a process group with an unexpected error code, or a
`/proc` read failure in `collectDescendantPids`), `finish()` never
ran (the run promise hung forever) AND the callback's rejection
escaped unhandled. Proved by test: on the old code the new test
hung the whole test file for 60 s.

Fix: `try/catch` around `terminate()`; `finish()` always runs
with `EXECUTION_TIMEOUT`, plus `terminationFailed: true` in the
result when the catch fired. The same hardening was applied to
the kill poller's catch path (`await terminate()` inside a `catch`
could itself throw and escape the interval callback): a nested
`try/catch` swallows the retry failure. Invariant, stated here
because the code relies on it: **a run always settles by
`timeoutMs` at the latest**, even when termination itself fails.

### C. Adapter poller: `catch { await cancel(); }` could throw

The kill poller in the adapter called `cancel()` in its `catch`
block unguarded. `cancel()` is now non-rejecting by construction
(`finishRun` converts cleanup failures to a resolved value and
`request.destroy()` is guarded), but a rejection escaping the
interval callback would still crash the process, so the catch path
has a defensive nested `try/catch` around the retry. Same shape
as B, same reason.

### D. Lock close() throwing skipped the lock removal

`src/audit/audit-log.js` `#withLock` and `bin/sentinel.js`
`withTokenRotationLock` both did `await handle.close()` then
`await fs.unlink(lockFile)` in a `finally`. If `close()` threw
(EBADF, EIO), the removal was skipped and the stale lock stayed
behind, blocking audit appends / token rotation with
`AUDIT_LOG_LOCKED` / `RESET_TOKEN_ROTATION_LOCKED` until the 60 s
stale-lock reaper removed it. Rare (close() almost never throws),
but the fix is one shared helper: `src/policy/lock-file.js`
`closeAndRemoveLock(handle, lockFile)` removes the file in a
`finally`, so removal always runs; a close() error propagates
after the removal, and a non-ENOENT removal error replaces it.

## Benign sites (audited, no change)

- `controlled-wrapper.js` `Promise.resolve(close()).then(onOk,
  onErr)` — both handlers present; a `close()` rejection becomes
  a `POLICY_ERROR` result.
- `local-http-adapter.js` `.then(...).catch(...)` on the
  `registerWorker` chain — the catch converts a registration
  failure to `PROCESS_ERROR`.
- `response.once('end', async ...)` in the adapter — `try/catch`
  inside.
- `trigger()` in both kill switches — `Promise.allSettled`,
  awaited; a failing `cancel` is recorded as `cancelled: false`
  with the error string, never an escaping rejection.
- `bin/sentinel.js` top-level `main(...).catch(...)` — every CLI
  path is covered.
- Every `audit.append`, `snapshot`, `reset`, `trigger`,
  `verifyChain`, `readEvents`, `healthCheck`, `backupState`,
  `restoreState`, `runDrill`, `runVerifyInstall`,
  `checkStatePermissions`, `ensurePrivateDir`, and `fs` promise
  call in `src/` and `bin/` is awaited (or returned). No `new
  Promise(async ...)` executor exists. No `fs` promise call is
  unawaited.
- `src/policy/safe-write.js` `finally { await handle.close(); }`:
  a close() failure after a successful write only surfaces the
  close error (the file was already written); no data loss, no
  lock left behind. Left as is, noted here.
- The drill's `waitForReady` / `waitForExit` Promise executors
  are synchronous (resolve only). The checker's `Promise.all`
  is awaited; `ephemeralReset` in the drill is awaited.

## The guard test

`tests/pending-promise-guard.test.js` runs a syntactic scanner
(`tests/helpers/pending-promise-scanner.js`) over `src/` and
`bin/` on every `npm test`. It flags four pattern classes:

- `unregister()` without `await` on the same line (definitions
  excluded);
- `.then(` occurrences — each must be allowlisted;
- `setTimeout(async` / `setInterval(async` — each must be
  allowlisted;
- `finishRun(` without `await` or `void` (definitions excluded);
- `new Promise(async` — always a violation.

The allowlist is `tests/pending-promise-allowlist.json`: one entry
per excused occurrence (`file`, `kind`, `substring`, `reason`).
The guard fails if an occurrence has no entry, or if an entry
matches nothing anymore (stale — the code moved on, so the excuse
must go too). Adding a new async timer or promise chain without
an allowlist entry fails the suite; that is the point.

The guard caught real issues before this round's commit: two
adapter `finishRun` call sites the manual audit had missed (the
registration-refused path and the `.catch()` tail of the
`registerWorker` chain) were changed to `void finishRun(...)`,
and one false positive — the wrapper's `finishRun` is the
synchronous `finish()`, which returns nothing to await — was
allowlisted with its reason.

## Known limitations (honest)

- The scanner is syntactic, not a data-flow analysis. It does
  not understand `${}` inside template literals, and an `await`
  split across two lines (`await\n  foo()`) is not recognised as
  awaited. It is a tripwire for the common shapes, not a proof —
  code review still owns the unusual ones.
- `finishRun` means two different things in two files: the
  adapter's returns a promise, the wrapper's is synchronous.
  The naming collision is confusing and is recorded here rather
  than renamed in this round; a rename is cheap if a later round
  wants it.
- `safe-write.js` close-after-write (above) is a known wart:
  a close() failure reports a failed write for a file that was
  in fact written.
