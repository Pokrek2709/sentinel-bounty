# Kill Switch v1

`src/policy/kill-switch.js` is a local policy core that fails closed once triggered. It performs no network activity and does not execute shell commands.

## Behavior

- Workers register a cancellation callback before starting an action.
- Triggering the switch marks it active before callbacks are dispatched, blocking new worker registrations and future policy checks immediately.
- Every registered callback receives the immutable trigger context.
- Callback errors are returned for audit/handling, but never reset the switch or permit new work.
- Reset is explicit and refused until all workers unregister.

There is no CLI command for this in-memory core. A future CLI must operate through a persistent session controller; creating a fresh process for `trigger` would not reach another process's in-memory worker registry.

## Runtime boundary

User-provided Muse lab evidence shows that runtime-level `process.kill` terminated one observed parent/child/detached-child process tree. Sentinel has no direct runtime cancellation API, so this module does not claim to call `process.kill`. A future controlled execution wrapper must implement each worker's cancellation callback using the supported runtime process/session termination mechanism and verify it in an authorized local lab.

The reported trial observed termination within seconds, not a hard one-second SLA.

## Persistence boundary

This first version is intentionally in-memory. If persistent kill-switch state is added, it must live outside the skill installation directory and must use a locked, atomic, mode-`0600` write path. The Muse lab report indicates that `flock` and atomic rename are available there, but that integration is not yet implemented or verified by this repository.
