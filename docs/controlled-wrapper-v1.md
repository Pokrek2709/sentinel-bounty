# Controlled execution wrapper v1

`src/execution/controlled-wrapper.js` is a local execution boundary for fixed, pre-registered commands. It does not perform network I/O itself and does not make arbitrary shell strings executable.

Before spawning, it requires all of these checks to pass:

1. Kill switch is inactive.
2. Tool name exists in a trusted fixed catalog; `shell` is always false.
3. URL is accepted by the target registry.
4. Scope fingerprint matches the registered target.
5. Bound Sentinel approval authorizes the exact target, action, estimate, and scope fingerprint.
6. Request governor grants a reservation.

The child is registered with the kill-switch core. On POSIX runtimes the child is started detached so cancellation can signal its process group (negative PID), and `/proc` parentage is scanned to signal known descendants such as `setsid()` children; the direct-child fallback remains for platforms where process-group signaling is unavailable. This is best-effort tree reaping, not a proof against a process that forks after the scan or hides outside `/proc`. Timeout and kill-switch cancellation send `SIGTERM`, then escalate to `SIGKILL` after the configured grace period if the process remains alive. A timeout is reported as `EXECUTION_TIMEOUT` even when the child exits promptly in response to the timeout signal; a kill-switch cancellation settles as `PROCESS_FAILED` without waiting indefinitely for inherited pipes. The wrapper also polls the kill-switch state while a child is active, allowing a persistent controller in another process to cancel it. The wrapper releases its governor reservation and unregisters the worker on completion.

Process-start and process-error responses intentionally avoid returning the full executable path; detailed paths should stay in local operator logs. This is not yet a network scanner or audit logger. A future network adapter must keep DNS/HTTP code outside this wrapper and pass through the same checks. Persistent kill-switch state is provided by the separate locked, atomic, mode-`0600` controller outside the skill installation directory. A token-gated local operator CLI now exposes status, trigger, and reset; a Muse-native identity/approval channel remains unverified.
