# Controlled execution wrapper v1

`src/execution/controlled-wrapper.js` is a local execution boundary for fixed, pre-registered commands. It does not perform network I/O itself and does not make arbitrary shell strings executable.

Before spawning, it requires all of these checks to pass:

1. Kill switch is inactive.
2. Tool name exists in a trusted fixed catalog; `shell` is always false.
3. URL is accepted by the target registry.
4. Scope fingerprint matches the registered target.
5. Bound Sentinel approval authorizes the exact target, action, estimate, and scope fingerprint.
6. Request governor grants a reservation.

The child is registered with the kill-switch core. Timeout and kill-switch cancellation send `SIGTERM`, then escalate to `SIGKILL` after the configured grace period if the process remains alive. The wrapper releases its governor reservation and unregisters the worker on completion.

This is not yet a network scanner, audit logger, or persistent session controller. A future network adapter must keep DNS/HTTP code outside this wrapper and pass through the same checks. Persistent kill-switch state should be added only through a locked, atomic, mode-`0600` state controller outside the skill installation directory.
