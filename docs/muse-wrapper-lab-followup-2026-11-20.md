# Muse wrapper and cancellation follow-up — 2026-11-20

Source: a user-provided report from a local-only Muse lab run after commit `bdc8cbd5ba1958775bdcfd09288650edc3cfa5e8`. This records runtime evidence for design decisions; it is not independent attestation and does not authorize target testing.

## Reported runtime evidence

- A wrapper process, nested Node child, ordinary `sleep`, and detached `sleep` were all terminated after one runtime `process.kill` action in the observed lab run.
- The runtime delivered `SIGTERM` first and escalated within a few seconds when a process ignored it. Exact grace timing was not measured.
- The killed process tree was isolated: a new local process could start after cancellation.
- A workspace state directory outside the reinstall-replaced skill directory was persistent. `/tmp` was ephemeral.
- Explicit file mode `0600` produced private state files. Writes without an explicit mode produced group-writable files under the reported umask and are not acceptable for Sentinel state.
- Atomic temp-file plus rename completed without leftover temp files. `flock` was available and contention tests showed that an exclusive lock blocks competing readers/writers as configured by the lab.

## Repository consequence

The repository now contains a fixed-command controlled wrapper that composes scope, method allowlisting, scope fingerprint, bound single-use approval, request governor, and the in-memory kill-switch core. It uses `shell: false`, timeout cancellation, and a SIGTERM/SIGKILL escalation path.

The wrapper is deliberately not a persistent session controller. Before any network adapter is considered, the project still needs a separate state component that uses an external workspace path, locking, atomic rename, explicit `0600` permissions, and a tested cross-process kill-switch protocol.
