# Muse PGID and cross-process kill-switch evidence — 2026-11-20

Source: user-provided report from a local-only Muse Linux lab. No real target, network, or scanner was used. This is evidence for engineering decisions, not independent runtime attestation.

## Confirmed

- `kill(-pgid, SIGTERM)` terminated the observed shell and ordinary descendants in one process group.
- A fresh process could activate the file-backed switch; an active wrapper poller observed it and rejected new work.
- Ten concurrent trigger attempts produced one winner and nine rejections without lost state updates.
- Locking plus atomic rename preserved complete state with mode `0600`; stale-lock recovery worked.
- Reset required an operator identity and refused while workers remained registered.
- Approval IDs did not survive reinstall/restart because the approval gate remains in-memory.
- Timeout was reported as `EXECUTION_TIMEOUT` for both SIGTERM-responsive and SIGTERM-ignoring children.

## Remaining limitation

A descendant that called `setsid()` escaped the original process-group kill and retained inherited stdio pipes until manual cleanup. The wrapper must therefore scan `/proc` parentage and signal known descendants, then settle kill-switch cancellation without waiting indefinitely for pipe closure. This is best-effort reaping; descendants created after the scan remain a residual limitation.
