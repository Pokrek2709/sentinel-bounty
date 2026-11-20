# Muse kill-switch lab evidence — 2026-11-20

Source: test report supplied by the project owner following a local-only Muse lab run of commit `bdc8cbd5ba1958775bdcfd09288650edc3cfa5e8`. This is user-supplied evidence and not an independent runtime attestation by this repository.

## Reported observations

- `npm test` completed with 18 passing tests before the local kill-switch worktree artifacts were reviewed here.
- A runtime cancellation test terminated an observed wrapper process, nested child, ordinary `sleep`, and a detached `sleep` after one `process.kill` action.
- The runtime first delivered `SIGTERM`; a process that ignored it was also terminated within a few seconds in two observed runs, consistent with later escalation. The exact grace period is not known.
- Cancellation affected the targeted process tree, not the entire chat/session: a later local process could start normally.
- A state directory beneath `~/workspace/sentinel-bounty/state/`, outside the reinstall-replaced skill directory, was recommended. Reported `flock` and atomic-rename experiments support a future state controller design, but Sentinel does not implement that controller yet.

## Engineering decision

The current in-memory `KillSwitch` is suitable only as a policy core: it blocks new registered work and calls cancellation callbacks. It does not expose a CLI, persist activation across processes, or call the Muse runtime cancellation API. Do not represent it as a complete process kill switch until a controlled execution wrapper and persistent session controller are implemented and lab-verified.
