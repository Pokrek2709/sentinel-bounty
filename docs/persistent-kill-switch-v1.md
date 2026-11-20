# Persistent kill switch v1

`src/policy/persistent-kill-switch.js` is a cross-process policy state controller for the local lab and future controlled wrapper. It is not a Muse-native API and it does not itself discover or kill arbitrary processes.

## State contract

- State lives at an explicit absolute path outside the installed skill directory, for example `~/workspace/sentinel-bounty/state/kill-switch.json`. The constructor requires both `stateFile` and `skillDirectory` and rejects paths inside the skill directory.
- Missing state means inactive; an active state is fail-closed for fresh processes.
- Writes use a temporary file, explicit mode `0600`, `chmod(0600)`, and atomic rename.
- A lock file serializes readers/writers and has bounded acquisition plus stale-lock recovery. The Muse lab separately verified that `flock` is available; this Node implementation avoids invoking a shell command for every state read.
- Approval state is intentionally not persisted by this controller. Reinstall/restart must not revive old approval IDs.
- The controller migrates legacy `{ "enabled": boolean, "reason": string }` and version-1 state shapes to version 2 while holding the state lock. `updatedAt` and `updated_at` are both accepted. Unknown or malformed shapes remain fail-closed errors.
- Worker registrations are persisted as short leases and renewed by the active wrapper. Reset reads leases under the state lock, so another process's live worker blocks reset. A reset also requires a secret operator token supplied through a secure channel; `resetBy` is audit context, not authentication.

The controlled wrapper polls this state while a child is active. A fresh controller can therefore activate the switch, and a wrapper in another process observes it and begins cancellation. The process-group cancellation path is strongest on POSIX runtimes; Windows uses the direct-child fallback.

This component still needs a production-grade operator UX and audit integration; the local HTTP adapter already uses it for lab-only cancellation.
