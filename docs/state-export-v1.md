# Portable state export — `sentinel state export` (Phase 8, round 58)

One portable document of the whole operator state — kill-switch
state + scope targets + audit summary — for migration or
off-machine inspection. EXPORT ONLY: there is no matching `state
import` in this round (see the open decision at the end).

## Command

```
sentinel state export [--state-dir <path>] [--out <file>]
```

Without `--out` the envelope is printed on stdout. With `--out`
the file is written mode `0600` through the round-34 safe-write
rules (a planted symlink at the output path is refused with
`STATE_EXPORT_SYMLINK_REFUSED`, exit 1) and the CLI prints
`State export written to <path>`. The command is read-only: it
never writes to the state directory, never arms or disarms the
switch, and works while the kill-switch is armed (exit 0, with
`active: true` in the exported state). One side effect is
inherited from the audit reader: asking for the chain summary
creates the state directory (0700) when it does not exist yet,
exactly as `audit export` does.

## Envelope

```json
{
  "exportVersion": 1,
  "exportedAt": "2026-11-26T07:00:00.000Z",
  "contents": {
    "killSwitchState": {
      "version": 2,
      "active": false,
      "trigger": null,
      "workers": []
    },
    "scopeTargets": [],
    "auditSummary": {
      "totalRecords": 70,
      "verifiedRecords": 0,
      "legacyRecords": 70,
      "brokenRecords": 0,
      "chainVerified": true,
      "anchorHash": null,
      "firstRecordedAt": "2026-11-20T17:36:56.055Z",
      "lastRecordedAt": "2026-11-20T18:06:25.173Z"
    }
  },
  "contentHash": "7b2b3faf…"
}
```

## What is included, exactly

- **killSwitchState** — the state file as stored
  (`kill-switch.json`), validated with the same `isValidState`
  the backup uses. The exported fields are exactly
  `{ version, active, trigger, workers }`; a trigger is
  `{ triggerId, triggeredBy, reason, triggeredAt }`; a worker is
  `{ workerId, pid, leaseExpiresAt }`. The state file carries NO
  token value and NO reset-token digest — the reset-token hash
  lives only in the kill-switch process memory, never on disk —
  so there is nothing credential-like to strip. A test asserts by
  construction that no exported key matches
  `/token|secret|password|api[-_]?key/i`.
- **scopeTargets** — the raw target objects from the round-53
  store (`<state-dir>/scope-targets.json`).
- **auditSummary** — counts and timestamps from round 56's
  `verifyChainPerRecord()`: `totalRecords`,
  `verifiedRecords`, `legacyRecords`, `brokenRecords`,
  `chainVerified`, `anchorHash`, `firstRecordedAt`,
  `lastRecordedAt`.

## What is deliberately NOT included

- Token values or reset-token digests (none exist on disk).
- The full audit log. The trail already has its own export
  (`sentinel audit export`, round 56); the state export carries
  only the summary, so the two documents stay single-purpose.

## Content hash

`contentHash` is SHA-256 over the canonical `contents` ONLY —
`JSON.stringify(contents)` with insertion order preserved,
the same convention as the round-37 backup hash. The timestamp
(`exportedAt`) is excluded, so the same state always yields the
same hash: two exports at different times are comparable by
hash, and a changed state yields a different hash (both proven
by tests).

## Missing and damaged inputs

- A missing kill-switch state file exports as the default
  inactive state (`{ version: 2, active: false, trigger: null,
  workers: [] }`), matching the kill-switch's own ENOENT
  semantics.
- A missing scope store exports as an empty list, not an error.
- A missing audit log exports as a zero-record summary
  (`chainVerified: true`, `anchorHash: null`, timestamps null).
- A CORRUPT kill-switch state file fails the whole export with
  `STATE_EXPORT_STATE_INVALID` (exit 1, `{ exported: false,
  reason }` on stdout, no file written). A legacy-shaped (v1)
  state file also fails as invalid: run any kill-switch command
  first — its locked reader migrates the file to v2 — and export
  again.
- A symlinked kill-switch state file fails with
  `STATE_EXPORT_SYMLINK_REFUSED` (exit 1, nothing written).
- A DAMAGED scope store fails the whole export with the store's
  own named error (`SCOPE_STORE_*` / `SCOPE_TARGET_*`, exit 1)
  instead of silently dropping the damaged target. This differs
  deliberately from the audit export (round 56), which lists
  broken records as error entries: audit records are evidence of
  tampering, while a damaged scope target cannot be migrated
  faithfully, and an export is a migration artifact — silently
  omitting a target would change scope on the destination.
- A broken audit chain is NOT a refusal: the export exits 0
  with `chainVerified: false` and the per-status counts, exactly
  as `audit export` shows broken records instead of refusing.
  An audit-log storage failure (`AUDIT_LOG_LOCKED`,
  `AUDIT_LOG_PERMISSION_DENIED`, `AUDIT_LOG_STORAGE_UNAVAILABLE`,
  `AUDIT_LOG_PATH_INVALID`) reports `{ exported: false, reason }`
  with exit 4, mirroring `audit export`.

## Honest limits

- The export shows what the state contains; it does not prove
  the state was not replaced wholesale. The audit summary
  inherits the round-43 limits: deletion of a leading prefix or
  of the last record is undetectable, and a full rewrite with
  recomputed hashes verifies clean. The content hash proves the
  export was not altered AFTER it was produced, not that the
  source state was honest.
- The export is a point-in-time snapshot. A state that changes
  between the kill-switch read and the audit read is exported
  as read; there is no cross-file transaction. For a
  migration, stop workers first (or trigger the kill-switch)
  and export, as with `backup`.

## Open decision

Whether a matching `state import` should ever exist, and under
what trust rules: whose state may be imported, how it is
verified (content hash alone proves nothing about provenance),
and what it may overwrite (never the audit log — restoring an
old log would erase intervening events, the same reason round
37 excludes the log from backup). Until the user decides, the
export is a one-way document.
