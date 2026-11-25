# State backup/restore and audit-log rotation (v1, round 37)

## State backup and restore

```text
sentinel backup --out <file> [--state-dir <path>]
sentinel restore --from <file> [--state-dir <path>]
```

Backup captures ONLY the kill-switch state file (`kill-switch.json`). The
audit log is deliberately NOT included: it is append-only evidence, and
restoring an old copy would silently erase intervening audit events — an
audit-integrity incident. Operators who need the audit trail copy
`audit.jsonl` and its `.N` archives separately, as plain files, and never
restore them over a live log. The backup envelope therefore contains no
audit events at all.

### Envelope format (schema version 1)

```json
{
  "schemaVersion": 1,
  "createdAt": "2026-11-26T03:00:00.000Z",
  "sha256": "<64-hex SHA-256>",
  "state": { "version": 2, "active": false, "trigger": null, "workers": [] }
}
```

The hash covers the canonical form `JSON.stringify(state)` — the parsed
state object re-serialized. Backup and restore compute the digest the
same way, so any edit to the enclosed state (or to the hash itself)
fails verification.

### Restore verification order (all before any write)

1. The input is a regular file — never a symlink (`BACKUP_SYMLINK_REFUSED`).
2. It parses as JSON (`BACKUP_CORRUPT`).
3. The schema version is an integer and is supported — currently only 1
   (`BACKUP_UNSUPPORTED_SCHEMA`).
4. The SHA-256 matches the enclosed state (`BACKUP_HASH_MISMATCH`).
5. The enclosed state has the v2 shape: `version: 2`, boolean `active`,
   `trigger` null or an object, `workers` an array of objects with a
   non-empty `workerId` and a finite `leaseExpiresAt`
   (`BACKUP_STATE_INVALID`).
6. The armed-with-leased-workers rule (below).
7. No fresh state lock is held (`BACKUP_STATE_LOCKED` — a lock younger
   than 60 s; a stale lock does not block a restore).

Any failure refuses with the named reason and writes nothing: no partial
state file is ever left behind. The restored state file is written
through `writeFileRefusingSymlink` (mode `0600`), so a symlinked
`kill-switch.json` target is refused too.

### Armed-with-leased-workers rule: REFUSE

This version picks REFUSE (not "restore and require a re-arm step"). A
backup whose state is `active: true` AND holds any worker lease that has
not yet expired is refused with `BACKUP_ARMED_WITH_LEASED_WORKERS`.
Those leases belong to processes that are gone — the state was wiped or
moved — so restoring them would plant phantom live workers that block a
later reset (`WORKERS_STILL_REGISTERED`). An armed state with no live
leases (empty `workers`, or all leases already expired) restores
normally, and the armed flag itself is preserved: a restore can never
silently disarm the switch. To recover an armed-with-leases backup, let
the leases expire and retry, or restore the state by hand after
confirming no worker with those IDs is alive.

### Exit codes and named errors

| Reason | Exit | Meaning |
| --- | --- | --- |
| `BACKUP_CORRUPT` | 3 | Input is not parseable JSON, not an object, or has a missing/malformed hash or state field |
| `BACKUP_HASH_MISMATCH` | 3 | Enclosed state does not match the envelope hash (tampered) |
| `BACKUP_UNSUPPORTED_SCHEMA` | 3 | `schemaVersion` is an integer but not 1 |
| `BACKUP_STATE_INVALID` | 3 | State file (backup) or enclosed state (restore) has the wrong shape |
| `BACKUP_ARMED_WITH_LEASED_WORKERS` | 3 | Armed state with a live worker lease (see rule above) |
| `BACKUP_SYMLINK_REFUSED` | 3 | Symlink at the backup output, the restore input, or the state file |
| `BACKUP_STATE_MISSING` | 1 | No `kill-switch.json` exists to back up |
| `BACKUP_NOT_FOUND` | 1 | No backup file exists at `--from` |
| `BACKUP_TOO_LARGE` | 1 | Backup file exceeds 1 MiB |
| `BACKUP_STATE_LOCKED` | 1 | A fresh state lock is held during restore |

Exit 3 is the fail-closed integrity refusal (same class as the
operator-token refusals); exit 1 is operational. Refusals print JSON
(`{"backedUp": false, "reason": ...}` / `{"restored": false, "reason": ...}`)
on stdout, like the kill-switch refusals. Backup reads the state file
without taking the state lock: state writes are atomic renames, so a
concurrent backup reads either the old or the new complete file, never
a torn one.

### Known limitations

- Backup is a point-in-time copy, not a transaction: state written after
  the backup is not in it, and restoring an old backup reverts later
  trigger/reset history. The audit log (excluded) is the record of what
  happened in between — keep it.
- Restore does not replay or validate the audit log, and does not append
  a restore event to it. A restore is an operator maintenance action;
  record it in your own run log.
- The 1 MiB backup size cap is a sanity bound (a v2 state file is a few
  hundred bytes); a state file bloated past it is refused rather than
  trusted.
- Schema version 2 does not exist yet. When the state shape changes, the
  new version must add a migration path here; old backups keep refusing
  with `BACKUP_UNSUPPORTED_SCHEMA` until then.

## Audit-log rotation (proved and completed, not rebuilt)

Rotation already existed in `src/audit/audit-log.js` before this round
and was NOT re-implemented: at `rotationBytes` (default 8 MiB) the active
log rotates to `.1`, older archives shift `.N-1` → `.N`, and retention is
3 archives (`.1`–`.3`). The hard per-record limit remains 32 KiB and the
active log limit remains 10 MiB. This round proves that behaviour with
tests and completes two gaps:

1. **Corrupt archives are REPORTED, not silently dropped.**
   `healthCheck()` now validates archives `1..retentionCount` as well as
   the active log. A malformed line (or a non-file) in an archive returns
   `{ healthy: false, reason: 'AUDIT_LOG_ARCHIVE_CORRUPT' }`. The
   existing codes are unchanged: a corrupt active log is still
   `AUDIT_LOG_CORRUPT`, a healthy log (including healthy archives) is
   still `{ healthy: true }`. Because `audit-health` runs through
   `healthCheck()`, `sentinel kill-switch audit-health` now reports a
   corrupt archive too, and `reset` / `rotate-token` / `revoke-token`
   stay fail-closed on it. The corrupt archive file itself is left in
   place for repair — it is never deleted by the check.
2. **Read scope is explicit.** `readEvents()` is active-log-only by
   design and stays that way; `readAllEvents()` (new) returns active
   plus archives, oldest first (`.N` … `.1`, then the active log). It is
   the complete record set: rotation moves records, never drops them.
   Like `readEvents()`, it throws on a corrupt line instead of skipping
   it — use `healthCheck()` to report corruption.

### Known limitations

- `healthCheck()` validates only archives `1..retentionCount`. A stray
  archive beyond retention (for example left by an older, larger
  retention setting) is ignored by the check, not reported. Rotation
  itself never creates one.
- Retention is a count bound, not a time bound: with heavy logging, three
  archives can cover minutes, not days. The audit trail is not a
  long-term archive — copy it elsewhere if retention matters.
- `readAllEvents()` loads every archive into memory. With the default
  8 MiB rotation limit and 3 archives that is at most ~32 MiB of JSONL;
  do not call it in a memory-constrained path without considering that.
