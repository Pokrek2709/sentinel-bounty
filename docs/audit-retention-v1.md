# Audit-log retention policy (v1, round 62)

## The problem

Round 37 proved audit-log rotation with bounded archives
(`retentionCount`, default 3) and round 43 added the SHA-256 hash
chain — honestly documenting that deleting a leading prefix is NOT
detected, because rotation retention legitimately drops the oldest
records. Until now there was no operator-configurable retention:
archives accumulated to the constructor's fixed bound and the oldest
archive fell off silently at every rotation, with nothing in the log
itself saying what left.

## The policy file

```text
sentinel audit retention [--state-dir <path>] [--max-archives <n>] [--max-records <n>] [--show]
```

The policy lives in `<state-dir>/audit-retention.json` (same state
directory as the kill-switch, audit log and scope store), mode 0600,
dir 0700, symlinks refused — the round-34/45 state-file rules. Shape:

```json
{ "schema_version": 1, "max_archives": 1, "max_records": 5 }
```

Both limits are optional; absent means "no limit from this policy"
(current behavior, no pruning). Values must be integers >= 1; zero,
negative, non-integer, non-numeric values, unknown keys, and a
`schema_version` other than 1 are all invalid
(`AUDIT_RETENTION_INVALID`, nothing written).

- `max_archives` — the number of rotated archives to retain (`.1`
  is the newest). Archives beyond it are deleted at rotation.
- `max_records` — the total number of records retained across the
  active log plus archives. After archive pruning, the oldest lines
  of the rotated-in active log (`.1`) are truncated to meet it.

Setting a limit merges with the existing policy (setting one limit
keeps the other). Setting is refused while the kill-switch is armed
(`AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE`, exit 1, checked
before any policy read or write — same guard pattern as round 53's
scope changes). A successful set writes an `AUDIT_RETENTION_SET`
audit record; a set whose audit append fails reports
`auditLogged: false` and exits 4. `--show` is read-only, works while
armed, and prints `{ policy, store }` (`policy: null` when no file
exists yet).

## Enforcement: lazy, at rotation, and recorded

Pruning is evaluated when rotation runs. Setting a policy does not
prune retroactively until the next rotation — a policy change alone
never rewrites history.

When rotation runs with a policy set, the prune is RECORDED, not
silent: an `AUDIT_LOG_PRUNED` anchor record is written to the new
active log together with the incoming record (one atomic temp-file
write, so there is no window where the anchor exists but the prune
did not happen). The anchor chains from the old tail and the
incoming record chains from the anchor, so the chain stays
verifiable after the prune. A policy that prunes nothing writes no
anchor and rotates exactly as before.

The anchor's details:

| Field | Value |
|---|---|
| `prunedCount` | Number of records that left the retained set in this rotation |
| `prunedFirstRecordedAt` | `recordedAt` of the oldest pruned record (null when none carries one) |
| `prunedLastRecordedAt` | `recordedAt` of the newest pruned record |
| `lastPrunedHash` | Hash of the newest pruned record (null when the newest pruned record is legacy / has no hash) |
| `maxArchives` / `maxRecords` | The policy limits in force for this prune (null when unset) |

The anchor shares the incoming record's `recordedAt` (not the clock
at build time): it precedes the incoming record in chain order, so
stamping it later would make `recordedAt` non-monotonic along the
chain and a later prune's first/last timestamps could invert (caught
by this round's own tests before the fix).

What leaves the retained set in one rotation, in chain order:

1. The oldest archive, dropped by the rotation itself (round 37:
   the archive at index `retentionCount` falls off when everything
   shifts). With a policy set this drop is anchored too — the anchor
   is a complete account of what left the retained set in this
   rotation. Without a policy the drop stays exactly as before:
   silent, no anchor.
2. Archives beyond `max_archives` (post-rotation index), when set.
3. The oldest lines of the rotated-in active log (`.1`), when
   `max_records` is set and the retained total still exceeds it.

The anchor itself (+1 record) and the incoming record (+1) count
toward the retained total. The anchor lives in the new active log,
never in `.1`, so truncation of `.1` can remove every old active
record: with `max_records = 1` the retained set bottoms out at 2
records (anchor + incoming) — a floor, documented here, not silently
violated.

## What verify and export report for a pruned log

`sentinel audit verify` reports `verified: true` after a prune. The
first retained chained record's `prevHash` is accepted as the anchor
(round 43's rule); the anchor record itself verifies like any other
record, and the incoming record chains from it. The pre-anchor
history is declared pruned, not verified: the `AUDIT_LOG_PRUNED`
anchor states the count and the last pruned hash, and an operator
who kept an external copy of a record hash can cross-check
`lastPrunedHash` against it. The round-43 honest limits are
unchanged: a leading-prefix deletion is still indistinguishable
from retention dropping it, and a full rewrite with recomputed
hashes still verifies clean — the chain is tamper-EVIDENCE, not
tamper-PREVENTION.

`sentinel audit export` (round 56) includes the anchor as an
ordinary record with chain status `verified`; the summary counts it
among the verified records. Nothing about the export format changes.

## Failure modes

| Situation | Behavior |
|---|---|
| No policy file | Rotation exactly as before (silent age-out, no anchor) |
| Policy file corrupt / symlink / non-file | Strict reads (`--show`, set) fail loudly with `AUDIT_RETENTION_INVALID` / `AUDIT_RETENTION_SYMLINK_REFUSED`. The rotation path reads leniently: a damaged policy is treated as "no policy" for that one rotation, so a corrupt file can never block audit appends (round 43's rule that the writer never refuses to append). The damage stays discoverable via `--show`. |
| Invalid limit on set | `AUDIT_RETENTION_INVALID`, nothing written |
| Set while armed | `AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE`, exit 1, nothing written |
| `max_records` below the floor | Retained set bottoms out at anchor + incoming (2 records); no error, no anchor deletion |
| Prune anchor itself | A normal chained record; it is pruned by a LATER rotation like any other record, and that later prune is anchored in turn |

## Open decision

Whether a matching `state import`-style restore of pruned history
should ever exist: no. Pruned records are gone by design — the
anchor is evidence of what left, not a backup. If an operator needs
the history, they export it (`sentinel audit export`) BEFORE setting
a retention policy, or keep the archives themselves. The anchor's
`lastPrunedHash` is the only bridge back to an externally kept copy.
