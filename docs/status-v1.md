# Operator status overview (`sentinel status`) — Phase 8, round 63

`sentinel status [--state-dir <path>] [--skill-dir <path>] [--json]`
is one read-only view of the whole operator state. Before this
command, seeing the whole picture took six commands
(`kill-switch status`, `kill-switch audit-health`, `scope list`,
`audit verify`, `audit retention --show`, `verify-install`,
`check-env`); `status` aggregates their read paths into one
object and one compact text page. It implements no new check of
its own except the aggregation.

## Fields

The JSON object (version 1) is:

```json
{
  "version": 1,
  "stateDir": "<absolute path>",
  "skillDir": "<absolute path>",
  "killSwitch": {
    "state": "inactive",
    "workers": 0,
    "trigger": null,
    "resetTokenConfigured": false
  },
  "audit": {
    "totalRecords": 70,
    "verifiedRecords": 0,
    "legacyRecords": 70,
    "brokenRecords": 0,
    "anchorHash": null,
    "firstRecordedAt": "2026-11-20T17:36:56.055Z",
    "lastRecordedAt": "2026-11-20T18:06:25.173Z",
    "chainVerified": true,
    "pruneAnchors": 0,
    "firstBrokenReason": null
  },
  "scope": { "targets": 0, "invalidTargets": 0 },
  "retention": { "set": false, "maxArchives": null, "maxRecords": null, "error": null },
  "verifyInstall": { "passed": 7, "failed": 0, "overall": "PASS" },
  "tools": { "total": 5, "available": 0, "missing": 5, "missingTools": ["docker", "subfinder", "dnsx", "httpx", "katana"] }
}
```

- `killSwitch.state` is `inactive` or `active`. `workers` counts
  live leases only (same counting as the lockless snapshot).
  `trigger` is the trigger object when active
  (`{triggerId, triggeredBy, reason, triggeredAt}` — the same
  fields `kill-switch status` already prints) and null otherwise.
  `resetTokenConfigured` reports whether the env-configured digest
  FILE exists as a regular file (lstat only, never read). The state
  file carries no token value and no digest (the reset-token hash
  lives only in process memory, round 58), so there is nothing
  credential-like to strip; the digest itself is never read or
  reported, only its file's presence. A symlink is NOT configured:
  the digest reader refuses symlinks, so a linked file is unusable
  and must not be reported as configured.
- `audit` replays the round-43/56 chain rules locklessly (same
  entry order — archives `.3`..`.1` oldest first, then the active
  log — same legacy/chained/broken rules, same summary fields).
  `pruneAnchors` counts `AUDIT_LOG_PRUNED` anchor records
  (round 62). `firstBrokenReason` is the `AUDIT_CHAIN_*` code of
  the first broken record, or null when the chain verifies.
  `firstRecordedAt` / `lastRecordedAt` are audit-log data.
- `scope.targets` is the store count; `invalidTargets` counts
  entries that fail per-entry validation (one bad entry never
  hides the rest).
- `retention` is the round-62 policy (`set`, `maxArchives`,
  `maxRecords`), `set: false` when unset, or `error` carrying
  the policy error code when the policy file is damaged.
- `verifyInstall` is pass/fail counts + overall from
  `runVerifyInstall` (counts only — the per-check reasons stay
  with `verify-install` itself).
- `tools` is available/missing counts + missing tool names from
  the checker's `loadToolNames` + `checkTool` (the same probing
  `check-env` uses, without check-env's storage-probe write).

The text form is the same fields in compact grouped lines:

```text
sentinel status — /home/hatch/workspace/sentinel-bounty/state
kill-switch: inactive (0 workers, reset token: not configured)
audit: 70 records (0 verified, 70 legacy, 0 broken), chain verified, last: 2026-11-20T18:06:25.173Z
scope: 0 targets (0 invalid)
retention: unset
verify-install: 7 passed, 0 failed — PASS
tools: 0 available, 5 missing (docker, subfinder, dnsx, httpx, katana)
```

## Read-only guarantee

`status` never writes, arms, rotates, prunes, or repairs
anything. Every read is lockless and creates nothing:

- kill-switch: `snapshotLockless()` — no lock file, no mkdir,
  no lease pruning. This is deliberately stricter than
  `kill-switch status`, which takes the lock to prune expired
  leases and can therefore create a lock file and fail on storage
  exhaustion. An expired lease is reported by its lease time
  through `registeredWorkers` (live leases only), not pruned.
- audit: plain `readFile` per file — no `AuditLog` lock, no
  temp-file cleanup, no state-dir creation. The chain walk is a
  deliberate duplication of `verifyChainPerRecord`'s rules
  without its lock; a test cross-checks the lockless summary
  against `verifyChainPerRecord()` on the same fixture so the two
  can never silently diverge.
- scope store, retention policy, verify-install checks, and tool
  probes are all reads or local version-command spawns.

A test proves the guarantee: the state files' contents AND
mtimes, and the state directory's own mtime, are identical before
and after a status run (module level and via the real CLI).
One inherited non-read: `checkTool` spawns the tool's version
command (e.g. `docker --version`) — a local probe, never a
network request and never a write to the state dir.

## Error semantics

| Situation | Result |
|---|---|
| Corrupt/unreadable kill-switch state (`KILL_SWITCH_STATE_*`) | Whole command fails, exit 1, JSON `{status: false, component: "killSwitch", reason}`. Fail-closed: a damaged switch must never be reported as "inactive". |
| Audit-log storage failure (`AUDIT_LOG_PERMISSION_DENIED` / `AUDIT_LOG_PATH_INVALID` / `AUDIT_LOG_STORAGE_UNAVAILABLE` / `AUDIT_LOG_UNAVAILABLE`) | Whole command fails, exit 1, component `"audit"`. An unreadable log is not an empty log. |
| Scope-store shape/symlink failure (`SCOPE_STORE_*`) | Whole command fails, exit 1, component `"scope"`. A damaged store must never be reported as "0 targets". |
| Audit-log content break (unparseable line, legacy after chained, prev/hash mismatch) | Reported inside the audit section as broken records with the `AUDIT_CHAIN_*` reason; the command still exits 0. Showing the break is the job (round 56's rule, applied here too). |
| Damaged retention policy (`AUDIT_RETENTION_*`) | Reported inside the retention section as its error code; the command still exits 0 (round 62's rule: a corrupt policy must never block operations). |
| Missing state directory | The empty view (inactive, 0 records, 0 targets, retention unset), not an error. No directory is created. |
| Unknown option | Exit 1, `Unknown option: <flag>` on stderr (the `parseOptions` rule shared by every command). |

## Determinism

The status object carries NO wall-clock timestamp
(`firstRecordedAt` / `lastRecordedAt` are audit-log data), so
the same state always renders the same JSON and the same text.
Tool counts can change only if a tool is installed or removed
between runs — that is data, not clock.

## What `status` is not

- Not a replacement for the individual commands: it shows
  counts and the first break, not the full trail (`audit
  export`), not per-check reasons (`verify-install`), not scope
  decisions (`scope list --url`), not the storage probe
  (`check-env`).
- Not a health gate: `audit-health` remains mandatory before
  reset, and `verify-install --fix` remains the repair path.
  `status` reports; it never repairs.
- Not an attestation: it reads local state only and proves
  nothing about the Muse runtime (same limit as `check-env`).
