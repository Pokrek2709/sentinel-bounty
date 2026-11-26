# Audit export — `sentinel audit export` (round 56, 2026-11-26)

## What it is

`sentinel audit export` dumps the whole retained audit trail — the
active log plus the rotated archives, oldest first — as a single
document an auditor can check independently. Every record carries
its hash-chain verification status, so the export shows exactly
which records verify and which do not.

```
sentinel audit export [--state-dir <path>] [--out <file>] [--format json|jsonl]
```

- `--format json` (default): one object,
  `{ exportVersion: 1, verified, summary, records }`.
- `--format jsonl`: one compact JSON line per record, then a final
  summary line marked
  `{ "type": "audit-export-summary", "exportVersion": 1, "verified": …, "summary": … }`.
  Record lines carry no `type` field, so a consumer can tell them
  apart. A consumer that only wants records stops before the last
  line; a consumer that only wants the verdict reads the last line.
- `--out <file>`: write to a file (mode `0600`, symlinked output
  paths refused, same safe-write rules as every other CLI output).
  Without `--out`, the export goes to stdout.
- Exit code is **0 even when the chain is broken**. The export's
  whole point is to show the break, not to refuse it — unlike
  `sentinel audit verify`, which exits 4 on a broken chain.
  Storage failures (lock, permission, path) still exit 4 with
  `{ "exported": false, "reason": "<AUDIT_LOG_* code>" }`.

## Per-record status

Each entry in `records` is:

```json
{
  "file": "audit.jsonl.1",
  "line": 3,
  "chain": { "status": "verified", "reason": null },
  "record": { "chainVersion": 1, "version": 1, "event": "…", "eventId": "…", "recordedAt": "…", "details": { … }, "prevHash": "…", "hash": "…" }
}
```

`chain.status` is one of:

- `verified` — a chained record whose `prevHash` matches the
  previous chained record's stored hash and whose stored hash
  recomputes from the documented formula.
- `legacy` — a record without a `hash` field, in the pre-chain
  prefix (written before round 43 added chaining). Legacy records
  are not verifiable and not broken; they are counted separately.
- `broken` — `chain.reason` carries the `AUDIT_CHAIN_*` code:
  - `AUDIT_CHAIN_HASH_MISMATCH` — the record's content was
    modified after it was written (stored hash does not recompute).
  - `AUDIT_CHAIN_PREV_MISMATCH` — the record's `prevHash` does not
    match its predecessor's stored hash (reordering, or deletion of
    a record that still has a successor in the retained set).
  - `AUDIT_CHAIN_LEGACY_AFTER_CHAINED` — a record without a hash
    field appears after a chained record.
  - `AUDIT_CHAIN_UNPARSEABLE` — the line is not valid JSONL, or is
    not an object with an `event` string. The entry's `record` is
    `null` and the raw line is never echoed back (it can carry long
    details, and the operator already has the file).

The walk continues past breaks: after a broken chained record the
next record is checked against the broken record's *stored* hash,
because that is what the next record's `prevHash` references. A
modified record therefore flags only itself; its successor still
verifies. The first chained record's `prevHash` is accepted as the
anchor (reported as `summary.anchorHash`) — it is not required to
equal the genesis hash, because rotation retention legitimately
drops the oldest records.

## Summary

```json
{
  "totalRecords": 8,
  "verifiedRecords": 7,
  "legacyRecords": 0,
  "brokenRecords": 1,
  "anchorHash": "0000…0000",
  "firstRecordedAt": "2026-11-26T00:00:00.000Z",
  "lastRecordedAt": "2026-11-26T00:00:02.000Z"
}
```

- `totalRecords` counts every retained line, including unparseable
  ones.
- `verifiedRecords` / `legacyRecords` / `brokenRecords` are counts
  by status. The top-level `verified` boolean is true exactly when
  `brokenRecords` is 0.
- `anchorHash` is the `prevHash` of the first chained record, or
  `null` when the log holds no chained records.
- `firstRecordedAt` / `lastRecordedAt` are the `recordedAt` values
  of the first and last *parseable* records, or `null` when the log
  holds none.

## Determinism

The export carries no timestamp (no `generatedAt`): the same log
always renders byte-identically, so an auditor can compare two
exports by hash. Record order is fixed (archives oldest first,
then the active log; lines in file order), and the JSON key order
is fixed by construction.

## Honest limits (carried over from round 43)

The export shows what the chain can prove, nothing more:

- Deleting a **leading prefix** of the log is undetectable: the
  first retained chained record becomes the new anchor.
- Deleting the **last record** is undetectable: it has no successor
  to contradict.
- A **full rewrite with recomputed hashes** verifies clean — the
  chain is tamper-evidence, not tamper-prevention. An attacker who
  can rewrite the whole log is outside this mechanism entirely.
- The export is read-only: it never writes to the log, never takes
  a lock that blocks the writer beyond the read, and works while
  the kill-switch is armed.

## Implementation notes

- `AuditLog#verifyChainPerRecord()` in `src/audit/audit-log.js`
  (the per-record walk; `verifyChain()` is unchanged and still
  stops at the first break). The entry-collection loop is shared
  between the two methods.
- `renderAuditExport(result, format)` in
  `src/audit/audit-export.js` (pure rendering; unknown formats
  throw `Invalid audit export format: <format> (expected "json" or
  "jsonl").`).
- Tests: `tests/audit-export.test.js` (13 tests: exact clean-log
  output, continue-past-break, mid-delete, garbage line, legacy
  prefix, rotation order, empty log, determinism, format refusal,
  CLI stdout/`--out`/JSONL/broken-log/refusals/armed-switch).
- See also `docs/audit-integrity-v1.md` (chain format and
  `audit verify`) and `docs/backup-restore-v1.md` (rotation and
  retention).
