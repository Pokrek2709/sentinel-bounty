# Audit-log integrity: hash chain and `audit verify` (v1, round 43)

## The chain

```text
sentinel audit verify [--state-dir <path>]
```

Every audit record appended after round 43 carries three extra fields:

| Field | Value |
|---|---|
| `chainVersion` | `1` (the chain format version; a future format change bumps this) |
| `prevHash` | 64-hex SHA-256 of the previous chained record, or the genesis constant for the first chained record of a fresh chain |
| `hash` | 64-hex SHA-256 of the canonical form below |

Genesis constant: `0000000000000000000000000000000000000000000000000000000000000000`
(64 zeroes).

### Canonical hash input (exact, reproducible)

```
hash = SHA-256(JSON.stringify({
  chainVersion: 1,
  version: <record version>,
  event: <event name>,
  eventId: <uuid>,
  recordedAt: <ISO timestamp>,
  details: <redacted details object>,
  prevHash: <64-hex>
}))
```

Keys in exactly that order. Insertion order is preserved by
`JSON.stringify` and by `JSON.parse`, so an independent checker that
rebuilds the object in the same order reproduces the hash. The details
hashed are the REDACTED details actually stored — never the caller's
raw values. The `hash` field itself is never part of its own input.

### Worked example

Record (fixed values, verifiable by hand with any SHA-256 tool):

```json
{
  "chainVersion": 1,
  "version": 1,
  "event": "KILL_SWITCH_TRIGGER",
  "eventId": "00000000-0000-0000-0000-000000000001",
  "recordedAt": "2026-11-26T00:00:00.000Z",
  "details": {"actor": "operator-1", "reason": "lab drill"},
  "prevHash": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Its `hash` is
`62df2d975be1b9dd00de9f3347526baec3f9a6b5ac3b75b5cea22b914b6dad81`.
The module exports `computeAuditRecordHash(record)` and
`GENESIS_PREV_HASH` so a checker can reuse the exact implementation
(`tests/audit-integrity.test.js` also recomputes a stored hash from
the raw line using only the documented formula and `node:crypto`).

## The verify command

`sentinel audit verify` replays the chain over the complete retained
set — rotated archives oldest first (`.3`, `.2`, `.1`), then the
active log — the same order as `readAllEvents()`. Output is JSON:

```json
{
  "verified": true,
  "totalRecords": 12,
  "legacyRecords": 0,
  "chainedRecords": 12,
  "anchorHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "brokenAt": null,
  "reason": null
}
```

`anchorHash` is the first chained record's `prevHash`: the anchor an
operator can compare against an external record, if one is kept.
Exit code is 0 when verified, 4 when the chain is broken (an audit
problem, like `audit-health`), 1 for operational errors. A storage
failure (lock, permission, path) is reported as JSON with the
classified `AUDIT_LOG_*` reason and exit 4.

`brokenAt` names the first broken link only (`{ file, line, reason }`
— the raw line is never echoed back). Reasons:

| Reason | Meaning |
|---|---|
| `AUDIT_CHAIN_HASH_MISMATCH` | A record's stored hash does not equal the recomputed hash (content was modified after writing). |
| `AUDIT_CHAIN_PREV_MISMATCH` | A record's `prevHash` does not equal the previous chained record's hash (a record was reordered or deleted before it). |
| `AUDIT_CHAIN_LEGACY_AFTER_CHAINED` | A record without a `hash` field appears after a chained record (a pre-chain record was smuggled in). |
| `AUDIT_CHAIN_UNPARSEABLE` | A line is not valid JSONL with an `event` string. |

## Legacy records (written before chaining)

Records appended before round 43 have no `chainVersion`/`prevHash`/
`hash` fields. They verify as a contiguous LEGACY PREFIX: they count
in `legacyRecords`, are otherwise skipped, and the first chained
record after them anchors from the genesis constant. If a legacy
record appears after a chained record, verification fails
(`AUDIT_CHAIN_LEGACY_AFTER_CHAINED`). Legacy records are unverifiable
by construction — deleting them is undetectable, and the result says
so via the `legacyRecords` count. Nothing is rewritten: the old
records stay exactly as written.

## Rotation interaction

The chain spans rotation boundaries: when the active log rotates, the
new record chains from the last record of the rotated-out log (the
writer reads the tail across the active log and the archives). The
first chained record's `prevHash` is accepted as the anchor whatever
it is — it is NOT required to equal the genesis constant — because
retention legitimately drops the oldest records (round 37: three
archives retained). A dropped prefix is therefore indistinguishable
from a deleted one, and verification does not pretend otherwise.

## What the chain does and does not do

The chain detects, after the fact:

- modification of any retained record (the record's own hash fails);
- reordering of any two retained records (the moved record's
  `prevHash` fails at its new position);
- deletion of any retained record that still has a successor (the
  successor's `prevHash` fails);
- a pre-chain record inserted after chained records;
- a garbage line anywhere in the retained set.

It does NOT detect:

- deletion of a leading prefix (indistinguishable from retention
  dropping it, or from a log that started later);
- deletion of the last record (it has no successor to contradict);
- a full rewrite of the log with freshly recomputed hashes. Anyone
  with state-directory write access can do that — the chain is
  tamper-EVIDENCE, not tamper-PREVENTION. An external anchor (copying
  `anchorHash` or a record hash out of the machine) is the only
  defense against a full rewrite.

The writer never refuses to append because the chain is broken: a
tampered log must not destroy the ability to record the very incident
that follows the tampering (e.g. a kill-switch trigger). Appending
chains from the last parseable chained record (skipping unparseable
lines); verification remains the separate `audit verify` diagnostic.
`healthCheck()` is unchanged — it stays structural-only
(`AUDIT_LOG_CORRUPT` / `AUDIT_LOG_ARCHIVE_CORRUPT`) and is still the
gate before reset/rotation/revocation, so a broken chain never blocks
a kill-switch operation.

## Cost

A chained record is ~310 bytes instead of ~130 (two 64-hex fields
plus `chainVersion`). The round-37 rotation tests were re-tuned to
the new size (limits 700/1,000 bytes instead of 300/700); rotation
behavior itself is unchanged. Verification reads the whole retained
set (active log up to 10 MiB plus up to three 8 MiB archives) under
the audit lock, so it briefly blocks concurrent appends — it is a
diagnostic, not a hot-path operation.
