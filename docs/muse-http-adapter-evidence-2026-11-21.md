# Muse HTTP adapter evidence — 2026-11-21

Source: user-provided real-run report from commit `147596e778ea4e4c36c9ca233657b1be86dcb713` in a Muse local HTTP lab. No public target, scanner, or external network target was used.

## Confirmed in Muse

- `localhost` GET returned the lab response; external hosts and IP literals were rejected before transport.
- Redirects returned as 302 and were not followed.
- Timeout and cross-process kill-switch cancellation completed without hanging.
- Scope fingerprint, approval binding, single-use approval, request budget, rate limit, and concurrency controls behaved as expected.
- Audit state outside the skill survived reinstall, stayed mode `0600`, used atomic rename, redacted sensitive values, and preserved concurrent writes under lock.
- Legacy approval IDs remained invalid after reinstall.

## Follow-up implemented

- HTTP response statuses are now sent to `RequestGovernor.recordResponse`, activating 429/503 backoff through the adapter.
- Persistent kill-switch state accepts the legacy `{ enabled, reason, updatedAt }` shape once and atomically migrates it to version 1 under the state lock. Approval state is not migrated.
