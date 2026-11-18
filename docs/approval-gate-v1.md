# Approval Gate v1

`src/policy/approval-gate.js` is a local, in-memory, fail-closed policy primitive. It does not invoke Muse approvals, execute a command, or make a network request.

## Bound approval contract

An approval request contains and later verifies all of the following:

- Target ID.
- Action identifier.
- Estimated number of requests (1–10,000).
- SHA-256 fingerprint of the scope configuration.
- Human-readable risk reason.
- Expiry: default and hard maximum of ten minutes.

An approval is single-use. A modified action, target, request estimate, or scope fingerprint is denied. Pending or approved requests expire fail-closed. In-memory state is deliberately lost on restart, so a stale approval cannot survive a skill reinstall or VM restart.

## Muse integration boundary

The documented Muse `permissions.preapprove` capability does not expose a generic Sentinel target/action binding. Therefore this gate cannot truthfully claim to be backed by a Muse approval card. A future controlled execution wrapper must:

1. Create and display this bound Sentinel request to the human researcher.
2. Record the human decision in this gate.
3. Request the separate Muse shell-execution approval for the exact wrapper command.
4. Consume the Sentinel approval immediately before one action.

Both approvals are required; neither one substitutes for the other.
