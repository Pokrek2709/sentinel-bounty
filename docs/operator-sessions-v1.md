# Local operator sessions v1 (round 98)

Local, file-backed operator sessions: a bounded token, a heartbeat,
a lease, and rotation — the F1 session story that needs no Meta
service. For operators starting, keeping alive, and ending a work
session; for implementers and reviewers of the session layer.

## What a session is

An operator session is a bounded work period for the human
operator, recorded in `<state-dir>/operator-sessions.json`
(`schema_version: 1`). Starting one mints a random 48-hex token,
returned ONCE; the file holds only its SHA-256 hash (the round 93
approval-token precedent). The session id is `ses-<24 hex>`.

A session is live only while ALL THREE bounds hold:

- **TTL** — an absolute expiry from start. Default 8 hours, min
  60 seconds, max 24 hours. Nothing extends it: not a heartbeat,
  not a rotation. A session ends at most a day after it starts.
- **Lease** — a liveness window, default 30 minutes, min 60
  seconds, max 2 hours. The session stays live only while the
  operator heartbeats at least once per lease. A lapsed lease ends
  the session even inside its TTL, and a heartbeat cannot revive a
  dead lease — or the lease would be a reminder, not a proof.
- **Status** — `active` or `revoked`. Revocation is final.

The derived status order is revoked, then expired, then
lease-lapsed, then active: a revoked session is dead even inside
its TTL, and an expired session reports `expired` even when its
lease also lapsed. Status is derived at read time, never stored
as `expired`/`lease_lapsed`, so a reader that forgets to check
cannot mistake a dead session for a live one.

## Commands

```text
sentinel session start [--label <label>] [--ttl-seconds <n>] [--lease-seconds <n>] [--state-dir <path>]
sentinel session heartbeat --token <token> [--state-dir <path>]
sentinel session list [--state-dir <path>] [--json]
sentinel session status <session-id> [--state-dir <path>] [--json]
sentinel session revoke <session-id> [--state-dir <path>]
sentinel session rotate <session-id> [--state-dir <path>]
```

- `start` mints the token and prints it once (JSON: `started`,
  `sessionId`, `token`, `expiresAt`, `leaseSeconds`). The label is
  an operator note (max 200 characters), never a secret.
- `heartbeat` proves liveness: it refreshes the lease clock and
  increments `heartbeatCount`. It refuses a revoked, expired, or
  lease-lapsed session — a dead lease cannot be revived.
- `list` shows live sessions as metadata only (id, label, derived
  status, expiry, lease, heartbeat/rotation counts) — never the
  token hash. Expired entries are pruned on list.
- `status <session-id>` shows one session with its remaining TTL
  and lease in milliseconds.
- `revoke <session-id>` ends a session. It is idempotent:
  revoking an already-revoked session succeeds with
  `revoked: false, alreadyRevoked: true` and writes nothing.
- `rotate <session-id>` replaces the token (the old one stops
  working immediately) and prints the new one once. The TTL is
  unchanged — rotation refreshes the credential, it never extends
  the session. The heartbeat clock is refreshed, because the
  operator is provably present at rotation.

Exit codes follow the target/fetch pattern: 0 on success, 1 on a
refusal (the reason code in JSON, e.g.
`OPERATOR_SESSION_LEASE_LAPSED`), 4 when an audit append failed
(`auditLogged: false`).

## Kill-switch interaction

| Action | While armed |
|---|---|
| `start`, `rotate` | Refused (`OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE`) — they create or refresh access |
| `revoke` | Allowed — revocation removes access, the fail-closed direction |
| `heartbeat`, `list`, `status` | Allowed — liveness and inspection; a heartbeat during an armed period keeps the lease alive, but it cannot make a fetch run, because fetch checks the switch itself |

## Fetch binding

`sentinel fetch --session-token <token>` binds a fetch to a live
operator session. The check runs after the fetch context resolves
and BEFORE the approval step, so a dead session refuses the fetch
without spending a one-time approval token (the round 94 rule:
a refusal decided before the token is read does not spend it).
On success the binding is audited as `PUBLIC_FETCH_SESSION_BOUND`
(session id, target, URL — metadata only) and the session id
rides the fetch result; on failure the refusal is audited as
`PUBLIC_FETCH_SESSION_INVALID` with the reason, never the token.
A fetch without `--session-token` behaves exactly as before —
sessions are an opt-in layer, not a new requirement on existing
commands. Minting an approval (`fetch --mint-approval
--session-token <token>`) validates the session the same way
before any token exists.

What is deliberately NOT bound: the minted approval token is not
recorded against the session, so consuming it does not re-check
which session minted it — the fetch-time check is the gate, and
it runs on every fetch. Mint-time binding is a future option, not
this round's.

## Token storage decision

Hash-only SHA-256 in a 0600 state file, same as the round 93
approval tokens. The file's protection is the OS permission model
(0600 file in a 0700 directory, symlinks refused, load-modify-save
under an exclusive lock), not a hardware-backed secret store.
The session token is never read from the environment: env vars
leak into process listings, and the reset-token pattern (env +
digest file) exists for the kill-switch reset, not for sessions.
The token is a bearer credential for the local lab only — anyone
holding it while the session is live can use it. That is the same
trust model as the one-time approval tokens, and the same limit:
if the user later wants a stronger token store, that is a new
decision, not a gap in this round.

## Audit events

`OPERATOR_SESSION_STARTED` (session id, label, expiry),
`OPERATOR_SESSION_HEARTBEAT` (session id, heartbeat count),
`OPERATOR_SESSION_REVOKED` (session id),
`OPERATOR_SESSION_ROTATED` (session id, rotation count).
No event carries a token or a token hash. Revoked entries are kept
until their TTL passes so a later validation reports `REVOKED`
(informative) instead of `NOT_FOUND`; expired entries are pruned
lazily.

## What sessions do not do

- No Meta service is called, and no official Muse API, quota, or
  native identity is involved — those are the F1 items deferred to
  the final stage. A session is local liveness, not platform
  identity.
- No auto-renewal: a session that lapses must be started again.
- No cross-machine sessions: the store is one state directory on
  one machine.
- Sessions are not shown by `sentinel status` (which aggregates
  kill-switch, audit, scope, retention, verify-install, and tools);
  inspect them with `session list` / `session status`.
- The lease is wall-clock based (`Date.now()`): a clock jump on
  the operator's machine moves the lease with it. That is the
  same clock the approval tokens and the kill-switch leases use.

## Known limitations

- On the interactive fetch path the session refusal still comes
  after the operator typed YA: the check runs inside
  `runPublicFetch`, after the prompt. The YA is not a stored
  credential, so nothing is lost but a keystroke — but the
  ordering is a wart, not a design choice, and a future round may
  move the check before the prompt.
- The session token is a bearer credential (see the storage
  decision above): possession while live is use. The mitigation
  is the TTL cap (24 hours), the lease (30 minutes default), and
  revocation — not a second factor.

## Tests

21 tests in `tests/operator-sessions.test.js`: module (start
once/hash-only, TTL/lease bounds, armed refusal, concurrent
starts, validate read-only, heartbeat refresh and no-revival,
expiry, revoke idempotence, rotate semantics, list/status
metadata, derived-status order, corrupt store shapes, symlink
refusal), fetch binding at module level with stub
transport/resolver (live binds and audits, dead refuses before
the approval step with zero requests, no token behaves as
before), and CLI spawn (full round-trip with audit events,
armed-switch matrix, unknown ids/tokens).
