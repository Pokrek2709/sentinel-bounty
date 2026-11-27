# Public-fetch activation drill v1 (round 94, Phase 4)

The activation drill proves the invocation path from
`docs/public-http-invocation-v1.md` actually activates — and that
the kill switch stops it at every point in the chain. It is the
round-94 answer to the question round 93 left open: the CLI
existed and its gates were unit-tested, but no one had yet run the
whole activation chain end to end, nor drilled the kill switch
against a fetch in progress.

The drill is automated in
`tests/public-fetch-activation-drill.test.js` (8 tests, stub
transport/resolver only, persistent kill switch in a temp state
directory). This doc is the operator runbook for replaying the
same steps by hand against lab state — and for reading the result
when a step refuses.

## Safety rules

- **Stub-only, lab state only.** The drill never touches a real
  socket or real DNS, and never touches the operator's real state
  directory: every step runs in a temp directory that is deleted
  afterwards. The CLI drill mints its token through the CLI, then
  the actual fetch runs at module level with stubs against the
  same CLI-produced state — the CLI fetch itself is never spawned
  with a valid token, because that would execute a real request.
- **No real target.** The drill target is `example.com` with a
  stub resolver answering a public address. A first fetch against
  a real registered target is an operator action, not a drill
  step: it still needs the user's word, a registered target with
  a verified authorization reference, and the five activation
  requirements.

## The activation chain

| # | Step | Command / call | What it checks | If it fails |
|---|------|----------------|----------------|-------------|
| 1 | Register | `sentinel target add example.com --scope /api --purpose <p> --auth-ref <ref>` | Exact host, path-prefix scope, purpose, reference; one registration per host | `PUBLIC_TARGET_INVALID`, `PUBLIC_TARGET_ALREADY_REGISTERED` |
| 2 | Preview | `sentinel fetch --url https://example.com/api/health` (preview on stderr) | URL parses; host registered; kill switch inactive; path inside scope | `INVALID_URL`, `PUBLIC_TARGET_NOT_REGISTERED`, `KILL_SWITCH_ACTIVE`, `PUBLIC_HTTP_OUT_OF_SCOPE` — nothing executed, no token spent |
| 3 | Mint | `sentinel fetch --url <url> --mint-approval` | Same checks as step 2, then mints a one-time token (5-minute TTL, bound to this exact URL/target/scope fingerprint) | Same reasons as step 2; the refusal is audited as `PUBLIC_FETCH_BLOCKED` |
| 4 | Fetch | `sentinel fetch --url <url> --approve-token <token>` (or type YA at the prompt) | Token binding, expiry, single-use — consumed BEFORE the adapter runs — then the adapter re-validates everything and resolves DNS AFTER the approval | `PUBLIC_FETCH_TOKEN_NOT_FOUND` / `_BINDING_MISMATCH` / `_EXPIRED` / `_CONSUMED`, `DNS_RESOLUTION_FAILED`, `RESOLVED_NON_PUBLIC_HOST` |

The audit trail of a successful chain reads, in order:
`PUBLIC_TARGET_ADDED` → `PUBLIC_FETCH_APPROVAL_MINTED` →
`PUBLIC_HTTP_REQUEST_ALLOWED` → `PUBLIC_HTTP_RESPONSE`. No
audit event carries the token, the response body, response
headers, or the authorization reference — the body goes to the
operator's stdout only.

### What a refusal does — and does not — spend

- A refusal decided **before** the token is read (unregistered
  host, out-of-scope path, armed kill switch, missing approval,
  interactive denial, binding mismatch, expiry) does **not**
  spend the token: the same token still fetches afterwards.
- A refusal decided **after** the token is consumed (DNS
  failure, and the adapter's own kill-switch re-check — see
  below) **burns** it: a replay reports
  `PUBLIC_FETCH_TOKEN_CONSUMED`.

## The kill-switch drill

| # | Step | What it proves |
|---|------|----------------|
| 1 | Trigger before fetch | `sentinel kill-switch trigger` → any fetch is refused with `KILL_SWITCH_ACTIVE`; zero requests, zero DNS; the token is **not** spent (still `consumed_at: null` in the store); minting is refused while armed |
| 2 | Reset restores service | `sentinel kill-switch reset` (operator reset token) → the switch is inactive; a fresh approval fetches again |
| 3 | Trip between consume and adapter run | The adapter re-checks the kill switch independently of the orchestration pre-check: if the switch trips in that window the fetch is refused with `KILL_SWITCH_ACTIVE`, zero requests, zero DNS — and the token is burned, because it was already consumed |
| 4 | In-flight cancellation, same process | Trigger during a hanging request aborts it: the fetch resolves `PROCESS_FAILED` with `cancellation: KILL_SWITCH_ACTIVE` and the request is destroyed — well before the 5 s timeout |
| 5 | In-flight cancellation, another process | A trigger from a second kill-switch instance (same state file) is caught by the adapter's 100 ms kill-switch poller: same abort, same result |
| 6 | Add/remove while armed | `target add` and `target remove` are refused with `PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE`; `target list` still works (read-only) |

### A token minted before the trigger

Documented semantics (round 94 judgment call): the kill switch
blocks **use** while armed; it does not revoke approvals. A
token minted before the trigger, never spent, still within its
5-minute TTL, remains valid after an authorized reset — the
operator who resets the switch resumes the service deliberately.
The drill pins this: the pre-trigger token fetches after reset.
If a future policy wants trigger to revoke outstanding tokens,
that is a new decision, not a gap in this drill.

### What the drill found (round 94)

One real gap, fixed in this round: the adapter's in-flight
abort carried `cancellation: 'KILL_SWITCH_ACTIVE'`, but the
fetch orchestration dropped the detail and returned a bare
`PROCESS_FAILED` — the operator could not tell a kill-switch
abort from any other process failure. `runPublicFetch` now
propagates `cancellation` when the adapter's refusal carries
it (additive only; the refusal reason stays the contract). The
drill tests pin the propagated field for both the direct-cancel
and the poller path.

## What the drill does not prove

- **No real-target execution.** Same boundary as round 93: the
  CLI exists and is drilled with stubs, but no operator has yet
  run `sentinel fetch` against a real registered target.
- **The interactive YA prompt on a real TTY** is still
  unexercised end to end in this environment (the confirm
  callback is unit-tested with stubs; the non-TTY refusal is
  tested via spawn).
- **Token storage is a hash in a 0600 state file**, not a
  hardware-backed secret store — the same as every other state
  file; a stolen file yields hashes, not usable tokens.

## Tests

`tests/public-fetch-activation-drill.test.js` (8 tests):

- Chain: register → preview → mint → fetch through the stub
  adapter, audit trail in order, no token/body/reference in the
  audit log.
- Refusal matrix: every gate refuses before any network, and a
  refusal before the token is read does not burn it; expiry and
  DNS-burn are pinned.
- Kill-switch drill: trigger-before-fetch (token unspent, mint
  refused), reset recovery (pre-trigger token still works),
  trip-between-consume-and-adapter (adapter re-check refuses,
  token burned, zero requests), in-flight abort via direct
  cancel and via the cross-instance poller, and the CLI
  cross-boundary drill (register → mint → trigger → add/remove/
  mint/fetch refusals → reset → CLI-minted token fetches at
  module level with stubs; audit trail in order).
