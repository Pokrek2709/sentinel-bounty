# Public-fetch invocation path v1 (round 93, Phase 4)

`sentinel fetch` is the ONLY command that invokes the GET-only
public-target HTTP adapter (`src/http/public-http-adapter.js`,
round 90). It closes the invocation gap the adapter doc left open:
until this round the gate was doubly closed because no command
reached the adapter at all. The gate itself is unchanged — this
round adds the human-facing half (registration, preview, explicit
approval) in front of it.

## The two steps

### 1. Register once: `sentinel target add`

```text
sentinel target add <host> --scope <path> --purpose <purpose> --auth-ref <reference> [--program <name>] [--state-dir <path>]
sentinel target list [--state-dir <path>] [--json]
sentinel target remove <host> [--state-dir <path>]
```

One registration per host, exact host only — no wildcards. The
entry is stored in `<state-dir>/public-targets.json`
(`src/scope/public-target-store.js`): host, path-prefix scope,
purpose, authorization reference, program name, request budget.
The store is separate from the scope-target store on purpose: the
scope schema cannot express a path-prefix allowlist
(`allowed_urls` is validated at registration but never enforced
in scope evaluation), so the prefix lives here and the fetch path
enforces it before the adapter runs.

- `target_id` IS the host (lowercased, canonical). Adding the
  same host with identical fields is an idempotent no-op; adding
  it with different fields is refused with
  `PUBLIC_TARGET_ALREADY_REGISTERED` — remove first, then re-add,
  so a changed scope or reference is an explicit, auditable act,
  never a silent overwrite.
- Like scope changes, add/remove are refused while the kill
  switch is armed
  (`PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE`), and a
  successful mutation writes an audit record
  (`PUBLIC_TARGET_ADDED` / `PUBLIC_TARGET_REMOVED`).
- `target list` is read-only and works while the switch is armed.
  It never prints the authorization reference (neither text nor
  JSON): the operator manages targets without seeing it, and the
  fetch command reads it from the store directly.
- Store discipline matches the other state files: parent
  directory private (0700), file 0600, planted symlinks refused,
  load-modify-save under an exclusive lock file.

### 2. Fetch each time: `sentinel fetch`

```text
sentinel fetch --url <url> [--state-dir <path>] [--timeout-ms <n>] [--max-body-bytes <n>] [--mint-approval] [--approve-token <token>]
```

The order is fixed and the first failing step decides:

1. **The URL parses** as http(s) without credentials or an IP
   host (`INVALID_URL`) — the same normalization the scope rule
   uses, so `//` and `/../` tricks cannot escape the scope prefix.
2. **The hostname is a registered public target**
   (`PUBLIC_TARGET_NOT_REGISTERED`) — refused outright, before
   any approval is spent or any DNS happens.
3. **The kill switch is not triggered**
   (`KILL_SWITCH_ACTIVE`).
4. **The request path falls inside the registered scope prefix**
   (`PUBLIC_HTTP_OUT_OF_SCOPE`) — `/` matches every path; `/api`
   matches `/api` and `/api/users`, never `/apix` or `/apiary`.
5. **The preview is shown** (stderr, so stdout stays clean
   JSON): GET only, no headers/body/credentials, timeout and body
   cap (defaults 5 s and 1 MiB; `--timeout-ms` 1–60000,
   `--max-body-bytes` 1–10485760). Nothing is executed yet.
6. **Explicit human approval** — exactly one of:
   - **Interactive:** the operator types YA at the prompt.
     Anything else denies (`PUBLIC_HTTP_APPROVAL_DENIED`) and
     nothing is executed. The operator must be at a terminal: a
     piped stdin cannot type YA
     (`PUBLIC_HTTP_APPROVAL_REQUIRES_TTY`). There is deliberately
     no `--yes` flag — a standing approval would defeat the gate.
   - **One-time token:** `fetch --mint-approval` mints a token
     after the preview checks pass and prints it ONCE on stdout.
     The token is bound to this exact URL, target, and scope
     fingerprint; it is single-use and expires after 5 minutes
     (`PUBLIC_FETCH_TOKEN_EXPIRED`). `fetch --approve-token
     <token>` consumes it BEFORE the adapter runs — a fetch that
     then fails (DNS included) still burns it
     (`PUBLIC_FETCH_TOKEN_CONSUMED` on replay,
     `PUBLIC_FETCH_TOKEN_BINDING_MISMATCH` for another URL,
     `PUBLIC_FETCH_TOKEN_NOT_FOUND` for an unknown token). The
     store (`<state-dir>/public-fetch-approvals.json`,
     `src/http/public-fetch-approvals.js`) holds only the SHA-256
     hash of each token, never the plaintext.
7. **The adapter runs** (`src/http/public-http-adapter.js`): its
   own gate re-validates everything — kill switch, public
   hostname, authorization-reference match, scope, `http_probing`
   method, scope fingerprint, governor reservation, the single-use
   in-process approval — then resolves DNS AFTER the approval
   (the round-90 judgment call: a failed resolution still
   consumes the approval) and refuses any resolved address that
   is not public (`RESOLVED_NON_PUBLIC_HOST`). A redirect is
   never followed: a 3xx is returned as-is with `redirected:
   true` in the result and the audit event, and no second request
   is made — so a redirect to a private or out-of-scope URL is
   refused by never being chased.

Timeout and body cap are execution parameters, not part of the
approval binding: a token minted with the defaults may be spent
with different `--timeout-ms` / `--max-body-bytes` values. The
binding is about WHAT is fetched (target + URL + scope), not how
long the wait is.

## What the fetch never does

- No standing or permanent approval; no auto-run; the skill
  never invokes the adapter without an operator in the middle.
  The human presses the button every time.
- No POST/PUT/DELETE — GET only. No request headers, no request
  body, no credentials in the URL.
- No redirect following (see step 7 above).
- No unbounded reads: the body is capped (`truncated: true`
  past it) and the result reports `contentLength`.
- No secret headers: response headers pass through `redact()`,
  so a `set-cookie` header arrives as `[REDACTED]`.
- No response body, response headers, or authorization reference
  in ANY audit event. The body goes to the operator's stdout
  only. Audit events for this path are metadata-only:
  `PUBLIC_FETCH_APPROVAL_MINTED` (targetId, url, expiresAt;
  never the token), `PUBLIC_FETCH_APPROVAL_DENIED`,
  `PUBLIC_FETCH_TOKEN_INVALID` (never the presented token), and
  `PUBLIC_FETCH_BLOCKED` (pre-adapter refusals). The adapter's
  own `PUBLIC_HTTP_REQUEST_ALLOWED` / `PUBLIC_HTTP_RESPONSE`
  events are the record of the request itself.

## Exit codes

- `0` — fetched (or minted, or a target mutation applied).
- `1` — gate refusal, usage error, or a named store error
  (printed as JSON on stdout for refusals, or as
  `sentinel: <CODE>: ...` on stderr for errors).
- `4` — an audit append failed (`auditLogged: false`): the
  action still applied, but the operator must treat the result
  as an audit-integrity incident (the kill-switch/scope pattern).

## Tests

`tests/public-http-invocation.test.js` (17 tests):

- Store: scope-prefix matching (including the `/apix` /
  `/apiary` non-match), validation (IP-literal and wildcard
  hosts refused), duplicate identical no-op, conflicting re-add
  refused, list never prints the reference.
- Tokens: mint returns the token once and the store holds only
  its hash; second use is `CONSUMED`; another URL is a binding
  mismatch; an old token is `EXPIRED`; an unknown token is
  `NOT_FOUND`.
- Preview: shows GET-only, timeout, body cap, scope — and
  touches no network; unregistered host, out-of-scope path, and
  armed kill switch are refused before any network.
- Fetch (module level, stub transport/resolver only): interactive
  happy path (body never reaches the audit log, headers
  redacted), interactive denial (nothing executed), token happy
  path + replay, DNS failure burns the token, expired/missing
  token refused, private resolved address refused, redirect
  reported but never followed (exactly one request).
- CLI spawn: target add/list/remove round-trip, add refused
  while the kill switch is armed, fetch refusals (unregistered
  host, missing token, non-TTY stdin), `--mint-approval`
  round-trip (preview on stderr, token once on stdout, hash
  only in the store). No CLI spawn test presents a valid token:
  that would execute a real fetch, and no test in this round
  touches a real socket or real DNS.

## Judgment calls (round 93)

- **Separate public-target store** instead of reusing the scope
  store: the scope schema cannot express a path-prefix
  allowlist, and widening `normalizeTarget` for it would change
  scope semantics for every consumer.
- **`target list` / `target remove` added** although the approved
  design only named `add`: without them the operator could only
  inspect or undo a registration by hand-editing the store.
- **No `--yes` flag:** the approved design allows interactive
  confirmation and/or a one-time token; a `--yes` would be a
  standing approval in disguise.
- **Token TTL 5 minutes:** short enough that a minted token
  cannot linger, long enough to copy-paste between two commands.
- **Exact host only, no wildcards:** a wildcard would widen the
  fetch surface beyond the single host the operator named.
- **Conflicting re-add refused** (rather than the scope store's
  silent idempotent no-op): a changed scope or reference must be
  explicit and auditable.
- **The adapter result gained `contentLength` and `redirected`:**
  both were already recorded in the audit event; the fetch result
  now carries them too (additive only, no behavior change).
- **Lock files ensure the state directory first:** opening a
  lock in a not-yet-existing state directory failed ENOENT and
  surfaced as a bogus `*_STORE_LOCKED`; the new stores create
  the private directory before opening the lock.
