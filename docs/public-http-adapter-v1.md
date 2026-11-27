# Public HTTP adapter v1 (round 90, Phase 4 groundwork)

`PublicHttpAdapter` (`src/http/public-http-adapter.js`) is
the GET-only adapter for PUBLIC targets — the counterpart
of `LocalHttpAdapter` (`src/http/local-http-adapter.js`),
which serves `localhost` only. It exists behind the same
activation gate, plus two rules the local adapter does not
need: a public-hostname rule and an authorization-
reference match.

## What this round builds — and what it does not

This round builds the adapter, its gate, its tests, and
this doc. It does NOT build a CLI command that invokes
it, and nothing in this round runs it against a real
target: there is no registered target with a verified
authorization reference, and the tests use a stub
transport and a stub resolver only (no real socket, no
real DNS). The adapter is groundwork for a future round
that adds the invocation path — with the activation
requirements verified at that time. Until then, the gate
is doubly closed: no command reaches the adapter at all.

## The gate, in order

The first failing rule decides; the rest are never
evaluated:

1. **Kill switch not triggered** (`assertNotTriggered`).
2. **The URL parses and is http(s)** — else
   `INVALID_URL`.
3. **The hostname is public by name** — `localhost` in
   any case is refused as `NON_PUBLIC_HOST`. IP-literal
   hosts are refused later by the scope rule (`URL_VALID`
   refuses IP hosts), so a public target must be named
   by domain.
4. **Authorization reference match** — the caller
   presents the target's `authorization_reference` and
   it must equal the reference recorded at registration
   (`TargetRegistry.getAuthorizationReference`, added
   round 90). A mismatch is
   `AUTHORIZATION_REFERENCE_MISMATCH`; an unregistered
   target is `TARGET_NOT_REGISTERED`. Neither value is
   ever logged: audit events carry `targetId` and `url`
   only.
5. **Scope accepts the exact URL** — `SCOPE_<reason>`.
6. **The target allows `http_probing`** — else
   `ACTION_NOT_ALLOWED`.
7. **The scope fingerprint matches** — else
   `SCOPE_FINGERPRINT_MISMATCH`.
8. **Governor acquires a reservation** for the hostname
   — else `GOVERNOR_<reason>`.
9. **The approval gate authorizes** the single-use
   approval — else the gate's reason.
10. **DNS resolution, AFTER the approval** — the lookup
    is part of the gated operation, not a pre-gate probe:
    the hostname is resolved (injectable `resolveHost`;
    default `dns.promises.lookup` with `{ all: true }`)
    and every resolved address must be public (see
    below). Failure is `DNS_RESOLUTION_FAILED`; a
    non-public address is `RESOLVED_NON_PUBLIC_HOST`.
    The approval is consumed by the attempt even when
    resolution fails — that is the fail-closed cost of a
    single-use approval — and the governor reservation is
    released.
11. **Audit append `PUBLIC_HTTP_REQUEST_ALLOWED`** —
    `AUDIT_UNAVAILABLE` on failure.
12. **Worker lease, then the request** — GET-only, 5 s
    timeout by default, 1 MiB body cap, headers redacted,
    redirects recorded but NEVER followed, kill-switch
    polling every 100 ms, cleanup awaited (the unregister
    discipline of the local adapter, round 47: a cleanup
    failure resolves with the real result plus
    `unregisterFailed: true`, never an unhandled
    rejection).

Why DNS comes after the approval, stated as the judgment
call it is: the lookup is a read-only resolution of an
already-scope-accepted hostname, and the request itself
still passes the full governor + approval + audit +
kill-switch gate. The alternative — resolving before the
approval — would spend the operator's single-use approval
on nothing when the host is unresolvable. The cost of
the chosen order is explicit: a failed resolution still
consumes the approval.

## What counts as public (SSRF guard)

`isPublicAddress` refuses loopback, private (RFC 1918),
link-local (including the cloud metadata address
`169.254.169.254`), CGNAT (`100.64/10`), documentation /
TEST-NET ranges, benchmarking (`198.18/15`),
multicast, and reserved space for IPv4; and loopback,
unspecified, link-local, unique-local, IPv4-mapped
(checked against the embedded IPv4 rules),
documentation (`2001:db8::/32`), and multicast for
IPv6. A DNS name that resolves to a private address is
an SSRF attempt, not a public target — the adapter
refuses it before any request is made.

## What the adapter never does

- No POST/PUT/DELETE — GET only, like the local adapter.
- No redirect following: a 3xx response is returned
  as-is with `redirected: true` in the audit event.
- No credentials in the URL: the scope rule refuses
  URLs with userinfo (`URL_VALID`).
- No unbounded reads: the body is capped at
  `maxBodyBytes` (default 1 MiB) and the result reports
  `truncated: true` past it.
- No secret headers: response headers pass through
  `redact()` (the audit log's redactor), so a
  `set-cookie` header arrives as `[REDACTED]`.
- No invocation path yet: there is no
  `sentinel public-http` command. The adapter is a
  library for a future round.

## Tests

`tests/public-http-adapter.test.js` (13 tests): the
address classifier (private/loopback/link-local/
reserved refused, public addresses accepted), the
registry getter, the happy path through the stub
transport (headers redacted), localhost refused,
IP-literal refused by scope, authorization-reference
mismatch refused (and neither value in the audit log),
unregistered target refused, out-of-allowlist domain
refused, private resolved address refused, metadata
address refused, DNS failure refused, triggered kill
switch refused, wrong fingerprint refused. Every refusal
test asserts the stub transport made zero requests.
