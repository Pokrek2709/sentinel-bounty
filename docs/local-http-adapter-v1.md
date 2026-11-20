# Local HTTP adapter v1

`src/http/local-http-adapter.js` is the first network-capable component, deliberately restricted to the authorized local lab:

- HTTP `GET` only.
- Hostname must be exactly `localhost`; IP literals and external hosts are rejected.
- Scope, `http_probing` method allowlist, scope fingerprint, single-use approval, request governor, and kill-switch checks run before connection.
- Redirects are not followed. A 3xx response is returned and audited as a response.
- Response body is bounded; audit records contain metadata only and never body content.
- Sensitive response headers are redacted before returning them to the caller.
- Kill-switch state is polled while the request is active and cancellation destroys the request.
- Response status is forwarded to the request governor, so `429`/`503` responses activate the configured backoff and halt policy.

This adapter is for local lab validation only. It must not be generalized to public targets until DNS/redirect policy, audit retention, operator approval UX, and a reviewed target authorization workflow are complete. The Muse real-run report confirmed localhost, redirect, timeout, cancellation, redaction, persistence, and lock behavior; it also exposed the need to wire response statuses into the governor, which is now implemented.
