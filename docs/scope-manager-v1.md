# Scope Manager v1

`src/scope/target-registry.js` is a local, non-networked scope gate. It is not an execution wrapper and cannot itself authorize any testing.

## Contract

- A target registration needs a non-empty target ID, program name, authorization reference, and at least one DNS allowlist entry.
- Authorization is recorded as `declared_not_verified`; the code does not claim it has validated a program's authorization.
- Matchers accept only HTTP(S) DNS hostnames. IP addresses, credentials in URLs, malformed URLs, and non-HTTP(S) protocols are denied.
- Exact allowlist entries match only that host. `*.example.test` matches subdomains but not `example.test`.
- An excluded domain takes precedence over any allowlist and excludes all of its child subdomains.
- Built-in risky path exclusions are `/logout`, `/signout`, `/delete`, `/reset-password`, and `/unsubscribe`. Target-specific exclusions are added to them. Matching is prefix-boundary aware and percent-decoded.
- `allowed_urls` are validated, but cannot expand `allowed_domains` in this version. This intentionally favors a narrower scope.

## Local usage

```text
node bin/sentinel.js check-scope --target path/to/local-target.json --url https://app.example.test/docs
```

The command parses and evaluates only local input; it never resolves the hostname or sends a request. A successful scope decision is not permission to run a tool: the future policy engine must also enforce approval, request budget, rate limit, and kill-switch state.
