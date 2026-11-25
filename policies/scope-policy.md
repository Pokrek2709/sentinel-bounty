# Sentinel Bounty — Scope Policy

## 1. Principle of Default Deny

- No security testing or network probing may occur against any host, IP, domain, or URL unless explicitly matched by an active authorized target scope.
- Subdomains are only permitted if explicitly declared or if wildcard domain coverage (e.g. `*.target.com`) is configured.

## 2. Exclusion Precedence

- Excluded domains and URLs take absolute precedence over wildcards and allowlists.
- If `target.com` has allowed `*.target.com`, but `admin.target.com` is in `excluded_domains`, any request directed to `admin.target.com` or any subdomain thereof must be immediately blocked.

## 3. Redirect Handling

- If an HTTP request directed to an in-scope URL returns an HTTP 301/302/307/308 redirect pointing to a third-party domain (e.g. `auth.external-provider.com`, `cdn.cloudflare.net`), automated scanners and crawlers must not automatically follow the redirect across the domain boundary unless the destination domain is independently registered in scope.

## 4. Path and Action Exclusions

- Paths matching destructive actions (e.g. `/logout`, `/signout`, `/delete`, `/reset-password`, `/unsubscribe`) must be excluded from automated crawling and parameter fuzzing to prevent session termination or accidental account disruption.
- These defaults are built into the scope manager (`DEFAULT_EXCLUDED_PATHS` in `src/scope/target-registry.js`). A target file may override them for that target only by declaring `default_excluded_paths` — a list that replaces the built-in defaults (an empty list means no default exclusions). The override is per-target, explicit, and visible in `sentinel scope list`; it does not change any other target. See `docs/scope-list-default-path-v1.md`.

## 5. Third-Party Services

- Third-party SaaS services hosted on external domains (e.g. Zendesk, Intercom, AWS S3 buckets not claimed by target) must never be scanned unless explicit written authorization from the third-party provider is documented.
