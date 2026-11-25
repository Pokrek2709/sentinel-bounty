# Scope-Decision Explainability v1

`sentinel check-scope --explain` (round 52, Phase 3) makes a scope decision
explainable: it shows the ordered rule trail behind the decision — which
rule matched, from which policy source, and what would change the outcome.
`--explain --json` carries the same trail as structured data. Plain
(non-explain) output is byte-identical to before this round.

## The decision, unchanged

Explainability only observes the decision logic; it does not change it.
The rules are evaluated in a fixed order and the first rule whose
condition holds decides the outcome; the rest are never evaluated:

| # | Rule | Decides | Source |
|---|------|---------|--------|
| 1 | `TARGET_REGISTERED` | `TARGET_NOT_REGISTERED` (deny) | `TargetRegistry` (registered from the `--target` file) |
| 2 | `URL_VALID` | `INVALID_URL` (deny) | built-in: `src/scope/target-registry.js` |
| 3 | `EXCLUDED_DOMAIN` | `EXCLUDED_DOMAIN` (deny) | target file (`excluded_domains`) |
| 4 | `ALLOWED_DOMAIN` | `HOST_OUT_OF_SCOPE` (deny) | target file (`allowed_domains`) |
| 5 | `EXCLUDED_PATH` | `EXCLUDED_PATH` (deny) | target file (`excluded_paths`) or built-in default |
| 6 | `IN_SCOPE` | `IN_SCOPE` (allow) | target file (`allowed_domains`) |

Excluded domains take precedence over allowed domains (policy
`policies/scope-policy.md` section 2); excluded paths are checked only
after the host is in scope (section 4). The trail records every rule in
this order and honestly marks the ones short-circuited by an earlier
decision as `not evaluated`.

## Policy sources

- Rules 3, 4, and 6 cite the `--target` file by its resolved absolute
  path, with the field name (`excluded_domains`, `allowed_domains`).
- Rule 5 cites the target file (`excluded_paths`) when the matched path
  comes from the target file, and cites the built-in default
  (`src/scope/target-registry.js`, `DEFAULT_EXCLUDED_PATHS`;
  `policies/scope-policy.md` section 4) when the matched path is one of
  the five built-in destructive-action paths (`/logout`, `/signout`,
  `/delete`, `/reset-password`, `/unsubscribe`).
- Rule 2 cites the built-in module; rule 1 cites the registry.

## Text output (`--explain`)

```
Scope decision
  Target: local-lab
  Request URL: https://outside.test/
  Decision: HOST_OUT_OF_SCOPE (denied)
  Policy source: /abs/path/to/target.json

  Rules evaluated in order:
  1. TARGET_REGISTERED: passed — Target "local-lab" is registered. (source: registry: TargetRegistry (registered from /abs/path/to/target.json))
  2. URL_VALID: passed — Request URL parses as an absolute http(s) URL. (source: built-in: src/scope/target-registry.js)
  3. EXCLUDED_DOMAIN: passed — Hostname "outside.test" matches no excluded domain. (source: target file: /abs/path/to/target.json (excluded_domains))
  4. ALLOWED_DOMAIN: DECIDED (deny) — Hostname "outside.test" matches no allowed domain. (source: target file: /abs/path/to/target.json (allowed_domains))
  5. EXCLUDED_PATH: not evaluated — An earlier rule already decided the outcome. (source: target file: /abs/path/to/target.json (excluded_paths))
  6. IN_SCOPE: not evaluated — An earlier rule already decided the outcome. (source: target file: /abs/path/to/target.json (allowed_domains))

  Deciding rule: ALLOWED_DOMAIN
  Suggestion: Add "outside.test" (or a matching wildcard) to allowed_domains in /abs/path/to/target.json.
```

## JSON output (`--explain --json`)

The plain JSON output gains an `explanation` object:

```json
{
  "targetId": "local-lab",
  "authorizationStatus": "declared_not_verified",
  "decision": { "allowed": false, "reason": "HOST_OUT_OF_SCOPE", "hostname": "outside.test" },
  "explanation": {
    "targetId": "local-lab",
    "requestUrl": "https://outside.test/",
    "decision": { "allowed": false, "reason": "HOST_OUT_OF_SCOPE", "hostname": "outside.test" },
    "rules": [
      {
        "rule": "ALLOWED_DOMAIN",
        "description": "The request hostname matches no allowed domain.",
        "evaluated": true,
        "matched": true,
        "outcome": "deny",
        "source": "target file: /abs/path/to/target.json (allowed_domains)",
        "detail": { "hostname": "outside.test" },
        "note": "Hostname \"outside.test\" matches no allowed domain."
      }
    ],
    "decidingRule": "ALLOWED_DOMAIN",
    "suggestion": "Add \"outside.test\" (or a matching wildcard) to allowed_domains in /abs/path/to/target.json.",
    "source": { "targetFile": "/abs/path/to/target.json" }
  },
  "safety": "No network request was made."
}
```

`outcome` is one of `pass`, `deny`, `allow`, `not-evaluated`; exactly one
rule has `matched: true` (the deciding rule). The JSON is deterministic:
the same input always renders byte-identical output. `--json` without
`--explain` is accepted and behaves exactly like plain output (JSON is
already the default format).

## Suggestions

Each deciding rule carries a one-line suggestion for what would change
the outcome:

- `TARGET_NOT_REGISTERED` — register the target first (with the
  `check-scope` command and the `target_id`).
- `INVALID_URL` — fix the request URL (absolute http(s), no credentials,
  no IP host).
- `EXCLUDED_DOMAIN` — remove the pattern from `excluded_domains`, or use
  a different host.
- `HOST_OUT_OF_SCOPE` — add the hostname (or a matching wildcard) to
  `allowed_domains`.
- `EXCLUDED_PATH` (configured) — remove the pattern from
  `excluded_paths`, or use a different path.
- `EXCLUDED_PATH` (built-in default) — the path is a built-in policy
  default and **cannot** be un-excluded from the target file; use a
  different path.
- `IN_SCOPE` — no change needed.

## Failure modes

- A corrupt `--target` file fails before any trail is produced
  (`Invalid JSON in <path>`, exit 1); a missing file fails the same way
  (`Cannot read <path>`, exit 1). No half-written trail is ever printed.
- The trail is computed from the same evaluation the plain decision uses
  (`evaluateTargetRequestWithTrail`); `explain().decision` is asserted
  identical to `evaluate()` across the full URL matrix in
  `tests/scope-explain.test.js`.

## Programmatic use

- `TargetRegistry.explain(targetId, requestUrl, { targetFile })` returns
  the frozen explanation object (`targetId`, `requestUrl`, `decision`,
  `rules`, `decidingRule`, `suggestion`, `source`).
- `evaluateTargetRequestWithTrail(target, requestUrl, source)` returns
  `{ decision, trail, decidingRule, suggestion }` for a normalized target
  (rules 2–6; no registry lookup).
- `renderScopeExplanationText(explanation)` renders the text form.

## Open items

- The scope policy itself is still a file the operator edits by hand;
  there is no `sentinel scope add/remove` command. That is a separate
  decision (operator tooling, not explainability).
- Built-in default excluded paths cannot be overridden from the target
  file. If a program ever needs one of them in scope, that is a policy
  decision for the user, not a flag this round adds.
