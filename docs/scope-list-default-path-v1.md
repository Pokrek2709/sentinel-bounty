# Scope list + overridable default excluded paths — v1 (round 54, Phase 3)

## What changed

Round 54 closes both open items from round 53:

1. **`sentinel scope list`** — the read-only complement to `scope
   add/remove`: it lists every target in the persistent store
   (`<state-dir>/scope-targets.json`), sorted by `target_id`, each with
   its validation status and, when `--url` is given, its scope decision
   for that URL.
2. **`default_excluded_paths`** — a target-file field that replaces
   the built-in default excluded paths (`DEFAULT_EXCLUDED_PATHS`) for
   that target only. The built-in defaults can now be overridden per
   target; the round-52 wording ("cannot be un-excluded") no longer
   applies.

## `sentinel scope list`

```
sentinel scope list [--state-dir <path>] [--store <file>] [--url <url>] [--json]
```

- `--state-dir` (default state directory) and `--store` (explicit
  store file) are mutually exclusive, like `check-scope`'s
  `--store`/`--target`.
- **Text output** (default): a header line
  `Scope targets in <store> (N):` and one line per target:
  `  <target_id> | valid | decision: <reason|—> | allowed_domains:
  <list> | excluded_paths: <list>` plus ` | defaults: overridden`
  when the target overrides the built-in defaults. An invalid entry
  prints as `  <target_id> | INVALID: <validation error>`. An empty
  store prints `No scope targets in <store>.` and exits 0.
- **JSON output** (`--json`): `{store, count, targets: [...]}`,
  deterministic — the same store listed twice is byte-identical, and
  a store written in the opposite order lists identically (sorted by
  `target_id`, plain string comparison; entries without a usable
  `target_id` sort last).
- **Decisions need a URL.** Without `--url` the decision column is
  `—` (`decision: null` in JSON): a scope decision is a property of a
  (target, URL) pair, and inventing a probe URL would fabricate data.
  With `--url`, each valid target is evaluated with the same
  `evaluateTargetRequest` that `check-scope` uses, and the decision
  (`IN_SCOPE`, `HOST_OUT_OF_SCOPE`, `EXCLUDED_PATH`, …) is attached.
- **Read-only.** `scope list` changes nothing, so it needs no
  kill-switch guard and works while the switch is armed (tested).
- **Per-entry validation.** One invalid entry does not hide the rest
  of the list: it is reported as `valid: false` with its validation
  error, and the valid entries are still listed. A damaged store
  *shape* (not an object, unsupported `schema_version`, no `targets`
  array, unreadable JSON) still fails the whole command loudly
  (`SCOPE_STORE_CORRUPT` / `SCOPE_STORE_UNSUPPORTED_SCHEMA`), because
  there is no list to report. A symlinked store file is refused
  (`SCOPE_STORE_SYMLINK_REFUSED`). An invalid `--url` fails with
  `SCOPE_LIST_INVALID_URL` and lists nothing.

The per-entry summary in JSON carries `targetId`, `valid`,
`programName`, `authorizationReference`, `allowedDomains`,
`excludedDomains`, `excludedPaths` (effective list, defaults +
`excluded_paths`), `defaultExcludedPathsOverridden`, `allowedMethods`,
`requiresApproval`, and `decision` (or `null`).

## `default_excluded_paths`

Field: `default_excluded_paths` (optional, array of absolute paths)
in the target object, validated by `normalizeTarget`.

| Field present? | Effective default list | `defaultExcludedPathsOverridden` |
|---|---|---|
| Absent | `DEFAULT_EXCLUDED_PATHS` (`/logout`, `/signout`, `/delete`, `/reset-password`, `/unsubscribe`) | `false` |
| Present, `[]` | none — no default exclusions for this target | `true` |
| Present, `['/custom', …]` | exactly that list | `true` |

Precedence: the target's effective `excludedPaths` are the deduped
union of the effective default list and the target's own
`excluded_paths`. The decision logic is unchanged — the same paths
deny the same requests; only *which* list supplies the defaults
changes.

Validation failures (non-array value, an entry that is not an
absolute path, a query or fragment) fail `normalizeTarget` with
`Invalid target registration: default_excluded_paths …` — there is no
silent fallback to the built-in list. `scope add` of such a target
fails with `SCOPE_TARGET_INVALID` and writes nothing; `check-scope`
exits 1 with the same message.

**Trail and suggestion.** When a request is denied by a path from the
effective default list, the `--explain` trail cites the right source:

- built-in defaults (no override): `built-in default:
  src/scope/target-registry.js (DEFAULT_EXCLUDED_PATHS);
  policies/scope-policy.md section 4`, and the suggestion now says
  the default can be overridden: *"To allow it for this target,
  declare `default_excluded_paths` in the target file — a list that
  replaces the built-in defaults — or use a different path."*
- overridden defaults: `target file: <file>
  (default_excluded_paths)`, and the suggestion says to remove the
  path from `default_excluded_paths`.
- a path from the target's own `excluded_paths`: `target file: <file>
  (excluded_paths)`, suggestion unchanged.

The decision object itself is unchanged
(`{allowed, reason, hostname, path, pattern}`) — the default-list
provenance is passed to the suggestion separately, so no decision
shape moved.

## Policy note

`policies/scope-policy.md` section 4 still states the default-deny
rationale for the built-in paths. The override does not weaken it for
any other target: it is per-target, explicit (a field in the target
file, visible in `scope list` and in the normalized target), and
audited like any other target registration — `scope add` of an
overriding target writes the same `SCOPE_TARGET_ADDED` record. An
operator who overrides the defaults for a target takes explicit
responsibility for that target's destructive-path exposure.

## Open items

- None for Phase 3 scope management at this level: the store now has
  add / remove / list, and the built-in defaults are overridable.
  What remains for Phase 3 as a whole is the Meta-side ceiling
  (official manifest, quotas, native identity) — not reachable by
  rounds — and any future scope-rule additions the operator wants
  (e.g. per-target method budgets beyond the existing rate limit).
