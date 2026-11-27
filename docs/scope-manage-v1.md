# Scope target management v1 — `sentinel scope add/remove` (round 53, Phase 3)

## Problem

Before this round there was no persistent scope registry and no CLI
management. `check-scope --target <file>` registered exactly one target
per invocation from the file the operator passed; nothing on disk
remembered it afterwards, and `sentinel scope add` printed the usage
text with exit 1. An operator who wanted to keep a standing list of
in-scope targets had to keep the target files around and pass one per
invocation, with no record of which targets were currently registered.

## The store

`<state-dir>/scope-targets.json` — the same state directory the
kill-switch and audit log use (default
`~/workspace/sentinel-bounty/state`).

- Format: `{ "schema_version": 1, "targets": [ <target object>, ... ] }`.
  Each entry is the raw target object exactly as the operator supplied
  it. The canonical target shape is the one `normalizeTarget`
  validates, so every stored entry is re-validated on every load: a
  damaged entry fails loudly (`SCOPE_TARGET_INVALID`) instead of
  silently changing scope.
- Placement is deliberate: the store is **not** inside the skill
  directory. A skill reinstall (fresh clone + rsync `--delete`) would
  wipe operator-managed files there, while the state directory
  survives reinstalls.
- Permissions follow the round-34/45 state-file rules: the parent
  directory is created private (`0700`, `ensurePrivateDir`), the file
  is written `0600` through `writeFileRefusingSymlink` (planted
  symlinks refused), and the state-permissions check in
  `verify-install` covers it.
- Concurrency: add/remove run load-modify-save under an exclusive
  lock file (`scope-targets.json.lock`, `wx` create, 5 s timeout,
  25 ms retry, 60 s stale reaper — the same shape as the audit log's
  lock). A lock that cannot be acquired in time fails with
  `SCOPE_STORE_LOCKED` and writes nothing.

## Commands

```
sentinel scope add <target.json> [--state-dir <path>]
sentinel scope remove <target-id> [--state-dir <path>]
```

`scope add` reads a target file (same file format as `check-scope
--target`, same bounded read, same `normalizeTarget` validation) and
appends it to the store. An invalid target fails with
`SCOPE_TARGET_INVALID` and writes nothing. Adding a `target_id` that
is already present is an **idempotent no-op**: exit 0, the result
reports `added: false, alreadyPresent: true`, the file is not
rewritten, and no audit record is written for it (there is no
`auditLogged` field on the no-op result — `false` would imply a
failed append).

`scope remove` deletes the entry with that `target_id`. Removing an
absent `target_id` fails with `SCOPE_TARGET_NOT_FOUND` and writes
nothing.

A successful mutation writes an audit record (`SCOPE_TARGET_ADDED` /
`SCOPE_TARGET_REMOVED`, with `targetId` and the store path) and
reports `auditLogged: true`. A mutation whose audit append fails
reports `auditLogged: false` and exits 4, following the kill-switch
trigger pattern.

### Armed-switch guard

Both commands refuse to run while the kill-switch is **armed**
(`SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE`, exit 1, JSON result with
the trigger). Rationale: scope changes while the switch is armed
would silently change what a stopped run covers. The guard is checked
before any target is read or written, via
`PersistentKillSwitch.assertNotTriggered()`.

## Resolving a stored target

```
sentinel check-scope --store <scope-targets.json> --target-id <id> --url <url> [--explain] [--json]
```

`--store` is the store **file** path. It is mutually exclusive with
`--target`. The target is resolved from the store and evaluated with
the unchanged `evaluate()` logic; `--explain` cites the store file as
the policy source. An absent `target_id` fails with
`SCOPE_TARGET_NOT_FOUND` (exit 1). The plain `--target` path is
unchanged.

## Named errors

| Code | Meaning |
| ---- | ------- |
| `SCOPE_TARGET_INVALID` | The supplied target (or a stored entry) fails `normalizeTarget` validation, or the target file cannot be read as a target. Nothing is written. |
| `SCOPE_TARGET_NOT_FOUND` | No entry with that `target_id` in the store. Nothing is written. |
| `SCOPE_STORE_CORRUPT` | The store file is not a JSON object, has no `targets` array, or cannot be read as JSON. |
| `SCOPE_STORE_UNSUPPORTED_SCHEMA` | `schema_version` is not 1. |
| `SCOPE_STORE_SYMLINK_REFUSED` | The store file is a symbolic link (load and save both refuse). |
| `SCOPE_STORE_LOCKED` | Another scope mutation holds the lock and the 5 s timeout expired. |
| `SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE` | The kill-switch is armed; scope changes are refused. |

All of these are thrown as `ScopeStoreError` (`.code` set, code also
prefixed in the message so the CLI's stderr line is greppable) except
the armed-switch refusal, which is a JSON result with exit 1.

## What this round does not do

The two items recorded here as "left for a later round" are now
closed; the section is kept so the history reads correctly:

- ~~No `scope list`.~~ Closed in round 54: `sentinel scope list`
  is the read-only complement to `scope add/remove` (see
  [scope-list-default-path-v1](scope-list-default-path-v1.md)).
- ~~Built-in default paths still cannot be overridden from the
  target file.~~ Closed in round 54: a target file may declare
  `default_excluded_paths`, which replaces the built-in defaults
  for that target only.
- **The decision logic is unchanged.** The store only remembers
  targets; `evaluate()` and `explain()` are untouched, and the plain
  `check-scope --target` path is byte-identical to before.

## Programmatic use

`src/scope/target-store.js`: `storePathFor(stateDirectory)`,
`loadScopeTargets(storePath)`, `saveScopeTargets(storePath, store)`,
`addScopeTarget(storePath, targetObject)`,
`removeScopeTarget(storePath, targetId)`,
`findScopeTarget(storePath, targetId)`, `ScopeStoreError`,
`SCHEMA_VERSION`, `STORE_FILE_NAME`.
