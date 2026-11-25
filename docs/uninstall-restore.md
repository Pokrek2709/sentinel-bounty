# Uninstall and restore

This document is the prompt and procedure an uninstaller pastes to
their agent when they remove this skill. It restores the machine to
its pre-install state as far as the skill's own files allow, without
destroying safety state as a shortcut.

## What to paste

> Uninstall the Sentinel Bounty skill following
> `docs/uninstall-restore.md` in the repository. Resolve any leased
> token and any armed kill-switch state first. Do not delete the
> state directory unless I confirm it. Report what was removed and
> what was kept, and verify the skill is no longer discoverable.

## 1. Resolve leased tokens and kill-switch state first

Before removing anything, run:

```sh
node bin/sentinel.js kill-switch status
node bin/sentinel.js kill-switch audit-health
```

- If a token is leased to a worker, revoke it:

```sh
SENTINEL_OPERATOR_RESET_TOKEN="current-token" SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE="/secure/path/operator-reset-token.sha256" node bin/sentinel.js kill-switch revoke-token --actor <id>
```

  Revocation needs the current token and a healthy audit path. It
  records `KILL_SWITCH_TOKEN_REVOKE_PENDING`, then removes the digest
  file and records `KILL_SWITCH_TOKEN_REVOKED`.
- Confirm `kill-switch status` shows no live worker leases
  (`registeredWorkers: 0`, `workers: []`). A reset is denied while a
  live lease remains; do not force it.
- If the kill switch is armed (`active: true`), do not remove the
  state to make the problem go away. Resolve it through the normal
  path: stop the workers, then reset with the operator token (see
  `README.md` for the reset command). Deleting an armed kill-switch
  state as a shortcut is forbidden by the contract.

**Never leave dangling state.** An armed kill switch or a leased
token must be resolved before removal. If revocation is impossible
because the token is lost, say so explicitly and record it as a
known leftover — do not silently delete the state and do not claim
the uninstall is clean.

## 2. Remove the installed skill copy

Remove the installed skill directory's files, including the root
`SKILL.md` copy placed there at install time (for Muse, typically
`~/workspace/custom-skills/sentinel-bounty/`). Remove the whole
installed directory only if it contains nothing the user added
outside the skill; otherwise remove the skill's own files and list
what was left behind and why.

Do not remove the repository clone in this step unless the user
explicitly asks for it (see step 5).

## 3. State directory: keep by default

The state directory (`~/workspace/sentinel-bounty/state/`, or the
configured `--state-dir`) is **kept by default**. It holds the
kill-switch state and the audit log, which are the evidence that
past lab runs stopped cleanly.

Remove it only if the user confirms, after step 1 has resolved any
armed state and any leased token. If the user does not confirm, keep
it and say so in the report. Removing state to hide an armed switch
or an unrevoked token is not a valid uninstall.

## 4. Verify the skill is no longer discoverable

Run the platform's skill search/listing for `sentinel bounty` and
confirm it no longer returns the skill. Then confirm the installed
CLI path is dead:

```sh
node ~/workspace/custom-skills/sentinel-bounty/bin/sentinel.js check-env
```

That command must fail because the file is gone (for example
`Cannot find module` or `ENOENT`). Record the verification commands
and their exact outputs. If the search still returns the skill, or
the CLI still runs, the uninstall is not complete — report that
instead of claiming success.

## 5. Report leftovers explicitly

The report must distinguish REMOVED from KEPT in a two-column list:

| REMOVED | KEPT |
| --- | --- |
| Installed skill directory and root `SKILL.md` copy | Repository clone (kept by choice unless the user says delete) |
| Leased operator token (revoked, digest file removed) — only if step 1 completed | State directory `~/workspace/sentinel-bounty/state/` (kept by default) |
| — | Digest file location, if it still exists (never print its contents) |
| — | Audit log `audit.jsonl` inside the kept state directory |
| — | Any known leftover recorded in step 1 (for example an unrevocable token, stated explicitly) |

If a row does not apply (for example no token was ever leased),
write "not applicable" in that row rather than omitting it, so the
reader can tell the case was checked, not skipped.

## 6. What uninstall must not do

- Do not delete an armed kill-switch state or an unrevoked token's
  state to finish faster.
- Do not print the contents of the digest file, and do not print any
  token.
- Do not delete the repository clone, the state directory, or the
  audit log without the user's explicit confirmation for that item.
- Do not claim the skill is gone until step 4's verification has
  actually been run and its outputs recorded.
