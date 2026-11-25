# Adapt to agent

This document is the prompt and procedure an installer pastes to their
agent when they download this skill. It adapts the platform-neutral
contract in this repository to the agent platform the installer actually
uses. It does not claim an official integration with any platform.

## What to paste

> Adapt the Sentinel Bounty skill in this repository to my agent
> platform. Follow `docs/adapt-to-agent.md` in the repository. Do not
> test any real target, do not install a network scanner, and do not
> print or store any token. Report gaps honestly in writing.

## 1. Read the contract first

Read `skills/sentinel-bounty/SKILL.md`. That file is the
platform-neutral contract: the operating personas, the safety rules,
the scope and approval requirements, and the local CLI commands.

It is **not** an official manifest for any platform. No official Meta
Muse manifest exists for this skill, and no official Muse API exists
for quotas, cancellation, or agent identity. Do not describe the
result as an official or verified integration.

## 2. Map the contract to the platform's own skill format

- **Muse:** place a copy named `SKILL.md` at the installed skill
  directory's root (for example
  `~/workspace/custom-skills/sentinel-bounty/SKILL.md`), plus a
  `skill.yaml` if the platform requires one. Discovery by literal
  name has been observed to work when `SKILL.md` is at the root; that
  observation is not a guarantee and not an official manifest.
- **Other platforms:** install at that platform's equivalent skill
  location and use its equivalent manifest, if any. If the platform
  has no skill/manifest mechanism, say so explicitly and do not
  invent one. Record the install path and the format used.

Copy the whole repository contents the skill needs (contract, `bin/`,
`src/`, `schemas/`, `policies/`, `examples/`, `knowledge/`,
`agents/`), not only the `SKILL.md` file, so the CLI commands the
contract names are present at the installed path.

## 3. Check the agent's capabilities honestly

Before claiming the skill works on this platform, check and record
each of these, with evidence, not assumption:

- Shell/exec access: can the agent run `node bin/sentinel.js ...`
  from the installed path?
- File read/write: can the agent read the contract and write local
  state outside the skill directory (default state directory
  `~/workspace/sentinel-bounty/state/`)?
- Subagent support: can the two personas (Lead Bug Hunter and
  Security Architect / Reviewer) run as separate roles, or must the
  second pass run sequentially in the same session?
- Skill discovery: how does the agent find skills — by literal name
  search, by index, by manifest? Test it (step 5).
- Approval flow for sensitive actions: how does the platform ask a
  human for approval, and does it block execution until approval is
  given? Record what the platform actually does; do not assume it
  matches the contract's approval gate.

Any capability that cannot be verified is recorded as
`not_verified`, not as working.

## 4. Run the verification commands

Run these from the repository (or installed) root. They are local
only and make no network request. The scope check uses the reserved
`example.test` domain from `examples/local-target.example.json` —
a lab target only. Never substitute a real target.

```sh
node bin/sentinel.js check-env
node bin/sentinel.js kill-switch status
node bin/sentinel.js check-scope --target examples/local-target.example.json --url https://app.example.test/docs
```

Expected results on a working local install:

- `check-env` exits 0 and reports `runtime` and `binaryExecution`
  as `verified`; `museSecureVm`, `skillInvocation`, and
  `processTermination` are `not_verified` outside a documented Muse
  runtime; network tools (`docker`, `subfinder`, `dnsx`, `httpx`,
  `katana`) are `unavailable` unless separately installed. The
  decision line is: "Muse Secure VM is not verified. Do not enable
  scanning or claim Muse integration from this report."
- `kill-switch status` reports `active: false` (or the stored state)
  with `registeredWorkers: 0` when no worker is running.
- `check-scope` reports `decision.allowed: true` with reason
  `IN_SCOPE` for `https://app.example.test/docs`, and
  `safety: "No network request was made."`

If any command fails, record the exact command, exit code, and
output. Do not work around a failure by changing the target, the
state directory, or the command.

## 5. Test skill discovery

Run the platform's skill search/listing for the literal name
`sentinel bounty` and for one persona query, `bug hunter`, and
record whether each returns the skill.

Known result on Muse (2026-11-26): the literal name finds the skill
at rank 1; the persona query `bug hunter` does **not** find it.
Persona-based discovery ("bug hunter", "security reviewer") may fail
on other platforms too. Report the observed result; do not claim
discovery works for queries you did not test.

## 6. Report gaps honestly, in writing

The adaptation report must state, explicitly:

- No official Meta Muse manifest exists; the installed file is a
  custom-skill copy, not a supported manifest integration.
- Skill discovery by literal name works (if observed), but
  persona-based discovery ("bug hunter", "security reviewer") may
  fail.
- There is no official Muse API for quotas, cancellation, or
  identity; the CLI is local-only.
- There is no network scanner and no public-target adapter. The
  only documented target is the local lab fixture
  (`examples/local-target.example.json`, `example.test`).
- Any capability from step 3 that was `not_verified` or
  `unavailable`, with the evidence for that status.

Do not soften a gap into a roadmap claim. A gap is a gap until a
test passes.

## 7. Record the adaptation for audit

Keep a short adaptation record in the repository (for example
`docs/adaptations/<platform>-<date>.md`) or next to the installed
skill. It must contain:

- What was changed: files installed, install path, and the format
  mapping (which contract section maps to which platform file).
- What was skipped and why.
- The `check-env` result (full output or a file reference).
- The discovery test results from step 5.
- The date and the agent platform.

Never include a token or a digest in the record. The reset token
lives in a secure vault; the digest file is mode `0600` and lives
outside the skill directory. Never print or store either value.

## 8. What adaptation must not do

- Do not test a real target or a public host.
- Do not install a network scanner.
- Do not claim official integration, verified status, or a supported
  manifest.
- Do not place a token, digest, or credential in a file, log, or
  chat message.
- Do not delete or modify the kill-switch state directory as part of
  adaptation. See `docs/uninstall-restore.md` for removal, which has
  its own procedure.
