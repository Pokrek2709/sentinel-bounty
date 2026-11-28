# Implementation status — 2026-11-21

This status records repository evidence, not planned capabilities.

## Status update — 2026-11-28 (round 97)

The table below is the 2026-11-21 snapshot, preserved as written.
Since it, two rows changed:

- **Phase 4 / 4b — public target support now exists, gated.**
  Round 90 built the public HTTP adapter groundwork, round 93 added
  the CLI invocation path (`sentinel target add` / `sentinel fetch`
  with preview and explicit human approval), and round 94 drilled
  the activation end to end with stubs. The table's "No public
  target support" and "no invocation path" no longer hold. No
  real-target fetch has been run; the first one still needs the
  user's word, a registered target, and a verified authorization
  reference.
- **Windows CI is green.** The four red Windows runs of rounds
  84/88/89/90 all failed on one environment-checker test
  (`docker --version` exits non-zero on the runner); the round-91
  fix was confirmed green on Windows CI (run 46052614644 for
  `fd4ed99`, conclusion success).

## Status update — 2026-11-28 (round 102)

The table below is the 2026-11-21 snapshot, preserved as written.
Since the round-97 addendum, one thing changed:

- **The Meta integration items are parked.** Round 102 (user
  decision 28 Nov 2026) removes them from the skill's active
  scope: the Phase 0/1/3 rows' Meta items (official manifest
  and registry, official API and quotas, native identity) no
  longer count toward completion, which is judged on local scope
  only. The items are preserved verbatim in
  [meta-integration-deferred-v1](meta-integration-deferred-v1.md).
  The snapshot table is preserved as written.

| Phase | Status | Evidence |
| --- | --- | --- |
| 0: Muse Secure VM feasibility | Partial | A direct custom-skill trial produced [capability evidence](muse-capability-evidence-2026-11-18.md). Official manifest integration, quotas, and Sentinel cancellation remain open. |
| 1: Skill foundation | Partial | The platform-neutral [skill contract](../skills/sentinel-bounty/SKILL.md) was discovered as a custom local skill only when copied to the installed skill root, as confirmed in the [follow-up trial](muse-capability-followup-2026-11-19.md). No official Meta Muse manifest exists. |
| 2: Environment checker | Implemented locally and trialed in Muse | `sentinel check-env` is non-networked; Python detection supports `python3` then `python`. |
| 3: Scope manager and policy engine | Partial | Local target registration, default-deny scope matching, rate limiting, request budgets, server-pressure backoff, bound approval, a fixed-command wrapper, process-group cancellation on POSIX, leased cross-process kill-switch state, bounded audit logging, and a token-gated local operator CLI exist. Muse-native identity/approval and public-target network adapters remain open. |
| 4: Local HTTP adapter | Initial lab-only implementation | GET-only `localhost` adapter exists with policy checks, governor response backoff, no redirect following, bounded output, redacted headers, and audit events. Muse real-run evidence is recorded in [HTTP adapter evidence](muse-http-adapter-evidence-2026-11-21.md). No public target support. |
| 4b: Public HTTP adapter (groundwork, round 90) | Adapter + gate implemented, no invocation path | `PublicHttpAdapter` (`src/http/public-http-adapter.js`) mirrors the local adapter with a public-hostname rule, an authorization-reference match against the registered target, and a post-approval DNS resolution that refuses non-public addresses (SSRF guard, incl. 169.254.169.254). Tests use a stub transport + stub resolver only; no CLI command invokes it yet and nothing runs against a real target. See [public HTTP adapter](public-http-adapter-v1.md). |

## Local-only result

The checked workspace ran Node.js and a child-process version command, wrote/read a storage marker across runs, and made zero network requests. It did not establish a Muse Secure VM, outbound networking, skill invocation, resource quotas, cancellation, or authorization for any target.
