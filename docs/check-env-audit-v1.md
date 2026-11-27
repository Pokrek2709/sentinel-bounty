# check-env audit (Phase 2 completion, round 41)

`sentinel check-env` is a local capability report: it makes zero network
requests and runs no security scanner. This document records the round-41
audit of what it actually verifies against what the repository documents,
what was fixed, and what is still deliberately left out.

## Audit table

| Documented requirement | Checked? | Minimum version enforced? | Missing-tool message actionable? |
| --- | --- | --- | --- |
| Node.js 18 or later (README.md, package.json `engines`) | Yes — `runtime` | **Fixed this round.** Before: `runtime` reported `verified` for any Node that executed, and only `verify-install` enforced the floor. Now `checkNodeVersion` parses the major version and reports `not_verified` with reason `Node.js 18.0.0 or later is required (found …)` below the floor. The floor constant mirrors `package.json` engines and is covered by a test. | n/a (runtime, not a tool) |
| No npm dependencies (README.md) | n/a — nothing to check | n/a | n/a |
| Tools `docker`, `subfinder`, `dnsx`, `httpx`, `katana` (`config/environment-tools.json`) | **Fixed this round.** Before: the checker used a hardcoded list and never read the config, so the documented list and the checked list could drift silently. Now the list is loaded from the config at runtime (`toolConfiguration` capability reports the source); a missing/unreadable/malformed config falls back to the built-in definitions and says so. A tool listed in the config with no checker definition is reported `not_verified` with reason `No version command is defined for this tool in the checker` — never silently skipped. A drift-guard test asserts the built-in definitions match the config list. | No documented minimum exists for any of these tools, so none is enforced. | **Fixed this round.** Before: `Command was not found on PATH.` only. Now every tool result carries `purpose` (why it matters); an unavailable tool additionally carries `installHint` (how to install it) and `docker` carries the caveat that a detected CLI is not evidence of a usable daemon. |
| Python (`python3`, then `python`) | **Removed in round 46 — not a requirement.** No component of this skill invokes a Python interpreter: there are no `.py` files in the repo, nothing spawns `python`, and README.md lists only Node.js 18+ as a requirement. The probe reported a capability nothing used and `disabledFeatures` listed a `python_based_tools` feature that does not exist. The `python` capability and the `python_based_tools` entry are gone from `check-env` output; `checkFirstAvailableCommand` is retained as a tested utility for future first-available probes. | n/a — nothing to enforce | n/a |
| Writable storage + cross-run persistence | Yes — `filesystem` | n/a | n/a |
| Process cancellation | **Fixed this round.** Before: `processTermination` reported the stale text `Controlled cancellation has not been implemented or verified in this phase` — false since the persistent kill switch landed (rounds 10–28) and the drill (round 39). Now `checkProcessTermination` runs an isolated probe: a `PersistentKillSwitch` against a fresh temporary state directory (never the real state dir, never armed, never triggered), snapshots it, and requires inactive + zero workers. End-to-end cancellation of a real worker is proven by `sentinel drill`, named in the result as `endToEndProof`. A probe failure reports `not_verified` with the reason. | n/a | n/a |
| Outbound networking | Deliberately `not_tested` — the checker makes no network request. | n/a | n/a |
| Muse Secure VM attestation | `not_verified` — environment-variable markers are not proof. Needs Meta. | n/a | n/a |
| Muse skill invocation | `not_verified` — needs Meta's supported manifest/activation. | n/a | n/a |
| Resource quotas (CPU, memory, disk, duration) | Informational only — host-visible values are not Secure VM quotas. | n/a | n/a |

## Considered and excluded

- **git / npm.** Install-time tools only (clone the repo, run `npm test`).
  The skill never shells out to either, so they are not environment
  requirements and are not checked.
- **Python minimum version.** None is documented anywhere, because
  Python is not a requirement at all (round 46): no component invokes
  a Python interpreter. If a Python-based tool is added later,
  document its minimum then and enforce it the same way as the Node
  floor.
- **`implementation-status.md`.** Dated 2026-11-21; it is a snapshot, not
  a live status page, so its Phase 2 row was left untouched. Current
  state is this document.

## Remaining known gaps

- **check-env reports; it does not gate.** It exits 0 even when tools are
  unavailable or the Node floor fails — it is a capability report.
  `sentinel verify-install` is the gate (Node >= 18, CLI reachable,
  kill-switch inactive, audit healthy, state permissions private,
  scope config, skill files).
- **The process-termination probe verifies the machinery, not a kill.**
  It proves the kill-switch state path works in isolation; the actual
  cancellation of a worker is proven by `sentinel drill` (round 39).
- **Tool purpose/install hints live in the checker, not the config.**
  The config is the source of truth for *which* tools are checked;
  `TOOL_DEFINITIONS` in `src/environment/checker.js` is the source of
  truth for *how* each is checked and what its hint says. A config tool
  without a definition fails loudly (`not_verified`) instead of drifting
  silently.

## Round 97 note

Five untested branches found by inspection and pinned by tests in
`tests/environment-checker.test.js` (no production change): the Node
floor constant now has a drift-guard test against `package.json`
`engines` (the round-41 claim that the mirror was "covered by a
test" was true of the floor behavior, not of the mirror itself);
`detectMuseEnvironment`'s `MUSE_` marker branch; both all-fail
branches of `checkFirstAvailableCommand` (all-ENOENT →
`unavailable`, mixed → `not_verified`); the `NOT_FOUND` code in
`checkCommand`; and the `checkStorage` failure path (probe
directory through a file → `unavailable`). The by-design gaps
above are unchanged.
