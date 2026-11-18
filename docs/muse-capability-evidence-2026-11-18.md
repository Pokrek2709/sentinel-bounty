# Muse capability evidence — 2026-11-18

Source: a capability report supplied by the project owner after direct testing in Muse Spark / `muse-app` 1.3. This document records that evidence for engineering decisions; it is not a claim that this repository independently authenticated the VM or a Meta-supported manifest.

## Verified in the reported custom-skill trial

| Area | Result | Engineering consequence |
| --- | --- | --- |
| Custom-skill discovery | A directory under `~/workspace/custom-skills/<name>/` with `SKILL.md` at its root was found by `muse.skill_search`. | Maintain `skills/sentinel-bounty/SKILL.md` as the source contract; install it at the custom-skill root when testing Muse. |
| CLI invocation | Muse read `SKILL.md`, then invoked `node bin/sentinel.js` through shell commands and parsed JSON stdout/files. | Keep CLI JSON stable; do not claim a custom tool-call API. |
| Runtime | Ubuntu 24.04.5, Node 24.22.1, and Python 3.12.3 via `python3` were reported. | The checker now tries `python3` before `python`. |
| Filesystem | A home/workspace marker survived a second run and VM restarts; `/tmp` was ephemeral. | Store durable, non-secret state beneath the workspace/home, never depend on `/tmp`. |
| Child processes | Version commands, exit statuses, pipes, environment variables, and working directory were reported to work. | A future wrapper can use controlled subprocesses, timeouts, and structured output. |
| Human approval | Shell execution showed Muse approval cards with command context. | Sentinel still needs its own context-rich approval decision before requesting a shell command. |
| Runtime cancellation | The runtime reportedly terminated a long process tree using `process.kill`. | This is a substrate for a future wrapper; it is not a Sentinel kill switch. |

## Explicitly not available or not verified

- No official Muse manifest or verified Muse integration was identified. This is a custom local skill only.
- No Sentinel-specific tool call, approval workflow, audit record, kill switch, or controlled execution wrapper exists yet.
- No runtime API was observed that enforces Sentinel's domain allowlist or validates redirects. Scope enforcement must happen before network I/O.
- Docker, `subfinder`, `dnsx`, `httpx`, and `katana` were unavailable in the tested VM.
- The checker intentionally made no network request. Egress was observed through a proxy in a separate runtime test, but this does not authorize target testing.
- Runtime resource observations are not guaranteed Secure VM quotas, and long output may be truncated.

## Safe installation shape for a custom-skill trial

```text
~/workspace/custom-skills/sentinel-bounty/
├── SKILL.md                 # copy of skills/sentinel-bounty/SKILL.md
├── bin/
├── src/
├── config/
├── schemas/
├── policies/
└── examples/
```

Run `npm test`, then only the local commands documented in the README. Do not install/bundle missing scanners as part of a custom-skill trial without a separately approved dependency and policy review.
