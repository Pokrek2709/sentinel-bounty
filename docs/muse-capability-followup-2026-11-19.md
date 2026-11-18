# Muse capability follow-up — 2026-11-19

Source: a follow-up report supplied by the project owner after reinstalling commit `b36e7081240dd1beb18794db3364f71a941bb054` in the tested Muse custom-skill environment. This is user-supplied test evidence, not independent attestation by this repository.

## Confirmed results

| Check | Result | Consequence |
| --- | --- | --- |
| Updated test suite | 14 passing, 0 failing. | The Python fallback change reached the custom-skill installation. |
| Python detection | `python3` was detected as Python 3.12.3. | Keep `python3` as the first probe and `python` as fallback. |
| Custom-skill discovery | `SKILL.md` at the installed skill root was found. A nested `skills/sentinel-bounty/SKILL.md` was not discovered. | The deployment procedure must copy the source contract to the custom-skill root. Do not rely on nested discovery. |
| Scope command | The local `.test` example produced `IN_SCOPE` without a network request. | Preserve this as a non-networked smoke check. |
| Runtime cancellation | A runtime `process.kill` test ended a parent and two child processes, including one detached child, in one observed trial. | A future wrapper may target this substrate, but Sentinel still has no kill switch. Do not generalize one trial into a guarantee. |

## Approval and storage constraints

- The reported `permissions.preapprove` API has no generic target/action binding for Sentinel. It cannot substitute for the local bound Approval Gate.
- Muse shell-execution approval and Sentinel policy approval must remain separate controls.
- Reinstalling replaces the skill directory. Persistent state, if later required, must be stored outside it beneath a workspace-controlled directory. `/tmp` is unsuitable.
- The current Approval Gate intentionally keeps approval state in memory and expires it within ten minutes. It does not persist consent across a restart or reinstall.

## Still unverified or unavailable

- Official Muse manifest integration and a Sentinel-specific tool-call API.
- Sentinel controlled execution wrapper, audit log, and kill switch.
- Docker and the proposed scanner binaries.
- A generic Sentinel approval binding in Muse's preapproval system.

## Next Muse validation after this change

When a future wrapper exists, test the following only in an authorized local lab: create a bound Sentinel approval, verify that a changed target/action/scope digest is rejected, confirm expiry, and confirm that the wrapper refuses execution before it reaches the shell. No target network request is required for this validation.
