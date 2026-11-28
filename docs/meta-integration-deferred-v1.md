# Meta integration items — parked (round 102)

The Meta integration items are parked, not deleted. Round 102
(user decision 28 Nov 2026) removes them from the skill's active
scope so development is no longer gated on Meta; the items below
are preserved verbatim so they can be restored if Meta opens a
supported path.

## Why parked

The items need Meta: an official manifest, a registry, an official
API with quotas, native identity, and persona indexing. No public
Muse skill registry exists — distribution is this GitHub repository
plus custom-skill install — and there is no supported manifest
format or activation mechanism to build against. None of the
detection, policy, invocation, session, or release work depends
on them, so keeping them as completion criteria only stalls the
phases they touch (F0, F1, F2, F3, F8). Parking them unblocks
those phases without losing the record.

## The parked items

1. The official supported manifest format and installation
   location.
2. A successful invocation through an official supported Muse
   integration, rather than the observed custom-skill shell
   invocation.
3. The supported tool/process/file/network permission model.
4. An approved local-lab test of the scope/policy gate and kill
   switch.
5. Persona indexing (a Phase 0/1 ceiling item from the round-32
   phase record; not in the SKILL.md list above).

Items 1–4 are the former "Expected future integration evidence"
section of `SKILL.md`, moved here verbatim in round 102.

## Local-scope completion criteria (round 102)

Phase completion is judged on local scope only:

- **F0** is complete when the skill is distributed versioned via
  GitHub plus custom-skill install with `verify-install` green.
- **F1** is complete when it is invocable through the supported
  local paths (the `sentinel` CLI and the custom-skill shell
  invocation) with the local permission model documented
  (approval gate, kill switch, scope manager, request governor).
- **F2** is complete when `sentinel check-env` reports local
  capabilities accurately (its tails were closed in round 97).
- **F3** is complete when the scope manager and policy engine
  cover local registration, default-deny matching, budgets,
  approval, and the kill switch (all built).
- **F8** is complete when the release process (CHANGELOG
  sections, version numbering, annotated tags) and the CI guards
  are in place and green (release v0.2.0, round 99).

Consequences (round 102): F0, F1, F2, F3, and F8 are complete
on local scope — their only remaining items were the parked Meta
items. F4 (first real fetch), F5 (second language parser), F6
(policy), and F7 (HackerOne/Bugcrowd templates unverified
against the live platforms' forms) are unchanged. The 1.0
release gate now rests on a first real fetch only (see
`docs/release-process-v1.md`).

## Restoration rule

To restore the Meta items: move this list back into the skill
contract as completion criteria, restore the pre-round-102
wording in the docs listed below as "rewritten", record a new
user decision with a date, and re-state the phase numbers. Do
not restore silently; a restoration is a scope decision, not a
doc edit.

## Inventory — every Meta reference in the repo (round 102)

Rewritten in round 102 (active completion criteria):

| File | Claim | Disposition |
| --- | --- | --- |
| `SKILL.md` (both copies) | "Expected future integration evidence" — the four items as promotion criteria | Moved here verbatim; replaced by the local-scope phase-completion section |
| `docs/release-process-v1.md` | "MAJOR stays 0 until the Meta items and a first real fetch are done"; "What is still NOT in any release: the official Meta skill release" | 1.0 gate is now a first real fetch only; Meta items parked, not a release gate |
| `docs/operator-sessions-v1.md` | F1 items "deferred to the final stage" | "Parked with the Meta integration items" |
| `docs/scope-explain-v1.md` | Phase 3 "Meta-side ceiling — not reachable by rounds" | Parked; Phase 3 completion judged on local scope only |
| `docs/scope-list-default-path-v1.md` | Same Phase 3 ceiling sentence | Same as above |
| `docs/controlled-wrapper-v1.md` | "A Muse-native identity/approval channel remains unverified" | Channel does not exist; parked, not a pending wrapper item |

Dated addendum over a preserved record (round 102):

| File | Claim | Disposition |
| --- | --- | --- |
| `docs/implementation-status.md` | Phase 0/1/3 table rows: official manifest, quotas, native identity "remain open" | Round-102 addendum over the preserved 2026-11-21 snapshot (round-97 precedent) |
| `docs/check-env-audit-v1.md` | Audit-table rows: Muse Secure VM attestation / Muse skill invocation "Needs Meta" | Round-102 note; rows remain as the record of what the checker reports |

Retained as fact or history (still true; not completion criteria):

| File | Claim | Why retained |
| --- | --- | --- |
| `README.md` | "Not an official or verified Meta Muse integration"; official activation "requires Meta's supported manifest format and a successful official integration invocation" | Factual status of the installation; states what official activation would require, not what completion requires |
| `docs/adapt-to-agent.md` | "No official Meta Muse manifest exists"; "no official Muse API exists for quotas, cancellation, or agent identity"; "do not claim official integration" | Factual statements about the world; platform-adaptation guidance, not a completion claim |
| `docs/muse-capability-evidence-2026-11-18.md` | "No official Muse manifest or verified Muse integration was identified" | Historical trial record (2026-11-18); true as a record of what was established |
| `docs/muse-capability-followup-2026-11-19.md` | "Official Muse manifest integration and a Sentinel-specific tool-call API" listed under "Still unverified or unavailable" | Historical trial record (2026-11-19) |
| `docs/muse-secure-vm-poc.md` | "Muse skill invocation: requires Meta's supported skill manifest/activation mechanism"; "Do not claim official Meta Muse manifest integration" | Historical PoC record; "deliberately left unverified" list |
| `docs/github-prototype-readiness.md` | "It is not a packaged Meta Muse skill" | Factual statement about what the repo is |
| `CHANGELOG.md` | All pre-round-102 Meta lines (rounds 97/98 "what remains" ceilings, round-32 phase record) | Historical record, never rewritten; the round-102 entry documents the change |
| `prd-sentinel-bounty.md`, `sad-sentinel-bounty.md` | Meta Muse as primary platform (frozen 2026-11-26 design snapshots) | Product design intent, not completion criteria |
| `src/environment/checker.js` | Check-env output: host-visible values "do not establish Secure VM quotas" | Factual output text |
| `src/policy/operator-sessions.js`, `src/policy/operator-status.js` | Internal comments ("no call to any Meta service", storage failure classes) | Internal comments; factual |
| `docs/operator-sessions-v1.md` (intro), `docs/README.md` (operator-sessions blurb) | "The F1 session story that needs no Meta service"; "no Meta service involved" | Already local-scope statements; retained |

Unrelated matches (not Meta items): `agents/api-security-tester/agent.md`
("request quotas" — generic rate limiting), `docs/ci-hardening-v1.md`
(GitHub API quota for the log archiver), `knowledge/owasp-wstg/overview.json`
("Metafiles" — OWASP entry), `src/scope/target-registry.js`
(`meta` variable name), `docs/report-docs-audit-v1.md` ("meta-doc"
meaning meta-document), HTML `<meta>` tags in report fixtures and
tests.
