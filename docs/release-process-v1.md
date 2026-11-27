# Release process v1 (round 98)

How a release of the sentinel-bounty skill is cut, what the
version numbers mean, and what v0.2.0 contains. For operators
cutting a release and reviewers checking that a tag means what it
says.

## How a release is cut

1. Rounds land on `main` with a CHANGELOG entry each, under
   `## [Unreleased]`, in the round's own commit.
2. Decide the version (see the numbering rules below).
3. Move the entries for the rounds in the release out of
   `[Unreleased]` into a `## [x.y.z] — YYYY-MM-DD` section, newest
   round first, verbatim — a release section is a record, not a
   rewrite.
4. Bump `package.json` `version` to the release version, so the
   tag line and the package agree.
5. Run the full suite (`npm test`, 0 fail), the win32 simulation,
   and `verify-install` (10/10 since round 98). A release never
   ships on a red suite.
6. Commit the release (CHANGELOG + version bump + any last
   packaging changes) with a `feat(round-N)` / `chore(release)`
   message naming the version.
7. Create an annotated tag `vX.Y.Z` on the release commit, with a
   message describing what the release contains.
8. Push the commit and the tag, then verify both from the remote
   (`git ls-remote` for HEAD and for the tag) — a tag is not
   released until the remote shows it.

`[Unreleased]` stays as a header with nothing under it between
releases; the next round's entry repopulates it.

## Version numbering

The release line is `v0.x`, pre-1.0, following semver for a 0.x
line:

- **MINOR** (`0.1.0` → `0.2.0`) when the release adds capability
  in a backward-compatible way — the normal case for a round that
  builds a feature.
- **PATCH** (`0.2.0` → `0.2.1`) when the release is fixes only,
  with no new capability.
- **MAJOR stays 0** until the two things that make this a 1.0
  are done: the Meta integration items (official manifest and
  registry, API and quotas, native identity) and a first real
  fetch against a real registered target. 1.0.0 before either
  would claim a stability the project does not have.

Three other `1.0.0` numbers in the repo are NOT the release
version and must not be confused with it:

- `package.json` said `1.0.0` before round 98 — the pre-tagging
  internal version, matching the PRD. Round 98 aligns it to the
  release line (0.2.0); the PRD's `Version: 1.0.0` is a frozen
  2026-11-26 snapshot and is left as it is, not rewritten.
- `config/environment-tools.json` `version: 1.0.0` is the tool
  config schema version.
- `src/environment/checker.js` `reportVersion: '1.0.0'` is the
  check-env report format version, and `POLICY_VERSION = '1.0.0'`
  (`docs/policy-versioning-v1.md`) is the F6 decision-set
  version. Both track their own thing, not the release.

## The [1.0.0] CHANGELOG section

The CHANGELOG section headed `## [1.0.0] — 2026-11-26` was
written before the release-tag line existed. It narrates rounds
1–32 (head commit `f42c61b`, 2026-11-25, verified present in
history after the clone was deepened in round 98) and was never
a tagged release — the first tagged release is v0.1.0 (round 90,
commit `c4c9060`). Round 98 retitles that section
`Pre-release baseline — rounds 1–32` and records this note on
it, without rewriting its content: the `1.0.0` label predates
the tag line and must not be read as a release version.

## Release notes — v0.2.0 (2026-11-28)

The second tagged release, on the round-98 commit. It covers
rounds 91–98 (round 92 made no code change — log verification
only — and has no entry):

- **Round 91** — the Windows run for `c4c9060`, diagnosed by
  name from the user-supplied log: one failing test
  (`environment-checker.test.js:71`, `docker --version` exits
  non-zero on the runner, so the probe reports `not_verified`),
  fixed test-only by accepting `not_verified` as a legitimate
  probe outcome.
- **Round 93** — the public-fetch invocation path: `sentinel
  target add/list/remove` and `sentinel fetch` (registration,
  preview, explicit human approval — interactive YA or a
  5-minute one-time token — SSRF guard, redirect never
  followed, metadata-only audit).
- **Round 94** — the activation drill: end-to-end chain,
  refusal matrix, kill-switch drill at every point including
  in-flight abort, and the operator runbook.
- **Round 95** — parser/taint scoping and the first AST-based
  detector, `tainted-deserialize` (stdlib-only JavaScript
  subset parser, intra-procedural taint; Acorn evaluated and
  not adopted).
- **Round 96** — F6 policy hardening: enforcement wired at
  report generation (false-positive exclusion first, then
  conservative semantic dedup), policy versioning
  (`POLICY_VERSION` 1.0.0), `sentinel policy`, and the AST
  evidence fallback.
- **Round 97** — F2/F3/F7/F8 tails: five pinned branches, the
  hyphen matcher fix, six stale docs corrected.
- **Round 98** — this release's packaging (this document, the
  CHANGELOG restructure, `verify-install` 7 → 10 checks) and
  local operator sessions (`sentinel session`, token /
  heartbeat / lease / rotation, fetch binding).

What is still NOT in any release: the official Meta skill
release (needs Meta's manifest), and a first real fetch (needs
the user's word, a registered target, and a verified
authorization reference). Both are recorded as the remaining
work, not as shipped.

## Release notes — v0.1.0 (2026-11-28)

The first tagged release, on the round-90 commit (`c4c9060`).
It covers rounds 34–90: the kill switch and token lifecycle,
scope and policy, the detector set (stub plus five regex
detectors), validation and dedup, the report pipeline in six
formats, the public HTTP adapter groundwork, the F6 policies,
and the `asset_url` scrub. Rounds 1–32 are narrated in the
pre-release baseline section below it.
