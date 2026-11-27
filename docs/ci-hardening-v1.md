# CI hardening v1 (round 99)

## What this is

The four-red-run saga (rounds 91–92) ended with a test fix, but the
saga exposed three procedural gaps no test covered: the Windows
simulation ran from a `/tmp` file the VM wipes on every restart, a
CHANGELOG entry could miss its code commit and land as a follow-up,
and the CLI help could drift from the detector registry without
anyone noticing. This document records the guards round 99 added for
those lessons, how to run them, and what they do not prove.

## The guards

### 1. The Windows simulation is a committed file, run by CI

`scripts/fake-win32.cjs` is the simulation preload (one line:
`process.platform` reads `'win32'`, plus a `SENTINEL_WIN32_SIM=1`
marker). Rounds 91–98 used `/tmp/fake-win32.cjs`; round 95 had to
rebuild it mid-round after a VM restart wiped `/tmp`. The committed
copy is the only one CI and operators use — never `/tmp`.

`.github/workflows/ci-guards.yml` runs on every push to `main` and
every pull request, on `ubuntu-latest`:

1. `npm test` — the full suite on Linux.
2. `node --test --require ./scripts/fake-win32.cjs` — the full suite
   under the Windows simulation (with `TEMP`, `TMP`, and
   `USERPROFILE` set to `/tmp`, as in the manual runs).
3. `node bin/sentinel.js verify-install` — all eleven checks.
4. The changelog rule (below) over the pushed range.

`windows-test.yml` is unchanged: it still runs the full suite on
`windows-latest`. The two workflows are complementary — the Linux
job catches regressions fast and proves the simulation works; the
Windows job is the real pass. The simulation proves branching logic
only, never a real Windows pass.

The workflow file is itself guarded by `tests/ci-guards.test.js`
(job name, runner, step commands, no `/tmp` preload reference,
`fetch-depth: 0` — the changelog step diffs the pushed range, and a
shallow checkout has no history to diff).

### 2. The pre-push gate

`scripts/pre-push-check.cjs` (or `npm run pre-push`) runs the same
four steps locally before a push: changelog rule, suite, Windows
simulation, `verify-install`. It fails fast on the first failing
step. Flags: `--changelog-only`, `--skip-tests`, `--skip-win32`,
`--skip-verify`, `--range <a>..<b>`, `--ci` (implies
`--changelog-only`; a git range that cannot be resolved is fatal
instead of a warning), `--help`.

The gate is deliberately NOT installed as a git hook by this round:
a hook the operator cannot see or disable would be a silent gate.
To wire it as a hook yourself, write `.git/hooks/pre-push` as:

```sh
#!/bin/sh
exec node scripts/pre-push-check.cjs
```

and `chmod +x` it. That is opt-in; the script never installs itself.

### 3. The changelog rule

A commit that touches code — `src/`, `bin/`, `tests/`, `scripts/`,
`.github/workflows/`, or `package.json` — must carry a CHANGELOG.md
entry in the SAME commit. Round 94's entry missed the main commit
and landed as follow-up commit `683169c`; the rule exists so that
cannot happen again. Docs-only commits are exempt (prose drift is
covered by the docs-crossref guard, `tests/docs-crossref.test.js`).
Merge commits carry no own diff and pass. The rule is per commit: a
range covering a code commit without its entry fails even if a later
commit adds the entry.

In CI the rule runs with the pushed range (`github.event.before`
to `github.sha`); an all-zero start (first push) falls back to
`HEAD~1..HEAD`. Locally the default range is `HEAD~1..HEAD`. A git
range that cannot be resolved warns and skips locally, and fails in
`--ci` mode — CI checks out with `fetch-depth: 0`, so history is
present there.

### 4. The `verify-install` ci-guards check (11th check)

`sentinel verify-install` now runs eleven checks. The new
`ci-guards` check is a consistency check, not a presence check: a
skill with none of the guard files passes vacuously (an installed
single-copy layout may ship without `.github/` or `scripts/`), and
what fails is inconsistency — a workflow pointing at the `/tmp`
preload, a workflow that never runs the simulation, a preload that
does not override `process.platform`, or a guard script that does
not parse. Presence of the CI job itself is pinned by
`tests/ci-guards.test.js`, not by the installer.

### 5. The log-archive procedure

The four red-run logs were archived by hand into
`~/workspace/sentinel-bounty/windows-ci-logs/` as
`logs_<check_suite_id>-<shortsha>/`. The procedure is now a
command:

```sh
node scripts/fetch-windows-logs.cjs --run-id 46052614644 \
  --out-dir ~/workspace/sentinel-bounty/windows-ci-logs
```

It resolves the run (head SHA, check_suite_id, conclusion) from the
GitHub API, downloads the logs zip (the API answers 302 to a signed
URL), and extracts it into the archive folder. An existing folder
is refused unless `--force` is given. Rate limits are reported, not
retried: unauthenticated calls get 60/hour per egress IP (rounds 88
and 92 both hit it); set `GITHUB_TOKEN` for the 5,000/hour
authenticated quota. The script never pushes, never commits, and
never touches the repo — it only writes the archive folder.
Extraction shells out to `unzip`, which must be installed.

## Regression tests added for paid-for lessons

- `tests/win32-sim.test.js` — the committed preload really
  overrides `process.platform`, and a simulated run really reads
  `'win32'` (skipped on real Linux; runs under the simulation).
- `tests/ci-guards.test.js` — the workflow's shape, and that
  `windows-test.yml` still runs the suite on `windows-latest`.
- `tests/pre-push-check.test.js` — the changelog rule against
  scratch git repos (code-only fails, CHANGELOG passes, per-commit
  enforcement, docs-only exempt, unresolvable range warns locally
  and throws in CI mode), plus the real repo's previous commit.
- `tests/fetch-windows-logs.test.js` — URL/folder conventions,
  rate-limit classification, and download+extract against a local
  stub API serving the committed fixture zip
  (`tests/fixtures/logs-sample.zip`).
- `tests/verify-install-ci-guards.test.js` — the ci-guards check:
  vacuous pass, consistent pass, and each inconsistency failing.
- `tests/detector-interface.test.js` — the CLI help names every
  registered built-in detector. Round 95 found the detect comment
  block never described the fifth detector (`insecure-transport`):
  the registry and the help had drifted silently. The test
  cross-checks the two sides (ids read from
  `src/detection/detector.js`, presence asserted in the CLI help),
  so a new detector must be added to the usage line or the suite
  fails.

## What the guards do not prove

- The Windows simulation is not a Windows pass. A green simulation
  proves the platform branches take the Windows path; only
  `windows-test.yml` on `windows-latest` proves the suite passes
  on Windows.
- The changelog rule checks the commit, not the content. A
  CHANGELOG entry can still be wrong or empty — the rule only
  guarantees it exists in the same commit as the code.
- The log archiver needs the network and API quota. A rate-limited
  download fails with `RATE_LIMITED` and the run must be retried
  later, with a token, or archived by hand from the Actions UI.
- The pre-push gate is a local convenience, not a safety gate. It
  can be skipped with `--skip-*` flags or by pushing without
  running it; the CI workflow is the enforcement point.
