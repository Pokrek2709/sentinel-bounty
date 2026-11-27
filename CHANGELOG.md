# Changelog — sentinel-bounty

All notable changes to this project are documented here. Entries are drawn
from the capability reports in `~/workspace/sentinel-bounty/`
(`capability-report-*.md`, rounds 1–32, 18–26 Nov 2026). Phase percentages
are the reports' own first-implementation estimates, not test counts.

## [Unreleased]

### Second real detector: dangerous-call over local text (round 87, 2026-11-27)

- Windows run verdict for the round-86 commit `4c10a44`
  (round 87, part 1): run 45984432990 completed
  2026-11-27T10:43:01Z with conclusion `success` — job `test`
  success, every step success including `Run npm test`. This is
  the third green Windows run in the project's history (after
  run 45881977604 for `d2d1991` and run 45884755893 for
  `82d68d4`) and the first green run for the round-86 commit
  itself, so the round-86 detector change causes no Windows
  regression. The red `933e0e7` run stays unexplained (the
  failing test name is still unknown, log download 403) and no
  fix was attempted; it is now sandwiched between three green
  runs on the same suite.
- F5's second real detector: `dangerous-call`
  (`src/detection/dangerous-call.js`, registered as the
  built-in `--detector dangerous-call` alongside `stub` and
  `secret-scan`; CLI help and `runDetect` comment updated).
  It scans the `content` string of an operator-supplied local
  input record for six risky code-sink patterns (eval, the
  Function constructor, command execution, innerHTML
  assignment, document.write, unsafe deserialization) and
  reports one finding per distinct call site (pattern, line,
  column, match) in four classes — code injection (CWE-94,
  high), OS command injection (CWE-78, high), cross-site
  scripting (CWE-79, medium), insecure deserialization
  (CWE-502, high) — confidence `potential`, never executing
  the code it scans. No network, no scanner, no target; the
  detector only ever sees text the operator hands it. Safety
  properties, all tested: a finding carries only the matched
  call text (never the whole source line, which could hold
  adjacent sensitive data); `finding_id` is deterministic
  (`dangerous-call-` + SHA-256 of pattern + line + column +
  match, first 16 hex); one finding per call site with the
  first occurrence line and column; at most 100 findings per
  record with the truncation recorded in `errors`, never
  silent; content over 1,000,000 characters is skipped; a
  record without usable content is counted in `skipped`,
  never thrown; batch records follow the stub convention
  (batch `tool` forced as `discovery_tool`). The detect →
  validate → dedupe → report pipeline is proven end to end by
  test (XSS and deserialization findings validate as
  `needs_evidence` — their checklists require a `response_log`
  / `evidence_notes` — and the JSON report carries the
  per-finding evidence checklist; code injection and OS
  command injection have no dedicated checklist class and
  resolve to the generic checklist). 15 new tests
  (`tests/dangerous-call.test.js`); see
  `docs/detection-dangerous-call-v1.md`. SKILL.md's detector
  paragraph now names `dangerous-call` as the second real
  detector (both copies, still 150 lines, `cmp` passes); the
  open decisions (which further detectors, auto-run, async)
  are unchanged.

### Third real detector: insecure-crypto over local text (round 88, 2026-11-27)

- Windows run verdict for the round-87 commit `e2d164b`
  could NOT be checked this round: the unauthenticated GitHub
  API returns 403 "API rate limit exceeded" for the shared
  egress IP (104.29.197.140) — no run list, no jobs, no
  verdict, and no fix was guessed from the absence. No token
  was used (none is available to this round) and no run log
  was downloaded. The check is deferred to the next round,
  when the rate-limit window may have reset; the red `933e0e7`
  run stays unexplained as before.
- F5's third real detector: `insecure-crypto`
  (`src/detection/insecure-crypto.js`, registered as the
  built-in `--detector insecure-crypto` alongside `stub`,
  `secret-scan`, and `dangerous-call`; CLI help and
  `runDetect` comment updated). It scans the `content` string
  of an operator-supplied local input record for six
  weak-cryptography call-site patterns (MD5/SHA-1 hash calls,
  ECB cipher mode, DES/3DES/RC4/ARC4 cipher instantiation,
  Node's deprecated `crypto.createCipher()` /
  `createDecipher()`, `Math.random()` / `random.random()`)
  and reports one finding per distinct call site in the
  `cryptographic failure` class (CWE-327, CWE-338 for the weak
  PRNG; DES/RC4 high, the rest medium — each medium pattern is
  only exploitable in a sensitive context the detector cannot
  prove), confidence `potential`, never executing the code it
  scans. No network, no scanner, no target; the detector only
  ever sees text the operator hands it. Safety properties, all
  tested: a finding carries only the matched call text (never
  the whole source line, which could hold adjacent sensitive
  data); `finding_id` is deterministic (`insecure-crypto-` +
  SHA-256 of pattern + line + column + match, first 16 hex);
  one finding per call site with the first occurrence line and
  column; at most 100 findings per record with the truncation
  recorded in `errors`, never silent; content over 1,000,000
  characters is skipped; a record without usable content is
  counted in `skipped`, never thrown; batch records follow the
  stub convention (batch `tool` forced as `discovery_tool`).
  A DES cipher in ECB mode is two distinct weaknesses and
  yields two findings, one per pattern (tested explicitly).
  The detect → validate → dedupe → report pipeline is proven
  end to end by test (findings validate as `valid` under the
  generic checklist — `cryptographic failure` has no dedicated
  checklist class and resolves to the generic fallback, the
  same situation as round 87's code-injection classes — and
  the JSON report carries the per-finding evidence checklist).
  16 new tests (`tests/insecure-crypto.test.js`); see
  `docs/detection-insecure-crypto-v1.md`. SKILL.md's detector
  paragraph now names `insecure-crypto` as the third real
  detector (both copies, still 150 lines, `cmp` passes); the
  open decisions (which further detectors, auto-run, async)
  are unchanged.

### Fourth real detector: hardcoded-credential over local text (round 89, 2026-11-28)

- Windows run verdicts, checked first this round (the
  round-88 API rate limit had reset): run 46034607189 for the
  round-87 commit `e2d164b` completed 2026-11-27T16:33:24Z
  with conclusion `success` — job `test` success, every step
  success including `Run npm test`. This is the fourth green
  Windows run in the project's history and the first green
  run for the round-87 commit itself, so the round-87
  detector change causes no Windows regression. The
  round-88 commit `98f09cb` is RED: run 46039065088 completed
  2026-11-27T17:07:30Z with conclusion `failure` — job `test`
  failed at step `Run npm test` (setup, checkout, setup-node
  all success). The failing test name is not retrievable
  from the lab without repo-admin log access (log download
  returns 403), so no fix was attempted — a blind fix is not
  a fix. A bounded local investigation found no
  Windows-hostile construct in the round-88 change (no
  `os.EOL` / `path.sep` / `process.platform` use in the new
  detector or its tests; the win32 simulation passes
  833/0/16; the new CLI test follows the same temp-dir
  pattern as the round-87 CLI test, which passed on Windows
  in run 46034607189) — so the red run stays unexplained,
  not resolved: it may be a flake in a timing-sensitive
  pre-existing test or a genuine Windows-only issue
  invisible without the log. The red `933e0e7` run is now
  joined by a second unexplained red run on the same suite.
- F5's fourth real detector: `hardcoded-credential`
  (`src/detection/hardcoded-credential.js`, registered as the
  built-in `--detector hardcoded-credential` alongside `stub`,
  `secret-scan`, `dangerous-call`, and `insecure-crypto`; CLI
  help and `runDetect` comment updated). It scans the
  `content` string of an operator-supplied local input record
  for credential-named variables assigned a quoted string
  literal (password / passwd / pwd, API key names,
  secret/token names — `=`, `:=`, or `:` operators) and
  reports one finding per distinct assignment site in one
  class — use of hard-coded credentials (CWE-798, high) —
  confidence `potential`, never executing the code it scans.
  No network, no scanner, no target; the detector only ever
  sees text the operator hands it. Safety properties, all
  tested: a finding NEVER carries the literal value — the
  matched assignment is rebuilt as `<name><operator> "****"`
  (fixed four asterisks, no length information) before any
  finding is built, so no layer can leak it, and the
  finding_id hashes the masked match, not the secret;
  `finding_id` is deterministic
  (`hardcoded-credential-` + SHA-256 of pattern + line +
  column + masked match, first 16 hex); one finding per
  assignment site; at most 100 findings per record with the
  truncation recorded in `errors`, never silent; content
  over 1,000,000 characters is skipped; a record without
  usable content is counted in `skipped`, never thrown;
  batch records follow the stub convention (batch `tool`
  forced as `discovery_tool`). The detect → validate →
  dedupe → report pipeline is proven end to end by test
  (findings validate as `valid` under the generic checklist
  — the class has no dedicated checklist — and the JSON and
  Markdown reports were both tested to contain no assigned
  literal). 15 new tests
  (`tests/hardcoded-credential.test.js`); see
  `docs/detection-hardcoded-credential-v1.md`. SKILL.md's
  detector paragraph now names `hardcoded-credential` as the
  fourth real detector (both copies, still 150 lines, `cmp`
  passes); the open decisions (which further detectors,
  auto-run, async) are unchanged.

### First real detector: secret-scan over local text (round 86, 2026-11-27)

- Windows run verdict for the round-85 commit `82d68d4`
  (round 86, part 1): run 45884755893 completed
  2026-11-26T19:36:10Z with conclusion `success` — job `test`
  success, every step success including `Run npm test`. This is
  the second green Windows run in the project's history (after
  run 45881977604 for `d2d1991`) and the first green run for
  the round-85 commit itself, so the round-85 ENOENT change
  causes no Windows regression. The red `933e0e7` run is now
  sandwiched between two green runs on the same suite, which
  strengthens the flake hypothesis — but the failing test name
  is still unknown (log download 403), so the red run stays
  unexplained, not resolved, and no fix was attempted. A green
  run proves no regression, not that the new ENOENT branches
  fired: they only fire on Windows when a state path goes
  through a file, which the suite does not exercise.
- F5's first real detector: `secret-scan`
  (`src/detection/secret-scan.js`, registered as the built-in
  `--detector secret-scan` alongside `stub`; CLI help and
  `runDetect` comment updated). It scans the `content` string
  of an operator-supplied local input record for five strict
  fixed-format credential patterns (AWS access key ID, GitHub
  classic and fine-grained tokens, Slack tokens, private-key
  PEM headers) and reports one finding per distinct secret in
  the `information disclosure` class (`severity: high`,
  `cwe_id: CWE-200`, confidence `potential` — it never checks
  whether a credential is live, because it never contacts any
  service). No network, no scanner, no target; the detector
  only ever sees text the operator hands it. Safety properties,
  all tested: a finding never contains the full matched secret
  (proof of concept and evidence carry first 4 + `****` +
  last 4; the PEM header is not secret material and is carried
  verbatim); `finding_id` is deterministic
  (`secret-scan-` + SHA-256 of pattern + value, first 16 hex);
  one finding per distinct (pattern, value) with the first
  occurrence line; at most 100 findings per record with the
  truncation recorded in `errors`, never silent; content over
  1,000,000 characters is skipped; a record without usable
  content is counted in `skipped`, never thrown; batch records
  follow the stub convention (batch `tool` forced as
  `discovery_tool`). The detect → validate → dedupe → report
  pipeline is proven end to end by test (findings validate as
  `needs_evidence` — the checklist also requires a
  `response_log` — and the JSON report carries the
  `information disclosure` evidence checklist). 16 new tests
  (`tests/secret-scan.test.js`); see
  `docs/detection-secret-scan-v1.md`. SKILL.md's detector
  paragraph now names `secret-scan` as the first real detector
  (both copies, still 150 lines, `cmp` passes); the open
  decisions (which further detectors, auto-run, async) are
  unchanged.
- Phase movement: F5 ~20% → ~35% (the interface plus the
  first working detector, CLI wiring, docs, and tests; more
  detectors and the auto-run/async decisions remain). All
  other phases unchanged.

### ENOENT-through-a-file: same taxonomy for every state reader (round 85, 2026-11-27)

- Round 83 fixed the ENOENT-through-a-file case at one call site
  (token-digest read). This round applies the same fix everywhere
  a state read treats ENOENT as "missing": on Windows a path
  through a file is reported as ENOENT, not ENOTDIR, so a
  broken path was previously misread as "no state yet". New
  module `src/policy/storage-errors.js` (round 85) now holds
  `classifyStateReadError()` (token-digest + kill-switch reads),
  `classifyTokenFileError()` (rotate/revoke-token), and the
  shared probe `hasNonDirectoryAncestor()` — walk ancestors
  with `lstat`; a file ancestor means the path is invalid, a
  missing ancestor is ignored, `EACCES`/`EPERM`/`ELOOP` abort
  the walk and return `false` (fail-closed: keep the original
  error). The probe is a property of the path, not of the
  error: the same ENOENT can mean "genuinely missing" on one
  machine and "invalid path" on another.
- Wired to every reader that assumed ENOENT means missing:
  `PersistentKillSwitch` (load + snapshotLockless),
  `collectAudit` (operator status), `auditStatePermissions`
  (throws `STATE_PERMISSION_PATH_INVALID`), the install
  verifier (CLI entrypoint, kill-switch, audit log, scope
  config checks — a file parent now fails the check instead
  of passing it as "nothing there yet"), `state-backup`
  (`BACKUP_STATE_INVALID` / `BACKUP_CORRUPT`) and
  `state-export` (`STATE_EXPORT_STATE_INVALID` instead of
  silently returning the empty default state), and the CLI
  itself (`bin/sentinel.js`): `auditHealthWithStateReserve`
  now reports `KILL_SWITCH_STATE_PATH_INVALID` instead of
  falling through as "no state file yet", and the
  token-rotation lock / metadata / removal paths report
  `RESET_TOKEN_ROTATION_PATH_INVALID`. Existing codes are
  reused; no new error code was invented. `verify-install`
  still passes 7/7.
- One regression test added (`tests/storage-errors.test.js`):
  synthetic Windows-style ENOENTs plus `ENOENT` with a real
  file ancestor. The new ENOENT branches are only reachable
  on Windows through real filesystem calls (on Linux a path
  through a file yields ENOTDIR, which the existing branches
  already map), so the Linux suite proves they do not change
  genuinely-missing behavior, not that they fire — the
  Windows run is the proof for that, same as round 83.
  Linux suite: 802 tests (801 + 1), 798 pass, 0 fail, 4
  skipped (win32-only); win32 simulation 786 pass, 0 fail,
  16 skipped. The audit-log EACCES probe test now also copies
  `storage-errors.js` into its scratch skill tree.
- Windows run verdict for the round-84 commit `933e0e7`
  (round 85, part 1): run 45882467549 completed
  2026-11-26T23:31:34Z with conclusion `failure` — job `test`
  failed, step `Run npm test` exit 1 after ~48 s. The failing
  test name is not visible through the API (log download 403),
  so no fix was attempted and none was guessed; the local
  suite is green 3x on the same commit, so this is either a
  Windows-only failure or a flake. The second consecutive
  green run was NOT recorded — there is no second green run.
  The evidence needed is the failing test name from the run
  log (user's admin access, when awake). No phase movement:
  audit found no other decision-free lab-local polish gap
  (see the round-85 capability report for the full audit).

### First green Windows run: the round-83 fixes are confirmed (round 84, 2026-11-27)

- The first `windows-test` run after round 83 (run 45881977604,
  head `d2d1991`, 2026-11-26T19:13:08Z) completed with
  conclusion `success` — job `test` success, every step success
  including `Run npm test` (~39 s). This is the first green
  Windows run in the project's history; the workflow had failed
  on every run since round 28 (53/53 before round 81, then the
  runs for `bcc3037` and `0897b2e`).
- The ten run-54 fixes from round 83 are therefore confirmed on
  a real Windows runner, not just by local simulation: (1)
  `redact()` no longer runs `new URL()` on Windows paths;
  (2) drill polite-cancel via IPC `cancel` on win32; (3)
  digest-read ENOENT walks ancestors and reports
  `RESET_TOKEN_FILE_PATH_INVALID` when a parent is a file;
  (4) the pending-promise scanner normalizes paths to
  forward slashes; (5) `checkTool` has a default command
  runner, so `sentinel status` now reports the real tool
  count. The `tests/windows-platform.test.js` win32-only
  tests, skipped on POSIX, are verified by this run itself.
- Safe status changes with this run: the "implemented but not
  proven to pass on Windows" caveat from rounds 81–83 is
  retired for these fixes. It is not a phase move — no new
  capability was built and no blocked decision was taken in
  this round (docs-only, +2 files). The remaining blockers
  are unchanged: `asset_url` scrub, F5 real detectors, F6
  policies, release tagging, and the local-lab rule.
- Linux suite stays green alongside: 801 tests, 797 pass,
  0 fail, 4 skipped (win32-only), `verify-install` 7/7.

### Fix the 10 Windows run-54 failures by name (round 83, 2026-11-27)

- The user uploaded the run-54 log archive, so all ten failing test
  names are known for the first time. Each is a genuine
  Windows-vs-Linux difference, none of them the POSIX mode bits
  round 81 fixed: (1) audit-log `redact()` ran `new URL()` on every
  string, and a Windows path `C:\...` parses as URL scheme `c`,
  whose `toString()` lowercases the drive letter — URL parsing is
  now gated on `scheme://`, credentials in real URLs are still
  stripped; (2-5) the drill's polite cancel was SIGTERM, which
  Windows cannot deliver to a handler (TerminateProcess kills
  outright), so the stubborn worker died on the polite step and the
  escalation check failed — the polite step is now an IPC `cancel`
  message on win32, SIGTERM unchanged on POSIX, SIGKILL escalation
  unchanged on both; (6-7) a path through a file yields ENOENT on
  Windows, not ENOTDIR, so rotate/revoke degraded to
  "unauthorized" — an ENOENT digest read now walks the ancestors
  and reports `RESET_TOKEN_FILE_PATH_INVALID` when a parent is a
  file; (8-9) the pending-promise scanner compared
  `path.relative` output (backslashes on Windows) against the
  forward-slash allowlist — relative paths are now normalized to
  forward slashes; (10) `sentinel status` always reported 0 tools
  available because `probeTools` called `checkTool` with no command
  runner and `checkTool` had no default — the runner now defaults
  to the real one (masked on Linux, where no documented tools are
  installed; exposed on Windows, where docker is installed).
- Linux mode assertions stay strict (0600/0700); no new platform
  skip was added. Safe status until a Windows run passes: the fix
  is implemented but not proven to pass on Windows.

### Windows run 54 verdict: round-81 fix not proven green (round 82, 2026-11-27)

- The first `windows-test` run after round 81 (run 54, head
  `bcc3037`, 2026-11-26T18:38:39Z) completed with conclusion
  `failure` — the `Run npm test` step failed with exit code 1
  after a near-full-duration run, the same shape as the 53
  runs before it. The POSIX-mode diagnosis from round 81
  therefore did not turn the run green. Safe status until a
  Windows run passes: the fix is implemented but not proven
  to pass on Windows.
- The failing test name is still not visible from the lab:
  the jobs API names only the failed step (`Run npm test`),
  and the check-run carries no output and a single
  annotation ("Process completed with exit code 1"). The run
  log download still needs admin access, and no fix was
  guessed from the verdict alone — per the user's rule for
  this round, an unreadable failing test name means stop,
  not speculate.
- Checked locally and cleared as a cause of the branching
  logic: a one-off platform simulation (a `--require`
  preload that reports `process.platform === 'win32'` so
  the suite's win32 branches and skips engage) ran the
  full suite green — 780 pass, 0 fail, 16 skipped. That is
  NOT proof the real Windows run passes: the simulation
  cannot reproduce OS-level Windows behavior (real `chmod`
  no-ops, real `0666`/`0777` mode bits, real path
  separators in the OS, real symlink privileges), so it
  only proves the branching logic, not the run.
- No code changed in this round and no test was loosened:
  the Linux `0600`/`0700` assertions stay strict, and no
  new platform skip or exception was added. What changed
  is the record only: this entry and a status paragraph
  in `docs/state-permissions-v1.md`. The next step is
  named, not taken: the failing test name is readable
  only from the Windows run log, which needs the user's
  admin access.

### Windows CI failure investigated and fixed (round 81, 2026-11-27)

- The `windows-test` workflow failed on all 53 runs since round
  28, always in the `npm test` step. The cause: the suite
  asserted POSIX permission bits (`stat().mode & 0o777 ===
  0o600` for files, `0o700` for directories) in ~20 places,
  and the whole round-45 permission layer encodes them
  end to end. On Windows those bits do not exist — Node
  reports every file as `0666` and every directory as `0777`,
  and `fs.chmod` is a no-op except for the read-only bit —
  so the assertions could never pass there. No other certain
  cause was found: POSIX shell commands, `mount`/`umount`,
  and the nobody probes were already skipped or
  platform-aware on `win32`, and no test concatenates paths
  with `'/'`.
- `src/policy/state-permissions.js` now knows the platform
  boundary in one place: `posixModesApply()` (`platform !==
  'win32'`). The audit skips mode checks on Windows
  (`posixModes: false` in the result) but still refuses
  symlinks and special files; repair therefore never reports
  a tightening it did not perform; `verify-install` passes
  the state-permissions check for a normal Windows state
  directory (its PASS message says POSIX modes do not apply
  there). The privacy guarantee on Windows is the OS ACL,
  which Node cannot observe — documented in
  `docs/state-permissions-v1.md`, not hidden.
- Tests assert modes through the new
  `tests/helpers/private-mode.js` (exact bits on POSIX;
  existence + entry kind on Windows). The mode-behavior
  tests in `tests/state-permissions.test.js` are skipped on
  Windows; `tests/windows-platform.test.js` pins the Windows
  behavior (skipped on POSIX — verified by the Windows CI
  run itself). Symlink-creation sites in four test files now
  skip instead of failing when the platform refuses to create
  a symlink (the `backup-restore.test.js` precedent). A new
  `.gitattributes` pins LF endings on checkout (defense
  against CRLF; the docs tests trim lines, so this is
  hardening, not a proven cause). SKILL.md gains one
  sentence noting the Windows exception to the permission
  standard.
- Honest limit: the exact failing test names on Windows were
  never readable from the lab (log download needs admin
  access), and there is no local Windows machine — the fix
  rests on documented Node behavior plus the 53/53 failure
  record, not on a reproduced Windows run. If the Windows
  run still fails after this round, the log will name the
  next cause.

### Report generated_at fallback unified (round 80, 2026-11-26)

- `generateReport`'s own `generated_at` fallback (newest finding
  `created_at` when `options.generatedAt` is absent) now calls
  the shared `pickGeneratedAt` helper with an empty reports
  array (`pickGeneratedAt([], findings)`) instead of its own
  lexical `.sort()` over `created_at`. The round-73 claim that
  the two orderings were "equivalent for valid ISO strings"
  was wrong on probe: a lexical sort and a `Date.parse` sort
  disagree on mixed timezone offsets (`2026-01-01T23:00:00-02:00`
  is 2026-01-02T01:00:00Z but sorts lexically before
  `2026-01-02T00:30:00Z`), non-padded dates (`2026-1-1`
  sorts lexically after `2026-01-02T00:00:00Z`), and two
  representations of the same instant (lexical order picks by
  string shape; `Date.parse` ties sort stably, so input order
  wins). `validateFinding` never checks `created_at`'s format
  (it is not a required field), so such values genuinely
  reach the fallback. The new behavior is the chronological
  one in all three cases; for same-format ISO inputs the
  output is byte-identical (sha256 goldens pinned on the
  pre-refactor code). This closes the last polish item from
  round 73's F5; the only remaining open item from the
  report rounds is the `asset_url` scrub decision, which
  needs the user.

### Report stats error findings (round 79, 2026-11-26)

- `sentinel report stats` now excludes findings with verdict
  `error` from every breakdown: their declared severity,
  CVSS score, class, and asset are not trusted, so they
  contribute to no severity bucket, no CVSS distribution, no
  class count, and no top-asset count. They are still counted
  in `total` and in the verdict counts, and are named by a new
  `error_findings` line in text (`Error findings: N (not
  counted in severity, CVSS, class, or top assets)`) and key
  in `--json` — present only when greater than zero, so
  generator-produced output stays byte-identical. Interaction
  with round 77's `invalid_severity`: the two are independent,
  not a partition — `invalid_severity` counts
  invalid/missing-severity findings regardless of verdict,
  `error_findings` counts verdict-`error` findings regardless
  of severity validity; every invalid-severity finding is
  `error`, so `invalid_severity` is always a subset of
  `error_findings`. The severity buckets sum to `total` minus
  `error_findings`. This closes the last breakdown-pollution
  item from round 74's F5. One consequence: the `unknown`
  class is unreachable through stats (any finding that would
  map to it is an `error` finding); `classOf` still returns
  `unknown` for direct callers. The summary line is unchanged
  (the generator's wording counts declared valid severity,
  error findings included) — on a hand-edited file it can name
  more criticals than the Severity line shows, and the Error
  findings line explains why. Two pre-existing tests were
  updated for the deliberate behavior change (the
  band-mismatch test, which used to pin the declared severity
  being counted, and the blank-type/missing-asset test, whose
  fixtures are `error` findings); generator-produced goldens
  (FIVE, empty, FIVE+FP, md/json) are unchanged.

### Report stats class resolution (round 78, 2026-11-26)

- `sentinel report stats` now resolves each finding's class
  through the validator's evidence-class resolution
  (`resolveEvidenceClass` over
  `knowledge/evidence-checklists.json`, 15 classes): aliases
  and prefixed spellings of one class merge into its
  canonical id — `SQLi` and `Blind SQL Injection` count as
  `sql injection`, `auth bypass via JWT` counts as
  `authentication bypass` by file-order precedence — while a
  spelling no class matches falls back to the normalized raw
  string and a missing or blank type still counts as
  `unknown`. The resolution needs no evidence (it matches the
  type string alone). This closes the raw-string limitation
  from round 74's F5. No existing golden moved
  (generator-produced fixtures spell their classes in full,
  which already equals the canonical id); the generator's
  md/json goldens are unchanged. One documented gap: the
  matcher does not normalize hyphens, so `sql-injection`
  matches neither `sql injection` nor `sqli` and stays its
  own class.

### Report stats reconciliation (round 77, 2026-11-26)

- `sentinel report stats` now reconciles the executive
  summary's number with `total` on hand-edited files: the
  summary counts only findings with a valid severity, while
  `total` counts every finding, so the two could diverge
  with no explanation (round 74 F5). The gap is now named
  `invalid_severity` (findings with an invalid or missing
  severity — also in the `error` verdict bucket) and carried
  in both renderers, but only when greater than zero: the
  text Total line reads `Total: N findings (M counted in
  summary, K invalid severity)`, and `--json` gains the
  `invalid_severity` key after `total`. Generator-produced
  output is byte-identical (no key, no parenthetical when
  the gap is zero). No other command changed; the
  generator's md/json goldens are unchanged.

### Docs cross-reference audit (round 76, 2026-11-26)

- Docs-only round: audited every documentation cross-reference
  and fixed the drift found — 7 doc links missing from the
  SKILL.md report-paragraph See-list (`reporting-v1`,
  `report-templates-v1`, `report-filter-v1`, `report-stats-v1`,
  `report-helpers-export-v1`, `report-generated-at-helper-v1`,
  `cvss-vector-v1`), 2 from the detect-paragraph See
  (`detection-stub-v1`, `validation-v1`), 2 from the
  scope-paragraph See (`scope-manager-v1`,
  `scope-explain-v1`), 5 from the foundation paragraph
  (`request-governor-v1`, `approval-gate-v1`,
  `controlled-wrapper-v1`, `kill-switch-v1`,
  `persistent-kill-switch-v1`), and 10 usage lines missing
  from the SKILL.md command code block (`drill`,
  `verify-install`, `report-diff`, and the 7 `report`
  subcommands) plus the stale `sentinel report` lines, which
  lacked `[--allow-mixed-targets] [--verifier stub|<path>]`.
  The code block now lists exactly the 32 CLI help usage
  lines. No command behavior or output changed. New guard
  test `tests/docs-crossref.test.js` (8 tests) pins the
  cross-references: docs index completeness, README-to-index
  link, report docs in SKILL.md, report subcommands in
  SKILL.md, code block vs CLI help, resolvable doc
  references, real flags in docs usage spans, and a
  SKILL.md-anchor-or-allowlist rule for every doc (14 docs
  deliberately unanchored, with reasons). Full audit in
  `docs/report-docs-audit-v1.md`.

### Report render command (round 75, 2026-11-26)

- New command `sentinel report render <report.json>
  --format markdown|json|html|csv|summary|jsonl [--out <file>]`:
  re-renders an existing JSON report file into another format
  through the generator's own render path, so the output is
  byte-identical to what the generator would have produced for
  the same finding set (same report_id derivation, same
  grouping, same counts). The source report's `generated_at`
  is carried through via the shared `pickGeneratedAt` helper
  (round 73) — never re-stamped; JSON output with no
  timestamp anywhere fails with
  `REPORT_RENDER_NO_GENERATED_AT`. A platform-template source
  is refused (`REPORT_RENDER_TEMPLATE_REFUSED`); a
  mixed-target source renders only when it declares
  `mixed_targets` (a hand-edited second target without the
  declaration is refused with
  `REPORT_MIXED_TARGETS_REFUSED`); transformation metadata
  blocks (`split`/`filter`/`anonymization`) are not carried
  through. The rendered report goes to stdout (pipeable) or
  `--out` (mode 0600), the one-line summary (`rendered N
  findings as <format> from <report-id>`) to stderr; read-only
  on the input. 26 new tests, including byte-identical
  re-renders in all six formats, the generated_at
  carry-through and fallback, template refusal,
  mixed-target render + refusal, and the CLI contract
  (stdout/stderr, --out mode 0600, input untouched, symlink
  refused).

### Report stats command (round 74, 2026-11-26)

- New command `sentinel report stats <report.json> [--json]`:
  a compact triage summary of one JSON report — total, counts
  by severity (generator's exported `countBySeverity`), counts
  by rule verdict from round 67's `validateOneFinding` (valid /
  false_positive / needs_evidence, plus an `error` bucket for
  findings failing the strict check), counts by class (the
  finding's `vulnerability_type`, normalized trim + lowercase,
  missing or blank counts as `unknown`), the CVSS distribution
  (scored vs unscored, min / max / mean over scored only, mean
  rounded to 2 decimals), the top 5 assets by finding count
  (count desc, ties by `asset_id`), and the generator's
  executive summary line. Exit 0 whenever the file parses —
  stats is a summary view, not a verdict, so even an
  all-false-positive report or a report full of `error`
  findings exits 0; shape failures carry `REPORT_DIFF_*`
  codes (the round-64 shared reader); read-only, no writing.
  22 new tests, including hand-computed goldens for a 5-finding
  set (text + JSON) and a 6-finding set with the false-positive
  fixture, the top-5 cap with tie-breaking, the empty report,
  determinism across input orders, and the md/json goldens
  unchanged.

### Shared `pickGeneratedAt` helper (round 73, 2026-11-26)

- Pure refactor, no new command and no output change:
  `pickGeneratedAt(reports, findings)` is now exported from
  `src/report/generator.js` (newest valid `generated_at` among
  the source reports, else newest finding `created_at`, else
  null, never the wall clock), and all four call sites —
  filter, split, merge (both inputs), anonymize — call it
  instead of their own copies, each keeping its own named
  error on null (`REPORT_FILTER/SPLIT/MERGE/ANONYMIZE_NO_GENERATED_AT`).
  Corrects round 72: the duplication was a quadruple, not a
  triple — `anonymize.js` carried a fourth copy the round-72
  audit missed. 9 golden sha256 pins prove the four commands'
  byte output is unchanged; 7 direct contract tests cover the
  helper. `generateReport`'s own fallback and
  `deriveExpectedReportId` deliberately left independent.

### Shared report-summary helpers exported (round 72, 2026-11-26)

- Pure refactor, no new command and no output change:
  `executiveSummary` is now exported from
  `src/report/generator.js` (alongside the already-exported
  `countBySeverity`), and the empty report built by
  `sentinel report filter` calls the helpers instead of
  hand-replicating the summary wording and the zero-counts
  object (round 71 F5). A byte-identical golden pins the
  empty report's bytes, and an anti-divergence test asserts
  the empty report's summary/counts equal
  `executiveSummary(countBySeverity([]), programName)` /
  `countBySeverity([])`, so a future generator wording change
  propagates automatically. Audit of the other report
  commands: JSONL and summary already reuse the exported
  helpers; `deriveExpectedReportId` is deliberately left an
  independent re-implementation (validate must check the
  generator, not call it); the `pickGeneratedAt` triple in
  filter/split/merge is found and deferred to a future round
  (the three copies differ in semantics and error codes).

### Report filter command (round 71, 2026-11-26)

- `sentinel report filter <report.json> [--severity
  <level>] [--verdict <rule-verdict>] [--out
  <filtered.json>]` keeps a threshold subset of one JSON
  report as one valid round-31 JSON report — `--severity`
  keeps findings at or above that level (matched
  case-insensitively), `--verdict` keeps findings whose
  RULE verdict from round 67's `validateOneFinding` (valid
  / false_positive / needs_evidence) equals the given
  value, NOT the stored `validation_status` workflow state
  (which would keep everything or nothing on
  generator-produced reports); at least one predicate is
  required (`REPORT_FILTER_NO_PREDICATE`), both AND
  together. The output is rendered by `generateReport`
  itself with its own recomputed report id (the generator's
  own derivation for the kept subset) and a `filter`
  metadata block (`from_report_id`, plus only the predicates
  given), and each output passes `report validate` cleanly
  with `report_id_matches: true`. An empty result is a
  valid empty report (total 0), not an error — built
  following `renderJson`'s shape since `generateReport`
  refuses an empty finding set for JSON. The filtered JSON
  goes to stdout (pipeable) or `--out` (mode 0600) with the
  one-line summary (`filtered K of N findings (severity >=
  high, verdict valid)`) on stderr. The input file is never
  modified. Docs, SKILL.md (both copies, `cmp` verified),
  and README updated.

### Report split command (round 70, 2026-11-26)

- `sentinel report split <report.json> --by
  severity|verdict --out-dir <dir> [--force]` splits one
  JSON report into one valid round-31 JSON report per
  non-empty group — one file per severity (critical / high
  / medium / low / informational) or per rule verdict
  (valid / false_positive / needs_evidence, from round
  67's `validateOneFinding`, NOT the stored
  `validation_status` workflow state, which carries
  detected / needs_review / validated / false_positive /
  duplicate / rejected and would put every
  generator-produced finding in one "validated" group).
  Each file is named `<report-id>-<group>.json` with its
  own recomputed report id (the generator's own
  derivation for that subset) and a `split` metadata
  block (`from_report_id`, `group_by`, `group`), and each
  passes `report validate` cleanly. Empty groups are not
  written. `--out-dir` is created mode 0700, refused when
  non-empty unless `--force` (which only overwrites the
  files this split writes), and refused inside the skill
  directory or the state directory. stdout lists only the
  written paths, one per line; the per-group summary
  lines go to stderr. The input file is never modified.
  Docs, SKILL.md (both copies, `cmp` verified), and
  README updated.

### Report anonymize command (round 69, 2026-11-26)

- `sentinel report anonymize <report.json>
  [--out <anon.json>] [--salt <hex>]` strips internal
  identifiers from a JSON report so it can be shared:
  `target_id`, `session_id`, and every finding's `asset_id`
  map to deterministic `anon-<sha256(salt + ':' +
  original).slice(0, 12)>` values (default salt is the
  fixed public constant `sentinel-report-anonymize-v1`; a
  provided salt must be hex, 8–64 chars, and is never
  printed anywhere — not in the output, the summary line,
  or an error message), and internal hostnames/IPs in
  `description` and evidence `notes` are scrubbed (IPv4
  dotted quads -> `anon-ip`, hostnames ending
  `.local`/`.internal` -> `anon-host`, nothing else).
  Severity, CVSS, verdict, checklist, `ai_verdict`,
  `finding_id`s, and finding order are preserved; the
  output is re-rendered by `generateReport` itself, so the
  `report_id` is unchanged by design (it derives from
  `program_name` + finding ids, which anonymization
  preserves) and the output passes `report validate`
  cleanly with `report_id_matches: true`; it carries
  `anonymized: true` plus an `anonymization` metadata
  block (`salt_source`, `patterns`, never the salt). The
  anonymized JSON goes to stdout (pipeable) or `--out`
  (mode 0600), with the one-line summary (`anonymized N
  findings (I identifiers replaced, S text
  substitutions)`) on stderr. This is de-identification
  for sharing, NOT cryptographic redaction — anyone
  holding the original report and the salt can reverse
  the mapping — and `asset_url`, `request`/`response`
  logs, `title`, `impact`, `remediation`,
  `steps_to_reproduce`, `proof_of_concept`, and
  `references` are NOT scrubbed (the `asset_url` gap is a
  known limitation, pinned by a test). Docs, SKILL.md
  (both copies, `cmp` verified), and README updated.

### Report merge command (round 68, 2026-11-26)

- `sentinel report merge <a-report.json> <b-report.json>
  [--out <merged.json>]` combines two JSON reports into one
  valid round-31 JSON report: identical findings (after
  canonicalization — keys sorted recursively, `merged_from`
  sorted as an id set) kept once, disjoint findings unioned, a
  same-id finding with different content fails with
  `REPORT_MERGE_CONFLICTING_FINDING` naming the id and the
  first differing field, both inputs must agree on
  `program_name` (`REPORT_MERGE_PROGRAM_MISMATCH`), differing
  targets merge as `target_ids` + `mixed_targets: true` (the
  round-49 convention; the merge itself is the opt-in), and
  every finding is checked with round 67's strict-check path
  (`REPORT_MERGE_INVALID_FINDING`). The merged report is
  rendered by `generateReport` itself (its report id is the
  generator's own derivation; a test pins the merged output
  byte-identical to a direct render of the same set);
  `generated_at` is the newer input value, else the newest
  finding `created_at`, else `REPORT_MERGE_NO_GENERATED_AT`.
  The merged JSON goes to stdout (pipeable) or `--out` (mode
  0600); the one-line summary (`merged N findings from A + B
  (X shared, 0 conflicts)`) goes to stderr. Docs, SKILL.md
  (both copies, `cmp` verified), and README updated.

### Report validation command (round 67, 2026-11-26)

- `sentinel report validate <report.json> [--json]` checks a JSON
  report file before the operator trusts it: shape (non-empty
  `report_id`, `findings` array, bounded at 10,000, duplicate
  `finding_id`s refused, symlinked input refused), per-finding
  strict generator check (required fields, severity band, CVSS
  vector/score agreement — a failure is an `error`) plus the
  rule-based verdict (`valid` / `false_positive` /
  `needs_evidence`, counted but never failing), and the report-id
  recomputation (SHA-256 of program + sorted finding ids, the
  same derivation as the generator; a mismatch is a warning, not
  a failure — the file may come from an older generator
  version). Exit 0 when the file parses and every finding
  validates; exit 1 only on structural errors and band
  mismatches. Text and JSON output are deterministic
  (per-finding entries sorted by `finding_id`); validate is
  read-only (a test proves the input file byte-identical
  afterwards). Docs, SKILL.md (both copies, `cmp` verified),
  and README updated.

### Streaming JSONL report export (round 66, 2026-11-26)

- `sentinel report --format jsonl` renders one JSON object per
  line: a summary line first (`type: "report-summary"`,
  `report_id`, `total`, `counts_by_severity`,
  `counts_by_verdict` over `validation_status`, `target_id`,
  `session_id`, plus `target_ids` + `mixed_targets` for opt-in
  multi-target reports), then one finding per line in the same
  grouped order as the flat JSON `findings` array, each line the
  same shape as the JSON format's finding entries (finding object
  plus `evidence_checklist`, plus advisory `ai_verdict` when a
  verifier ran). Deterministic across input orders; no
  `--generated-at` needed (output identical with and without it);
  an empty set renders the summary line only (total 0), not an
  error. Template + jsonl refused like the other text formats;
  `--json` refused as an unknown option (jsonl is its own
  format); mixed-target rules unchanged. Counts are reused from
  the shared helpers (`countBySeverity`,
  `countByVerdict`), never re-implemented. Docs, SKILL.md (both
  copies, `cmp` verified), and README updated. Two deliberate
  test-expectation changes: the unknown-format error now lists six
  formats, so the round-55 and round-61 assertions were updated
  to the new message.

### Three more evidence checklists (round 65, 2026-11-26)

- Per-class evidence checklists grow from twelve classes to fifteen
  (`knowledge/evidence-checklists.json`, no code change):
  clickjacking (`response_log` — the framing response showing the
  page rendered inside a foreign frame with no X-Frame-Options or
  CSP frame-ancestors), open redirect (`request_log` +
  `response_log` — the redirect parameter and the Location header
  returned), and JSON Web Token weakness (`evidence_notes` — the
  forged or unsigned token and the response accepting it; the
  finding schema has no dedicated token field, the same limitation
  as reentrancy's trace). CVSS scores for the three new full
  fixtures are hand-computed from the FIRST 3.1 formula and
  cross-checked against the repo scorer (clickjacking 5.4 medium,
  open redirect 6.1 medium, JWT 9.8 critical). Matching is
  unchanged (first match in file order wins); the three new
  classes sit last, so every earlier class wins a tie — `auth
  bypass via JWT` stays authentication bypass, `Open Redirect via
  XSS` stays XSS, `Clickjacking via CSRF` stays CSRF, `JWT in SQL
  Injection` stays SQL injection. The round-31 `potential-full`
  fixture is an open redirect finding and now resolves to that
  class; the generic-fallback tests retarget a clone at `Missing
  Authentication` instead. Docs, SKILL.md (both copies, `cmp`
  verified), and README updated.

### Report diff between two runs (round 64, 2026-11-26)

- `sentinel report-diff <old-report.json> <new-report.json>
  [--format markdown|json] [--out <diff.md>]` compares two JSON
  reports from two runs: added / removed / changed findings,
  matched by `finding_id`, compared on severity / `cvss_score` /
  verdict (`validation_status`) / `asset_id` only. `merged_from`
  is provenance, not substance, so a `merged_from`-only
  difference is unchanged. Inputs are read bounded (10 MiB,
  depth 100) with a symlink refusal; shape errors are named
  (`REPORT_DIFF_INVALID_REPORT`, `REPORT_DIFF_INVALID_FINDING`,
  `REPORT_DIFF_DUPLICATE_FINDING_ID`,
  `REPORT_DIFF_SYMLINK_REFUSED`,
  `REPORT_DIFF_TOO_MANY_FINDINGS`) and fail before any output is
  produced. Added / removed entries are compact summaries, not
  full findings; the diff's own `report_id` is a hash of the two
  source report ids plus the sorted id lists, so the same pair of
  report sets renders byte-identically in both formats. An empty
  diff renders the counts line plus "No differences." The diff
  does not re-validate findings and never runs a verifier;
  `--template` is refused.

### Operator status overview (round 63, 2026-11-26)

- `sentinel status [--state-dir <path>] [--skill-dir <path>]
  [--json]` gives one strictly read-only overview of the whole
  operator state: kill-switch state (active/inactive, live-worker
  count, trigger when active, reset-token file presence — never
  the value), audit chain counts (total/verified/legacy/broken,
  anchor hash, first/last timestamps, prune-anchor count, first
  break reason), scope target counts, retention policy,
  verify-install pass/fail counts, and tool availability counts.
  Every read is lockless and creates nothing: the kill-switch is
  read with `snapshotLockless()` (no lock file, no mkdir, no lease
  pruning — stricter than `kill-switch status`, which takes the
  lock), the audit log is read with plain `readFile` and its chain
  replayed with the round-43/56 rules, and the scope store,
  retention policy, verify-install, and tool probes are all reads
  or local version-command spawns. A test proves it: state file
  contents AND mtimes, and the state directory's own mtime, are
  identical before and after a status run (module level and via
  the real CLI). Failure semantics: a corrupt/unreadable
  kill-switch state, audit-log storage failure, or damaged scope
  store fails the whole command (exit 1, JSON with the component
  named); audit content breaks and a damaged retention policy are
  reported inside their sections and the command still exits 0; a
  missing state directory is the empty view, not an error. The
  status object carries no wall-clock timestamp, so the same state
  renders byte-identically. New module
  `src/policy/operator-status.js` (15 tests: golden text + JSON,
  lockless-vs-locked chain cross-check, read-only proof, armed,
  empty, corrupt kill-switch/scope, corrupt audit content,
  damaged retention, token presence, direct-command count match,
  CLI text/JSON/unknown-option, CLI read-only proof) plus a guard
  test: the installed-copy root `SKILL.md` must be byte-identical
  to the canonical copy when present (skipped in a fresh clone,
  which has no root copy). That guard caught a real drift: the
  root copy had missed the round-62 retention command line and
  paragraph — re-copied in this round.

### Audit-log retention policy (round 62, 2026-11-26)

- `sentinel audit retention [--max-archives <n>] [--max-records
  <n>] [--show]` manages the operator's retention limits in
  `<state-dir>/audit-retention.json` (mode 0600, symlinks refused,
  schema v1; both limits optional, integers >= 1). Limits are
  enforced lazily at rotation: archives beyond `max_archives` are
  deleted and the oldest lines of the rotated-in active log are
  truncated to `max_records`. Every prune is RECORDED, not silent —
  an `AUDIT_LOG_PRUNED` anchor record (count, first/last
  timestamps, hash of the last pruned record, limits in force) is
  written to the new active log together with the incoming record
  in one atomic write, chained from the old tail, so
  `audit verify` still reports `verified: true` after a prune and
  `audit export` shows the anchor as a verified record. Setting a
  limit is refused while the kill-switch is armed
  (`AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE`) and writes an
  `AUDIT_RETENTION_SET` audit record. A corrupt policy file fails
  loudly on `--show`/set but never blocks audit appends (rotation
  reads it leniently). With `max_records = 1` the retained set
  bottoms out at anchor + incoming (2 records). New module
  `src/audit/audit-retention.js`; `AuditLog.append` gains the
  rotation-branch plan/enforce steps. Two bugs of this round's own
  caught by its tests before commit: the anchor was first prepended
  to the in-memory active log and lost when rotation renamed the
  on-disk file (fixed by writing anchor + incoming record to the
  new active log in one write), and the anchor was first stamped
  with the clock, making `recordedAt` non-monotonic along the chain
  (fixed by sharing the incoming record's timestamp). The round-39
  EACCES nobody probe now also copies `audit-retention.js`,
  `safe-write.js`, and `input-limits.js` into its scratch layout,
  and the `audit bogus` error message is back to
  `Unknown audit action: bogus` (a round-62 wording change broke
  the existing test's expectation).

### Compact summary report format (round 61, 2026-11-26)

- `sentinel report --format summary` renders a validated finding
  set as a one-page plain-text executive summary — report id,
  target/session, severity and verdict counts, highest severity,
  the top 10 findings (severity then finding_id, with a "+N more"
  line), the advisory AI-verdict count, and a pointer to the full
  report. Plain text by design (pasteable into chat/email/tickets);
  no `--generated-at` needed, like CSV. An empty finding set
  renders the zero-count summary with "No findings." instead of
  erroring. A platform template with summary output is refused
  (`Template "<name>" renders Markdown only; summary output uses
  the generic template.`); the report command has no `--json`
  flag, so a stray `--json` is refused as `Unknown option:
  --json`. The verdict counts are over the findings'
  `validation_status` values, not the validator's rule verdict
  enum (documented in `docs/report-summary-v1.md`). New renderer
  `src/report/summary.js`; `src/report/generator.js` dispatches
  to it (required lazily to avoid a require cycle over
  `SEVERITY_ORDER`). Markdown/JSON/HTML/CSV output byte-identical
  (golden hashes re-pinned).

### Bugcrowd report template (round 60, 2026-11-26)

- `sentinel report --template bugcrowd` renders one validated
  finding into Bugcrowd's section layout (Description, Steps to
  Reproduce, Impact, Recommended Fix, Supporting Material),
  mirroring round 59's HackerOne pattern. No code change was
  needed: the template is data only, a new JSON file in
  `knowledge/report-templates/`, loaded and shape-validated by
  the existing `src/report/templates.js` (only the CLI help text
  names the new template). A finding without `proof_of_concept`
  fails with a named error (required for "Steps to Reproduce");
  JSON output adds `"template": "bugcrowd"`. Honest limit: the
  section order and names follow Bugcrowd's standard report
  structure as commonly documented and were derived offline —
  the layout has NOT been verified against the live platform's
  submission form, so check it before sending a real submission
  (documented in `docs/report-templates-v1.md` and the
  template's own description). Immunefi/Code4rena/HackerOne
  outputs are byte-identical (golden hashes unmoved). Suite
  493 → 496 tests.

### HackerOne report template (round 59, 2026-11-26)

- `sentinel report --template hackerone` renders one validated
  finding into HackerOne's section layout (Vulnerability
  Description, Steps to Reproduce, Impact, Recommended Fix,
  Supporting Material), mirroring round 35's Immunefi/Code4rena
  pattern. No code change was needed: the template is data only,
  a new JSON file in `knowledge/report-templates/`, loaded and
  shape-validated by the existing `src/report/templates.js`.
  A finding without `proof_of_concept` fails with a named error
  (required for "Steps to Reproduce"); JSON output adds
  `"template": "hackerone"`. Honest limit: the section order and
  names follow HackerOne's standard report structure as commonly
  documented and were derived offline — the layout has NOT been
  verified against the live platform's submission form, so check
  it before sending a real submission (documented in
  `docs/report-templates-v1.md` and the template's own
  description). Immunefi/Code4rena outputs are byte-identical
  (golden hashes unmoved). Suite 490 → 493 tests.

### Portable state export (round 58, 2026-11-26)

- `sentinel state export [--state-dir <path>] [--out <file>]`
  produces one portable JSON envelope of the whole operator
  state — kill-switch state + scope targets + audit summary —
  with a SHA-256 `contentHash` over the canonical `contents`
  only (the timestamp is excluded, so the same state always
  yields the same hash). The kill-switch state is exported as
  stored (`{ version, active, trigger, workers }`); the state
  file carries no token value or reset-token digest, and a test
  asserts by construction that no exported key matches
  `token|secret|password|api-key`. The audit summary carries
  counts and timestamps from round 56's per-record verification,
  not the full log (which already has its own export). Missing
  state/store/log export as the empty state; a corrupt state
  file fails with `STATE_EXPORT_STATE_INVALID`, a symlinked
  state file or output with `STATE_EXPORT_SYMLINK_REFUSED`, and
  a damaged scope store fails the whole export rather than
  dropping a target. A broken audit chain still exports with
  exit 0 (`chainVerified: false`). EXPORT ONLY — no `state
  import` exists; importing foreign state is an open user
  decision. 14 new tests in `tests/state-export.test.js`, suite
  476 → 490.

### Four more per-class evidence checklists (round 57, 2026-11-26)

- `knowledge/evidence-checklists.json` now defines twelve
  vulnerability classes (was eight): XXE (`xml external entity`,
  aliases `xml external entity` / `xxe`, extra required
  `request_log` + `response_log`), insecure deserialization
  (aliases `insecure deserialization` / `deserialization`, extra
  required `evidence_notes`), path traversal (aliases `path
  traversal` / `directory traversal` / `traversal`, extra required
  `request_log` + `response_log`), and business logic flaw
  (aliases `business logic flaw` / `business logic` / `logic
  flaw` / `business-logic`, extra required `evidence_notes`).
  Each follows the round-40 pattern exactly (required items +
  recommended items + `match` aliases + a `why`); no validator
  code changed — the new classes are a knowledge-file edit, four
  fixtures, and tests. File order is precedence, so a type
  containing both an old alias and a new alias still resolves to
  the old class (proven: `SQL Injection via path traversal` stays
  SQL injection, `SSRF via XML` stays SSRF). 4 new tests in
  `tests/evidence-checklists.test.js`, suite 472 → 476.

### Verifiable audit export (round 56, 2026-11-26)

- `sentinel audit export [--state-dir <path>] [--out <file>]
  [--format json|jsonl]` dumps the whole retained audit trail —
  active log plus rotated archives, oldest first — with each
  record's hash-chain status attached (`verified` / `legacy` /
  `broken`, with the `AUDIT_CHAIN_*` reason for broken records)
  and a summary with per-status counts (`totalRecords`,
  `verifiedRecords`, `legacyRecords`, `brokenRecords`,
  `anchorHash`, `firstRecordedAt`, `lastRecordedAt`). The
  top-level `verified` boolean is true exactly when no record is
  broken. JSON renders one object
  `{ exportVersion: 1, verified, summary, records }`; JSONL renders
  one compact line per record plus a final summary line marked
  `{ "type": "audit-export-summary", … }` (record lines carry no
  `type` field). A broken chain is NOT a refusal — the export exits
  0 and shows exactly which records verify and which do not —
  unlike `audit verify`, which exits 4 on a broken chain. The
  export carries no timestamp, so the same log always renders
  byte-identically. `--out` writes mode `0600` and refuses a
  symlinked output path; an unknown `--format` fails before the log
  is touched. The per-record walk continues past breaks (a modified
  record flags only itself; its successor still verifies, checked
  against the modified record's stored hash). A garbage line becomes
  an error entry with its file and line and a `null` record, never
  silently dropped. The same honest limits as the chain itself
  apply (prefix/last-record deletion undetectable, full rewrite
  outside the mechanism), documented in
  `docs/audit-export-v1.md`. `verifyChain()` is unchanged (the
  entry-collection loop is now shared). 13 new tests in
  `tests/audit-export.test.js`, suite 459 → 472.

### Flat CSV report export (round 55, 2026-11-26)

- `sentinel report --format csv` renders the same validated,
  grouped findings as a flat export: one row per finding plus a
  header row, in the same grouped order as the flat JSON
  `findings` array (targets ascending, then asset groups
  ascending, findings inside a group by severity then
  `finding_id`). Columns, in fixed order: `finding_id`,
  `target_id`, `asset_id`, `severity`, `cvss_base_score`,
  `cvss_temporal_score`, `cvss_environmental_score`, `verdict`
  (the finding's `validation_status`), `evidence_checklist`
  (`present/total` plus missing items joined with `; `, or
  `(complete)`), `merged_from` (joined with `; `, empty for a
  singleton), `ai_verdict` (the advisory line, empty without a
  verifier). Scores are plain numbers; a missing score is an empty
  cell. No `generated_at` is needed, so CSV output never requires
  `--generated-at`.
- Every field is RFC 4180 escaped (`escapeCsvField` in
  `src/report/generator.js`): a field containing a double quote, a
  comma, or a line break is wrapped in double quotes with inner
  quotes doubled. Hostile values (`<script>`, `=cmd`, `+cmd`,
  `@cmd`) render verbatim as inert text — the file itself never
  executes anything — and the generator deliberately does not
  alter values to defuse them. Formula injection is a
  spreadsheet-consumer risk, documented in
  `docs/report-csv-v1.md`: open exports with data-import (cells
  as text) or in a text editor, never double-click a CSV whose
  findings may carry attacker-controlled strings.
- An empty finding set renders the header row only (exit 0);
  every other format still requires at least one finding. A
  platform template with `--format csv` is refused with the same
  named error as HTML (`Template "<name>" renders Markdown only;
  CSV output uses the generic template.`), for empty and
  non-empty sets alike. Mixed-target input without
  `--allow-mixed-targets` is refused with
  `REPORT_MIXED_TARGETS_REFUSED`; with the flag, rows render for
  all targets in ascending target order. Markdown and JSON output
  are unchanged: the round-43 golden hashes are re-pinned in
  `tests/report-csv.test.js` (15 new tests, suite 444 → 459).

### Scope list and overridable default excluded paths (round 54, 2026-11-26)

- `sentinel scope list [--state-dir <path>] [--store <file>] [--url
  <url>] [--json]` lists every target in the persistent store
  (`<state-dir>/scope-targets.json`), sorted by `target_id`, each with
  its validation status and a summary of the normalized target. Without
  `--url` there is no decision to report (`decision: null` in JSON,
  `—` in text) — a scope decision is a property of a (target, URL)
  pair, and inventing a probe URL would fabricate data; with `--url`,
  each valid target is evaluated with the same
  `evaluateTargetRequest` that `check-scope` uses. One invalid entry
  is reported as `valid: false` with its validation error instead of
  hiding the rest of the list; a damaged store *shape* still fails
  loudly (`SCOPE_STORE_CORRUPT` /
  `SCOPE_STORE_UNSUPPORTED_SCHEMA`), a symlinked store is refused
  (`SCOPE_STORE_SYMLINK_REFUSED`), and an invalid `--url` fails with
  `SCOPE_LIST_INVALID_URL`. JSON output is deterministic (same store
  twice, or written in the opposite order, lists byte-identically).
  The command is read-only, needs no kill-switch guard, and works
  while the switch is armed. An empty store prints `No scope targets
  in <store>.` and exits 0.
- A target file may now declare `default_excluded_paths` — a list
  that replaces the built-in default excluded paths
  (`DEFAULT_EXCLUDED_PATHS`: `/logout`, `/signout`, `/delete`,
  `/reset-password`, `/unsubscribe`) for that target only; an empty
  list means no default exclusions. Absent the field, the built-ins
  stand. An invalid value (non-array, or an entry that is not an
  absolute path) fails `normalizeTarget` loudly with no silent
  fallback; `scope add` of such a target fails with
  `SCOPE_TARGET_INVALID` and writes nothing. The decision object is
  unchanged; the `--explain` trail now cites the right source for a
  default-list denial (built-in vs. `target file:
  <file> (default_excluded_paths)`) and the suggestion names the
  override instead of the round-52 "cannot be un-excluded" wording
  (one round-52 test expectation was updated for the intentional
  policy change). `policies/scope-policy.md` section 4 records the
  override. Open items from round 53 are now both closed; what
  remains for Phase 3 is the Meta-side ceiling, not reachable by
  rounds.

### Scope target management (round 53, 2026-11-26)

- `sentinel scope add <target.json> [--state-dir <path>]` and
  `sentinel scope remove <target-id> [--state-dir <path>]` manage the
  persistent store `<state-dir>/scope-targets.json` (`{schema_version:
  1, targets: [...]}`; the store lives in the state directory, not
  the skill directory, so it survives reinstalls). Entries are the raw
  target objects as supplied and are re-validated with
  `normalizeTarget` on every load, so a damaged entry fails loudly
  instead of silently changing scope. The parent directory is created
  private (`0700`), the file is written `0600` with planted symlinks
  refused, and mutations run under an exclusive lock file
  (`scope-targets.json.lock`, 5 s timeout, 60 s stale reaper).
  Successful mutations write an audit record (`SCOPE_TARGET_ADDED` /
  `SCOPE_TARGET_REMOVED`); a mutation whose audit append fails exits
  4. Adding an already-present `target_id` is an idempotent no-op
  (exit 0, `added: false, alreadyPresent: true`, no rewrite, no audit
  record). Both commands refuse while the kill-switch is armed
  (`SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE`, exit 1, JSON result).
  `sentinel check-scope --store <scope-targets.json> --target-id <id>
  --url <url> [--explain] [--json]` resolves a stored target and
  evaluates it with the unchanged decision logic (`--store` and
  `--target` are mutually exclusive). Named errors:
  `SCOPE_TARGET_INVALID`, `SCOPE_TARGET_NOT_FOUND`,
  `SCOPE_STORE_CORRUPT`, `SCOPE_STORE_UNSUPPORTED_SCHEMA`,
  `SCOPE_STORE_SYMLINK_REFUSED`, `SCOPE_STORE_LOCKED`. The decision
  logic is unchanged and the plain `--target` path is byte-identical.
  Open items: no `scope list` yet; the built-in default excluded
  paths still cannot be overridden from the target file.

### Scope-decision explainability (round 52, 2026-11-26)

- `sentinel check-scope --target <target.json> --url <url> [--explain]
  [--json]` explains a scope decision: the ordered rule trail (which rule
  matched, from which policy source), the deciding rule, and a one-line
  suggestion for what would change the outcome. `--explain` prints a
  human-readable trail; `--explain --json` carries the same trail as
  structured data under `explanation` (rules with `evaluated` / `matched`
  / `outcome` / `source` / `detail` / `note`, `decidingRule`,
  `suggestion`, `source.targetFile`). Plain (non-explain) output is
  byte-identical to before this round. The six rules are evaluated in a
  fixed order (`TARGET_REGISTERED`, `URL_VALID`, `EXCLUDED_DOMAIN`,
  `ALLOWED_DOMAIN`, `EXCLUDED_PATH`, `IN_SCOPE`); the first rule whose
  condition holds decides and the rest are honestly marked
  `not evaluated`. Excluded-path matches cite the target file
  (`excluded_paths`) or the built-in default
  (`DEFAULT_EXCLUDED_PATHS`; `policies/scope-policy.md` section 4) —
  built-in defaults cannot be un-excluded from the target file, and the
  suggestion says so. The decision logic itself is unchanged:
  `explain().decision` is asserted identical to `evaluate()` across the
  full URL matrix. A corrupt or missing `--target` file fails before any
  trail is produced (`Invalid JSON in <path>` / `Cannot read <path>`,
  exit 1). Programmatic use: `TargetRegistry.explain(targetId, url, {
  targetFile })`, `evaluateTargetRequestWithTrail(target, url, source)`,
  `renderScopeExplanationText(explanation)`.

### Pluggable detector interface (round 51, 2026-11-26)

- The detector contract is defined (`src/detection/detector.js`):
  a SYNCHRONOUS function `detector(input, defaults) -> {
  findings, skipped, errors }` where `input` is a raw
  detector-input record (the shape `normalizeRawFinding()`
  accepts) or a batch record `{ tool, results: [...] }`, and the
  envelope carries normalized finding records (each re-normalized
  on validation, so a non-conformant finding is refused, not
  repaired), a non-negative integer `skipped` count, and an
  `errors` array of strings. A detector must not make network
  requests, write outside its return value, or invent data; a
  Promise return is refused (`DETECTOR_INVALID_RESULT`). The
  built-in stub detector is the reference implementation (it
  normalizes its input and nothing else; batch `tool` forced as
  `discovery_tool`; bad records counted in `skipped`). The shared
  batch normalizer `runDetectorOnRecords` is now used by both the
  stub detector and `runStubDetector` (round 31, behavior
  unchanged — verified by test). `loadDetector` loads a custom
  module only from inside the skill directory (same safety rules
  as the round-50 verifier loader: no symlinks, realpath inside
  the real skill root, export a function or an object with a
  `detect` function), with named refusals
  (`DETECTOR_NOT_FOUND`, `DETECTOR_SYMLINK_REFUSED`,
  `DETECTOR_PATH_OUTSIDE_SKILL`, `DETECTOR_INVALID_MODULE`,
  `DETECTOR_LOAD_FAILED`). `runDetector` runs against a defensive
  copy and records a throwing or invalid detector as an error
  envelope, never a crash. `sentinel detect [--detector
  stub|<path>] --input <record.json> [--session-id <id>]
  [--target-id <id>] [--asset-id <id>] [--out <findings.json>]`
  prints the findings as JSON (or writes them mode `0600`,
  symlink-refusing); a bad detector path fails cleanly with no
  output file. The output findings are directly consumable by the
  validator (detect → validate → dedupe → report proven end to
  end by test). NO real detector is built; which detectors to
  build, whether detection should ever run automatically, and
  whether detectors may be asynchronous remain open user
  decisions.

### Pluggable AI-verdict interface, advisory only (round 50, 2026-11-26)

- The verifier contract is defined (`src/analysis/ai-verdict.js`):
  a SYNCHRONOUS function `verifier(finding) -> { verdict,
  confidence, reasons }` with verdict one of `valid` /
  `false_positive` / `needs_evidence`, confidence a finite number
  in `[0, 1]`, and reasons an array of strings; the verifier
  receives a defensive copy of the finding and cannot mutate it. A
  verifier that returns a Promise is refused as an invalid result
  (the validator and generator are synchronous and deterministic).
  The built-in stub verifier is the default: it always returns
  `needs_evidence` with confidence 0 and the reason "no AI model
  configured", and never claims a finding valid or false_positive.
  `loadVerifier` loads a custom module only from inside the skill
  directory (absolute paths must resolve inside the skill root;
  relative paths resolve under it; the file must not be a symlink
  and its realpath must stay inside the real skill root; the export
  must be a function or an object with a `verify` function), with
  named refusals (`AI_VERDICT_NOT_FOUND`,
  `AI_VERDICT_SYMLINK_REFUSED`, `AI_VERDICT_PATH_OUTSIDE_SKILL`,
  `AI_VERDICT_INVALID_MODULE`, `AI_VERDICT_LOAD_FAILED`).
  `validateFinding(finding, { verifier })` computes the rule
  verdict first, unchanged, then records `aiVerdict` +
  `aiVerdictSource` — the rule verdict NEVER changes because of
  the AI verdict (tested both directions). `sentinel report
  --verifier stub|<path>` attaches `ai_verdict` +
  `ai_verdict_source` to every finding and renders it distinctly,
  labelled advisory, in Markdown, HTML, and JSON; platform
  templates do not render it in Markdown (fixed sections) but
  their JSON form still carries it. A verifier that throws or
  returns an invalid result is recorded as a `needs_evidence`
  error, never a crash. When no verifier is configured, no
  `ai_verdict` is attached and the report is byte-identical to the
  pre-round-50 output (the round-44 golden hashes still pass). NO
  model is plugged in; choosing the model, and whether the AI
  verdict should ever override the rule verdict, remain open user
  decisions.

### Mixed-target reports with explicit opt-in (round 49, 2026-11-26)

- A report covering more than one distinct `target_id` is now
  refused by default (`REPORT_MIXED_TARGETS_REFUSED`, naming the
  target count and every target, and pointing at the opt-in flag) —
  the pre-round-49 generator rendered mixed input silently and put
  only the first finding's `target_id` into JSON `target_id`,
  dropping the rest (verified by probe before the change). With
  `--allow-mixed-targets` (generator option `allowMixedTargets`)
  the report groups by target first, then by asset within each
  target (reusing `groupFindingsByAsset`), in deterministic order
  (target ascending, asset ascending, severity, finding id), with
  the finding number global across targets, and states the full
  target list in its header in all three formats (Markdown sentence
  + `## Target:` sections with `### Asset:` subsections; HTML
  paragraph + `<h2>Target:` / `<h3>Asset:`; JSON `target_ids`
  sorted array + `mixed_targets: true` + `target_id` per group,
  while top-level `target_id` holds the first target in sorted
  order, as `schemas/report.schema.json` still requires it).
  Platform templates render one finding per report, so they can
  never be mixed-target; the mixed-target check runs before the
  template branch. Single-target output is byte-identical to
  before (the round-44 golden hashes still pass). No automatic
  splitting into one report per target; whether mixed-target
  reports should ever be the default remains a user decision.

### Conservative semantic dedup v1 (round 48, 2026-11-26)

- Second dedup pass after the exact-key dedup (`semanticDedupeFindings`
  in `src/analysis/validator.js`, run over the exact pass's
  representatives): two findings merge ONLY when all four hold — same
  normalized `vulnerability_type`, same `asset_id` (exact), same CVSS
  base vector AND same severity (or, when neither carries a vector,
  the same severity band), and at least one shared evidence entry
  (same entry value; an empty `{}` entry never counts). The
  same-severity requirement in the vector branch is a deliberate
  tightening beyond the brief's minimum (identical base vectors
  imply identical computed scores, so a pair that differs there is
  mislabelled input). The merged finding keeps the union of
  evidence, steps, and references, the highest effective base score
  (with a shared vector, the score the vector computes — never a
  declared score that would disagree with it), and `merged_from`,
  the list of all member ids including the representative's (also
  declared as an optional property in `schemas/finding.schema.json`).
  Grouping is greedy on the representative, not transitive-closure.
  The generator renders `merged_from` in Markdown, JSON, and HTML;
  singletons render exactly as before (the golden hashes in
  `tests/report-html.test.js` still pass unchanged). Fuzzy text
  similarity and same type + asset without shared evidence are
  deliberately out of scope — looser matching is an open policy
  question for the user. Suite 341 → 356 tests. See
  `docs/semantic-dedup-v1.md`.

### Pending-promise audit (round 47, 2026-11-26)

- Audited every unawaited async call in `src/` and `bin/` (all
  `async` functions enumerated, every call site checked for
  `await` / `return` / `.catch()` / both-handled `.then()`; also
  `fs` promises, `new Promise(async ...)` executors, async timer
  callbacks, and async event handlers). Four real risks fixed:
  (1) the HTTP adapter's `cleanup()` called the async
  `unregister()` fire-and-forget — `get()` could resolve before
  the worker record was removed, and a write rejection became an
  unhandled rejection; `finishRun` now awaits cleanup and never
  rejects (a cleanup failure resolves with the real result plus
  `unregisterFailed: true`); (2) the controlled wrapper's
  timeout callback let a throwing `terminate()` hang the run
  forever and escape unhandled — the run now always settles by
  `timeoutMs`, reporting `terminationFailed: true`, and the kill
  poller's catch-path `terminate()` is guarded the same way;
  (3) the adapter poller's `catch { await cancel(); }` is
  guarded with a nested `try/catch`; (4) lock close/unlink
  ordering: a throwing `close()` used to skip the lock removal
  (stale lock for up to 60 s) — new shared helper
  `src/policy/lock-file.js` `closeAndRemoveLock` removes the
  lock file even when `close()` throws, used by the audit log
  and the CLI token-rotation lock. A regression guard runs on
  every `npm test` (`tests/pending-promise-guard.test.js` +
  `tests/pending-promise-allowlist.json`): it flags bare
  `unregister()`, unallowlisted `.then(` and async timers, bare
  `finishRun(`, and `new Promise(async`. The guard caught two
  adapter `finishRun` sites the manual audit had missed before
  the commit. Full audit, benign-site list, and guard limits in
  `docs/pending-promise-audit-v1.md`.

### Test hygiene and Python-not-required (round 46, 2026-11-26)

- Test temp dirs are now owned by a shared helper,
  `tests/helpers/temp-dir.js` (`makeTempDir(t, prefix)` registers
  removal with `t.after()`, which runs even when the test fails):
  90 async `fs.mkdtemp` sites across 12 test files migrated, plus
  the `tempDir`/`tempStateDir` helpers in the CLI-security and
  drill tests and the round-45 local helper (now the shared one).
  The 8 sync `mkdtempSync` sites were left alone — they already
  clean up in `try...finally`. The migration exposed one real
  bug: the drill test called the async `unregister()` without
  awaiting it, so its state write raced the new removal
  (`ENOTEMPTY`); the test now awaits it. A new
  `tests/temp-dir-helper.test.js` proves cleanup after a passing
  test and after a failing test (the child `node --test` run
  needs `NODE_TEST_CONTEXT`/`NODE_TEST_WORKER_ID` scrubbed from
  its env, or the runner refuses the recursive run). Before this
  round `/tmp` held 1,698 leaked test dirs (123M); a full green
  suite now leaves zero new ones, and the accumulated debris was
  removed (`/tmp` 39M after). Suite 327 → 330 tests.
- Python is not a requirement: no component invokes a Python
  interpreter (no `.py` files, nothing spawns `python`, README
  lists only Node.js 18+). The `check-env` Python probe and the
  `python_based_tools` disabled-feature entry are removed;
  `checkFirstAvailableCommand` stays as a tested utility for
  future first-available probes. `docs/check-env-audit-v1.md`
  and README.md record the decision, closing the last
  round-41 gap that was fixable without Meta. See the round-46
  capability report.

### State-file permissions audit and repair (round 45, 2026-11-26)

- New permission standard for the state directory (files `0600`,
  directories `0700`, no symlinks), enforced and verified in
  `src/policy/state-permissions.js`: `sentinel verify-install`
  gained a seventh check (`state-permissions`, reporting each
  violation by path with actual vs expected mode), and
  `sentinel verify-install --fix` tightens loose modes inside the
  state dir only, refusing symlinks (`STATE_PERMISSION_SYMLINK_REFUSED`).
  Writers now guarantee the state directory itself is `0700` even
  when it already exists (`ensurePrivateDir` — `mkdir({ recursive,
  mode })` alone never chmods an existing directory, which is how
  the live state dir stayed `2770`). The live install's audit
  found exactly three violations (state dir `2770`, two legacy
  `0660` files from Nov 18) and `--fix` repaired all three; the
  install now passes 7/7. A chmod that fails with `EACCES`/`EPERM`
  inside `ensurePrivateDir` is swallowed so the caller's next
  operation surfaces the properly classified permission error —
  throwing the raw `EPERM` regressed the round-27 EACCES probes
  (fixed here, and the probes now mirror the repo layout to load
  the new dependency). Fresh writes stay `0600`/`0700` under
  umask `022` (tested). Suite 316 → 327 tests. See
  `docs/state-permissions-v1.md`.

### Standalone HTML report export (round 44, 2026-11-26)

- `sentinel report --format html` renders the same validated,
  grouped findings as Markdown/JSON into one self-contained HTML
  file: inline CSS only, no JavaScript, no external resources (no
  CDN links, images, fonts, `@import`, `url()`, or any `href`/`src`
  attribute). It carries report ID, severity summary, executive
  summary, per-asset sections in the round-42 grouping order, CVSS
  base/temporal/environmental scores, and the per-class evidence
  checklist with `[x]`/`[ ]` marks; it is deterministic
  (byte-identical across runs and input orders). Finding content is
  untrusted, so every interpolated value is HTML-escaped
  (`escapeHtml`, exported from `src/report/generator.js`);
  references and asset URLs render as inert text, never as links.
  The hostile-content test pins the honest subtlety: `onerror`,
  `onload`, `src=`, and `javascript:` still appear in the file as
  escaped text inside `&lt;...&gt;` — the check is tag-based (every
  tag must be one the generator emits, no tag may carry
  `href`/`src`), not string-absence. Platform templates stay
  Markdown-only: `--format html` with `--template immunefi|code4rena`
  fails cleanly. Markdown/JSON output is unchanged (golden SHA-256
  hashes pinned in `tests/report-html.test.js`). Suite 305 → 316
  tests. See `docs/report-html-v1.md`.

### Audit-log hash chain and `audit verify` (round 43, 2026-11-26)

- Every audit record now carries a SHA-256 hash chained to the
  previous record (format v1: `chainVersion`, `prevHash`, `hash`;
  hash over the canonical JSON of the record's fields in documented
  order, genesis prevHash is 64 zeroes; a worked example with a
  hand-verifiable hash is in `docs/audit-integrity-v1.md`).
  `sentinel audit verify` replays the chain over the active log plus
  rotated archives (oldest first) and reports the first broken link
  with its file and line (exit 4 when broken): modification
  (`AUDIT_CHAIN_HASH_MISMATCH`), reordering or middle deletion
  (`AUDIT_CHAIN_PREV_MISMATCH`), a legacy record after chained ones
  (`AUDIT_CHAIN_LEGACY_AFTER_CHAINED`), an unparseable line
  (`AUDIT_CHAIN_UNPARSEABLE`). Pre-chain records verify as a legacy
  prefix and are never rewritten. Honest limits, pinned by tests:
  deleting a leading prefix or the last record is undetectable, and a
  full rewrite with recomputed hashes is outside the mechanism
  (tamper-evidence, not tamper-prevention). The writer never refuses
  to append because the chain is broken, so a tampered log cannot
  destroy the ability to record the incident that follows;
  `healthCheck()` stays structural-only and remains the gate before
  reset. A chained record is ~310 bytes (was ~130), so the round-37
  rotation tests were re-tuned to the new size (limits 700/1,000
  bytes); rotation behavior is unchanged. Suite 295 → 305 tests.
  See `docs/audit-integrity-v1.md`.

### Report grouping by asset (round 42, 2026-11-26)

- `sentinel report` now groups findings by `asset_id` in both output
  formats (generic template only): groups ordered by asset_id
  ascending (plain string order, never locale-dependent), findings
  inside a group by severity (critical first) then finding_id, with a
  global finding number across groups. The order is a pure function
  of the finding set, so the same findings in any input order produce
  byte-identical output (tested). Markdown gains a per-asset section
  (`## Asset: <id> — N finding(s) (critical: …, …)`); JSON gains a
  `groups` array (per-group counts and findings, each carrying its
  evidence checklist) alongside the flat `findings` array, which
  follows the same grouped order (documented in
  `schemas/report.schema.json`). A missing/empty/non-string asset_id
  maps to the `"unassigned"` group (defensive: the generator rejects
  such findings first, since asset_id is a required schema field).
  Grouping never changes a verdict — validation and deduplication
  happen before it. Platform-template JSON keeps its previous flat
  shape (no `groups` key); grouping across different targets
  (split, tag, or refuse) remains an open policy decision. One test
  expectation was corrected during the round (MIX-003 is low, CVSS
  2.0 — not high as first assumed; the code was already correct).
  Suite 284 → 295 tests. See `docs/report-grouping-v1.md`.

### check-env completion audit (round 41, 2026-11-26)

- `sentinel check-env` now enforces the documented Node.js 18 minimum
  (`runtime` reports `not_verified` below the floor, with the floor
  named; the constant mirrors `package.json` engines), loads its tool
  list from `config/environment-tools.json` at runtime (new
  `toolConfiguration` capability reports the source; a missing,
  unreadable, or malformed config falls back to the built-in
  definitions and says so; a config tool with no checker definition is
  reported `not_verified`, never silently skipped; a drift-guard test
  asserts the built-in definitions match the config list), reports
  each tool's purpose and — when unavailable — an install hint (plus
  the docker-CLI-is-not-a-daemon caveat), and probes the kill-switch
  state machinery in an isolated temporary directory
  (`processTermination` verified; end-to-end cancellation is proven by
  `sentinel drill`). The stale `processTermination` text (`Controlled
  cancellation has not been implemented…`) is gone. Considered and
  excluded: git/npm (install-time only), a Python minimum version
  (none documented), and `implementation-status.md` (a dated 21 Nov
  snapshot, left untouched). Remaining: check-env reports but does not
  gate (exit 0 even on failures; `verify-install` is the gate), and
  the probe verifies the machinery, not a kill. See
  `docs/check-env-audit-v1.md`. Suite 275 → 284 tests. This round also
  repairs the CHANGELOG gap below (round 39 was missing).

### Per-class evidence checklists (round 40, 2026-11-26)

- `knowledge/evidence-checklists.json` defines eight vulnerability
  classes (XSS, SQLi, SSRF, broken access control, authentication
  bypass, CSRF, reentrancy, information disclosure), each with
  required and recommended evidence items; the validator resolves a
  finding's free-form `vulnerability_type` to a class by
  trim+lowercase equals-or-contains matching (so `Stored
  Cross-Site Scripting` and `xss` both resolve to XSS) and enforces
  the class's required items — e.g. XSS/SQLi/broken access control/
  authentication bypass/information disclosure additionally require
  a `response_log`, SSRF requires `request_log` AND `response_log`,
  CSRF requires `request_log`, reentrancy requires `evidence_notes`.
  Unknown types fall back to the generic seven-item checklist. A
  missing class-required item is a `needs_evidence` reason named
  `missing <item> (required for <class id>)`; an evidence-derived
  item is only checked when the evidence array itself is present, so
  a missing array reports only `missing evidence`. The generator
  renders the checklist per finding (Markdown `### Evidence
  Checklist` section; JSON `evidence_checklist` object); platform
  templates keep their fixed sections in Markdown. The checklist
  spec loader throws on a malformed spec and the validator falls
  back to generic on load failure, keeping its never-throws
  contract. Regression fixed in this round: the validator's CVSS
  ratings were a top-level require, which crashed the operator-CLI
  `bin/`+`src/`-only copy run as `nobody` once the generator
  required the validator — the ratings are now loaded lazily on
  first use. Checklists verify PRESENCE, not truth.

### Incident-response drill (round 39, 2026-11-26)

- `sentinel drill [--state-dir <path>] [--recover]`
  (`src/policy/incident-drill.js`): kill-switch end-to-end against
  fake lab workers — two phases (cooperative worker cancelled via
  SIGTERM; stubborn SIGTERM-ignoring worker escalated to SIGKILL
  after a 1,000 ms grace), then audit verification and reset. Drill
  state is scoped to the drill directory and never touches real
  state; the drill refuses while the real kill switch is armed or
  real workers are registered, and only ever cancels workers it
  started itself; `--recover` recovers an interrupted run (PID
  liveness check, `DRILL_RECOVERED` audit record). Three bugs were
  caught by the drill's own tests during the round and fixed: a
  readiness race (SIGTERM before the handler was installed), an
  `exitCode`-only aliveness check (signal-killed reads null), a
  `DRILL_START` record written before pre-checks (refusals posed as
  abandoned runs), and an unawaited `unregister()` racing `reset()`
  (suite flake under load). CLI drill 30/30 PASS standalone; suite
  254 → 261 tests. Phase 8 ~80% → ~82%. The drill proves the
  machinery against a local sleep loop; it does not prove
  cancellation of a real tool or a networked worker. See
  `docs/drill-v1.md`.

### CVSS 3.1 temporal + environmental metrics (round 38, 2026-11-26)

- `src/analysis/cvss.js` parses and scores the full CVSS 3.1 vector:
  temporal metrics E/RL/RC (`Roundup(BaseScore x E x RL x RC)`) and
  environmental metrics CR/IR/AR/MAV/MAC/MPR/MUI/MS/MC/MI/MA
  (ModifiedISCBase capped at 0.915, scope-changed/unchanged
  modified-impact formulas, double Roundup before the temporal
  multipliers). Modified metrics fall back to their base metric on X
  (MS to S, requirements to 1.00). Values live in
  `knowledge/cvss/cvss-calc.json` (`temporal`/`environmental`
  tables); the module holds only the formulas. `resolveCvss()`
  returns `temporalScore`/`environmentalScore` plus named
  `temporalError`/`environmentalError` mismatches, and the validator
  and report generator enforce the same strict rule as for the base
  score; the generator fills in and renders derived temporal/
  environmental scores (generic and Immunefi/Code4rena templates).
  Severity is still checked against the BASE score only. Scores are
  computed only for metric groups the vector carries (absent = null,
  never fabricated from all-X). New optional schema fields
  `cvss_temporal_score` / `cvss_environmental_score`. Expected
  scores are hand-derived from the FIRST specification's formulas
  and cross-checked with an independent computation — no network
  oracle was reachable, so they are NOT copied from the FIRST
  calculator; re-checking them against it is the first verification
  for a future networked run. See
  `docs/cvss-temporal-environmental-v1.md`. Suite 225 → 254 tests.

### State backup/restore and audit-log rotation proof (round 37, 2026-11-26)

- `sentinel backup --out <file>` / `sentinel restore --from <file>`
  (`src/policy/state-backup.js`, `--state-dir` supported): backup
  captures only `kill-switch.json` in a schema-version 1 envelope
  carrying a SHA-256 integrity hash; the audit log is deliberately
  excluded (append-only evidence — restoring an old copy would erase
  intervening events). Restore verifies hash and schema version before
  writing anything and refuses with a named error and no partial write
  on corrupt input, hash mismatch, or unsupported schema. The
  armed-with-leased-workers rule is REFUSE
  (`BACKUP_ARMED_WITH_LEASED_WORKERS`): an armed state holding a live
  lease is not restored, so no phantom workers can block a later reset;
  an armed state with no live leases restores normally and stays armed.
  Backup/restore never follow symlinks for output or input, and restore
  refuses while a fresh state lock is held. See
  `docs/backup-restore-v1.md`. Audit rotation itself was NOT rebuilt
  (8 MiB / retain 3 already existed): this round proves it with tests
  (trigger at limit, no records lost across rotation, archives bounded
  at retention) and completes it — `healthCheck()` now validates the
  rotated archives and reports a corrupt one as
  `AUDIT_LOG_ARCHIVE_CORRUPT` instead of silently dropping it, and
  `readAllEvents()` returns active plus archives, oldest first, while
  `readEvents()` stays active-log-only by design.

### CVSS 3.1 base-vector parsing and scoring (round 36, 2026-11-26)

- `src/analysis/cvss.js` parses a CVSS 3.1 base vector and computes the
  base score per the FIRST specification (scope-changed formula and
  Roundup included), with severity bands from the shared
  `knowledge/cvss/cvss-calc.json` table — no second band table. The
  validator and the report generator share `resolveCvss()`: a malformed
  vector fails by name, a vector disagreeing with a declared score
  fails by name, and a vector-only finding derives its score (and is
  checked/rendered with it) instead of going unscored. Four lab
  fixtures carried declared scores contradicting their own vectors
  (STUB-001 8.2 vs 6.1, potential-full 6.5 vs 5.4, duplicate-a/b 5.3
  vs 5.4); the declared scores were corrected to the computed values
  and the affected test expectations updated. See
  `docs/cvss-vector-v1.md`. Temporal/environmental metrics are out of
  scope; the stub normalizer still derives severity from the declared
  score only (documented limitation).

### Report templates for Immunefi and Code4rena (round 35, 2026-11-26)

- `sentinel report --template immunefi|code4rena` renders one validated
  finding into a platform's section layout (one finding per report;
  `--findings` with a template fails cleanly). Templates are data, not
  code: JSON files in `knowledge/report-templates/`, loaded and
  shape-validated at runtime by `src/report/templates.js`; adding a
  platform is a new data file. A required section with no source data
  fails with a named field (a finding without `proof_of_concept` cannot
  be rendered in either template); an optional section with no data is
  omitted. `--format json --template <name>` keeps the generic JSON
  shape and adds a `"template"` field. Cantina submissions use the
  Code4rena template (same section set; see
  `docs/report-templates-v1.md` for the caveat). Deterministic:
  same input, byte-identical output, Markdown and JSON.

### Security self-review of the CLI (round 34, 2026-11-26)

- Report/check-env output writes now refuse a planted symlink at the
  exact output path (`src/policy/safe-write.js`: lstat pre-check plus
  `O_NOFOLLOW` on POSIX), so attacker-influenced report content can
  never be redirected to the link target. The check-env storage marker
  write uses the same guard.
- Finding/target input files are bounded (`src/policy/input-limits.js`):
  10 MiB per file, 10,000 findings per `--findings` array, 100 nesting
  levels (checked iteratively, never recursively).
- `countBySeverity` ignores severities outside the schema bands, so a
  hostile severity can never reach a bucket or inflate the total.
- Probed and found NOT vulnerable (regression tests added):
  prototype pollution via parsed JSON, argument injection (spawn is
  `shell: false` with fixed allowlisted args), malicious kill-switch
  state and audit-log lines (fail closed, hostile entries dropped).

## [1.0.0] — 2026-11-26

First consolidated release of the lab-local Sentinel Bounty skill, as
installed at `~/workspace/custom-skills/sentinel-bounty/`. Development ran
autonomously in 32 rounds under the standing limits: **local lab only, no
network scanner, no public targets**. Head commit `f42c61b`
(`test(phases-5-7): commit pipeline integration test, expand fixtures,
harden validator`).

### Kill switch / token lifecycle

- Persistent cross-process kill switch with process-group (PGID) kill of
  the lab process tree; kill state survives restarts and is stored in
  versioned JSON state files (mode 0600, atomic temp-write + rename).
- Bound single-use approval gate: approvals are recorded in state but are
  not authorization by themselves — execution still requires a runtime
  approval card (`permissions.preapprove` has no generic Sentinel binding).
- Token-gated operator CLI (`sentinel`): hash-file token gate, operator
  audit, race stress tested. Tokens are expiring and auditable: rotation
  is serialized, expiry metadata normalized to ISO (`validUntil`), reset
  repair documented, and revocation is crash-recoverable
  (`REVOKE_PENDING` + idempotent retry, scoped by token key; 100-cycle
  revoke run green). Corrupt token files now fail closed with
  `RESET_TOKEN_FILE_CORRUPT`.
- Audit log is append-only JSONL; audit health is classified on storage
  failures (including disk-full / ENOSPC recovery), and audit fails
  closed. Secrets are never written to state files — Secure Vault only.

### Scope & policy

- Default-deny scope manager with allowlist/exclusion rules and path
  blocking; target registry refuses IP literals and non-localhost hosts.
- Request governor: token-bucket rate limit, request budget, and 429/503
  backoff. Localhost-only HTTP GET adapter (`LOCALHOST_ONLY` enforcement,
  audited); every non-localhost attempt is blocked with zero transport
  calls. No scanner tools are installed or invoked anywhere.
- Environment checker probes runtime, filesystem, and persistence, and
  detects `python3` before `python`. Network is `not_tested`; external
  tools (docker, subfinder, dnsx, httpx, katana) are all `unavailable`
  in the lab.

### Detection stub (phase 5 — partial)

- Lab-local detection scaffolding only: `src/detection/` normalizes raw
  scanner-shaped fixture output into the finding schema (strict, no
  invented data; `impact`/`remediation` required, severity derived from
  `cvss_score` with inclusive lower-bound bands ≥9.0 / ≥7.0 / ≥4.0 / >0 /
  0). The stub detector never aborts on one bad result — it counts it in
  `skipped` with the error recorded. No real detector and no scanner
  integration exist; phase 5 needs a user scope decision before it can
  move past scaffolding.

### Validation (phase 6 — partial)

- Rule-based finding validator: verdicts `valid` / `false_positive` /
  `needs_evidence` / `needs_manual_review`, with a documented precedence
  order (missing field → analyst `false_positive` → manual review →
  severity/CVSS mismatch + missing evidence → confidence rules). It never
  throws on malformed input. Unknown severities and invalid `cvss_score`
  values (non-finite, out of [0, 10]) are rejected as `needs_evidence`,
  never `valid`.
- Root-cause dedup by `vulnerability_type|asset_id|normalized-first-step`
  (exact-key only — no semantic similarity). Fixed 7-item evidence
  checklist, always fully listed. No AI-model verdict, no semantic dedup,
  no live verification.

### Reporting (phase 7 — partial)

- Deterministic report generator (`sentinel report`): Markdown + JSON
  from validated findings, with strict severity/completeness rules
  (a report that must fail never leaves a half-written file). Two CLI
  runs with a fixed `generated_at` are byte-identical (same SHA-256).
- End-to-end pipeline (stub → validator → dedupe → report) is covered
  by a committed integration test, including a mixed fixture exercising
  dedup, verdicts, skipped findings, and a `valid` confirmed finding.
  No PDF output, no multi-session aggregation, no mixed-target grouping,
  no false-positive policy yet.

### Adaptation / uninstall

- Agent adaptation protocol (`docs/adapt-to-agent.md`): maps the skill
  contract to another agent platform and records the result. It is a
  documentation answer to the missing official manifest, not a
  substitute for one — the skill cannot be made "official" by rounds.
- Uninstall-restore protocol (`docs/uninstall-restore.md`): verified on
  a scratch copy only (kill-switch trigger → reset → revoke → removal →
  dead-CLI check), with the real install and real state untouched.
  Literal-name skill discovery works; persona-based discovery does not.

### Testing

- `npm test`: **148/148 PASS, 0 fail on Linux** (Node v24), verified on
  both the repo clone and the installed copy after reinstall. Suite grew
  from 13 tests (18 Nov) to 148 (26 Nov), including lock-error
  classification matrices (EEXIST + live lock stays `STATE_LOCKED`;
  permission failures classified separately), disk-full, and token
  lifecycle stress tests.
- Phase completion (per the round-32 report): phase 0 ~50%, phase 1
  ~65%, phase 2 ~95%, phase 3 ~92%, phase 4 ~25% (local lab adapter
  only), phase 5 ~15%, phase 6 ~30%, phase 7 ~45%, phase 8 ~70%.

## Known issues

- **Windows CI native run: GREEN on the round-87 commit, RED on the round-88 commit.**
  GitHub Actions `windows-latest` passed `npm test` four times —
  run 45881977604, head `d2d1991`, 2026-11-26T19:13:08Z,
  conclusion `success`, the first green Windows run in the
  project's history (round 84) — run 45884755893, head
  `82d68d4`, 2026-11-26T19:36:10Z, conclusion `success` (round
  86) — run 45984432990, head `4c10a44`,
  2026-11-27T10:43:01Z, conclusion `success` (round 87), the
  first green run for the round-86 commit itself — and run
  46034607189, head `e2d164b`, 2026-11-27T16:33:24Z,
  conclusion `success` (round 89), the first green run for
  the round-87 commit itself. Two runs are RED and unexplained.
  Between the first two green runs, run 45882467549 for head
  `933e0e7` (round 84's docs-only commit) completed
  2026-11-26T23:31:34Z with conclusion `failure`: job `test`
  failed, step `Run npm test` exit 1 after ~48 s (setup,
  checkout, setup-node all success). And run 46039065088 for
  head `98f09cb` (round 88's detector commit) completed
  2026-11-27T17:07:30Z with conclusion `failure`: job `test`
  failed at step `Run npm test` (setup, checkout, setup-node
  all success). The failing test name is not retrievable from
  the lab without repo-admin log access (log download returns
  403), so no fix was attempted for either red run — a blind
  fix is not a fix. A bounded local investigation in round 89
  found no Windows-hostile construct in the round-88 change,
  so the second red run stays unexplained, not resolved; it
  may be a flake in a timing-sensitive pre-existing test or a
  genuine Windows-only issue invisible without the log. The
  evidence that decides either red run is the failing test
  name from the run log, which needs the user's admin access.
  The ten run-54 failures were fixed by name in round 83 after
  the user uploaded the run log; the same path applies here
  when the user is awake.
- **Phases 0–1 cannot reach 100% by rounds.** They need Meta: an
  official manifest, quotas, native identity, and persona indexing.
  There is no public Muse skill registry — distribution is this GitHub
  repo plus custom-skill install.
- **Phase 4 and public adapters are blocked** by the local-lab-only
  constraint until the user lifts it.
- A 25 Nov reinstall attempt shipped a commit with six unresolved merge
  conflicts (`826d9587`); the user fixed them upstream and the
  continuation commit (`1056e20c`) passed 60/60. The broken commit is
  history, not the current tree.
