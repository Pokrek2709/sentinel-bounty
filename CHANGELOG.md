# Changelog — sentinel-bounty

All notable changes to this project are documented here. Entries are drawn
from the capability reports in `~/workspace/sentinel-bounty/`
(`capability-report-*.md`, rounds 1–32, 18–26 Nov 2026). Phase percentages
are the reports' own first-implementation estimates, not test counts.

## [Unreleased]

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

- **Windows CI native run FAILS.** GitHub Actions `windows-latest` fails
  at `npm test` (runs 45451156030, 45687748470, 45689157563) with zero
  check-run annotations, so the failing test name is not retrievable
  without repo-admin log access. A hypothesis fix (pin Actions to
  Node 24, skip the two tmpfs tests on win32) was disproven by CI —
  the failure is neither the tmpfs tests nor the action versions. No
  further blind fix will be attempted; the log must be read by the
  repo admin first.
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
