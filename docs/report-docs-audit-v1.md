# Documentation cross-reference audit (round 76, Phase 7)

Round 75's capability report (F4/F5) documented a drift: the
SKILL.md See-list lacked the filter, stats, helpers-export, and
generated-at-helper doc links from rounds 71–74. This round audited
every documentation cross-reference in the repo, fixed the drift
found, and added a guard test (`tests/docs-crossref.test.js`) so a
future round that adds a doc or a command and forgets the lists fails
in the suite instead of drifting silently.

## Audit method

All checks ran locally, no network, no scanners. The audit scripts
were throwaway Python over the repo tree (not committed); the
durable form of every check is the guard test.

1. **Docs inventory:** list every `docs/*.md` file (59 files at audit
   time) and check each is listed in `docs/README.md`, referenced
   from `README.md` or reachable through the docs index it links,
   and referenced from `skills/sentinel-bounty/SKILL.md` where the
   SKILL.md paragraph convention applies.
2. **Link resolution:** extract every `docs/<x>.md` reference and
   every relative Markdown link in `docs/*.md`, `README.md`,
   `SKILL.md`, and `CHANGELOG.md`, and check the target exists.
3. **Command coverage:** extract the 32 usage lines from
   `node bin/sentinel.js --help` (which writes to stderr and exits
   1) and compare them, as a set, with the 22 usage lines in the
   SKILL.md command code block.
4. **Flag coverage:** collect every `--flag` in the CLI help and
   check every backticked `` `sentinel ...` `` usage span in
   `docs/*.md` uses only those flags; check every `sentinel ...`
   command spelling in the docs against the help usage lines.

## Drift found and fixed

### D1 — SKILL.md report-paragraph See-list: 7 doc links missing

`skills/sentinel-bounty/SKILL.md` lines 73–79 (before this round).
The paragraph describes the base generator, the platform templates,
the filter/stats commands, the shared helpers, and the CVSS
severity/score rule, but the See-list named none of their docs:

| Missing link | Documents |
| --- | --- |
| `docs/reporting-v1.md` | the base report generator (`sentinel report`) |
| `docs/report-templates-v1.md` | platform templates (`--template immunefi\|code4rena\|hackerone\|bugcrowd`) |
| `docs/report-filter-v1.md` | `sentinel report filter` (round 71; named in round 75 F4) |
| `docs/report-stats-v1.md` | `sentinel report stats` (round 74; named in round 75 F4) |
| `docs/report-helpers-export-v1.md` | shared summary helpers (round 72; named in round 75 F4) |
| `docs/report-generated-at-helper-v1.md` | shared `pickGeneratedAt` helper (round 73; named in round 75 F4) |
| `docs/cvss-vector-v1.md` | CVSS 3.1 base scoring, which the paragraph's severity/score rule relies on |

Fix: all seven appended to the See-list. Note the first two are
older than rounds 71–74 — the drift predates the four round-75
named; the audit caught them because it checked the whole list,
not just the four named.

### D2 — SKILL.md command code block: 10 usage lines missing, 2 stale

`skills/sentinel-bounty/SKILL.md` lines 23–44 (before this round)
listed 22 usage lines; the CLI help lists 32. Missing entirely:

- `sentinel drill [--state-dir <path>] [--recover]`
- `sentinel verify-install [--state-dir <path>] [--skill-dir <path>] [--fix]`
- `sentinel report-diff <old-report.json> <new-report.json> [--format markdown|json] [--out <diff.md>]`
- `sentinel report validate <report.json> [--json]`
- `sentinel report merge <a-report.json> <b-report.json> [--out <merged.json>]`
- `sentinel report anonymize <report.json> [--out <anon.json>] [--salt <hex>]`
- `sentinel report split <report.json> --by severity|verdict --out-dir <dir> [--force]`
- `sentinel report filter <report.json> [--severity <level>] [--verdict <rule-verdict>] [--out <filtered.json>]`
- `sentinel report stats <report.json> [--json]`
- `sentinel report render <report.json> --format markdown|json|html|csv|summary|jsonl [--out <file>]`

Stale: the two `sentinel report --finding` / `--findings` lines
lacked `[--allow-mixed-targets] [--verifier stub|<path>]`, which
the CLI help carries. The subcommands were all described in the
prose paragraph below the code block, so an operator reading the
whole contract saw them — but the code block is presented as "its
implemented local commands are", and as a list it was wrong.

Fix: the code block now lists exactly the 32 CLI help usage lines,
in help order. The guard test pins the equality.

### D3 — SKILL.md detect-paragraph See: 2 doc links missing

Line 51 (before this round) linked only
`docs/detector-interface-v1.md`, while the paragraph describes the
stub detector ("The built-in stub detector ... is the reference
implementation") and the validator ("every returned finding is
re-normalized on validation"):

- `docs/detection-stub-v1.md`
- `docs/validation-v1.md`

Fix: both added to the See.

### D4 — SKILL.md scope-paragraph See: 2 doc links missing

Line 49 (before this round) linked only
`docs/scope-manage-v1.md` and `docs/scope-list-default-path-v1.md`,
while the scope feature also has:

- `docs/scope-manager-v1.md` — the scope gate core (default-deny
  registration, DNS-host matching)
- `docs/scope-explain-v1.md` — `check-scope --explain`, which the
  code block lists but no SKILL.md prose explains anywhere

Fix: both added to the See.

### D5 — SKILL.md foundation paragraph: 5 doc links missing

Line 83 (before this round) names six foundation components with
no links at all. Five now have a See sentence (the sixth, the
scope manager, is linked from the scope paragraph, D4, and is not
linked twice):

- `docs/request-governor-v1.md`
- `docs/approval-gate-v1.md`
- `docs/controlled-wrapper-v1.md`
- `docs/kill-switch-v1.md`
- `docs/persistent-kill-switch-v1.md`

## Audited, no drift

- **`docs/README.md` is complete:** all 59 docs files are listed,
  one line each, and no entry points at a nonexistent file.
- **`README.md` is not a full index by design:** it names the key
  docs in prose and defers the full list to the docs index
  (line 69: "For the full documentation list, see the
  [docs index](README.md)"). All 24 docs files not named
  directly in `README.md` are listed in the docs index, so every
  doc is reachable from the README in one hop. The guard asserts
  the README links the docs index; it does not demand the README
  name every doc.
- **No broken links:** every `docs/<x>.md` reference and every
  relative link in `docs/*.md`, `README.md`, `SKILL.md`, and
  `CHANGELOG.md` resolves to a file that exists (0 broken).
- **No bad flags:** every `--flag` in a backticked
  `` `sentinel ...` `` usage span in `docs/*.md` is a flag the CLI
  help defines. Five apparent hits were verified as false
  positives: `rsync --delete` (scope-manage-v1.md),
  `python3 --version` (muse-secure-vm-poc.md),
  `docker --version` (status-v1.md), and two explicitly
  hypothetical `--where` mentions (report-filter-v1.md:161 and
  report-split-v1.md:179 — both say a `--where` style filter is a
  future round, not an existing flag).
- **No bad command spellings:** every `sentinel ...` spelling in
  the docs matches a CLI usage line (the apparent mismatches were
  usage fragments with flags, e.g.
  `sentinel report --format csv`, all valid).

## Deliberately not linked from SKILL.md

Fourteen docs have no SKILL.md anchor by decision, recorded in the
guard test's `NO_SKILL_ANCHOR` allowlist with a reason each. A new
doc must gain a SKILL.md anchor or an allowlist entry with a
reason; it cannot drift silently.

| Doc | Reason |
| --- | --- |
| `docs/README.md` | the index itself |
| `report-docs-audit-v1.md` (this file) | meta-doc about the docs cross-references; no SKILL.md paragraph describes the audit |
| `implementation-status.md` | phase-by-phase status snapshot as of 2026-11-21, not operator reference |
| `github-prototype-readiness.md` | sharing-readiness doc; linked from the repo README |
| `muse-capability-evidence-2026-11-18.md`, `muse-capability-followup-2026-11-19.md`, `muse-capability-pgid-2026-11-20.md`, `muse-kill-switch-lab-evidence-2026-11-20.md`, `muse-wrapper-lab-followup-2026-11-20.md`, `muse-http-adapter-evidence-2026-11-21.md`, `muse-secure-vm-poc.md` | user-supplied lab evidence / PoC procedure, not operator reference (two capability docs are already linked from the repo README) |
| `pipeline-v1.md` | end-to-end pipeline doc; no SKILL.md paragraph describes the pipeline as a whole |
| `cvss-temporal-environmental-v1.md` | temporal/environmental metrics not mentioned in SKILL.md prose |
| `local-http-adapter-v1.md` | lab HTTP adapter; no SKILL.md paragraph describes it |
| `pending-promise-audit-v1.md` | implementer async-safety audit; no SKILL.md paragraph describes async safety |

## The guard

`tests/docs-crossref.test.js` (8 tests) asserts:

1. Every `docs/*.md` file is listed in `docs/README.md`, and no
   index entry dangles.
2. `README.md` links `docs/README.md`.
3. Every `docs/report-*.md` file is referenced in `SKILL.md`.
4. Every `report <subcommand>` in the CLI help appears in
   `SKILL.md`.
5. The SKILL.md command code block is exactly the CLI help usage
   lines (same set). The help writes to stderr and exits 1; the
   test reads the text, not the code.
6. Every `docs/<x>.md` reference in `docs/`, `README.md`,
   `SKILL.md`, and `CHANGELOG.md` resolves to an existing file.
7. Every backticked `` `sentinel ...` `` usage span in `docs/*.md`
   uses only flags the CLI help defines.
8. Every `docs/*.md` file has a SKILL.md anchor or an explicit
   allowlist entry (with a reason), and no allowlist entry is
   stale.

Proven against the pre-fix tree: 5 pass / 3 fail — the three
failing tests were exactly the drift tests (report docs in
SKILL.md, code block vs help, anchor-or-allowlist, the last
naming all 16 unanchored docs). After the fix: 8/8 green.

## Out of scope (not fixed here)

- The `asset_url` scrub decision (round 69) is a user decision,
  not a docs issue.
- The stats F5 gaps (round 74 — summary/total divergence on
  hand-edited files, raw class strings, error findings
  contributing severity) and the un-unified `generateReport`
  fallback (round 73) are behavior questions, not docs drift;
  they stay open as documented limitations.
- `README.md` does not list `sentinel drill` or every doc by name;
  that is prose design, not drift — the README is not a command
  list or a full index.
