# Report diff between two runs (round 64, Phase 7)

`sentinel report-diff <old-report.json> <new-report.json>
[--format markdown|json] [--out <diff.md>]` compares two JSON
reports from two runs of the same program and shows what changed:
which findings are new, which are gone, and which changed. It is
the answer to the only question that matters after a re-run — an
operator previously had to read two full reports side by side.

The implementation lives in `src/report/report-diff.js`
(`diffReports`, `renderReportDiffMarkdown`,
`renderReportDiffJson`, `readReportFile`, `deriveDiffReportId`);
the CLI handler is `runReportDiff` in `bin/sentinel.js`.

## Matching and compared fields

Findings are matched by `finding_id` only. A finding present in
the new report but not the old one is `added`; one in the old but
not the new is `removed`; one present in both is `changed` when any
compared field differs, otherwise it counts toward `unchanged`
(count only — unchanged findings are never listed).

Compared fields, in the fixed order they render in a `changed`
entry: `severity`, `cvss_score`, `verdict`, `asset_id`. `verdict`
is the finding's `validation_status` field, under the same name
the CSV export's `verdict` column uses (see
`src/report/generator.js`: the column carries
validation_status). A missing value normalizes to `null` and
renders as `none` (`Not scored` for `cvss_score`), so "absent"
compares equal to "absent".

`merged_from` is deliberately NOT a compared field: it is
provenance from the semantic dedup pass (round 48), not
substance — two findings that differ only in `merged_from` are
the same finding. Description, steps, evidence, references, and
every other field are likewise not compared; the diff is a triage
view, and the full finding lives in the source report.

## Output

Markdown (default) and JSON. Both are deterministic: added /
removed / changed are sorted by `finding_id` (plain string
order), the changed field list is in the fixed field order above,
and the diff's own `report_id` is a SHA-256 hash of the two source
report ids plus the sorted id lists (`RPT-<12 hex>`, the same
derivation family as the generator's report ids) — so the same two
report sets in any finding order produce byte-identical output in
both formats. No `--generated-at`: like CSV (round 55) and the
summary (round 61), a diff carries no wall-clock timestamp.

Markdown layout, in order:

```text
Report Diff — RPT-<diff id>
Old report: RPT-<old>
New report: RPT-<new>
Counts: <a> added, <r> removed, <c> changed, <u> unchanged

Added (<a>):
- <id> | <severity> | CVSS <score> | <asset> | <verdict>

Removed (<r>):
- <id> | <severity> | CVSS <score> | <asset> | <verdict>

Changed (<c>):
- <id>:
  - <field>: <old> -> <new>

Unchanged: <u> finding(s).
```

Only non-empty categories render a section. An empty diff
renders the counts line plus `No differences.` — it is not an
error.

JSON shape:

```json
{
  "report_id": "RPT-<diff id>",
  "old_report_id": "RPT-<old>",
  "new_report_id": "RPT-<new>",
  "added": [{ "finding_id": "...", "severity": "...", "cvss_score": 5, "verdict": "...", "asset_id": "..." }],
  "removed": [{ "..." }],
  "changed": [{ "finding_id": "...", "changes": [{ "field": "severity", "old": "medium", "new": "high" }] }],
  "counts": { "added": 1, "removed": 1, "changed": 1, "unchanged": 1 }
}
```

`added` / `removed` entries are compact summaries (id + the four
compared fields), not full findings — the full finding lives in
the source report, and a compact row keeps the diff deterministic
and readable.

## Input rules

Inputs are JSON report files in the round-31 JSON report format
(an object with `report_id` and a `findings` array). They are read
bounded (10 MiB, depth 100 — `src/policy/input-limits.js`) and a
symlinked input is refused. The diff does NOT re-validate the
findings against the finding schema: a diff compares reports, it
does not re-judge them. Shape errors are named and fail before
any output is produced, so a bad input can never leave a
half-written output file behind:

| Error | Meaning |
| --- | --- |
| `REPORT_DIFF_INVALID_REPORT` | Not a JSON object, no `report_id`, no `findings` array, or unreadable / malformed JSON |
| `REPORT_DIFF_INVALID_FINDING` | A finding has no `finding_id` |
| `REPORT_DIFF_DUPLICATE_FINDING_ID` | The same `finding_id` twice in one report (the match would be ambiguous; a generated report never contains one) |
| `REPORT_DIFF_SYMLINK_REFUSED` | An input path is a symbolic link |
| `REPORT_DIFF_TOO_MANY_FINDINGS` | More than 10,000 findings in one report |

`--template` does not apply to a diff (a diff compares two
reports, it does not render one) and is refused with a named
error. `--out` writes through the round-34 safe-write helper
(symlink refused, mode `0600`); without `--out` the diff goes to
stdout.

Mixed targets: a diff compares by `finding_id` regardless of
`target_id`, so reports from different targets (or a
mixed-target report, round 49) diff fine. A changed `target_id`
on a finding is not itself a compared field, so a finding that
merely moved target is unchanged.

## What the diff deliberately does not do

- No re-validation of findings against the finding schema.
- No AI verdict: the diff never runs a verifier and never
  attaches one; `ai_verdict` on a finding is not a compared
  field.
- No severity re-derivation from CVSS: the compared `severity`
  is the stored value, not a recomputed one — a finding whose
  stored severity disagrees with its score is a generator error,
  and the diff reports the stored values as they are.
