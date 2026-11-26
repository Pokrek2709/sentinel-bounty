# Shared report-summary helpers are exported (round 72, Phase 7)

`src/report/generator.js` now exports `executiveSummary` alongside
the already-exported `countBySeverity`, and the one place that
hand-replicated the generator's summary wording — the empty report
built by `sentinel report filter` (round 71) — now calls the
helpers instead of copying them. This is a pure refactor: no new
command, no new user-facing behavior, no output changes. The
byte-identical empty-report golden in `tests/report-filter.test.js`
proves it.

## Why

Round 71's `renderEmptyReport` (in `src/report/filter.js`) built
the empty filtered report by hand, because `generateReport` refuses
an empty finding set for JSON. Its `executive_summary` was a
template literal copied from the generator's `executiveSummary`
wording, and its `findings_summary` was a hand-written zero-counts
object literal. Round 71 documented the risk in its own F5: if the
generator's wording ever changed, the empty report's wording would
silently diverge — and the test that pinned the wording verbatim
would not catch the divergence as a divergence (it would just fail
as a stale golden, with no signal about which copy was right).

`countBySeverity` was already exported from the generator (it is
in the round-31 `module.exports`); `executiveSummary` was not.
This round exports it. `renderEmptyReport` now does:

```js
const zeroCounts = countBySeverity([]);
executive_summary: executiveSummary(zeroCounts, programName),
findings_summary: zeroCounts,
```

`executiveSummary(countBySeverity([]), programName)` IS the
zero-count summary by construction (the helper maps
`SEVERITY_ORDER` to `0 <severity>` parts and falls back to
`informational` as the highest severity when every count is 0),
so a future wording change in the generator propagates to the
empty report automatically.

## Audit: every other place that could replicate generator wording/counting

Checked repo-wide (round 72). Only the filter empty report
duplicated a generator helper.

| Place | What it does | Verdict |
|---|---|---|
| `src/report/jsonl.js` (round 66) | Receives `counts` (a `countBySeverity` result) from the generator and calls the already-exported `countByVerdict` from `src/report/summary.js`. It re-keys the counts into `counts_by_severity` with a fixed key order — a shape transformation, not a duplication. | Already reuses; left as-is. |
| `src/report/summary.js` (round 61) | `countByVerdict` is exported and is the single source for verdict counts in both the summary and JSONL formats. | Already reuses; left as-is. |
| `src/report/validate.js` (round 67) | `deriveExpectedReportId` re-implements the generator's `deriveReportId` (SHA-256 of program + sorted finding ids). | **Deliberately left duplicated.** Validate exists to check the generator's output; if it called the generator's own derivation, a bug in that derivation would be invisible to the check. The independence is the point. The verdict counts in `validateReport` (`valid` / `false_positive` / `needs_evidence` / `errors`) are validate's own domain, not generator severity counts — no duplication there either. |
| `src/report/split.js` (round 70) / `src/report/merge.js` (round 68) | `split` / `filter` metadata blocks and the merge summary line are those commands' own metadata, not generator wording. Each group's / merged report is rendered by `generateReport` itself. | No duplication; left as-is. |
| `pickGeneratedAt` in `filter.js` / `split.js` / `merge.js` | Three copies of the "input `generated_at`, else newest finding `created_at`, else a named error" rule. The generator holds the same logic inline in `generateReport`, not as a named helper. | **Found, deferred, documented here.** The three copies differ in semantics (merge takes the newer of TWO inputs' timestamps; filter and split take one input's), and their errors are module-specific (`REPORT_FILTER_NO_GENERATED_AT` vs `REPORT_SPLIT_NO_GENERATED_AT` vs `REPORT_MERGE_NO_GENERATED_AT`). Unifying them means extracting a named helper from the generator and giving each module its own error wrapping — a bigger design change than this round's wording/counting scope. Recommendation for a future round: extract `pickGeneratedAt(report, findings)` from `generateReport`, export it, and refactor the three call sites onto it, keeping each module's error code. Until then the three copies are pinned by their own tests. |

The Markdown / JSON / HTML / CSV / summary renderers themselves
were not touched (out of scope, as briefed).

## Tests (anti-divergence)

In `tests/report-filter.test.js`:

- **Golden (written before the refactor, green on the old code).**
  The empty report for the five-finding fixture filtered to
  nothing (`--severity critical --verdict needs_evidence`) is
  pinned byte-for-byte, including the `RPT-11ba7f2d7f84` id and
  the full `executive_summary` string. It passed before the
  refactor and after it — the refactor changed no output byte.
  If it ever fails, the refactor (or a generator change) changed
  output: revert, do not update the golden silently.
- **Anti-divergence.** The empty report's `executive_summary`
  must equal `executiveSummary(countBySeverity([]), programName)`
  and its `findings_summary` must deep-equal
  `countBySeverity([])`, calling the exported helpers directly.
  A future wording change in `executiveSummary` propagates to
  the empty report automatically, so this test still passes —
  unlike the verbatim pin in the older 'empty result' test,
  which would (correctly) fail and force a deliberate golden
  update instead.

In `tests/report-generator.test.js`:

- **Export contract.** `executiveSummary` and `countBySeverity`
  are functions, and a generated JSON report's
  `executive_summary` / `findings_summary` equal exactly what
  the helpers return for the same finding set — the same
  equality the empty filter report now relies on, pinned at the
  source.

Suite: 698 tests green (695 in round 71 + 3 new). All existing
filter / split / merge / validate / JSONL goldens unchanged.
