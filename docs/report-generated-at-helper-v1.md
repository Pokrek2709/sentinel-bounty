# Shared `pickGeneratedAt` helper (round 73, Phase 7)

`pickGeneratedAt(reports, findings)` is exported from
`src/report/generator.js`. It is the single implementation of the
rule that `filter.js`, `split.js`, `merge.js`, and `anonymize.js`
each previously carried as their own copy: the `generated_at` for
a derived report. This round is a pure refactor — no new command,
no output change, no error-code change.

## Contract

```js
pickGeneratedAt(reports, findings) // -> string | null
```

- `reports` is an array of source report objects (one element for
  filter/split/anonymize, two for merge).
- Returns the newest valid ISO `generated_at` among `reports`;
  else the newest valid `created_at` among `findings`; else
  `null`.
- A value counts only when it is a string that `Date.parse`
  accepts; anything else (non-string, unparseable) is ignored.
- Never invents a timestamp from the wall clock.
- Returns `null` when nothing is available. The helper never
  throws: each caller throws its OWN named error on `null`, so
  every error code is preserved exactly (see the table below).

## Call sites unified (all four)

| Module | Call | Error on `null` (unchanged) |
| --- | --- | --- |
| `src/report/filter.js` | `pickGeneratedAt([report], kept.length > 0 ? kept : report.findings)` | `REPORT_FILTER_NO_GENERATED_AT` |
| `src/report/split.js` | `pickGeneratedAt([report], groupFindings)` | `REPORT_SPLIT_NO_GENERATED_AT` |
| `src/report/merge.js` | `pickGeneratedAt([a, b], merged)` | `REPORT_MERGE_NO_GENERATED_AT` |
| `src/report/anonymize.js` | `pickGeneratedAt([report], anonymized)` | `REPORT_ANONYMIZE_NO_GENERATED_AT` |

Correction to round 72's F5 and its CHANGELOG entry: the
duplication was a **quadruple**, not a triple — `anonymize.js`
carried a fourth copy that round 72's audit missed. All four
are now unified; no local `pickGeneratedAt` definition remains
anywhere in `src/`.

## Error-code preservation

The four error messages differ in wording (filter and anonymize
name "the report", split names "this group", merge names
"neither report"), and the codes differ per module. The helper
takes no error argument precisely so the wording stays with the
module that owns it: the selection logic is shared, the failure
identity is not. Tests pin each module's code
(`tests/report-generated-at-helper.test.js`, error-codes
preserved group) and the existing per-module tests still assert
the same codes.

## What was deliberately NOT unified

- `deriveExpectedReportId` (round 67) stays an independent
  re-implementation: validate must check the generator, not
  call it (round 72's audit, unchanged).

## Round 80: the generator fallback is now unified too

The bullet above used to list `generateReport`'s own fallback
(newest finding `created_at` when `options.generatedAt` is
absent) as deliberately not unified. Round 80 closed it:
`generateReport` now calls `pickGeneratedAt([], reported)` —
an empty reports array is the findings-only entry point, and
the helper's doc comment says so. The "equivalent for valid
ISO strings" claim from round 73 turned out to be wrong on
probe: a lexical `.sort()` and a `Date.parse` sort disagree
whenever the strings are not all in the same shape — mixed
timezone offsets (`2026-01-01T23:00:00-02:00` is
2026-01-02T01:00:00Z but sorts lexically before
`2026-01-02T00:30:00Z`), non-padded dates (`2026-1-1` sorts
lexically after `2026-01-02T00:00:00Z`), and two
representations of the same instant (lexical order picks by
string shape; `Date.parse` ties sort stably, so input order
wins). `validateFinding` never checks `created_at`'s format
(it is not a required field), so such values genuinely reach
the fallback — the helper's `Date.parse` filter was already
the only guard. The new behavior is the chronological one in
all three cases; for same-format ISO inputs the output is
byte-identical (pinned by sha256 goldens in
`tests/report-generator.test.js`, written on the old code
first). The fallback still returns null when nothing is
available, so the JSON "requires a generated_at" error is
unchanged.

## Tests

`tests/report-generated-at-helper.test.js` (20 tests):

- 9 golden sha256 pins: the byte output of filter (non-empty and
  empty), split (`--by severity` and `--by verdict`), merge
  (same `generated_at` and newer second input), anonymize, and
  the `created_at` fallback for filter and split — pinned on the
  pre-refactor code and green after the refactor, so the
  refactor is provably byte-identical.
- 4 error-code preservation tests, one per module.
- 7 direct contract tests for the exported helper (single
  report, invalid `generated_at` fallback, two reports newest
  wins both orders, one valid among invalid, newest
  `created_at`, `null` when nothing exists, non-string and
  unparseable values ignored).
