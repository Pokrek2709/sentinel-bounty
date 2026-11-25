# CVSS 3.1 base-vector parsing and scoring (v1)

`src/analysis/cvss.js` parses a CVSS 3.1 base vector string, computes the
base score from it, and resolves the effective score for a finding
record. It is the single place in the codebase that knows the CVSS 3.1
base formulas; the validator (`src/analysis/validator.js`) and the
report generator (`src/report/generator.js`) both call it through
`resolveCvss()` instead of implementing their own checks.

## What it does

- **Parse** (`parseCvssVector`): a vector such as
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` into its eight base
  metrics `{ AV, AC, PR, UI, S, C, I, A }`. Matching is case-sensitive
  (the specification's grammar is uppercase only). Every failure throws
  an `Error` with a `code` property and a message starting with
  `invalid cvss_vector: ...`:
  - `CVSS_INVALID_TYPE` — not a string
  - `CVSS_EMPTY_VECTOR` — empty or whitespace-only string
  - `CVSS_INVALID_PREFIX` — anything other than `CVSS:3.1`
  - `CVSS_MALFORMED_PART` — a part that is not `KEY:VALUE`
  - `CVSS_UNKNOWN_METRIC` — a key outside the eight base metrics
    (this is also how temporal/environmental parts are rejected —
    they are never silently truncated)
  - `CVSS_DUPLICATE_METRIC` — the same metric twice
  - `CVSS_UNKNOWN_VALUE` — a value outside the metric's table
  - `CVSS_MISSING_METRIC` — fewer than eight metrics
- **Score** (`computeBaseScore`, `scoreCvssVector`): the base score per
  the FIRST CVSS v3.1 specification, plus the severity band from the
  shared table in `knowledge/cvss/cvss-calc.json` (no second band
  table exists anywhere). Metric values come from that JSON at
  runtime; the module holds only the formulas.
- **Resolve** (`resolveCvss`): the shared finding-level rule used by
  the validator and the generator (see "Precedence" below).

## Formulas (FIRST CVSS v3.1, base metrics only)

```
ISCBase        = 1 - [(1 - C) x (1 - I) x (1 - A)]
Scope U: Impact = 6.42 x ISCBase
Scope C: Impact = 7.52 x [ISCBase - 0.029] - 3.25 x [ISCBase - 0.02]^15
Exploitability = 8.22 x AV x AC x PR x UI
  (PR uses the scope-changed table when S is C, else the unchanged one)
Impact <= 0            -> base score 0.0
Scope U: Roundup(min(Impact + Exploitability, 10))
Scope C: Roundup(min(1.08 x (Impact + Exploitability), 10))
```

`roundUp` is the FIRST reference implementation's algorithm: the
smallest number with one decimal place that is equal to or higher
than the input, computed in integer space so float noise does not
round a score up (`Roundup(4.02) = 4.1`; `Roundup(4.00) = 4.0`;
`Roundup(6.9000000001) = 6.9`).

## Worked examples (the specification's own values)

| Vector | Score | Severity |
| --- | ---: | --- |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | critical |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | critical |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium |
| `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 | high |
| `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | high |
| `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 | critical |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0.0 | informational |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | high |

These are the oracle for `tests/cvss.test.js` — they are the FIRST
specification's and calculator's published values, not values fitted
to this implementation. Note the 9.9 row: with scope changed, PR:L
uses 0.68 (changed table), not 0.62 (unchanged table).

## Precedence (vector vs declared score)

`resolveCvss(finding)` returns `{ effectiveScore, vectorScore, error }`:

1. A **malformed vector** is an error of its own
   (`invalid cvss_vector: ...`). It never also produces a mismatch —
   with no computed score there is nothing to compare against.
2. A **vector that disagrees with a declared score** is an error
   (`cvss_vector/cvss_score mismatch: vector computes to X but
   cvss_score is Y`). The declared score and the computed score are
   compared after rounding the declared score to one decimal, so
   float noise such as `9.8000000001` does not fail.
3. A **vector-derived score beats a missing score**: when the vector
   parses and no valid declared score exists, the computed score is
   the effective score — the severity is checked against it instead
   of going unchecked.
4. A **declared score that is present but invalid** (not a number,
   out of range) is ignored here and reported as `invalid
   cvss_score` by the callers; the vector score is still used as the
   effective score, so one bad field does not hide the other.
5. **Missing score AND missing vector** leave the severity unchecked,
   as before. A missing or empty-string vector is absent, not an
   error; a non-string vector is an error.

The validator collects these as reasons (a finding can report both a
vector mismatch and missing evidence); the report generator throws
on the first one. In both, a `false_positive` confidence still wins
over a bad vector — a dead finding's label is moot. When only the
vector is present, the generator returns the finding with
`cvss_score` filled in with the derived score, so the rendered
report shows the score instead of "Not scored".

## Known limitations

- **Base metrics only.** Temporal (E, RL, RC) and environmental
  (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA) metrics are out
  of scope: a vector carrying them is rejected as an unknown metric.
  Adding them would need the temporal/environmental formulas plus a
  decision about which score (base vs temporal vs environmental) the
  severity bands and the report use.
- **The stub normalizer does not cross-check the vector.**
  `src/detection/normalized-record.js` derives severity from the
  declared score only; a raw record whose vector disagrees with its
  score normalizes fine and is caught later, by the validator and
  the generator. Wiring the check into normalization is a future
  round's item.
- **Scores are base scores.** The module never claims a temporal or
  environmental score; callers that need those must say so
  explicitly rather than relabelling the base score.
