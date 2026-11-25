# CVSS 3.1 temporal + environmental metrics (v1)

`src/analysis/cvss.js` now parses and scores the full CVSS 3.1 vector:
the eight base metrics (see
[cvss-vector-v1](cvss-vector-v1.md)) plus the three temporal metrics
(E, RL, RC) and the eleven environmental metrics (CR, IR, AR, MAV,
MAC, MPR, MUI, MS, MC, MI, MA). Metric values live in
`knowledge/cvss/cvss-calc.json` (`temporal` and `environmental`
tables, added in this round); the module holds only the formulas.
The validator (`src/analysis/validator.js`) and the report generator
(`src/report/generator.js`) enforce the same strict rule for the
temporal and environmental scores as for the base score: a declared
score that disagrees with the vector's computed score fails by name.

## Parser extensions

`parseCvssVector` accepts all 22 metrics. The eight base metrics
are still required; temporal and environmental metrics are optional
and absent means X (Not Defined). The return value is a flat object
with the eight base metrics plus whichever temporal/environmental
metrics the vector carries — an absent metric stays absent from the
object (it is not materialised as `"X"`), so callers can tell "the
analyst said Not Defined" (explicit `E:X`) from "the analyst said
nothing" (no `E` key). The three-letter modified keys (MAV, MAC,
MPR, MUI) required widening the part regex from `{1,2}` to `{1,3}`.
Error codes are unchanged (`CVSS_UNKNOWN_METRIC`,
`CVSS_DUPLICATE_METRIC`, `CVSS_UNKNOWN_VALUE`,
`CVSS_MALFORMED_PART`, `CVSS_MISSING_METRIC`, and the rest); a
vector with an unknown metric or a bad value is still rejected,
never silently truncated.

## Formulas (FIRST CVSS v3.1)

```
TemporalScore = Roundup(BaseScore x E x RL x RC)
  (a missing temporal metric is X = 1.00)

ModifiedISCBase = min(1 - [(1 - MC x CR) x (1 - MI x IR) x (1 - MA x AR)], 0.915)
Modified scope U: ModifiedImpact = 6.42 x ModifiedISCBase
Modified scope C: ModifiedImpact = 7.52 x [ModifiedISCBase - 0.029]
                                - 3.25 x [ModifiedISCBase - 0.02]^15
ModifiedExploitability = 8.22 x MAV x MAC x MPR x MUI
  (MPR uses the scope-changed table when MS is C, else the unchanged one)
ModifiedImpact <= 0 -> environmental score 0.0
Modified scope U: EnvironmentalScore =
  Roundup(Roundup(min(ModifiedImpact + ModifiedExploitability, 10)) x E x RL x RC)
Modified scope C: EnvironmentalScore =
  Roundup(Roundup(min(1.08 x (ModifiedImpact + ModifiedExploitability), 10)) x E x RL x RC)
```

Fallback rules (the specification's "Not Defined" semantics):

- A modified metric of X (or absent) falls back to its base metric:
  MAV→AV, MAC→AC, MPR→PR, MUI→UI, MC→C, MI→I, MA→A. In the
  tables the X entry for a modified metric is `null` — it means
  "fall back", not a number — and the code resolves it.
- MS of X (or absent) falls back to S (the base scope). The MPR
  table selection follows the *modified* scope, so a vector with
  `S:U/MS:C` uses the changed PR table for MPR.
- A requirement of X (or absent) is 1.00; a temporal metric of X
  (or absent) is 1.00.
- The modified base score is rounded up *before* the temporal
  multipliers are applied (the specification's double Roundup):
  `Roundup(8.0 x 0.94 x 0.95) = 7.2`, not 7.1.

## Worked examples (formula-derived, cross-checked)

| Vector (suffix on base) | Base | Temporal | Environmental |
| --- | ---: | ---: | ---: |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `E:P/RL:O/RC:C` | 9.8 | 8.8 | — |
| `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` + `E:U/RL:W/RC:R` | 6.1 | 5.2 | — |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `CR:L/IR:L/AR:L` | 9.8 | — | 8.0 |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `CR:H/IR:H/AR:H` | 9.8 | — | 9.8 |
| `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` + `CR:H/IR:H/AR:H` | 6.1 | — | 7.4 |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `MAV:P` | 9.8 | — | 6.8 |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `MS:C` | 9.8 | — | 10.0 |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + `E:P/RL:O/RC:C/CR:L/IR:L/AR:L` | 9.8 | 8.8 | 7.2 |

These are the oracle for `tests/cvss-temporal-environmental.test.js`.
They are hand-computed from the specification's formulas and
cross-checked with an independent throwaway computation (a direct
transcription of the formulas that does not import the module under
test). **They are not values copied from the FIRST calculator: no
network oracle was reachable from this lab, so the calculator could
not be consulted.** If a future run can reach the FIRST calculator,
re-checking these eight rows against it is the first verification
to do — a disagreement would mean the transcription (not the
implementation) is wrong somewhere, and both must be re-derived
together. The base-score rows are the specification's own published
values (see cvss-vector-v1.md) and were not re-derived this way.

## Precedence (vector vs declared scores)

`resolveCvss(finding)` now returns `{ effectiveScore, vectorScore,
error, temporalScore, environmentalScore, temporalError,
environmentalError }`:

1. A **malformed vector** is an error of its own
   (`invalid cvss_vector: ...`), as before. It never also produces
   a mismatch.
2. A **vector that disagrees with a declared base score** is an
   error (`cvss_vector/cvss_score mismatch: ...`), as before.
3. A **vector that disagrees with a declared temporal score** is an
   error of its own (`cvss_vector/cvss_temporal_score mismatch:
   vector computes to X but cvss_temporal_score is Y`). The same
   rule, separately, for the environmental score
   (`cvss_vector/cvss_environmental_score mismatch: ...`). The
   three mismatches are independent reasons: a finding can report
   a base mismatch and a temporal mismatch at once.
4. A **declared temporal/environmental score that is present but
   invalid** (not a number, out of range) is ignored here and
   reported as `invalid cvss_temporal_score` /
   `invalid cvss_environmental_score` by the callers — the same
   pattern as `invalid cvss_score`.
5. **Scores are only computed for metric groups the vector carries.**
   `temporalScore` is null when the vector has no temporal metric,
   and `environmentalScore` is null when it has no environmental
   metric — even though the score would equal the base score if
   computed (all X). An explicit X counts as present. This is
   deliberate: the generator must not fill in or render values the
   analyst never stated, so a base-only finding renders no temporal
   or environmental lines at all.
6. **Severity is checked against the BASE score only.**
   `effectiveScore` is unchanged (declared base score when valid,
   else the vector-derived base score). A temporal score of 6.7 and
   an environmental score of 5.7 on a base-7.5 finding do not
   re-band its severity from high to medium. The CVSS severity
   bands describe the base score; the temporal and environmental
   scores are reported alongside it, not instead of it.
7. When only the vector is present, the generator returns the
   finding with every computed score it did not declare filled in
   (`cvss_score`, `cvss_temporal_score`,
   `cvss_environmental_score`), so the rendered report shows the
   derived scores instead of "Not scored" — and the Markdown and
   JSON renderings carry them (`- **CVSS temporal:** 6.7`,
   `- **CVSS environmental:** 5.1`, plus the JSON fields). The
   platform templates (Immunefi, Code4rena) render the same two
   lines in their header when the fields are present.

The validator collects all of these as reasons (a finding can
report a temporal mismatch and missing evidence together); the
report generator throws on the first one. In both, a
`false_positive` confidence still wins over a bad vector.

## New finding fields

`schemas/finding.schema.json` gains two optional properties,
`cvss_temporal_score` and `cvss_environmental_score` (number, 0–10),
alongside `cvss_score`. They are not required fields.

## Known limitations

- **No offline FIRST-calculator oracle.** The expected scores in
  the tests are formula-derived and independently cross-checked,
  not copied from the FIRST calculator (see "Worked examples").
- **The stub normalizer does not carry the new fields.**
  `src/detection/normalized-record.js` drops unknown keys, so a raw
  record's `cvss_temporal_score` / `cvss_environmental_score` do
  not survive normalization; the validator and generator work on
  finding records directly. Wiring the fields through normalization
  is a future round's item (same class of gap as the round-36
  vector note in cvss-vector-v1.md).
- **Severity stays base-scored.** Temporal and environmental scores
  are reported, never used to re-band severity (see precedence
  rule 6). A consumer that needs a temporal/environmental severity
  must band those scores itself.
- **No CVSS 4.0.** This module is CVSS 3.1 only; a 4.0 vector
  (`CVSS:4.0/...`) fails with `CVSS_INVALID_PREFIX`.
