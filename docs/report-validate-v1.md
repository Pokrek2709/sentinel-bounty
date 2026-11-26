# Report validation (round 67, Phase 7)

`sentinel report validate <report.json> [--json]` checks a JSON
report file before the operator trusts it. The generator renders
reports and `report-diff` compares two of them, but until now a
malformed or tampered report file was only discovered when another
command choked on it. Validate answers the question up front: is
this file a well-formed report whose findings check out?

The implementation lives in `src/report/validate.js`
(`readReportFileForValidation`, `validateReport`,
`renderReportValidationText`, `renderReportValidationJson`,
`deriveExpectedReportId`); the CLI handler is
`runReportValidate` in `bin/sentinel.js`, reached as a
subcommand of `sentinel report` (intercepted before
`parseOptions`, which would otherwise reject `validate` as an
unknown option).

## Checks

In order:

1. **Shape.** The file must parse as a JSON report object with a
   non-empty `report_id` string and a `findings` array, bounded
   at `MAX_FINDINGS` (10,000) with duplicate `finding_id`s
   refused. A symlinked input is refused. Shape failures are
   named errors (`REPORT_VALIDATE_INVALID_REPORT`,
   `REPORT_VALIDATE_INVALID_FINDING`,
   `REPORT_VALIDATE_DUPLICATE_FINDING_ID`,
   `REPORT_VALIDATE_TOO_MANY_FINDINGS`,
   `REPORT_VALIDATE_SYMLINK_REFUSED`) and fail before any
   verdict is produced, so a bad file can never yield a partial
   verdict.
2. **Per finding.** The strict generator check
   (`src/report/generator.js` `validateFinding` — required
   fields, severity band, CVSS vector/score agreement) runs
   first. A finding that fails it is an `error`: a structural
   defect of the file, because the generator would never have
   produced it. A finding that passes it gets its rule-based
   verdict from `src/analysis/validator.js` `validateFinding` —
   `valid`, `false_positive`, or `needs_evidence` — with the
   validator's reasons carried verbatim.
3. **Report id.** The id is recomputed the same way the
   generator derives it (SHA-256 of `{ program, sorted finding
   ids }`, first 12 hex chars — see `deriveExpectedReportId`,
   replicated rather than imported because the generator does
   not export it; the test "a generator-produced report
   validates VALID" pins the two together, so if the generator
   ever changes the formula that test fails loudly instead of
   silently agreeing) and compared with the file's `report_id`.
   A mismatch is a **warning**, not a failure — the file may
   come from an older generator version — reported as
   `report_id_matches: false` with a warning line. When
   `program_name` is missing the id cannot be recomputed at
   all, which is likewise a warning, not an error.

## Output

Text (default) and JSON (`--json`). Both are deterministic:
per-finding entries are sorted by `finding_id` (plain string
order), so the same finding set in any file order validates to
byte-identical output. No `--generated-at`: a validation
carries no wall-clock timestamp.

Text layout, in order:

```text
Report Validation — VALID
Report ID: RPT-<id> (verified)
Counts: <n> findings, <v> valid, <f> false_positive, <e> needs_evidence, <x> errors
- <id> [<status>]: <reason>; <reason>
```

The report-id line reads `(verified)` when the recomputed id
matches, otherwise `(warning: <warning text>)`. Per-finding
lines appear only for findings whose status is not `valid`,
in `finding_id` order; when every finding is valid the last
line is `All findings valid.`

JSON layout (fixed key order):

```json
{
  "status": "VALID",
  "report_id": "RPT-0536be9278ec",
  "report_id_matches": true,
  "report_id_warning": null,
  "counts": { "findings": 3, "valid": 1, "false_positive": 0, "needs_evidence": 2, "errors": 0 },
  "findings": [
    { "finding_id": "FND-CRIT-001", "status": "valid", "reasons": ["confirmed with complete evidence (proof_of_concept, evidence, steps_to_reproduce)"] }
  ]
}
```

## Exit-code rule

Exit 0 when the file parses and every finding validates — that
includes `false_positive` and `needs_evidence` findings, which
are counted but do not fail the exit code: they are findings,
not file defects. Only structural errors and band mismatches
(the `error` findings) fail, with exit 1. Shape failures
(malformed JSON, wrong shape, duplicate ids, symlinked input)
also exit 1, via the named error on stderr, like every other
command.

## What validate deliberately does not do

- No re-scoring beyond the band check: the severity/CVSS
  agreement is checked, but no new score is computed or
  written back.
- No AI verdict: the advisory verdict is a generation-time
  annotation, not a validation check.
- No audit-chain verification: that is `audit verify`'s job;
  a report file carries no chain.
- No re-rendering and no writing of any kind: validate is
  read-only. A test proves the input file is byte-identical
  (and its mtime unchanged) after a validate run.
