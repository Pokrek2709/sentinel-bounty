# Pipeline Integration v1 (round 32)

`tests/pipeline-integration.test.js` commits the end-to-end chain that
round 31 proved only with a throwaway driver: stub detector →
validator → dedup → report generator, all in-process over local
fixtures. No scanner, no network, no live target.

## The chain

```text
runStubDetector(fixture, defaults)   # src/detection/stub-detector.js
  -> validateFinding(finding)         # src/analysis/validator.js
  -> dedupeFindings(findings)         # src/analysis/validator.js
  -> generateReport(deduped, opts)    # src/report/generator.js
```

The report is built over the **deduped** set (first finding of each
group, in group order), so the same root cause is reported once.

## Fixtures

- `tests/fixtures/stub-scanner-output.json` (round 31) — 2 valid
  results + 1 deliberately bad result missing `title`. Pipeline: 2
  findings, 1 skipped, both verdicts `needs_evidence`, 0 duplicates,
  report counts 1 high / 1 medium. Markdown and JSON are each
  generated twice and asserted byte-identical.
- `tests/fixtures/stub-scanner-mixed.json` (round 32) — 6 results
  exercising the edges in one run:
  - `MIX-001` / `MIX-002` — same root cause (same vulnerability type,
    asset, normalized first step), different surface (different id,
    title, later steps). They dedupe to 1 group.
  - `MIX-003` — `confidence: false_positive`; verdict
    `false_positive`, and it is still rendered in the report (the
    generator renders what it is given; excluding false positives from
    reports is a policy decision for a later round, not silent
    behavior here).
  - `MIX-004` — missing `impact`; skipped by the stub with an error
    naming `impact`.
  - `MIX-005` — severity `low` with `cvss_score` 9.8; skipped by the
    stub with a severity-mismatch error.
  - `MIX-006` — confirmed, fully evidenced; verdict `valid`.
  - Pipeline: 4 findings, 2 skipped, 3 dedup groups, 1 duplicate;
    report over the deduped set counts high 2 / low 1 / total 3.

## Failure paths (also tested)

- A finding missing required fields fails the report with an error
  naming the fields, and the CLI leaves **no** output file behind
  (`tests/fixtures/report-incomplete.json` via `bin/sentinel.js
  report --finding ... --out ...` in a temp dir).
- A severity/cvss mismatch fails `generateReport` (throws matching
  `/mismatch/`) while `validateFinding` flags the same fixture as
  `needs_evidence` with a `severity/cvss mismatch` reason — the two
  stages agree the finding is bad, in their own ways.

## What is NOT covered here

- Mixed-target findings are rendered as-is, not grouped or split
  (documented limitation of the report generator; needs a grouping
  rule decision).
- False-positive findings are included in reports (see MIX-003 above).
- No AI-model verdict, no semantic dedup, no real detector — all need
  scope decisions, per the round-31 open items.
