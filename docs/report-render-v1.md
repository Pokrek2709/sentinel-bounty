# Re-render an existing report into another format (round 75, Phase 7)

`sentinel report render <report.json> --format markdown|json|html|csv|summary|jsonl
[--out <file>]` re-renders an existing JSON report file into
another format, through the generator's own render path.

Every report command so far either generates a report from
findings or transforms one report into another, but an operator
who already HAS a JSON report file and wants it as Markdown,
HTML, CSV, summary, or JSONL had no way to get it without
re-running the whole pipeline. Render closes that loop: it is a
format conversion of an existing artifact, not a new
generation.

The implementation lives in `src/report/render.js`
(`renderReport`); the CLI handler is `runReportRender` in
`bin/sentinel.js`.

## Byte-identical guarantee

The output is byte-identical to what the generator would have
produced for the same finding set — the same report_id
derivation, the same grouping, the same counts — because the
findings go through `generateReport` itself with the source
report's program name (`program_name`, or `Unnamed Program`
when absent) and generated_at. The only input the render adds
is the requested format.

## generated_at: carried through, never re-stamped

The source report's own `generated_at` is carried through, via
the shared `pickGeneratedAt` helper (round 73): the source's
`generated_at` when valid, else the newest finding `created_at`,
else nothing. A re-render never invents a new timestamp.

For JSON output a missing timestamp fails with
`REPORT_RENDER_NO_GENERATED_AT` (the report schema requires
`generated_at`); every other format renders without one —
Markdown/HTML print "Not specified", CSV/summary/JSONL carry
no timestamp at all — the generator's own behavior.

## Format

`--format` is required and must be one of `markdown`, `json`,
`html`, `csv`, `summary`, `jsonl`. Anything else fails with
`REPORT_RENDER_INVALID_FORMAT`, which lists all six formats.

## Mixed targets

A source report that declares `mixed_targets` renders with the
opt-in carried by its own declaration — the report itself is
the opt-in, so no `--allow-mixed-targets` flag is needed (and
none is accepted). A hand-edited file that smuggles a second
target in without the declaration is refused by the generator
with `REPORT_MIXED_TARGETS_REFUSED`, the same fail-closed
logic as generation (round 49).

## Template reports are refused

A source report that carries a platform template (`immunefi`,
`code4rena`, `hackerone`, `bugcrowd`) is refused with
`REPORT_RENDER_TEMPLATE_REFUSED`. A template report is a
one-finding platform submission; re-rendering it through the
generic path would lose the template, and re-rendering it
through the template path is generation, not conversion.
Generate it again from the finding with `--template` instead.
A report whose `template` field is absent or `generic`
renders normally.

## Output

The rendered report goes to stdout (pipeable) or `--out`
(safe-write, mode 0600); the one-line summary (`rendered N
findings as <format> from <report-id>`) always goes to stderr,
so stdout stays a clean report. The render is computed fully
in memory first, so a bad input can never leave a
half-written file behind. The input file is never modified.

## What render deliberately does not do

- No re-validation of its own: render does not re-judge
  verdicts, re-score, or run an AI verifier (same as
  diff/merge: a render re-renders, it does not re-judge).
  The generator's own render path still applies its strict
  check — a finding whose severity disagrees with its CVSS
  score, or that is missing a required field, fails the
  render with the generator's error — because byte-identical
  output requires going through that path.
- No re-scoring: scores are the file's scores.
- Transformation metadata is not carried through: a source
  report that came from split / filter / anonymize carries a
  `split`, `filter`, or `anonymization` block, and the
  rendered output is a fresh generic report of the findings —
  no such block — because the generator's output for the same
  finding set has none. The block is provenance of the
  transformation, not of the findings.
- A report rendered from a hand-edited JSON file carries the
  hand-edited content. Validate it first with
  `report validate` if you distrust the file.

## Errors

- `REPORT_RENDER_INVALID_FORMAT`: unknown `--format` value
  (the message lists all six formats).
- `REPORT_RENDER_TEMPLATE_REFUSED`: the source report
  carries a platform template.
- `REPORT_RENDER_NO_GENERATED_AT`: JSON render with no
  timestamp in the source report and no `created_at` on any
  finding.
- `REPORT_MIXED_TARGETS_REFUSED` (generator): the source
  covers two targets without declaring `mixed_targets`.
- Shape failures carry `REPORT_DIFF_*` codes (the round-64
  shared reader: bounded 10 MiB, depth 100, symlinked input
  refused).
