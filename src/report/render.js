// Report render (round 75, Phase 7): re-render an existing JSON
// report file into another format — Markdown, JSON, HTML, CSV,
// summary, or JSONL — through the generator's own render path.
//
// Every report command so far either generates a report from
// findings or transforms one report into another, but an operator
// who already HAS a JSON report file and wants it as Markdown,
// HTML, CSV, summary, or JSONL had no way to get it without
// re-running the whole pipeline. Render closes that loop: it is a
// format conversion of an existing artifact, not a new generation.
//
// Byte-identical guarantee: the output is byte-identical to what
// the generator would have produced for the same finding set —
// the same report_id derivation, the same grouping, the same
// counts — because the findings go through generateReport itself
// with the source report's program name and generated_at. The
// only input the render adds is the requested format.
//
// generated_at: the source report's own generated_at is carried
// through, via the shared pickGeneratedAt helper (round 73) —
// the source's generated_at when valid, else the newest finding
// created_at, else nothing. A re-render never invents a new
// timestamp. For JSON output a missing timestamp fails with
// REPORT_RENDER_NO_GENERATED_AT (the report schema requires
// generated_at); every other format renders without one
// (Markdown/HTML print "Not specified", CSV/summary/JSONL carry
// no timestamp at all), the generator's own behavior.
//
// Mixed targets (round 49 rules): a source report that declares
// mixed_targets renders with the opt-in carried by its own
// declaration — the report itself is the opt-in, so no flag is
// needed. A hand-edited file that smuggles a second target in
// without the declaration is refused by the generator with
// REPORT_MIXED_TARGETS_REFUSED, the same fail-closed logic as
// generation.
//
// Template reports: a source report that carries a platform
// template (immunefi / code4rena / hackerone / bugcrowd) is
// refused with REPORT_RENDER_TEMPLATE_REFUSED. A template report
// is a one-finding platform submission; re-rendering it through
// the generic path would lose the template, and re-rendering it
// through the template path is generation, not conversion.
// Generate it again from the finding with --template instead.
// A report whose template field is absent or 'generic' renders
// normally.
//
// Validation: render does NOT add any validation of its own —
// it does not re-judge verdicts, re-score, or run an AI
// verifier (same as diff/merge: a render re-renders, it does
// not re-judge). The generator's own render path still applies
// its strict check (a finding whose severity disagrees with its
// CVSS score, or that is missing a required field, fails the
// render with the generator's error), because byte-identical
// output requires going through that path. A report rendered
// from a hand-edited file carries the hand-edited content —
// validate it first with `report validate` if you distrust the
// file.
//
// Transformation metadata is NOT carried through: a source
// report that came from split / filter / anonymize carries a
// `split`, `filter`, or `anonymization` block, and the rendered
// output is a fresh generic report of the findings — no such
// block — because the generator's output for the same finding
// set has none. The block is provenance of the transformation,
// not of the findings.
//
// Inputs are read with readReportFile from report-diff.js (round
// 64): bounded (10 MiB, depth 100), symlinked input refused.
// Shape failures therefore carry REPORT_DIFF_* codes — the reader
// is shared, not re-implemented — and fail before any output is
// produced, so a bad input can never leave a half-written file
// behind. Read-only on the input: the only write is --out.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const { generateReport, pickGeneratedAt } = require('./generator');
const { programOf } = require('./merge');

// The six formats the generator renders (see generateReport).
const RENDER_FORMATS = ['markdown', 'json', 'html', 'csv', 'summary', 'jsonl'];

// Re-render a parsed report object (report_id + findings array,
// shape-checked first) into the requested format. Returns
// { report, summary } where report is the rendered text and
// summary is { format, total, report_id } for the CLI's
// one-line stderr line. Throws named errors: an unknown format
// (REPORT_RENDER_INVALID_FORMAT, listing all six), a template
// report (REPORT_RENDER_TEMPLATE_REFUSED), or a JSON render
// with no timestamp anywhere (REPORT_RENDER_NO_GENERATED_AT).
// A mixed-target source without its own declaration, and any
// finding that fails the generator's strict check, fail with
// the generator's own errors.
function renderReport(report, { format }) {
  if (typeof format !== 'string' || !RENDER_FORMATS.includes(format)) {
    throw new Error(
      `REPORT_RENDER_INVALID_FORMAT: unknown format "${String(format)}" ` +
      '(expected "markdown", "json", "html", "csv", "summary", or "jsonl").',
    );
  }
  const template = typeof report.template === 'string' ? report.template.trim() : '';
  if (template !== '' && template !== 'generic') {
    throw new Error(
      `REPORT_RENDER_TEMPLATE_REFUSED: report uses template "${template}"; ` +
      're-rendering a platform-template report is not supported — ' +
      `generate it again from the finding with --template ${template}.`,
    );
  }
  const generatedAt = pickGeneratedAt([report], report.findings);
  if (format === 'json' && generatedAt === null) {
    throw new Error(
      'REPORT_RENDER_NO_GENERATED_AT: cannot render JSON without a generated_at timestamp: ' +
      'the source report has none and no finding carries a created_at.',
    );
  }
  const rendered = generateReport(report.findings, {
    programName: programOf(report),
    generatedAt,
    format,
    allowMixedTargets: report.mixed_targets === true,
  });
  return {
    report: rendered,
    summary: {
      format,
      total: report.findings.length,
      report_id: report.report_id,
    },
  };
}

module.exports = {
  RENDER_FORMATS,
  renderReport,
};
