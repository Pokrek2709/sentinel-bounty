// Report render (round 75): `sentinel report render <report.json>
// --format markdown|json|html|csv|summary|jsonl [--out <file>]`
// re-renders an existing JSON report file into another format
// through the generator's own render path, so the output is
// byte-identical to what the generator would have produced for
// the same finding set. The source report's generated_at is
// carried through (never re-stamped); a platform-template source
// is refused; a mixed-target source renders only when it
// declares mixed_targets; render adds no validation of its own.
// Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { renderReport, RENDER_FORMATS } = require('../src/report/render');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const ALL = loadFixture('report-findings-array.json');
const CRIT = ALL[0];
const MED = ALL[1];
const LOW = ALL[2];
// HIGH and INFO are clones of MED/LOW with a changed score only:
// neither carries a cvss_vector, so no vector can disagree with
// the new score, and the strict check passes.
const HIGH = { ...clone(MED), finding_id: 'FND-HIGH-001', severity: 'high', cvss_score: 7.0 };
const INFO = { ...clone(LOW), finding_id: 'FND-INFO-001', severity: 'informational', cvss_score: 0.0 };
const FIVE = [CRIT, HIGH, MED, LOW, INFO];
const FP = loadFixture('false-positive.json');
const PROGRAM = 'Lab Program';
const GENERATED_AT = '2026-11-26T02:00:00.000Z';
// The FIVE set's report id (same derivation as the generator's;
// the stats golden pins it too).
const FIVE_REPORT_ID = 'RPT-3aeafa977190';

// A generator-produced JSON report for the given findings
// (program "Lab Program", fixed generated_at so ids are stable).
function generatedReport(findings, generatedAt = GENERATED_AT, programName = PROGRAM, extraOptions = {}) {
  return JSON.parse(generateReport(findings, {
    programName,
    generatedAt,
    format: 'json',
    ...extraOptions,
  }));
}

function direct(findings, format, extraOptions = {}) {
  return generateReport(findings, {
    programName: PROGRAM,
    generatedAt: GENERATED_AT,
    format,
    ...extraOptions,
  });
}

test('RENDER_FORMATS lists exactly the six generator formats', () => {
  assert.deepEqual(RENDER_FORMATS, ['markdown', 'json', 'html', 'csv', 'summary', 'jsonl']);
});

for (const format of RENDER_FORMATS) {
  test(`re-rendering to ${format} is byte-identical to direct generation`, () => {
    const rendered = renderReport(generatedReport(FIVE), { format });
    assert.equal(rendered.report, direct(FIVE, format));
    assert.deepEqual(rendered.summary, { format, total: 5, report_id: FIVE_REPORT_ID });
  });
}

test('rendering is deterministic across source input orders', () => {
  const forward = generatedReport(FIVE);
  const shuffled = generatedReport([INFO, LOW, CRIT, MED, HIGH]);
  assert.deepEqual(shuffled, forward);
  for (const format of RENDER_FORMATS) {
    assert.equal(
      renderReport(shuffled, { format }).report,
      renderReport(forward, { format }).report,
    );
  }
});

test('the source generated_at is carried through, not re-stamped', () => {
  // The findings' created_at is 2026-11-26T00:00:00.000Z; the
  // source report's generated_at is 02:00 — the render must keep
  // the source value.
  const rendered = renderReport(generatedReport(FIVE), { format: 'markdown' });
  assert.match(rendered.report, /Generated: 2026-11-26T02:00:00\.000Z/);
  const json = JSON.parse(renderReport(generatedReport(FIVE), { format: 'json' }).report);
  assert.equal(json.generated_at, GENERATED_AT);
  assert.equal(json.report_id, FIVE_REPORT_ID);
});

test('a source without generated_at falls back to the newest finding created_at', () => {
  const report = generatedReport(FIVE);
  delete report.generated_at;
  const rendered = renderReport(report, { format: 'markdown' });
  assert.match(rendered.report, /Generated: 2026-11-26T00:00:00\.000Z/);
  // JSON still renders: the fallback timestamp satisfies the schema.
  const json = JSON.parse(renderReport(report, { format: 'json' }).report);
  assert.equal(json.generated_at, '2026-11-26T00:00:00.000Z');
});

test('JSON render with no timestamp anywhere fails with the named error; markdown renders "Not specified"', () => {
  const report = generatedReport(FIVE);
  delete report.generated_at;
  for (const finding of report.findings) delete finding.created_at;
  assert.throws(
    () => renderReport(report, { format: 'json' }),
    (error) => {
      assert.match(error.message, /REPORT_RENDER_NO_GENERATED_AT/);
      return true;
    },
  );
  const rendered = renderReport(report, { format: 'markdown' });
  assert.match(rendered.report, /Generated: Not specified/);
});

test('an unknown or missing format fails with the named error listing all six formats', () => {
  const report = generatedReport(FIVE);
  for (const bad of ['pdf', 'yaml', '', undefined, null]) {
    assert.throws(
      () => renderReport(report, { format: bad }),
      (error) => {
        assert.match(error.message, /REPORT_RENDER_INVALID_FORMAT/);
        assert.match(error.message, /"markdown", "json", "html", "csv", "summary", or "jsonl"/);
        return true;
      },
    );
  }
});

test('a platform-template source is refused; an explicit generic template renders', () => {
  const templated = JSON.parse(generateReport([CRIT], {
    programName: PROGRAM,
    generatedAt: GENERATED_AT,
    format: 'json',
    template: 'immunefi',
  }));
  assert.equal(templated.template, 'immunefi');
  assert.throws(
    () => renderReport(templated, { format: 'markdown' }),
    (error) => {
      assert.match(error.message, /REPORT_RENDER_TEMPLATE_REFUSED/);
      assert.match(error.message, /immunefi/);
      return true;
    },
  );
  const generic = generatedReport(FIVE);
  generic.template = 'generic';
  assert.equal(renderReport(generic, { format: 'markdown' }).report, direct(FIVE, 'markdown'));
});

test('a mixed-target source renders when it declares mixed_targets, byte-identical to direct generation', () => {
  // FIVE + FP: the FP fixture names another target, so the
  // report is generated with the explicit opt-in.
  const mixed = generatedReport([...FIVE, FP], GENERATED_AT, PROGRAM, { allowMixedTargets: true });
  assert.equal(mixed.mixed_targets, true);
  for (const format of RENDER_FORMATS) {
    assert.equal(
      renderReport(mixed, { format }).report,
      direct([...FIVE, FP], format, { allowMixedTargets: true }),
    );
  }
});

test('a hand-edited second target without the declaration is refused by the generator', () => {
  const edited = generatedReport(FIVE);
  edited.findings[0].target_id = 'TGT-LAB-002';
  assert.throws(
    () => renderReport(edited, { format: 'markdown' }),
    (error) => {
      assert.match(error.message, /REPORT_MIXED_TARGETS_REFUSED/);
      return true;
    },
  );
});

test('an empty source renders the empty-set outputs for csv/summary/jsonl and refuses markdown/json', () => {
  const empty = { report_id: 'RPT-000000000000', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [] };
  assert.equal(renderReport(empty, { format: 'csv' }).report, direct([], 'csv'));
  assert.equal(renderReport(empty, { format: 'summary' }).report, direct([], 'summary'));
  assert.equal(renderReport(empty, { format: 'jsonl' }).report, direct([], 'jsonl'));
  assert.throws(
    () => renderReport(empty, { format: 'markdown' }),
    /At least one finding is required/,
  );
  assert.throws(
    () => renderReport(empty, { format: 'json' }),
    /At least one finding is required/,
  );
});

test('transformation metadata blocks are not carried through to the rendered report', () => {
  const source = generatedReport(FIVE);
  source.split = { from_report_id: 'RPT-OLD', group_by: 'severity', group: 'critical' };
  source.filter = { from_report_id: 'RPT-OLD', severity: 'high' };
  source.anonymized = true;
  source.anonymization = { salt_source: 'default', patterns: [] };
  const parsed = JSON.parse(renderReport(source, { format: 'json' }).report);
  assert.equal('split' in parsed, false);
  assert.equal('filter' in parsed, false);
  assert.equal('anonymized' in parsed, false);
  assert.equal('anonymization' in parsed, false);
  assert.equal(parsed.report_id, FIVE_REPORT_ID);
});

test('CLI report render prints the exact markdown and the summary line on stderr', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'markdown'], { cwd: dir });
  assert.equal(stdout, direct(FIVE, 'markdown'));
  assert.equal(stderr, `rendered 5 findings as markdown from ${FIVE_REPORT_ID}\n`);
});

test('CLI report render --format json prints pure parseable JSON, byte-identical to the source', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'json'], { cwd: dir });
  assert.equal(stdout, direct(FIVE, 'json'));
  assert.deepEqual(JSON.parse(stdout), generatedReport(FIVE));
  assert.equal(stderr, `rendered 5 findings as json from ${FIVE_REPORT_ID}\n`);
});

test('CLI report render --format jsonl prints one parseable JSON object per line', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'jsonl'], { cwd: dir });
  assert.equal(stdout, direct(FIVE, 'jsonl'));
  const lines = stdout.trimEnd().split('\n');
  assert.equal(lines.length, 6);
  assert.equal(JSON.parse(lines[0]).type, 'report-summary');
  assert.equal(JSON.parse(lines[0]).total, 5);
  for (const line of lines.slice(1)) assert.equal(typeof JSON.parse(line).finding_id, 'string');
});

test('CLI report render --out writes mode 0600, reports the path, and leaves the input untouched', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  const input = JSON.stringify(generatedReport(FIVE), null, 2);
  fs.writeFileSync(filePath, input);
  const before = fs.statSync(filePath);
  const outPath = path.join(dir, 'out.md');
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'markdown', '--out', outPath], { cwd: dir });
  assert.equal(stdout, `Rendered report written to ${outPath}\n`);
  assert.equal(stderr, `rendered 5 findings as markdown from ${FIVE_REPORT_ID}\n`);
  assert.equal(fs.readFileSync(outPath, 'utf8'), direct(FIVE, 'markdown'));
  assert.equal(fs.statSync(outPath).mode & 0o777, 0o600);
  const after = fs.statSync(filePath);
  assert.equal(fs.readFileSync(filePath, 'utf8'), input);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test('CLI report render without --format fails with the usage error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', filePath], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /requires --format/);
      return true;
    },
  );
});

test('CLI report render with an unknown format or unknown option fails', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'pdf'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_RENDER_INVALID_FORMAT/);
      return true;
    },
  );
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', filePath, '--format', 'markdown', '--bogus', 'x'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /Unknown option: --bogus/);
      return true;
    },
  );
});

test('CLI report render on a malformed or wrong-shape input fails with a named error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const badPath = path.join(dir, 'bad.json');
  fs.writeFileSync(badPath, '{ not json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', badPath, '--format', 'markdown'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  const shapePath = path.join(dir, 'shape.json');
  fs.writeFileSync(shapePath, JSON.stringify({ report_id: 'RPT-X' }));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', shapePath, '--format', 'markdown'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
});

test('CLI report render refuses a symlinked input', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  const realPath = path.join(dir, 'real.json');
  const linkPath = path.join(dir, 'link.json');
  fs.writeFileSync(realPath, JSON.stringify(generatedReport(FIVE), null, 2));
  fs.symlinkSync(realPath, linkPath);
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', linkPath, '--format', 'markdown'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI report render with no file fails with the usage error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-render-');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'render', '--format', 'markdown'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /requires a report file/);
      return true;
    },
  );
});
