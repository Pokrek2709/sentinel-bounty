// Report diff (round 64): `sentinel report-diff <old.json> <new.json>`
// compares two JSON reports from two runs and shows added, removed,
// and changed findings — matched by finding_id, compared on
// severity / cvss_score / verdict (validation_status) / asset_id
// only. `merged_from` is provenance, not substance: two findings
// that differ only in merged_from are unchanged. A diff does NOT
// re-validate findings; it compares reports. Fixtures only; no
// scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  diffReports,
  renderReportDiffMarkdown,
  renderReportDiffJson,
  readReportFile,
} = require('../src/report/report-diff');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// A minimal report object for module-level tests: the diff only
// needs report_id + the findings' compared fields.
function report(reportId, findings) {
  return { report_id: reportId, findings };
}

function finding(findingId, overrides = {}) {
  return {
    finding_id: findingId,
    severity: 'medium',
    cvss_score: 5.0,
    validation_status: 'validated',
    asset_id: 'lab-app/profile',
    ...overrides,
  };
}

// The exact Markdown diff for the shared fixture pair (old: the 3
// findings of report-findings-array.json; new: CRIT unchanged, MED
// severity/score/verdict changed, LOW removed, NEW added).
const EXPECTED_DIFF_MARKDOWN = [
  'Report Diff — RPT-7e3937d9559c',
  'Old report: RPT-0536be9278ec',
  'New report: RPT-72abf10d55e5',
  'Counts: 1 added, 1 removed, 1 changed, 1 unchanged',
  '',
  'Added (1):',
  '- FND-NEW-001 | medium | CVSS 5 | lab-app/admin | validated',
  '',
  'Removed (1):',
  '- FND-LOW-001 | low | CVSS 2.5 | lab-app/robots | validated',
  '',
  'Changed (1):',
  '- FND-MED-001:',
  '  - severity: medium -> high',
  '  - cvss_score: 5 -> 7.5',
  '  - verdict: validated -> needs_review',
  '',
  'Unchanged: 1 finding.',
  '',
].join('\n');

const EXPECTED_DIFF_JSON = {
  report_id: 'RPT-7e3937d9559c',
  old_report_id: 'RPT-0536be9278ec',
  new_report_id: 'RPT-72abf10d55e5',
  added: [
    {
      finding_id: 'FND-NEW-001',
      severity: 'medium',
      cvss_score: 5,
      verdict: 'validated',
      asset_id: 'lab-app/admin',
    },
  ],
  removed: [
    {
      finding_id: 'FND-LOW-001',
      severity: 'low',
      cvss_score: 2.5,
      verdict: 'validated',
      asset_id: 'lab-app/robots',
    },
  ],
  changed: [
    {
      finding_id: 'FND-MED-001',
      changes: [
        { field: 'severity', old: 'medium', new: 'high' },
        { field: 'cvss_score', old: 5, new: 7.5 },
        { field: 'verdict', old: 'validated', new: 'needs_review' },
      ],
    },
  ],
  counts: { added: 1, removed: 1, changed: 1, unchanged: 1 },
};

test('diff renders the exact golden Markdown for the fixture pair', () => {
  const diff = diffReports(loadFixture('diff-old-report.json'), loadFixture('diff-new-report.json'));
  assert.equal(renderReportDiffMarkdown(diff), EXPECTED_DIFF_MARKDOWN);
});

test('diff renders the exact golden JSON for the fixture pair', () => {
  const diff = diffReports(loadFixture('diff-old-report.json'), loadFixture('diff-new-report.json'));
  assert.deepEqual(JSON.parse(renderReportDiffJson(diff)), EXPECTED_DIFF_JSON);
  assert.equal(renderReportDiffJson(diff), `${JSON.stringify(EXPECTED_DIFF_JSON, null, 2)}\n`);
});

test('identical reports diff to an empty diff, not an error', () => {
  const oldReport = loadFixture('diff-old-report.json');
  const diff = diffReports(oldReport, clone(oldReport));
  assert.deepEqual(diff.counts, { added: 0, removed: 0, changed: 0, unchanged: 3 });
  assert.equal(renderReportDiffMarkdown(diff), [
    'Report Diff — RPT-0ce2513283a5',
    'Old report: RPT-0536be9278ec',
    'New report: RPT-0536be9278ec',
    'Counts: 0 added, 0 removed, 0 changed, 3 unchanged',
    '',
    'No differences.',
    '',
  ].join('\n'));
});

test('added-only and removed-only cases list just that category', () => {
  const onlyAdded = diffReports(report('RPT-OLD', []), report('RPT-NEW', [finding('FND-A')]));
  assert.deepEqual(onlyAdded.counts, { added: 1, removed: 0, changed: 0, unchanged: 0 });
  assert.ok(renderReportDiffMarkdown(onlyAdded).includes('Added (1):\n- FND-A | medium | CVSS 5 | lab-app/profile | validated'));
  assert.ok(!renderReportDiffMarkdown(onlyAdded).includes('Removed'));
  const onlyRemoved = diffReports(report('RPT-OLD', [finding('FND-A')]), report('RPT-NEW', []));
  assert.deepEqual(onlyRemoved.counts, { added: 0, removed: 1, changed: 0, unchanged: 0 });
  assert.ok(renderReportDiffMarkdown(onlyRemoved).includes('Removed (1):\n- FND-A | medium | CVSS 5 | lab-app/profile | validated'));
});

test('a severity-only change lists only severity', () => {
  const diff = diffReports(
    report('RPT-OLD', [finding('FND-A')]),
    report('RPT-NEW', [finding('FND-A', { severity: 'high' })]),
  );
  assert.deepEqual(diff.changed, [{ finding_id: 'FND-A', changes: [{ field: 'severity', old: 'medium', new: 'high' }] }]);
});

test('a score-only change lists only cvss_score', () => {
  const diff = diffReports(
    report('RPT-OLD', [finding('FND-A')]),
    report('RPT-NEW', [finding('FND-A', { cvss_score: 7.5 })]),
  );
  assert.deepEqual(diff.changed, [{ finding_id: 'FND-A', changes: [{ field: 'cvss_score', old: 5, new: 7.5 }] }]);
});

test('a verdict-only change lists only verdict (validation_status)', () => {
  const diff = diffReports(
    report('RPT-OLD', [finding('FND-A')]),
    report('RPT-NEW', [finding('FND-A', { validation_status: 'needs_review' })]),
  );
  assert.deepEqual(diff.changed, [{ finding_id: 'FND-A', changes: [{ field: 'verdict', old: 'validated', new: 'needs_review' }] }]);
});

test('an asset-only change lists only asset_id', () => {
  const diff = diffReports(
    report('RPT-OLD', [finding('FND-A')]),
    report('RPT-NEW', [finding('FND-A', { asset_id: 'lab-app/other' })]),
  );
  assert.deepEqual(diff.changed, [{ finding_id: 'FND-A', changes: [{ field: 'asset_id', old: 'lab-app/profile', new: 'lab-app/other' }] }]);
});

test('a merged_from-only difference is unchanged (provenance, not substance)', () => {
  const diff = diffReports(
    report('RPT-OLD', [finding('FND-A')]),
    report('RPT-NEW', [finding('FND-A', { merged_from: ['FND-A', 'FND-B'] })]),
  );
  assert.deepEqual(diff.counts, { added: 0, removed: 0, changed: 0, unchanged: 1 });
});

test('the same report sets in any finding order diff byte-identically', () => {
  const oldReport = loadFixture('diff-old-report.json');
  const newReport = loadFixture('diff-new-report.json');
  const reversedOld = { ...oldReport, findings: [...oldReport.findings].reverse() };
  const reversedNew = { ...newReport, findings: [...newReport.findings].reverse() };
  assert.equal(
    renderReportDiffMarkdown(diffReports(oldReport, newReport)),
    renderReportDiffMarkdown(diffReports(reversedOld, reversedNew)),
  );
  assert.equal(
    renderReportDiffJson(diffReports(oldReport, newReport)),
    renderReportDiffJson(diffReports(reversedOld, reversedNew)),
  );
});

test('readReportFile refuses malformed and wrong-shape inputs with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const cases = [
    ['malformed.json', '{ not json', /REPORT_DIFF_INVALID_REPORT/],
    ['array.json', '[]', /REPORT_DIFF_INVALID_REPORT/],
    ['no-findings.json', JSON.stringify({ report_id: 'RPT-X' }), /REPORT_DIFF_INVALID_REPORT: .* has no findings array/],
    ['no-id.json', JSON.stringify({ findings: [] }), /REPORT_DIFF_INVALID_REPORT: .* has no report_id/],
    ['no-finding-id.json', JSON.stringify({ report_id: 'RPT-X', findings: [{ severity: 'low' }] }), /REPORT_DIFF_INVALID_FINDING/],
    ['duplicate.json', JSON.stringify({ report_id: 'RPT-X', findings: [finding('FND-A'), finding('FND-A')] }), /REPORT_DIFF_DUPLICATE_FINDING_ID: .*FND-A/],
  ];
  for (const [name, content, pattern] of cases) {
    const filePath = path.join(dir, name);
    fs.writeFileSync(filePath, content);
    await assert.rejects(() => readReportFile(filePath), pattern, name);
  }
});

test('readReportFile refuses a symlinked input', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const real = path.join(dir, 'real.json');
  fs.writeFileSync(real, JSON.stringify({ report_id: 'RPT-X', findings: [] }));
  const link = path.join(dir, 'link.json');
  fs.symlinkSync(real, link);
  await assert.rejects(() => readReportFile(link), /REPORT_DIFF_SYMLINK_REFUSED/);
});

test('readReportFile refuses more than 10,000 findings', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const findings = Array.from({ length: 10001 }, (_, index) => finding(`FND-${String(index).padStart(5, '0')}`));
  const filePath = path.join(dir, 'too-many.json');
  fs.writeFileSync(filePath, JSON.stringify({ report_id: 'RPT-X', findings }));
  await assert.rejects(() => readReportFile(filePath), /REPORT_DIFF_TOO_MANY_FINDINGS/);
});

test('CLI report-diff prints the exact golden Markdown to stdout', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report-diff', oldPath, newPath], { cwd: dir });
  assert.equal(stdout, EXPECTED_DIFF_MARKDOWN);
});

test('CLI report-diff --format json prints the golden JSON', async () => {
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report-diff', oldPath, newPath, '--format', 'json']);
  assert.deepEqual(JSON.parse(stdout), EXPECTED_DIFF_JSON);
});

test('CLI report-diff --out writes mode 0600 with the same content as stdout', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  const outPath = path.join(dir, 'diff.md');
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report-diff', oldPath, newPath, '--out', outPath]);
  assert.ok(stdout.includes('written to'), 'writes a confirmation line');
  assert.equal(fs.readFileSync(outPath, 'utf8'), EXPECTED_DIFF_MARKDOWN);
  assert.equal(fs.statSync(outPath).mode & 0o777, 0o600);
});

test('CLI report-diff refuses --template cleanly', async () => {
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report-diff', oldPath, newPath, '--template', 'immunefi']),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /report-diff does not take --template/);
      return true;
    },
  );
});

test('CLI report-diff requires two report files', async () => {
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report-diff', oldPath]),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /report-diff requires two report files/);
      return true;
    },
  );
});

test('CLI report-diff on a malformed input fails with a named error and writes no file', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const badPath = path.join(dir, 'bad.json');
  fs.writeFileSync(badPath, '{ not json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  const outPath = path.join(dir, 'diff.md');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report-diff', badPath, newPath, '--out', outPath]),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  assert.ok(!fs.existsSync(outPath), 'no half-written output file');
});

test('CLI report-diff --out through a symlink is refused and the target is untouched', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-diff-');
  const target = path.join(dir, 'target.txt');
  fs.writeFileSync(target, 'original');
  const link = path.join(dir, 'link.md');
  fs.symlinkSync(target, link);
  const oldPath = path.join(__dirname, 'fixtures', 'diff-old-report.json');
  const newPath = path.join(__dirname, 'fixtures', 'diff-new-report.json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report-diff', oldPath, newPath, '--out', link]),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /Refusing to write through a symbolic link/);
      return true;
    },
  );
  assert.equal(fs.readFileSync(target, 'utf8'), 'original');
});
