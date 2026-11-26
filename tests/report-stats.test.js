// Report stats (round 74): `sentinel report stats <report.json>
// [--json]` prints a compact triage summary of one JSON report —
// total, counts by severity / rule verdict / class, the CVSS
// distribution, and the top 5 assets — plus the generator's
// executive summary line. Severity counts come from the
// generator's exported `countBySeverity`, the summary line from
// its exported `executiveSummary`, and verdicts from round 67's
// `validateOneFinding` (the RULE verdict, not the stored
// `validation_status` workflow state). Stats never fails on
// content: exit 0 whenever the file parses, even for an
// all-false-positive report or a report full of `error`
// findings. Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { computeReportStats, renderReportStatsText, renderReportStatsJson, classOf } = require('../src/report/stats');
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
// Rule verdicts in the FIVE set: CRIT is valid; HIGH, MED, LOW,
// INFO are needs_evidence (all carry validation_status
// "validated" — the workflow state, which is NOT the verdict).
const FP = loadFixture('false-positive.json');
const PROGRAM = 'Lab Program';
const GENERATED_AT = '2026-11-26T02:00:00.000Z';

// A generator-produced JSON report for the given findings
// (program "Lab Program", fixed generated_at so ids are stable).
function generatedReport(findings, generatedAt = GENERATED_AT, programName = PROGRAM) {
  return JSON.parse(generateReport(findings, {
    programName,
    generatedAt,
    format: 'json',
  }));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// Hand-computed stats for the FIVE set:
//   severity: 1 critical, 1 high, 1 medium, 1 low, 1 informational
//   verdict: 1 valid (CRIT), 4 needs_evidence
//   class: information disclosure 4 (HIGH, MED, LOW, INFO),
//     sql injection 1 (CRIT)
//   cvss: 5 scored (9.8 + 7.0 + 5.0 + 2.5 + 0.0 = 24.3, mean 4.86),
//     min 0, max 9.8
//   top assets: lab-app/profile 2 (HIGH, MED), lab-app/robots 2
//     (LOW, INFO), lab-app/login 1 (CRIT) — the tie at 2 breaks
//     by asset_id string order ('profile' < 'robots').
const EXPECTED_FIVE_STATS = {
  report_id: 'RPT-3aeafa977190',
  summary: 'Program Lab Program: 5 validated finding(s) — 1 critical, 1 high, 1 medium, 1 low, 1 informational. Highest severity: critical. All findings in this report were validated against the finding schema before rendering.',
  total: 5,
  by_severity: { critical: 1, high: 1, medium: 1, low: 1, informational: 1 },
  by_verdict: { valid: 1, false_positive: 0, needs_evidence: 4, error: 0 },
  by_class: [
    { class: 'information disclosure', count: 4 },
    { class: 'sql injection', count: 1 },
  ],
  cvss: { scored: 5, unscored: 0, min: 0, max: 9.8, mean: 4.86 },
  top_assets: [
    { asset_id: 'lab-app/profile', count: 2 },
    { asset_id: 'lab-app/robots', count: 2 },
    { asset_id: 'lab-app/login', count: 1 },
  ],
};

const EXPECTED_FIVE_TEXT = `Report Stats — RPT-3aeafa977190
Program Lab Program: 5 validated finding(s) — 1 critical, 1 high, 1 medium, 1 low, 1 informational. Highest severity: critical. All findings in this report were validated against the finding schema before rendering.
Total: 5 findings
Severity: critical 1, high 1, medium 1, low 1, informational 1
Verdict: valid 1, false_positive 0, needs_evidence 4, error 0
Class: information disclosure 4, sql injection 1
CVSS: 5 scored, 0 unscored; min 0, max 9.8, mean 4.86
Top assets:
- lab-app/profile: 2
- lab-app/robots: 2
- lab-app/login: 1
`;

const EXPECTED_FIVE_JSON = `{
  "report_id": "RPT-3aeafa977190",
  "summary": "Program Lab Program: 5 validated finding(s) — 1 critical, 1 high, 1 medium, 1 low, 1 informational. Highest severity: critical. All findings in this report were validated against the finding schema before rendering.",
  "total": 5,
  "by_severity": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 1,
    "informational": 1
  },
  "by_verdict": {
    "valid": 1,
    "false_positive": 0,
    "needs_evidence": 4,
    "error": 0
  },
  "by_class": [
    {
      "class": "information disclosure",
      "count": 4
    },
    {
      "class": "sql injection",
      "count": 1
    }
  ],
  "cvss": {
    "scored": 5,
    "unscored": 0,
    "min": 0,
    "max": 9.8,
    "mean": 4.86
  },
  "top_assets": [
    {
      "asset_id": "lab-app/profile",
      "count": 2
    },
    {
      "asset_id": "lab-app/robots",
      "count": 2
    },
    {
      "asset_id": "lab-app/login",
      "count": 1
    }
  ]
}
`;

const EXPECTED_EMPTY_TEXT = `Report Stats — RPT-000000000000
Program Lab Program: 0 validated finding(s) — 0 critical, 0 high, 0 medium, 0 low, 0 informational. Highest severity: informational. All findings in this report were validated against the finding schema before rendering.
Total: 0 findings
Severity: critical 0, high 0, medium 0, low 0, informational 0
Verdict: valid 0, false_positive 0, needs_evidence 0, error 0
Class: none
CVSS: 0 scored, 0 unscored; no scored findings
Top assets: none
`;

// A report object built literally (not via generateReport, which
// refuses error findings): the stats module takes a parsed report.
function literalReport(findings, reportId = 'RPT-000000000000') {
  return { report_id: reportId, program_name: PROGRAM, generated_at: GENERATED_AT, findings };
}

test('stats of the FIVE set match the hand-computed values exactly', () => {
  assert.deepEqual(computeReportStats(generatedReport(FIVE)), EXPECTED_FIVE_STATS);
});

test('stats text of the FIVE set matches the golden text', () => {
  assert.equal(renderReportStatsText(computeReportStats(generatedReport(FIVE))), EXPECTED_FIVE_TEXT);
});

test('stats JSON of the FIVE set matches the golden JSON', () => {
  assert.equal(renderReportStatsJson(computeReportStats(generatedReport(FIVE))), EXPECTED_FIVE_JSON);
});

test('adding the false-positive fixture changes verdict, class, CVSS, and top assets exactly as hand-computed', () => {
  // FIVE + FP (mixed targets — the FP fixture names another
  // target, so the report is generated with the explicit opt-in).
  // Hand-computed: total 6; low 2; false_positive 1; classes add
  // missing authentication 1; cvss mean (24.3 + 2) / 6 = 4.38;
  // top assets add lab-asset-03 1.
  const report = JSON.parse(generateReport([...FIVE, FP], {
    programName: PROGRAM,
    generatedAt: GENERATED_AT,
    format: 'json',
    allowMixedTargets: true,
  }));
  const stats = computeReportStats(report);
  assert.equal(stats.total, 6);
  assert.deepEqual(stats.by_severity, { critical: 1, high: 1, medium: 1, low: 2, informational: 1 });
  assert.deepEqual(stats.by_verdict, { valid: 1, false_positive: 1, needs_evidence: 4, error: 0 });
  assert.deepEqual(stats.by_class, [
    { class: 'information disclosure', count: 4 },
    { class: 'missing authentication', count: 1 },
    { class: 'sql injection', count: 1 },
  ]);
  assert.deepEqual(stats.cvss, { scored: 6, unscored: 0, min: 0, max: 9.8, mean: 4.38 });
  assert.deepEqual(stats.top_assets, [
    { asset_id: 'lab-app/profile', count: 2 },
    { asset_id: 'lab-app/robots', count: 2 },
    { asset_id: 'lab-app/login', count: 1 },
    { asset_id: 'lab-asset-03', count: 1 },
  ]);
});

test('classOf normalizes the class and maps a missing or blank type to unknown', () => {
  assert.equal(classOf({ vulnerability_type: '  SQL Injection ' }), 'sql injection');
  assert.equal(classOf({ vulnerability_type: 'SQL Injection' }), 'sql injection');
  assert.equal(classOf({ vulnerability_type: '' }), 'unknown');
  assert.equal(classOf({ vulnerability_type: '   ' }), 'unknown');
  assert.equal(classOf({}), 'unknown');
});

test('an unscored finding counts as unscored and leaves min/max/mean to the scored ones', () => {
  // No cvss_score and no cvss_vector: the strict check passes
  // (needs_evidence), so only the CVSS counting changes.
  const noscore = { ...clone(LOW), finding_id: 'FND-NOSCORE-001' };
  delete noscore.cvss_score;
  delete noscore.cvss_vector;
  const stats = computeReportStats(literalReport([CRIT, MED, noscore]));
  assert.deepEqual(stats.cvss, { scored: 2, unscored: 1, min: 5, max: 9.8, mean: 7.4 });
  assert.deepEqual(stats.by_verdict, { valid: 1, false_positive: 0, needs_evidence: 2, error: 0 });
});

test('a band-mismatch finding counts as an error verdict and is still included in the total', () => {
  // Critical severity with a 2.5 score: the strict check throws,
  // so validateOneFinding returns status 'error'.
  const band = { ...clone(LOW), finding_id: 'FND-BAND-001', severity: 'critical' };
  const stats = computeReportStats(literalReport([CRIT, band]));
  assert.equal(stats.total, 2);
  assert.deepEqual(stats.by_verdict, { valid: 1, false_positive: 0, needs_evidence: 0, error: 1 });
  // The severity count still counts the declared severity.
  assert.deepEqual(stats.by_severity, { critical: 2, high: 0, medium: 0, low: 0, informational: 0 });
});

test('a blank class counts as unknown and a finding without an asset is excluded from top assets but kept in the total', () => {
  const blankType = { ...clone(LOW), finding_id: 'FND-BLANKTYPE-001', vulnerability_type: '   ' };
  const noAsset = { ...clone(LOW), finding_id: 'FND-NOASSET-001' };
  delete noAsset.asset_id;
  const stats = computeReportStats(literalReport([CRIT, blankType, noAsset]));
  assert.equal(stats.total, 3);
  // CRIT is 'sql injection', blankType is 'unknown', noAsset keeps
  // LOW's 'information disclosure' — all count 1, so the order is
  // class-name ascending.
  assert.deepEqual(stats.by_class, [
    { class: 'information disclosure', count: 1 },
    { class: 'sql injection', count: 1 },
    { class: 'unknown', count: 1 },
  ]);
  assert.deepEqual(stats.top_assets, [
    { asset_id: 'lab-app/login', count: 1 },
    { asset_id: 'lab-app/robots', count: 1 },
  ]);
});

test('top assets caps at 5, dropping the lowest count, ties broken by asset_id', () => {
  // Assets with counts 3, 2, 2, 1, 1, 1: the sixth (a-6, count 1)
  // drops, and the tie at 1 breaks by asset_id (a-4, a-5, a-6).
  function withAsset(findingId, assetId) {
    return { ...clone(LOW), finding_id: findingId, asset_id: assetId };
  }
  const findings = [
    withAsset('FND-A1-001', 'a-1'), withAsset('FND-A1-002', 'a-1'), withAsset('FND-A1-003', 'a-1'),
    withAsset('FND-A2-001', 'a-2'), withAsset('FND-A2-002', 'a-2'),
    withAsset('FND-A3-001', 'a-3'), withAsset('FND-A3-002', 'a-3'),
    withAsset('FND-A4-001', 'a-4'),
    withAsset('FND-A5-001', 'a-5'),
    withAsset('FND-A6-001', 'a-6'),
  ];
  const stats = computeReportStats(literalReport(findings));
  assert.equal(stats.total, 10);
  assert.deepEqual(stats.top_assets, [
    { asset_id: 'a-1', count: 3 },
    { asset_id: 'a-2', count: 2 },
    { asset_id: 'a-3', count: 2 },
    { asset_id: 'a-4', count: 1 },
    { asset_id: 'a-5', count: 1 },
  ]);
});

test('an empty report stats to zero counts, null CVSS, and the golden empty text', () => {
  const stats = computeReportStats(literalReport([]));
  assert.deepEqual(stats, {
    report_id: 'RPT-000000000000',
    summary: 'Program Lab Program: 0 validated finding(s) — 0 critical, 0 high, 0 medium, 0 low, 0 informational. Highest severity: informational. All findings in this report were validated against the finding schema before rendering.',
    total: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    by_verdict: { valid: 0, false_positive: 0, needs_evidence: 0, error: 0 },
    by_class: [],
    cvss: { scored: 0, unscored: 0, min: null, max: null, mean: null },
    top_assets: [],
  });
  assert.equal(renderReportStatsText(stats), EXPECTED_EMPTY_TEXT);
});

test('stats are deterministic across input orders', () => {
  const forward = computeReportStats(generatedReport(FIVE));
  const shuffled = computeReportStats(generatedReport([INFO, LOW, CRIT, MED, HIGH]));
  assert.deepEqual(shuffled, forward);
  assert.equal(renderReportStatsText(shuffled), renderReportStatsText(forward));
  assert.equal(renderReportStatsJson(shuffled), renderReportStatsJson(forward));
});

test('CLI report stats prints the exact golden text and exits 0', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath], { cwd: dir });
  assert.equal(stdout, EXPECTED_FIVE_TEXT);
});

test('CLI report stats --json prints the golden JSON and exits 0', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath, '--json'], { cwd: dir });
  assert.deepEqual(JSON.parse(stdout), EXPECTED_FIVE_STATS);
});

test('CLI report stats exits 0 on an all-false-positive report', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const report = JSON.parse(generateReport([FP], {
    programName: PROGRAM,
    generatedAt: GENERATED_AT,
    format: 'json',
  }));
  const filePath = path.join(dir, 'fp.json');
  fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath], { cwd: dir });
  assert.match(stdout, /Total: 1 finding\n/);
  assert.match(stdout, /Verdict: valid 0, false_positive 1, needs_evidence 0, error 0/);
});

test('CLI report stats exits 0 on a report with an error finding — stats never fails on content', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const band = { ...clone(LOW), finding_id: 'FND-BAND-001', severity: 'critical' };
  const filePath = path.join(dir, 'band.json');
  fs.writeFileSync(filePath, JSON.stringify(literalReport([CRIT, band], 'RPT-3aeafa977190'), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath], { cwd: dir });
  assert.match(stdout, /Total: 2 findings\n/);
  assert.match(stdout, /Verdict: valid 1, false_positive 0, needs_evidence 0, error 1/);
});

test('CLI report stats on a malformed input fails with a named error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'bad.json');
  fs.writeFileSync(filePath, '{ not json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
});

test('CLI report stats on a wrong-shape input fails with a named error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'bad.json');
  fs.writeFileSync(filePath, JSON.stringify({ report_id: 'RPT-X' }));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  const filePath2 = path.join(dir, 'bad2.json');
  fs.writeFileSync(filePath2, JSON.stringify({ findings: [] }));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath2], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
});

test('CLI report stats refuses a symlinked input', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const realPath = path.join(dir, 'real.json');
  const linkPath = path.join(dir, 'link.json');
  fs.writeFileSync(realPath, JSON.stringify(generatedReport(FIVE), null, 2));
  fs.symlinkSync(realPath, linkPath);
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats', linkPath], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI report stats requires a report file', async () => {
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats']),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /report stats requires a report file/);
      return true;
    },
  );
});

test('CLI report stats rejects an unknown option', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(FIVE), null, 2));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath, '--bogus'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /Unknown option: --bogus/);
      return true;
    },
  );
});

test('stats never writes: the input file is byte-identical afterwards', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-stats-');
  const filePath = path.join(dir, 'report.json');
  const content = JSON.stringify(generatedReport(FIVE), null, 2);
  fs.writeFileSync(filePath, content);
  const before = fs.statSync(filePath);
  await execFileAsync(process.execPath, [CLI, 'report', 'stats', filePath, '--json'], { cwd: dir });
  const after = fs.statSync(filePath);
  assert.equal(fs.readFileSync(filePath, 'utf8'), content);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test('the other report goldens do not move', () => {
  const findings = loadFixture('report-findings-array.json');
  // The golden hashes were captured with generatedAt 02:00 (see
  // tests/ai-verdict.test.js OPTIONS); the markdown carries the
  // timestamp, so any other value moves the hash.
  const markdown = generateReport(findings, { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', format: 'markdown' });
  const json = generateReport(findings, { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', format: 'json' });
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
});
