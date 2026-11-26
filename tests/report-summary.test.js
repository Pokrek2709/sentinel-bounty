// Compact summary report format (round 61): `sentinel report
// --format summary` renders a one-page plain-text executive
// summary — headline counts plus the top findings — instead of the
// full report. Plain text by design (see src/report/summary.js):
// a summary is pasted into chat, email, or a ticket more often than
// it is rendered. No --generated-at (like CSV, round 55); an empty
// finding set renders the zero-count summary, not an error; a
// platform template with summary output is refused, like HTML and
// CSV. Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { renderSummary, countByVerdict, TOP_FINDINGS_LIMIT } = require('../src/report/summary');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// The exact summary for the shared 3-finding fixture (see the smoke
// run in the round-61 report): report id RPT-0536be9278ec is the
// deterministic hash of program + sorted finding ids.
const EXPECTED_SUMMARY = [
  'Bug Bounty Report Summary — Lab Program',
  'Report ID: RPT-0536be9278ec',
  'Target: TGT-LAB-001',
  'Session: SES-REPORT-001',
  'Findings: 3 total (critical: 1, high: 0, medium: 1, low: 1, informational: 0)',
  'Verdicts: validated: 3',
  'Highest severity: critical',
  '',
  'Top findings:',
  '1. FND-CRIT-001 | critical | CVSS 9.8 | lab-app/login | validated',
  '2. FND-MED-001 | medium | CVSS 5 | lab-app/profile | validated',
  '3. FND-LOW-001 | low | CVSS 2.5 | lab-app/robots | validated',
  '',
  'AI verdicts (advisory): 0 of 3 findings carry an AI verdict.',
  '',
  'See the full report for descriptions, steps, evidence, and references.',
  '',
].join('\n');

test('summary renders the exact golden text for the shared fixture', () => {
  const summary = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'summary' });
  assert.equal(summary, EXPECTED_SUMMARY);
});

test('summary counts match the Markdown report counts for the same set', () => {
  const findings = loadFixture('report-findings-array.json');
  const summary = generateReport(findings, { ...OPTIONS, format: 'summary' });
  const markdown = generateReport(findings, OPTIONS);
  // Both formats count the same findings: pull the severity rows
  // out of the Markdown summary table and compare with the summary
  // counts line.
  const countsLine = summary.split('\n').find((line) => line.startsWith('Findings: '));
  for (const severity of ['critical', 'high', 'medium', 'low', 'informational']) {
    const markdownCount = markdown.match(new RegExp(`\\| ${severity} \\| (\\d+) \\|`))[1];
    assert.ok(countsLine.includes(`${severity}: ${markdownCount}`), `${severity} count ${markdownCount} in both formats`);
  }
  assert.ok(countsLine.includes('3 total'), 'total agrees');
});

test('countByVerdict orders by count descending, then name ascending', () => {
  assert.deepEqual(
    countByVerdict([
      { validation_status: 'validated' },
      { validation_status: 'needs_review' },
      { validation_status: 'validated' },
      { validation_status: 'false_positive' },
    ]),
    [['validated', 2], ['false_positive', 1], ['needs_review', 1]],
  );
  assert.deepEqual(countByVerdict([]), []);
  // A finding without a usable status counts as unknown, never lost.
  assert.deepEqual(countByVerdict([{}]), [['unknown', 1]]);
});

test('summary verdict counts use validation_status, mixed values in order', () => {
  const findings = loadFixture('report-findings-array.json');
  findings[1].validation_status = 'needs_review';
  const summary = generateReport(findings, { ...OPTIONS, format: 'summary' });
  // validated 2 first (higher count), then needs_review 1.
  assert.ok(summary.includes('Verdicts: validated: 2, needs_review: 1'), 'mixed verdicts in count order');
  // The top-findings rows carry the per-finding status too.
  assert.ok(summary.includes('FND-MED-001 | medium | CVSS 5 | lab-app/profile | needs_review'));
});

test('summary is deterministic: same findings in any input order produce byte-identical output', () => {
  const array = loadFixture('report-findings-array.json');
  const first = generateReport(array, { ...OPTIONS, format: 'summary' });
  const second = generateReport([...array].reverse(), { ...OPTIONS, format: 'summary' });
  assert.equal(sha256(first), sha256(second), 'reversed input order must not change the output');
  assert.equal(first, second);
});

test('summary ignores --generated-at: with and without it the output is identical', () => {
  const findings = loadFixture('report-findings-array.json');
  const withGeneratedAt = generateReport(findings, { ...OPTIONS, format: 'summary' });
  const withoutGeneratedAt = generateReport(findings, { programName: 'Lab Program', format: 'summary' });
  assert.equal(withGeneratedAt, withoutGeneratedAt, 'no timestamp in the summary');
});

test('summary top-findings table truncates at 10 rows with a "+N more" line', () => {
  // 12 findings built by cloning the critical fixture and re-banding:
  // the vector is removed so the declared score is the only score
  // (a vector disagreeing with the new score would fail validation).
  // 2 critical + 2 high + 3 medium + 3 low = 10 shown; the 2
  // informational findings are cut.
  const base = loadFixture('report-critical.json');
  const bands = [
    ['critical', 9.8], ['critical', 9.8],
    ['high', 7.5], ['high', 7.5],
    ['medium', 5.0], ['medium', 5.0], ['medium', 5.0],
    ['low', 2.5], ['low', 2.5], ['low', 2.5],
    ['informational', 0.0], ['informational', 0.0],
  ];
  const findings = bands.map(([severity, score], index) => {
    const finding = clone(base);
    finding.finding_id = `FND-T${String(index + 1).padStart(2, '0')}`;
    finding.severity = severity;
    finding.cvss_score = score;
    delete finding.cvss_vector;
    delete finding.cvss_temporal_score;
    delete finding.cvss_environmental_score;
    return finding;
  });
  assert.equal(TOP_FINDINGS_LIMIT, 10, 'the limit is 10 by design');
  const summary = generateReport(findings, { ...OPTIONS, format: 'summary' });
  assert.ok(summary.includes('Findings: 12 total (critical: 2, high: 2, medium: 3, low: 3, informational: 2)'));
  // Rows 1-10 in severity-then-id order; the informational rows
  // never appear.
  for (let index = 1; index <= 10; index += 1) {
    assert.ok(summary.includes(`${index}. FND-T${String(index).padStart(2, '0')} |`), `row ${index} present`);
  }
  assert.ok(!summary.includes('FND-T11'), 'informational finding 11 cut');
  assert.ok(!summary.includes('FND-T12'), 'informational finding 12 cut');
  assert.ok(summary.includes('... and 2 more findings (see the full report).'), 'truncation line names the remainder');
});

test('summary with an empty finding set renders zero counts and "No findings."', () => {
  const summary = generateReport([], { programName: 'Lab Program', format: 'summary' });
  assert.equal(summary, [
    'Bug Bounty Report Summary — Lab Program',
    'Report ID: RPT-11ba7f2d7f84',
    'Target: not specified',
    'Findings: 0 total (critical: 0, high: 0, medium: 0, low: 0, informational: 0)',
    'Verdicts: none',
    'Highest severity: none',
    '',
    'No findings.',
    '',
  ].join('\n'));
  // Every other format still requires at least one finding.
  assert.throws(() => generateReport([], { format: 'markdown' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'json' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'html' }), /At least one finding is required/);
  assert.throws(() => generateReport('not-an-array', { format: 'summary' }), /expects an array/);
});

test('summary renders the advisory AI-verdict count when a verifier ran', () => {
  const finding = loadFixture('report-critical.json');
  const withVerifier = generateReport([finding], { ...OPTIONS, format: 'summary', verifier: 'stub' });
  assert.ok(withVerifier.includes('AI verdicts (advisory): 1 of 1 finding carries an AI verdict.'), 'stub verdict counted');
  const withoutVerifier = generateReport([finding], { ...OPTIONS, format: 'summary' });
  assert.ok(withoutVerifier.includes('AI verdicts (advisory): 0 of 1 finding carries an AI verdict.'), 'no verifier, zero counted');
});

test('summary rejects a platform template, like HTML and CSV do', () => {
  assert.throws(
    () => generateReport([loadFixture('report-critical.json')], { ...OPTIONS, format: 'summary', template: 'immunefi' }),
    /renders Markdown only; summary output uses the generic template/,
  );
  assert.throws(
    () => generateReport([], { format: 'summary', template: 'code4rena' }),
    /renders Markdown only; summary output uses the generic template/,
  );
});

test('summary refuses mixed-target input by default and renders it with the opt-in', () => {
  const mixed = loadFixture('mixed-target-findings.json');
  assert.throws(
    () => generateReport(mixed, { ...OPTIONS, format: 'summary' }),
    /REPORT_MIXED_TARGETS_REFUSED/,
  );
  const summary = generateReport(mixed, { ...OPTIONS, format: 'summary', allowMixedTargets: true });
  assert.ok(summary.includes('Targets: local-lab, local-lab-2'), 'both targets named, ascending');
  // Verdict tie (1 each) breaks by name ascending.
  assert.ok(summary.includes('Verdicts: needs_review: 1, validated: 1'), 'verdict tie in name order');
  assert.ok(summary.includes('F-R31-CONFIRMED-FULL | high | CVSS 7.5 | lab-asset-01 | validated'));
  assert.ok(summary.includes('F-R31-POTENTIAL-FULL | medium | CVSS 5.4 | lab-asset-02 | needs_review'));
});

test('renderSummary omits the session line when no session id is given', () => {
  const rendered = renderSummary({
    reportId: 'RPT-test',
    programName: 'Lab Program',
    targetIds: ['TGT-1'],
    multiTarget: false,
    sessionId: null,
    counts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 },
    orderedFindings: [{
      finding_id: 'F-1', severity: 'high', cvss_score: 7.5,
      asset_id: 'app', validation_status: 'validated',
    }],
    aiVerdictCount: 0,
  });
  assert.ok(!rendered.includes('Session:'), 'no session line without a session id');
  assert.ok(rendered.includes('Target: TGT-1'));
});

test('an unknown format is still rejected with the updated named error', () => {
  assert.throws(
    () => generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'yaml' }),
    /Invalid format: yaml \(expected "markdown", "json", "html", "csv", or "summary"\)/,
  );
});

test('Markdown, JSON, HTML, and CSV output are unchanged by the summary addition (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  const html = generateReport(findings, { ...OPTIONS, format: 'html' });
  const csv = generateReport(findings, { ...OPTIONS, format: 'csv' });
  // Hashes captured from the pre-change generator (round 43, commit
  // c3bec85, re-pinned in the round-44/55 tests): adding a format
  // must not move a byte of the old ones.
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
  assert.ok(html.startsWith('<!DOCTYPE html>'), 'html renders');
  assert.ok(html.includes('FND-CRIT-001'), 'html carries the findings');
  assert.equal(csv, [
    'finding_id,target_id,asset_id,severity,cvss_base_score,cvss_temporal_score,cvss_environmental_score,verdict,evidence_checklist,merged_from,ai_verdict',
    'FND-CRIT-001,TGT-LAB-001,lab-app/login,critical,9.8,,,validated,9/9 (complete),,',
    'FND-MED-001,TGT-LAB-001,lab-app/profile,medium,5,,,validated,3/10 (missing: proof_of_concept; evidence; response_log; cwe_id; cvss_vector; request_log; evidence_notes),,',
    'FND-LOW-001,TGT-LAB-001,lab-app/robots,low,2.5,,,validated,3/10 (missing: proof_of_concept; evidence; response_log; cwe_id; cvss_vector; request_log; evidence_notes),,',
    '',
  ].join('\n'), 'csv unchanged');
});

test('CLI report --format summary --out writes a plain-text file with mode 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r61-');
  const output = path.join(directory, 'report.txt');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--format', 'summary', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
    '--out', output,
  ]);
  assert.match(stdout, /Report written to/);
  const summary = fs.readFileSync(output, 'utf8');
  assert.equal(summary, EXPECTED_SUMMARY);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600, 'report file is private');
});

test('CLI report --format summary prints to stdout without --out', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--format', 'summary', '--program', 'Lab Program',
  ]);
  assert.equal(stdout, EXPECTED_SUMMARY);
});

test('CLI report --format summary --template immunefi fails cleanly and writes no file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r61-');
  const output = path.join(directory, 'report.txt');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
      '--format', 'summary', '--template', 'immunefi', '--out', output,
    ]),
    (error) => {
      assert.match(error.stderr, /renders Markdown only; summary output uses the generic template/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(output), false);
});

test('CLI report --format summary --json is refused as an unknown option', async (t) => {
  // The report command has no --json flag: summary is a text
  // format, and JSON output is --format json. The parser refuses
  // the stray flag cleanly instead of silently ignoring it.
  const directory = await makeTempDir(t, 'sentinel-r61-');
  const output = path.join(directory, 'report.txt');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
      '--format', 'summary', '--json', '--out', output,
    ]),
    (error) => {
      assert.match(error.stderr, /Unknown option: --json/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(output), false);
});
