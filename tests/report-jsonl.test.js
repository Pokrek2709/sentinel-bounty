// JSONL report format (round 66): `sentinel report --format
// jsonl` renders one JSON object per line — a summary line first,
// then one finding per line in the same grouped order as the flat
// JSON `findings` array — for pipeline consumers that want to
// stream findings without parsing a whole JSON document. No
// --generated-at (like CSV and summary, rounds 55/61); an empty
// finding set renders the summary line only, not an error; a
// platform template with jsonl output is refused, like HTML, CSV,
// and summary. Fixtures only; no scanner, no network, no live
// target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { renderJsonl } = require('../src/report/jsonl');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateModeSync } = require('./helpers/private-mode');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function parseLines(output) {
  return output.trimEnd().split('\n').map((line) => JSON.parse(line));
}

// The exact summary line for the shared 3-finding fixture (report
// id RPT-0536be9278ec is the deterministic hash of program +
// sorted finding ids, same as the summary golden in round 61).
const EXPECTED_SUMMARY_LINE = '{"type":"report-summary","report_id":"RPT-0536be9278ec","total":3,"counts_by_severity":{"critical":1,"high":0,"medium":1,"low":1,"informational":0},"counts_by_verdict":{"validated":3},"target_id":"TGT-LAB-001","session_id":"SES-REPORT-001"}';

test('jsonl renders the exact summary line and the pinned full-output hash for the shared fixture', () => {
  const jsonl = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'jsonl' });
  const lines = jsonl.trimEnd().split('\n');
  assert.equal(lines.length, 4, 'summary line + 3 finding lines');
  assert.equal(lines[0], EXPECTED_SUMMARY_LINE);
  // Pinned hash of the whole output, computed from the first run:
  // guards the finding lines byte-for-byte, including the
  // evidence_checklist objects.
  assert.equal(sha256(jsonl), 'bb15d9296b416cac5df40e29e5ffd2d331aa3be38e7164e54d5a54e0a926eb65');
});

test('jsonl finding lines match the JSON format finding entries field-for-field', () => {
  const findings = loadFixture('report-findings-array.json');
  const json = JSON.parse(generateReport(findings, { ...OPTIONS, format: 'json' }));
  const parsed = parseLines(generateReport(findings, { ...OPTIONS, format: 'jsonl' }));
  const [summary, ...findingLines] = parsed;
  assert.equal(summary.type, 'report-summary');
  assert.equal(summary.report_id, json.report_id, 'same report id as JSON');
  assert.equal(summary.target_id, json.target_id, 'same target id as JSON');
  assert.equal(summary.session_id, json.session_id, 'same session id as JSON');
  assert.deepEqual(findingLines, json.findings, 'finding lines are the JSON findings entries, in the same order');
  // Order is the grouped order: asset ascending, then severity,
  // then finding_id — the same order the Markdown report uses.
  assert.deepEqual(
    findingLines.map((finding) => finding.finding_id),
    ['FND-CRIT-001', 'FND-MED-001', 'FND-LOW-001'],
  );
});

test('jsonl summary counts match the Markdown report counts for the same set', () => {
  const findings = loadFixture('report-findings-array.json');
  const [summary] = parseLines(generateReport(findings, { ...OPTIONS, format: 'jsonl' }));
  const markdown = generateReport(findings, OPTIONS);
  assert.equal(summary.total, 3);
  for (const severity of ['critical', 'high', 'medium', 'low', 'informational']) {
    const markdownCount = Number(markdown.match(new RegExp(`\\| ${severity} \\| (\\d+) \\|`))[1]);
    assert.equal(summary.counts_by_severity[severity], markdownCount, `${severity} count agrees`);
  }
  assert.deepEqual(summary.counts_by_verdict, { validated: 3 });
});

test('jsonl is deterministic: same findings in any input order produce byte-identical output', () => {
  const array = loadFixture('report-findings-array.json');
  const first = generateReport(array, { ...OPTIONS, format: 'jsonl' });
  const second = generateReport([...array].reverse(), { ...OPTIONS, format: 'jsonl' });
  assert.equal(sha256(first), sha256(second), 'reversed input order must not change the output');
  assert.equal(first, second);
});

test('jsonl ignores --generated-at: with and without it the output is identical', () => {
  const findings = loadFixture('report-findings-array.json');
  const withGeneratedAt = generateReport(findings, { ...OPTIONS, format: 'jsonl' });
  const withoutGeneratedAt = generateReport(findings, { programName: 'Lab Program', format: 'jsonl' });
  assert.equal(withGeneratedAt, withoutGeneratedAt, 'no timestamp in the JSONL export');
});

test('jsonl with an empty finding set renders the summary line only', () => {
  const jsonl = generateReport([], { programName: 'Lab Program', format: 'jsonl' });
  assert.equal(jsonl, '{"type":"report-summary","report_id":"RPT-11ba7f2d7f84","total":0,"counts_by_severity":{"critical":0,"high":0,"medium":0,"low":0,"informational":0},"counts_by_verdict":{}}\n');
  assert.equal(parseLines(jsonl).length, 1, 'one line only');
  // Every other format still requires at least one finding, except
  // CSV (header only) and summary (zero-count summary).
  assert.throws(() => generateReport([], { format: 'markdown' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'json' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'html' }), /At least one finding is required/);
  assert.throws(() => generateReport('not-an-array', { format: 'jsonl' }), /expects an array/);
});

test('jsonl finding lines carry the advisory ai_verdict when a verifier ran, and none otherwise', () => {
  const finding = loadFixture('report-critical.json');
  const withVerifier = parseLines(generateReport([finding], { ...OPTIONS, format: 'jsonl', verifier: 'stub' }));
  assert.equal(withVerifier[1].ai_verdict.verdict, 'needs_evidence', 'stub verdict attached to the finding line');
  const withoutVerifier = parseLines(generateReport([finding], { ...OPTIONS, format: 'jsonl' }));
  assert.equal(withoutVerifier[1].ai_verdict, undefined, 'no verifier, no ai_verdict field');
  // The summary line does not gain a field from the verifier.
  assert.equal(withVerifier[0].type, 'report-summary');
});

test('jsonl rejects a platform template, like HTML, CSV, and summary do', () => {
  assert.throws(
    () => generateReport([loadFixture('report-critical.json')], { ...OPTIONS, format: 'jsonl', template: 'immunefi' }),
    /renders Markdown only; JSONL output uses the generic template/,
  );
  assert.throws(
    () => generateReport([], { format: 'jsonl', template: 'code4rena' }),
    /renders Markdown only; JSONL output uses the generic template/,
  );
});

test('jsonl refuses mixed-target input by default and renders it with the opt-in', () => {
  const mixed = loadFixture('mixed-target-findings.json');
  assert.throws(
    () => generateReport(mixed, { ...OPTIONS, format: 'jsonl' }),
    /REPORT_MIXED_TARGETS_REFUSED/,
  );
  const [summary, ...findingLines] = parseLines(
    generateReport(mixed, { ...OPTIONS, format: 'jsonl', allowMixedTargets: true }),
  );
  assert.equal(summary.target_id, 'local-lab', 'first target in sorted order');
  assert.deepEqual(summary.target_ids, ['local-lab', 'local-lab-2'], 'both targets named, ascending');
  assert.equal(summary.mixed_targets, true, 'mixed-target flag set');
  // Verdict tie (1 each) breaks by name ascending.
  assert.deepEqual(summary.counts_by_verdict, { needs_review: 1, validated: 1 });
  assert.deepEqual(
    findingLines.map((finding) => finding.finding_id),
    ['F-R31-CONFIRMED-FULL', 'F-R31-POTENTIAL-FULL'],
  );
});

test('renderJsonl omits the session field when no session id is given', () => {
  const rendered = renderJsonl({
    reportId: 'RPT-test',
    targetId: 'TGT-1',
    sessionId: null,
    targetIds: ['TGT-1'],
    multiTarget: false,
    counts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 },
    orderedFindings: [{
      finding_id: 'F-1', severity: 'high', cvss_score: 7.5,
      asset_id: 'app', validation_status: 'validated',
    }],
  });
  const [summary, findingLine] = parseLines(rendered);
  assert.equal(summary.session_id, undefined, 'no session field without a session id');
  assert.equal(summary.target_id, 'TGT-1');
  assert.equal(findingLine.finding_id, 'F-1');
});

test('an unknown format is still rejected with the updated named error', () => {
  assert.throws(
    () => generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'yaml' }),
    /Invalid format: yaml \(expected "markdown", "json", "html", "csv", "summary", or "jsonl"\)/,
  );
});

test('Markdown, JSON, HTML, CSV, and summary output are unchanged by the jsonl addition (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  const html = generateReport(findings, { ...OPTIONS, format: 'html' });
  const csv = generateReport(findings, { ...OPTIONS, format: 'csv' });
  const summary = generateReport(findings, { ...OPTIONS, format: 'summary' });
  // Hashes captured from the pre-change generator (round 43, commit
  // c3bec85, re-pinned in the round-44/55/61 tests): adding a format
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
  assert.equal(summary, [
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
  ].join('\n'), 'summary unchanged');
});

test('CLI report --format jsonl --out writes a JSONL file with mode 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r66-');
  const output = path.join(directory, 'report.jsonl');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--format', 'jsonl', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
    '--out', output,
  ]);
  assert.match(stdout, /Report written to/);
  const jsonl = fs.readFileSync(output, 'utf8');
  const lines = jsonl.trimEnd().split('\n');
  assert.equal(lines[0], EXPECTED_SUMMARY_LINE);
  assert.equal(lines.length, 4);
  assertPrivateModeSync(output, 0o600, 'report file is private');
});

test('CLI report --format jsonl prints to stdout without --out', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--format', 'jsonl', '--program', 'Lab Program',
  ]);
  assert.equal(stdout.trimEnd().split('\n')[0], EXPECTED_SUMMARY_LINE);
});

test('CLI report --format jsonl --template immunefi fails cleanly and writes no file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r66-');
  const output = path.join(directory, 'report.jsonl');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
      '--format', 'jsonl', '--template', 'immunefi', '--out', output,
    ]),
    (error) => {
      assert.match(error.stderr, /renders Markdown only; JSONL output uses the generic template/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(output), false);
});

test('CLI report --format jsonl --json is refused as an unknown option', async (t) => {
  // The report command has no --json flag: jsonl is its own format,
  // and JSON output is --format json. The parser refuses the stray
  // flag cleanly instead of silently ignoring it.
  const directory = await makeTempDir(t, 'sentinel-r66-');
  const output = path.join(directory, 'report.jsonl');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
      '--format', 'jsonl', '--json', '--out', output,
    ]),
    (error) => {
      assert.match(error.stderr, /Unknown option: --json/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(output), false);
});
