// Report validation (round 67): `sentinel report validate <file.json>`
// checks a JSON report file before the operator trusts it — shape,
// per-finding strict check + rule verdict, and the report-id
// recomputation. Exit 0 when the file parses and every finding
// validates (false_positive / needs_evidence are findings, not
// defects); only structural errors and band mismatches fail.
// Validate is read-only: it never writes. Fixtures only; no
// scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const {
  deriveExpectedReportId,
  readReportFileForValidation,
  validateReport,
  renderReportValidationText,
  renderReportValidationJson,
} = require('../src/report/validate');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// A generator-produced JSON report from the shared 3-finding
// fixture set (program "Lab Program", fixed generated_at so the
// report id is stable: RPT-0536be9278ec, the round-61 golden id).
function generatedReport(findings = loadFixture('report-findings-array.json')) {
  const json = generateReport(findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-26T00:00:00.000Z',
    format: 'json',
  });
  return JSON.parse(json);
}

// The exact text validation of the generator-produced report:
// CRIT is valid; MED and LOW are needs_evidence (the fixture
// carries no proof_of_concept or evidence for them) — findings,
// not defects, so the report is still VALID.
const EXPECTED_VALIDATION_TEXT = [
  'Report Validation — VALID',
  'Report ID: RPT-0536be9278ec (verified)',
  'Counts: 3 findings, 1 valid, 0 false_positive, 2 needs_evidence, 0 errors',
  '- FND-LOW-001 [needs_evidence]: missing proof_of_concept; missing evidence',
  '- FND-MED-001 [needs_evidence]: missing proof_of_concept; missing evidence',
  '',
].join('\n');

const EXPECTED_VALIDATION_JSON = {
  status: 'VALID',
  report_id: 'RPT-0536be9278ec',
  report_id_matches: true,
  report_id_warning: null,
  counts: { findings: 3, valid: 1, false_positive: 0, needs_evidence: 2, errors: 0 },
  findings: [
    {
      finding_id: 'FND-CRIT-001',
      status: 'valid',
      reasons: ['confirmed with complete evidence (proof_of_concept, evidence, steps_to_reproduce)'],
    },
    {
      finding_id: 'FND-LOW-001',
      status: 'needs_evidence',
      reasons: ['missing proof_of_concept', 'missing evidence'],
    },
    {
      finding_id: 'FND-MED-001',
      status: 'needs_evidence',
      reasons: ['missing proof_of_concept', 'missing evidence'],
    },
  ],
};

test('a generator-produced report validates VALID with the exact golden text', () => {
  const result = validateReport(generatedReport());
  assert.equal(renderReportValidationText(result), EXPECTED_VALIDATION_TEXT);
});

test('a generator-produced report validates VALID with the exact golden JSON', () => {
  const result = validateReport(generatedReport());
  assert.deepEqual(JSON.parse(renderReportValidationJson(result)), EXPECTED_VALIDATION_JSON);
});

test('a fully evidenced report validates with every finding valid', () => {
  const findings = loadFixture('report-findings-array.json');
  for (const finding of findings) {
    if (!finding.proof_of_concept) finding.proof_of_concept = 'lab proof of concept';
    if (!finding.evidence || finding.evidence.length === 0) {
      // MED/LOW are information-disclosure class, which requires
      // response_log: the evidence entry must carry a response (and
      // a request and notes, so every checklist item is present).
      finding.evidence = [{ request: 'GET /profile', response: 'HTTP 200 with another user\'s profile', notes: 'lab evidence' }];
    }
  }
  const result = validateReport(generatedReport(findings));
  assert.equal(result.status, 'VALID');
  assert.deepEqual(result.counts, { findings: 3, valid: 3, false_positive: 0, needs_evidence: 0, errors: 0 });
  assert.ok(renderReportValidationText(result).includes('All findings valid.'));
});

test('the same finding set in any file order validates byte-identically', () => {
  const report = generatedReport();
  const reversed = { ...report, findings: [...report.findings].reverse() };
  assert.equal(
    renderReportValidationText(validateReport(report)),
    renderReportValidationText(validateReport(reversed)),
  );
  assert.equal(
    renderReportValidationJson(validateReport(report)),
    renderReportValidationJson(validateReport(reversed)),
  );
});

test('a finding missing a required field is an error naming the field', () => {
  const report = generatedReport();
  delete report.findings[0].description;
  const result = validateReport(report);
  assert.equal(result.status, 'INVALID');
  assert.equal(result.counts.errors, 1);
  const entry = result.findings.find((item) => item.finding_id === 'FND-CRIT-001');
  assert.equal(entry.status, 'error');
  assert.match(entry.reasons[0], /missing required field\(s\): description/);
});

test('a severity/CVSS mismatch is an error, not a needs_evidence verdict', () => {
  const report = generatedReport();
  report.findings[0].severity = 'medium';
  const result = validateReport(report);
  assert.equal(result.status, 'INVALID');
  assert.equal(result.counts.errors, 1);
  const entry = result.findings.find((item) => item.finding_id === 'FND-CRIT-001');
  assert.equal(entry.status, 'error');
  assert.match(entry.reasons[0], /severity\/score mismatch/);
});

test('a malformed CVSS vector is an error naming the vector', () => {
  const report = generatedReport();
  report.findings[0].cvss_vector = 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const result = validateReport(report);
  assert.equal(result.status, 'INVALID');
  assert.equal(result.counts.errors, 1);
  const entry = result.findings.find((item) => item.finding_id === 'FND-CRIT-001');
  assert.equal(entry.status, 'error');
  assert.match(entry.reasons[0], /vector/i);
});

test('a declared score that disagrees with its vector is an error', () => {
  const report = generatedReport();
  report.findings[0].cvss_score = 5.0;
  const result = validateReport(report);
  assert.equal(result.status, 'INVALID');
  assert.equal(result.counts.errors, 1);
  const entry = result.findings.find((item) => item.finding_id === 'FND-CRIT-001');
  assert.equal(entry.status, 'error');
});

test('a duplicate finding_id throws a named error before any verdict', () => {
  const report = generatedReport();
  report.findings.push(clone(report.findings[0]));
  assert.throws(() => validateReport(report), /REPORT_VALIDATE_DUPLICATE_FINDING_ID: .*FND-CRIT-001/);
});

test('a report_id mismatch is a warning, not a failure', () => {
  const report = generatedReport();
  report.report_id = 'RPT-000000000000';
  const result = validateReport(report);
  assert.equal(result.status, 'VALID');
  assert.equal(result.report_id_matches, false);
  assert.match(result.report_id_warning, /report_id mismatch: expected RPT-0536be9278ec, found RPT-000000000000/);
  assert.match(renderReportValidationText(result), /\(warning: report_id mismatch/);
});

test('a missing program_name makes the report id unverifiable, not invalid', () => {
  const report = generatedReport();
  delete report.program_name;
  const result = validateReport(report);
  assert.equal(result.status, 'VALID');
  assert.equal(result.report_id_matches, false);
  assert.match(result.report_id_warning, /cannot verify report_id: program_name is missing/);
});

test('false_positive and needs_evidence findings count but do not fail', () => {
  const findings = [loadFixture('false-positive.json'), loadFixture('confirmed-missing-poc.json')];
  const report = {
    report_id: deriveExpectedReportId('Lab Program', findings),
    program_name: 'Lab Program',
    findings,
  };
  const result = validateReport(report);
  assert.equal(result.status, 'VALID');
  assert.deepEqual(result.counts, { findings: 2, valid: 0, false_positive: 1, needs_evidence: 1, errors: 0 });
  assert.equal(result.report_id_matches, true);
  assert.ok(renderReportValidationText(result).includes('- F-R31-FALSE-POSITIVE [false_positive]: confidence field says false_positive'));
  assert.ok(renderReportValidationText(result).includes('- F-R31-CONFIRMED-NO-POC [needs_evidence]: missing proof_of_concept'));
});

test('readReportFileForValidation refuses malformed and wrong-shape inputs with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const cases = [
    ['malformed.json', '{ not json', /REPORT_VALIDATE_INVALID_REPORT/],
    ['array.json', '[]', /REPORT_VALIDATE_INVALID_REPORT/],
    ['no-findings.json', JSON.stringify({ report_id: 'RPT-X' }), /REPORT_VALIDATE_INVALID_REPORT: .* has no findings array/],
    ['no-id.json', JSON.stringify({ findings: [] }), /REPORT_VALIDATE_INVALID_REPORT: .* has no report_id/],
    ['no-finding-id.json', JSON.stringify({ report_id: 'RPT-X', findings: [{ severity: 'low' }] }), /REPORT_VALIDATE_INVALID_FINDING/],
    ['duplicate.json', JSON.stringify({ report_id: 'RPT-X', findings: [{ finding_id: 'FND-A' }, { finding_id: 'FND-A' }] }), /REPORT_VALIDATE_DUPLICATE_FINDING_ID: .*FND-A/],
  ];
  for (const [name, content, pattern] of cases) {
    const filePath = path.join(dir, name);
    fs.writeFileSync(filePath, content);
    await assert.rejects(() => readReportFileForValidation(filePath), pattern, name);
  }
});

test('readReportFileForValidation refuses a symlinked input', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const real = path.join(dir, 'real.json');
  fs.writeFileSync(real, JSON.stringify({ report_id: 'RPT-X', findings: [] }));
  const link = path.join(dir, 'link.json');
  fs.symlinkSync(real, link);
  await assert.rejects(() => readReportFileForValidation(link), /REPORT_VALIDATE_SYMLINK_REFUSED/);
});

test('readReportFileForValidation refuses more than 10,000 findings', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const findings = Array.from({ length: 10001 }, (_, index) => ({ finding_id: `FND-${String(index).padStart(5, '0')}` }));
  const filePath = path.join(dir, 'too-many.json');
  fs.writeFileSync(filePath, JSON.stringify({ report_id: 'RPT-X', findings }));
  await assert.rejects(() => readReportFileForValidation(filePath), /REPORT_VALIDATE_TOO_MANY_FINDINGS/);
});

test('CLI report validate prints the exact golden text and exits 0', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath], { cwd: dir });
  assert.equal(stdout, EXPECTED_VALIDATION_TEXT);
});

test('CLI report validate --json prints the golden JSON and exits 0', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(), null, 2));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath, '--json'], { cwd: dir });
  assert.deepEqual(JSON.parse(stdout), EXPECTED_VALIDATION_JSON);
});

test('CLI report validate exits 1 with INVALID on an error finding', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const report = generatedReport();
  delete report.findings[0].description;
  const filePath = path.join(dir, 'bad.json');
  fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath], { cwd: dir }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stdout || '', /Report Validation — INVALID/);
      assert.match(error.stdout || '', /missing required field\(s\): description/);
      return true;
    },
  );
});

test('CLI report validate on a malformed input fails with a named error', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const filePath = path.join(dir, 'bad.json');
  fs.writeFileSync(filePath, '{ not json');
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /REPORT_VALIDATE_INVALID_REPORT/);
      return true;
    },
  );
});

test('CLI report validate requires a report file', async () => {
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'validate']),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /report validate requires a report file/);
      return true;
    },
  );
});

test('CLI report validate rejects an unknown option', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const filePath = path.join(dir, 'report.json');
  fs.writeFileSync(filePath, JSON.stringify(generatedReport(), null, 2));
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath, '--bogus'], { cwd: dir }),
    (error) => {
      assert.match(error.stderr || error.stdout || '', /Unknown option: --bogus/);
      return true;
    },
  );
});

test('validate never writes: the input file is byte-identical afterwards', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-validate-');
  const filePath = path.join(dir, 'report.json');
  const content = JSON.stringify(generatedReport(), null, 2);
  fs.writeFileSync(filePath, content);
  const before = fs.statSync(filePath);
  await execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath, '--json'], { cwd: dir });
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
