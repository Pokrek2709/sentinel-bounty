const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport, validateFinding, severityForScore, countBySeverity, executiveSummary } = require('../src/report/generator');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

const critical = () => loadFixture('report-critical.json');
const medium = () => loadFixture('report-medium.json');
const findingsArray = () => loadFixture('report-findings-array.json');

test('severityForScore maps every band boundary', () => {
  assert.equal(severityForScore(0.0), 'informational');
  assert.equal(severityForScore(0.1), 'low');
  assert.equal(severityForScore(3.9), 'low');
  assert.equal(severityForScore(4.0), 'medium');
  assert.equal(severityForScore(6.9), 'medium');
  assert.equal(severityForScore(7.0), 'high');
  assert.equal(severityForScore(8.9), 'high');
  assert.equal(severityForScore(9.0), 'critical');
  assert.equal(severityForScore(10.0), 'critical');
});

test('severityForScore rejects out-of-range scores', () => {
  assert.throws(() => severityForScore(-0.1), /Invalid cvss_score/);
  assert.throws(() => severityForScore(10.1), /Invalid cvss_score/);
  assert.throws(() => severityForScore('9.8'), /Invalid cvss_score/);
});

test('generateReport is deterministic: same input, byte-identical output', () => {
  const options = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };
  const first = generateReport(findingsArray(), options);
  const second = generateReport(findingsArray(), options);
  assert.equal(first, second);
  const firstJson = generateReport(findingsArray(), { ...options, format: 'json' });
  const secondJson = generateReport(findingsArray(), { ...options, format: 'json' });
  assert.equal(firstJson, secondJson);
});

test('executiveSummary and countBySeverity are exported and match the JSON report (round 72)', () => {
  // Export contract: the helpers other report commands reuse must
  // stay exported, and the JSON report's own summary/counts must be
  // exactly what the helpers return for the same set — the same
  // equality the empty filter report now relies on.
  const options = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', format: 'json' };
  const parsed = JSON.parse(generateReport(findingsArray(), options));
  assert.equal(typeof executiveSummary, 'function');
  assert.equal(typeof countBySeverity, 'function');
  assert.deepEqual(parsed.findings_summary, countBySeverity(findingsArray()));
  assert.equal(parsed.executive_summary, executiveSummary(countBySeverity(findingsArray()), 'Lab Program'));
});

test('generateReport with no explicit generated_at never invents a wall-clock time', () => {
  // The findings carry created_at 2026-11-26T00:00:00.000Z, so the
  // report reuses that timestamp instead of the current time.
  const report = generateReport(findingsArray(), { programName: 'Lab Program' });
  assert.match(report, /2026-11-26T00:00:00\.000Z/);
});

test('severity/score mismatch fails with a clear error', () => {
  const finding = critical();
  finding.severity = 'high'; // cvss 9.8 maps to critical
  assert.throws(() => validateFinding(finding, 0), /severity\/score mismatch.*critical/);
  assert.throws(() => generateReport([finding], { programName: 'Lab' }), /severity\/score mismatch/);
});

test('missing required field fails and names the missing field(s)', () => {
  const finding = loadFixture('report-incomplete.json');
  // The incomplete fixture lacks impact and remediation.
  assert.throws(() => validateFinding(finding, 0), /missing required field\(s\): impact, remediation/);
  assert.throws(() => generateReport([finding], { programName: 'Lab' }), /impact, remediation/);
});

test('markdown output has a summary counts table and one section per finding', () => {
  const report = generateReport(findingsArray(), { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(report, /# Bug Bounty Report — Lab Program/);
  assert.match(report, /\| critical \| 1 \|/);
  assert.match(report, /\| medium \| 1 \|/);
  assert.match(report, /\| low \| 1 \|/);
  assert.match(report, /\| high \| 0 \|/);
  assert.match(report, /\| total \| 3 \|/);
  assert.match(report, /## 1\. SQL injection in login username parameter \[CRITICAL\]/);
  assert.match(report, /## 2\. Verbose error messages disclose internal paths \[MEDIUM\]/);
  assert.match(report, /## 3\. robots\.txt discloses administrative path \[LOW\]/);
  assert.match(report, /### Steps to Reproduce/);
  assert.match(report, /### Proof of Concept/);
  assert.match(report, /### Impact/);
  assert.match(report, /### Remediation/);
  assert.match(report, /### References/);
  assert.match(report, /CWE-89/);
  assert.match(report, /CVSS:.*9\.8/);
  assert.match(report, /lab-app\/login \(https:\/\/lab\.example\.internal\/login\)/);
});

test('summary counts are correct for a single critical finding', () => {
  const report = generateReport([critical()], { programName: 'Lab', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(report, /\| critical \| 1 \|/);
  assert.match(report, /\| total \| 1 \|/);
});

test('JSON output conforms to the report schema shape', () => {
  const parsed = JSON.parse(generateReport(findingsArray(), {
    programName: 'Lab Program',
    generatedAt: '2026-11-26T02:00:00.000Z',
    format: 'json',
  }));
  for (const key of ['report_id', 'program_name', 'generated_at', 'executive_summary', 'findings_summary', 'findings']) {
    assert.ok(key in parsed, `missing required key: ${key}`);
  }
  assert.equal(parsed.program_name, 'Lab Program');
  assert.equal(parsed.generated_at, '2026-11-26T02:00:00.000Z');
  assert.equal(parsed.target_id, 'TGT-LAB-001');
  assert.deepEqual(parsed.findings_summary, { critical: 1, high: 0, medium: 1, low: 1, informational: 0, total: 3 });
  assert.equal(parsed.findings.length, 3);
  assert.equal(parsed.findings[0].finding_id, 'FND-CRIT-001');
  assert.match(parsed.report_id, /^RPT-[0-9a-f]{12}$/);
  assert.match(parsed.executive_summary, /3 validated finding/);
});

test('JSON output requires a generated_at timestamp', () => {
  const finding = medium();
  delete finding.created_at;
  assert.throws(
    () => generateReport([finding], { programName: 'Lab', format: 'json' }),
    /requires a generated_at timestamp/,
  );
});

test('generateReport rejects an empty findings list and unknown formats', () => {
  assert.throws(() => generateReport([]), /At least one finding is required/);
  assert.throws(() => generateReport([critical()], { format: 'pdf' }), /Invalid format/);
});

test('CLI report prints markdown to stdout', async () => {
  const fixture = path.join(__dirname, 'fixtures', 'report-critical.json');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--finding', fixture, '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
  ]);
  assert.match(stdout, /# Bug Bounty Report — Lab Program/);
  assert.match(stdout, /SQL injection in login username parameter \[CRITICAL\]/);
});

test('CLI report --findings --format json --out writes the file', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-report-'));
  try {
    const output = path.join(directory, 'report.json');
    const { stdout } = await execFileAsync(process.execPath, [
      CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
      '--format', 'json', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
      '--out', output,
    ]);
    assert.match(stdout, /Report written to/);
    const parsed = JSON.parse(fs.readFileSync(output, 'utf8'));
    assert.equal(parsed.findings_summary.total, 3);
    assert.equal(parsed.findings_summary.critical, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI report with an incomplete finding exits non-zero and creates no output file', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-report-'));
  try {
    const output = path.join(directory, 'report.md');
    await assert.rejects(
      execFileAsync(process.execPath, [
        CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-incomplete.json'), '--out', output,
      ]),
      (error) => {
        assert.match(error.stderr, /missing required field\(s\): impact, remediation/);
        assert.notEqual(error.code, 0);
        return true;
      },
    );
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI report requires exactly one of --finding and --findings', async () => {
  const fixture = path.join(__dirname, 'fixtures', 'report-critical.json');
  const array = path.join(__dirname, 'fixtures', 'report-findings-array.json');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', '--finding', fixture, '--findings', array]),
    (error) => {
      assert.match(error.stderr, /exactly one of --finding and --findings/);
      return true;
    },
  );
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report']),
    (error) => {
      assert.match(error.stderr, /exactly one of --finding and --findings/);
      return true;
    },
  );
});
