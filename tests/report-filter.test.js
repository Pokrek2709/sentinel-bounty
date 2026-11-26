// Report filter (round 71): `sentinel report filter <report.json>
// [--severity <level>] [--verdict <rule-verdict>] [--out
// <filtered.json>]` keeps a threshold subset of one JSON report —
// only High and above, only valid verdicts, or both AND-combined —
// as one valid round-31 JSON report with its own recomputed report
// id and a `filter` metadata block. An empty result is a valid
// empty report (total 0), not an error. The verdict predicate uses
// the RULE verdict from round 67's validateOneFinding (valid /
// false_positive / needs_evidence), NOT the stored
// validation_status workflow state. Fixtures only; no scanner, no
// network, no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { filterReport } = require('../src/report/filter');
const { validateReport, deriveExpectedReportId } = require('../src/report/validate');
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
// "validated" — the workflow state, which is NOT the predicate).
const FP = loadFixture('false-positive.json');
const CONFIRMED_NO_POC = loadFixture('confirmed-missing-poc.json');
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

function filteredIds(result) {
  return JSON.parse(result.report).findings.map((f) => f.finding_id);
}

test('severity >= high keeps exactly the critical and high findings', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'high' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001', 'FND-HIGH-001']);
  assert.deepEqual(result.summary, {
    total: 5,
    kept: 2,
    from_report_id: 'RPT-3aeafa977190',
    report_id: deriveExpectedReportId(PROGRAM, [CRIT, HIGH]),
    severity: 'high',
    verdict: null,
  });
  assert.deepEqual(JSON.parse(result.report).filter, { from_report_id: 'RPT-3aeafa977190', severity: 'high' });
});

test('severity >= low keeps everything except informational', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'low' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001', 'FND-HIGH-001', 'FND-MED-001', 'FND-LOW-001']);
  assert.equal(result.summary.kept, 4);
});

test('severity informational keeps all five findings', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'informational' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001', 'FND-HIGH-001', 'FND-MED-001', 'FND-LOW-001', 'FND-INFO-001']);
  assert.equal(result.summary.kept, 5);
});

test('severity critical keeps only the critical finding', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'critical' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001']);
});

test('severity level is matched case-insensitively', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'HIGH' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001', 'FND-HIGH-001']);
  assert.equal(result.summary.severity, 'high');
});

test('verdict valid keeps only the valid finding', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { verdict: 'valid' });
  assert.deepEqual(filteredIds(result), ['FND-CRIT-001']);
  assert.deepEqual(JSON.parse(result.report).filter, { from_report_id: 'RPT-3aeafa977190', verdict: 'valid' });
});

test('verdict needs_evidence keeps the four unconfirmed findings', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { verdict: 'needs_evidence' });
  assert.deepEqual(filteredIds(result), ['FND-HIGH-001', 'FND-MED-001', 'FND-LOW-001', 'FND-INFO-001']);
});

test('verdict false_positive keeps only the false-positive finding', () => {
  const source = generatedReport([FP, CONFIRMED_NO_POC]);
  const result = filterReport(source, { verdict: 'false_positive' });
  assert.deepEqual(filteredIds(result), ['F-R31-FALSE-POSITIVE']);
});

test('verdict does NOT use the stored validation_status workflow state', () => {
  // Every finding in the FIVE set carries validation_status
  // "validated" — if the predicate read that field, `valid`
  // would keep nothing and `validated` would keep everything.
  // The rule verdict is what filters: CRIT is valid, the rest
  // are needs_evidence.
  const source = generatedReport(FIVE);
  assert.equal(filterReport(source, { verdict: 'valid' }).summary.kept, 1);
  assert.equal(filterReport(source, { verdict: 'needs_evidence' }).summary.kept, 4);
  assert.throws(() => filterReport(source, { verdict: 'validated' }), /REPORT_FILTER_INVALID_VERDICT: --verdict must be one of valid, false_positive, needs_evidence/);
});

test('combined predicates AND correctly', () => {
  const source = generatedReport(FIVE);
  assert.deepEqual(filteredIds(filterReport(source, { severity: 'high', verdict: 'needs_evidence' })), ['FND-HIGH-001']);
  assert.deepEqual(filteredIds(filterReport(source, { severity: 'medium', verdict: 'valid' })), ['FND-CRIT-001']);
  assert.deepEqual(filteredIds(filterReport(source, { severity: 'low', verdict: 'needs_evidence' })), ['FND-HIGH-001', 'FND-MED-001', 'FND-LOW-001']);
  const combined = JSON.parse(filterReport(source, { severity: 'high', verdict: 'needs_evidence' }).report);
  assert.deepEqual(combined.filter, { from_report_id: 'RPT-3aeafa977190', severity: 'high', verdict: 'needs_evidence' });
});

test('no predicate is refused with a named error', () => {
  const source = generatedReport(FIVE);
  assert.throws(() => filterReport(source, {}), /REPORT_FILTER_NO_PREDICATE/);
  assert.throws(() => filterReport(source, { severity: '  ', verdict: '' }), /REPORT_FILTER_NO_PREDICATE/);
});

test('unknown severity is refused with a named error listing the five values', () => {
  const source = generatedReport(FIVE);
  assert.throws(
    () => filterReport(source, { severity: 'severe' }),
    /REPORT_FILTER_INVALID_SEVERITY: --severity must be one of critical, high, medium, low, informational \(got "severe"\)\./,
  );
});

test('unknown verdict is refused with a named error listing the three values', () => {
  const source = generatedReport(FIVE);
  assert.throws(
    () => filterReport(source, { verdict: 'maybe' }),
    /REPORT_FILTER_INVALID_VERDICT: --verdict must be one of valid, false_positive, needs_evidence \(got "maybe"\)\./,
  );
});

test('empty result is a valid empty report, not an error', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'critical', verdict: 'needs_evidence' });
  const parsed = JSON.parse(result.report);
  assert.deepEqual(parsed.findings, []);
  assert.deepEqual(parsed.findings_summary, { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 });
  assert.equal(parsed.report_id, deriveExpectedReportId(PROGRAM, []));
  assert.equal(parsed.target_id, source.target_id);
  assert.equal(parsed.program_name, PROGRAM);
  assert.equal(parsed.generated_at, GENERATED_AT);
  assert.equal(
    parsed.executive_summary,
    'Program Lab Program: 0 validated finding(s) — 0 critical, 0 high, 0 medium, 0 low, 0 informational. '
    + 'Highest severity: informational. All findings in this report were validated against the finding schema before rendering.',
  );
  assert.deepEqual(parsed.filter, { from_report_id: 'RPT-3aeafa977190', severity: 'critical', verdict: 'needs_evidence' });
  assert.deepEqual(result.summary, {
    total: 5,
    kept: 0,
    from_report_id: 'RPT-3aeafa977190',
    report_id: deriveExpectedReportId(PROGRAM, []),
    severity: 'critical',
    verdict: 'needs_evidence',
  });
  const validation = validateReport(parsed);
  assert.equal(validation.status, 'VALID');
  assert.equal(validation.report_id_matches, true);
  assert.deepEqual(validation.counts, { findings: 0, valid: 0, false_positive: 0, needs_evidence: 0, errors: 0 });
});

test('filtered output passes report validate cleanly with report_id_matches true', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'high' });
  const validation = validateReport(JSON.parse(result.report));
  assert.equal(validation.status, 'VALID');
  assert.equal(validation.report_id_matches, true);
  assert.deepEqual(validation.counts, { findings: 2, valid: 1, false_positive: 0, needs_evidence: 1, errors: 0 });
});

test('report_id is the generator derivation for the kept subset, and the output is byte-identical to a direct render plus the filter block', () => {
  const source = generatedReport(FIVE);
  const kept = [CRIT, HIGH];
  const result = filterReport(source, { severity: 'high' });
  const parsed = JSON.parse(result.report);
  assert.equal(parsed.report_id, deriveExpectedReportId(PROGRAM, kept));
  const direct = JSON.parse(generateReport(kept, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  direct.filter = { from_report_id: 'RPT-3aeafa977190', severity: 'high' };
  assert.equal(result.report, `${JSON.stringify(direct, null, 2)}\n`);
});

test('filter is deterministic across runs and across input finding order', () => {
  const source = generatedReport(FIVE);
  const shuffled = clone(source);
  shuffled.findings = [LOW, INFO, CRIT, MED, HIGH].map((finding) => {
    const rendered = source.findings.find((item) => item.finding_id === finding.finding_id);
    return rendered;
  });
  const first = filterReport(source, { severity: 'medium' });
  const second = filterReport(source, { severity: 'medium' });
  const fromShuffled = filterReport(shuffled, { severity: 'medium' });
  assert.equal(first.report, second.report);
  assert.equal(first.report, fromShuffled.report);
});

test('a finding failing the strict check fails the filter with a named error', () => {
  const source = generatedReport(FIVE);
  source.findings[0].severity = 'medium';
  assert.throws(() => filterReport(source, { severity: 'low' }), /REPORT_FILTER_INVALID_FINDING: finding FND-CRIT-001 fails the strict check: .*severity\/score mismatch/);
});

test('malformed inputs fail with named errors from the shared reader', () => {
  assert.throws(() => filterReport(null, { severity: 'high' }), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => filterReport({ report_id: 'RPT-x' }, { severity: 'high' }), /REPORT_DIFF_INVALID_REPORT: .* has no findings array/);
  const duplicate = generatedReport(FIVE);
  duplicate.findings.push(clone(duplicate.findings[0]));
  assert.throws(() => filterReport(duplicate, { severity: 'high' }), /REPORT_DIFF_DUPLICATE_FINDING_ID: .*FND-CRIT-001/);
});

test('generated_at falls back to the newest finding created_at when the source has none', () => {
  const source = generatedReport([CRIT, MED]);
  delete source.generated_at;
  const result = filterReport(source, { severity: 'critical' });
  assert.equal(JSON.parse(result.report).generated_at, '2026-11-26T00:00:00.000Z');
});

test('a report with no generated_at and no finding created_at fails with a named error', () => {
  const source = generatedReport([CRIT, MED]);
  delete source.generated_at;
  source.findings.forEach((finding) => { delete finding.created_at; });
  assert.throws(() => filterReport(source, { severity: 'critical' }), /REPORT_FILTER_NO_GENERATED_AT/);
});

test('the other report goldens do not move', () => {
  const markdown = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'markdown' });
  const json = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf');
});

test('CLI: stdout is pure JSON, the summary goes to stderr', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-filter-');
  const inPath = path.join(dir, 'in.json');
  fs.writeFileSync(inPath, generateReport(FIVE, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'filter', inPath, '--severity', 'high']);
  const parsed = JSON.parse(stdout);
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001', 'FND-HIGH-001']);
  assert.deepEqual(parsed.filter, { from_report_id: 'RPT-3aeafa977190', severity: 'high' });
  assert.equal(stderr, 'filtered 2 of 5 findings (severity >= high)\n');
});

test('CLI: --out writes mode 0600, stdout names the file, and the input is untouched', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-filter-');
  const inPath = path.join(dir, 'in.json');
  const outPath = path.join(dir, 'filtered.json');
  const input = generateReport(FIVE, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  fs.writeFileSync(inPath, input);
  const before = fs.statSync(inPath);
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'filter', inPath, '--verdict', 'valid', '--out', outPath]);
  assert.equal(stdout, `Filtered report written to ${outPath}\n`);
  assert.equal(stderr, 'filtered 1 of 5 findings (verdict valid)\n');
  assert.equal(fs.statSync(outPath).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(outPath, 'utf8')).findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  const after = fs.statSync(inPath);
  assert.equal(fs.readFileSync(inPath, 'utf8'), input);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test('CLI: a symlinked input is refused', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-filter-');
  const realPath = path.join(dir, 'real.json');
  const linkPath = path.join(dir, 'link.json');
  fs.writeFileSync(realPath, generateReport(FIVE, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.symlinkSync(realPath, linkPath);
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'filter', linkPath, '--severity', 'high']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI: missing predicates and unknown values fail with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-filter-');
  const inPath = path.join(dir, 'in.json');
  fs.writeFileSync(inPath, generateReport(FIVE, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  for (const args of [
    [],
    ['--severity', 'severe'],
    ['--verdict', 'maybe'],
    ['--bogus', 'x'],
  ]) {
    await assert.rejects(
      execFileAsync(process.execPath, [CLI, 'report', 'filter', inPath, ...args]),
      (error) => {
        assert.equal(error.code, 1);
        assert.match(error.stderr, /REPORT_FILTER_(NO_PREDICATE|INVALID_SEVERITY|INVALID_VERDICT)|Unknown option/);
        return true;
      },
    );
  }
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'filter']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /report filter requires a report file/);
      return true;
    },
  );
});

test('CLI: filtering twice gives byte-identical output', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-filter-');
  const inPath = path.join(dir, 'in.json');
  fs.writeFileSync(inPath, generateReport(FIVE, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const first = await execFileAsync(process.execPath, [CLI, 'report', 'filter', inPath, '--severity', 'medium', '--verdict', 'needs_evidence']);
  const second = await execFileAsync(process.execPath, [CLI, 'report', 'filter', inPath, '--severity', 'medium', '--verdict', 'needs_evidence']);
  assert.equal(first.stdout, second.stdout);
  assert.equal(first.stderr, second.stderr);
  assert.deepEqual(JSON.parse(first.stdout).findings.map((f) => f.finding_id), ['FND-HIGH-001', 'FND-MED-001']);
});
