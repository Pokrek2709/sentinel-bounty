// Report merge (round 68): `sentinel report merge <a.json> <b.json>`
// combines two JSON reports into one valid round-31 JSON report —
// identical findings kept once, disjoint findings unioned, a
// same-id finding with different content fails the merge with
// REPORT_MERGE_CONFLICTING_FINDING instead of silently picking
// one version. The merged report is rendered by generateReport
// itself, so its report id, groups, counts, and mixed-target
// fields are the generator's own. Fixtures only; no scanner, no
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
const { mergeReports, canonicalFindingString, firstDifferingField } = require('../src/report/merge');
const { validateReport } = require('../src/report/validate');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateModeSync } = require('./helpers/private-mode');

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

test('disjoint pair merges to the union with the shared finding kept once', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([MED, LOW]);
  const merged = mergeReports(a, b);
  assert.deepEqual(merged.summary, { total: 3, fromA: 2, fromB: 2, shared: 1 });
  const parsed = JSON.parse(merged.report);
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001', 'FND-MED-001', 'FND-LOW-001']);
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
  assert.equal(parsed.program_name, PROGRAM);
  assert.equal(parsed.generated_at, GENERATED_AT);
  assert.equal(parsed.target_id, 'TGT-LAB-001');
  assert.equal(parsed.session_id, 'SES-REPORT-001');
});

test('merged report is byte-identical to a direct render of the same set', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([MED, LOW]);
  const merged = mergeReports(a, b);
  const direct = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  assert.equal(merged.report, direct);
});

test('merged output passes report validate cleanly', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([MED, LOW]);
  const merged = mergeReports(a, b);
  const result = validateReport(JSON.parse(merged.report));
  assert.equal(result.status, 'VALID');
  assert.equal(result.report_id_matches, true);
  assert.deepEqual(result.counts, { findings: 3, valid: 1, false_positive: 0, needs_evidence: 2, errors: 0 });
});

test('merge is deterministic across argument order', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([MED, LOW]);
  assert.equal(mergeReports(a, b).report, mergeReports(b, a).report);
});

test('merged_from order does not matter: it is an id set, not a list', () => {
  const medA = { ...clone(MED), merged_from: ['FND-X', 'FND-Y'] };
  const medB = { ...clone(MED), merged_from: ['FND-Y', 'FND-X'] };
  const a = { report_id: 'RPT-A', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [medA] };
  const b = { report_id: 'RPT-B', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [medB] };
  const merged = mergeReports(a, b);
  assert.deepEqual(merged.summary, { total: 1, fromA: 1, fromB: 1, shared: 1 });
  assert.equal(canonicalFindingString(medA), canonicalFindingString(medB));
});

test('key order does not matter: canonicalization sorts keys', () => {
  const reversed = {};
  for (const key of Object.keys(MED).reverse()) reversed[key] = MED[key];
  const a = { report_id: 'RPT-A', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [clone(MED)] };
  const b = { report_id: 'RPT-B', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [reversed] };
  const merged = mergeReports(a, b);
  assert.deepEqual(merged.summary, { total: 1, fromA: 1, fromB: 1, shared: 1 });
});

test('conflicting same-id finding fails naming the id and the first differing field', () => {
  const medHigh = { ...clone(MED), severity: 'high', cvss_score: 7.0 };
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([medHigh, LOW]);
  assert.throws(
    () => mergeReports(a, b),
    (error) => {
      assert.match(error.message, /REPORT_MERGE_CONFLICTING_FINDING/);
      assert.match(error.message, /FND-MED-001/);
      assert.match(error.message, /cvss_score/);
      return true;
    },
  );
  // The first differing field in sorted key order is cvss_score
  // (5.0 vs 7.0); severity differs too, but it sorts later.
  assert.deepEqual(
    firstDifferingField(MED, medHigh),
    { field: 'cvss_score', old: '5', new: '7' },
  );
});

test('program mismatch fails instead of misattributing the findings', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([LOW], GENERATED_AT, 'Other Program');
  assert.throws(
    () => mergeReports(a, b),
    (error) => {
      assert.match(error.message, /REPORT_MERGE_PROGRAM_MISMATCH/);
      assert.match(error.message, /Lab Program/);
      assert.match(error.message, /Other Program/);
      return true;
    },
  );
});

test('a finding that fails the strict check fails the merge', () => {
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([MED, LOW]);
  b.findings[0].severity = 'critical'; // MED still scores 5.0: band mismatch
  assert.throws(
    () => mergeReports(a, b),
    (error) => {
      assert.match(error.message, /REPORT_MERGE_INVALID_FINDING/);
      assert.match(error.message, /FND-MED-001/);
      return true;
    },
  );
});

test('both reports empty fails as empty, not as a zero-finding report', () => {
  const empty = (id) => ({ report_id: id, program_name: PROGRAM, generated_at: GENERATED_AT, findings: [] });
  assert.throws(
    () => mergeReports(empty('RPT-A'), empty('RPT-B')),
    /REPORT_MERGE_EMPTY/,
  );
});

test('generated_at is the newer of the two inputs', () => {
  const a = generatedReport([CRIT, MED], '2026-11-26T02:00:00.000Z');
  const b = generatedReport([LOW], '2026-11-26T03:00:00.000Z');
  const merged = mergeReports(a, b);
  assert.equal(JSON.parse(merged.report).generated_at, '2026-11-26T03:00:00.000Z');
});

test('no generated_at anywhere fails instead of inventing a timestamp', () => {
  const noCreated = (finding) => {
    const copy = clone(finding);
    delete copy.created_at;
    return copy;
  };
  const a = { report_id: 'RPT-A', program_name: PROGRAM, findings: [noCreated(MED)] };
  const b = { report_id: 'RPT-B', program_name: PROGRAM, findings: [noCreated(LOW)] };
  assert.throws(() => mergeReports(a, b), /REPORT_MERGE_NO_GENERATED_AT/);
});

test('different targets merge as a mixed-target report', () => {
  const lowOther = { ...clone(LOW), target_id: 'TGT-LAB-002' };
  const a = generatedReport([CRIT, MED]);
  const b = generatedReport([lowOther]);
  const merged = mergeReports(a, b);
  const parsed = JSON.parse(merged.report);
  assert.equal(parsed.mixed_targets, true);
  assert.deepEqual(parsed.target_ids, ['TGT-LAB-001', 'TGT-LAB-002']);
  assert.equal(parsed.target_id, 'TGT-LAB-001');
  assert.equal(parsed.findings.length, 3);
});

test('merged set over MAX_FINDINGS fails instead of rendering a giant report', () => {
  const many = (prefix, count) => {
    const out = [];
    for (let i = 0; i < count; i += 1) {
      out.push({ ...clone(MED), finding_id: `FND-${prefix}-${String(i).padStart(5, '0')}` });
    }
    return out;
  };
  const a = { report_id: 'RPT-A', program_name: PROGRAM, generated_at: GENERATED_AT, findings: many('A', 6000) };
  const b = { report_id: 'RPT-B', program_name: PROGRAM, generated_at: GENERATED_AT, findings: many('B', 6000) };
  assert.throws(() => mergeReports(a, b), /REPORT_MERGE_TOO_MANY_FINDINGS/);
});

test('malformed inputs fail with the shared reader’s named errors', () => {
  const a = generatedReport([CRIT, MED]);
  assert.throws(() => mergeReports(null, a), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => mergeReports({ findings: [] }, a), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => mergeReports({ report_id: 'RPT-A' }, a), /REPORT_DIFF_INVALID_REPORT/);
  const dup = generatedReport([MED, MED]);
  assert.throws(() => mergeReports(dup, a), /REPORT_DIFF_DUPLICATE_FINDING_ID/);
});

test('the other report goldens do not move', () => {
  const markdown = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'markdown' });
  const json = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf');
});

test('CLI: stdout is pure JSON and the summary line goes to stderr', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-merge-');
  const aPath = path.join(dir, 'a.json');
  const bPath = path.join(dir, 'b.json');
  fs.writeFileSync(aPath, generateReport([CRIT, MED], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.writeFileSync(bPath, generateReport([MED, LOW], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, bPath]);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001', 'FND-MED-001', 'FND-LOW-001']);
  assert.equal(stderr, 'merged 3 findings from 2 + 2 (1 shared, 0 conflicts)\n');
});

test('CLI: --out writes mode 0600 and stdout carries only the confirmation', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-merge-');
  const aPath = path.join(dir, 'a.json');
  const bPath = path.join(dir, 'b.json');
  const outPath = path.join(dir, 'merged.json');
  fs.writeFileSync(aPath, generateReport([CRIT, MED], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.writeFileSync(bPath, generateReport([MED, LOW], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, bPath, '--out', outPath]);
  assert.equal(stdout, `Merged report written to ${outPath}\n`);
  assert.equal(stderr, 'merged 3 findings from 2 + 2 (1 shared, 0 conflicts)\n');
  assertPrivateModeSync(outPath, 0o600);
  const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
});

test('CLI: conflicting inputs fail with exit 1 and write no file', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-merge-');
  const aPath = path.join(dir, 'a.json');
  const bPath = path.join(dir, 'b.json');
  const outPath = path.join(dir, 'merged.json');
  const medHigh = { ...clone(MED), severity: 'high', cvss_score: 7.0 };
  fs.writeFileSync(aPath, generateReport([CRIT, MED], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.writeFileSync(bPath, generateReport([medHigh, LOW], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, bPath, '--out', outPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_MERGE_CONFLICTING_FINDING/);
      assert.match(error.stderr, /FND-MED-001/);
      return true;
    },
  );
  assert.equal(fs.existsSync(outPath), false);
});

test('CLI: malformed and symlinked inputs fail with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-merge-');
  const aPath = path.join(dir, 'a.json');
  const bPath = path.join(dir, 'b.json');
  const linkPath = path.join(dir, 'link.json');
  fs.writeFileSync(aPath, generateReport([CRIT, MED], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.writeFileSync(bPath, '{not json');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, bPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  fs.writeFileSync(bPath, generateReport([MED, LOW], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.symlinkSync(bPath, linkPath);
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, linkPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI: merge requires two files and rejects unknown options', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-merge-');
  const aPath = path.join(dir, 'a.json');
  fs.writeFileSync(aPath, generateReport([CRIT, MED], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /report merge requires two report files/);
      return true;
    },
  );
  const bPath = path.join(dir, 'b.json');
  fs.writeFileSync(bPath, generateReport([MED, LOW], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'merge', aPath, bPath, '--bogus']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /Unknown option: --bogus/);
      return true;
    },
  );
});
