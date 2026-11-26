// Report split (round 70): `sentinel report split <report.json>
// --by severity|verdict --out-dir <dir>` splits one JSON report
// into one valid round-31 JSON report per group — one file per
// non-empty severity (or rule verdict), each with its own
// recomputed report id and a `split` metadata block, so each team
// gets a report that stands on its own. Each output is rendered
// by generateReport itself, so it passes `report validate` with
// report_id_matches: true by construction. Fixtures only; no
// scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { splitReport } = require('../src/report/split');
const { validateReport, deriveExpectedReportId } = require('../src/report/validate');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const SKILL_DIR = path.resolve(__dirname, '..');
const STATE_DIR = path.join(os.homedir(), 'workspace', 'sentinel-bounty', 'state');

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

test('severity split: five findings split into five groups with the right findings each', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  assert.deepEqual(
    split.files.map((file) => [file.group, file.count]),
    [['critical', 1], ['high', 1], ['medium', 1], ['low', 1], ['informational', 1]],
  );
  const byGroup = new Map(split.files.map((file) => [file.group, JSON.parse(file.report)]));
  assert.deepEqual(byGroup.get('critical').findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.deepEqual(byGroup.get('high').findings.map((f) => f.finding_id), ['FND-HIGH-001']);
  assert.deepEqual(byGroup.get('medium').findings.map((f) => f.finding_id), ['FND-MED-001']);
  assert.deepEqual(byGroup.get('low').findings.map((f) => f.finding_id), ['FND-LOW-001']);
  assert.deepEqual(byGroup.get('informational').findings.map((f) => f.finding_id), ['FND-INFO-001']);
  assert.deepEqual(split.summary, {
    total: 5,
    from_report_id: 'RPT-3aeafa977190',
    group_by: 'severity',
    groups: [
      { group: 'critical', count: 1, fileName: 'RPT-f4341c7c301c-critical.json' },
      { group: 'high', count: 1, fileName: 'RPT-66db21e4081a-high.json' },
      { group: 'medium', count: 1, fileName: 'RPT-dfe972674eb8-medium.json' },
      { group: 'low', count: 1, fileName: 'RPT-e70c87e276a9-low.json' },
      { group: 'informational', count: 1, fileName: 'RPT-4528b17080cf-informational.json' },
    ],
  });
});

test('each split output carries the split metadata block and its own recomputed report id', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  for (const file of split.files) {
    const parsed = JSON.parse(file.report);
    assert.deepEqual(parsed.split, {
      from_report_id: 'RPT-3aeafa977190',
      group_by: 'severity',
      group: file.group,
    });
    // The report id is the generator's own derivation for that
    // subset (pinned independently via validate.js).
    assert.equal(parsed.report_id, deriveExpectedReportId(PROGRAM, parsed.findings));
    assert.equal(file.fileName, `${parsed.report_id}-${file.group}.json`);
    // Same program, target, and session as the source.
    assert.equal(parsed.program_name, PROGRAM);
    assert.equal(parsed.target_id, 'TGT-LAB-001');
    assert.equal(parsed.session_id, 'SES-REPORT-001');
    assert.equal(parsed.generated_at, GENERATED_AT);
  }
});

test('each split output is a direct render of its subset plus the split block', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  for (const file of split.files) {
    const parsed = JSON.parse(file.report);
    const direct = generateReport(parsed.findings, {
      programName: PROGRAM,
      generatedAt: GENERATED_AT,
      format: 'json',
      allowMixedTargets: true,
    });
    delete parsed.split;
    assert.equal(`${JSON.stringify(parsed, null, 2)}\n`, direct);
  }
});

test('each split output passes report validate cleanly', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  for (const file of split.files) {
    const result = validateReport(JSON.parse(file.report));
    assert.equal(result.status, 'VALID');
    assert.equal(result.report_id_matches, true);
    assert.equal(result.counts.findings, 1);
    assert.equal(result.counts.errors, 0);
  }
});

test('the union of the split outputs equals the source finding set', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  const union = split.files
    .flatMap((file) => JSON.parse(file.report).findings.map((f) => f.finding_id))
    .sort();
  assert.deepEqual(union, ['FND-CRIT-001', 'FND-HIGH-001', 'FND-INFO-001', 'FND-LOW-001', 'FND-MED-001']);
  assert.equal(union.length, new Set(union).size); // no duplication
});

test('verdict split groups by the rule verdict, not the stored validation_status', () => {
  // Every fixture finding carries stored validation_status
  // "validated" — grouping by that field would put all three
  // in one group. The rule verdict splits them 1 valid / 2
  // needs_evidence, and no group is ever named "validated".
  const source = generatedReport(ALL);
  const split = splitReport(source, { groupBy: 'verdict' });
  assert.deepEqual(
    split.files.map((file) => [file.group, file.count]),
    [['valid', 1], ['needs_evidence', 2]],
  );
  const byGroup = new Map(split.files.map((file) => [file.group, JSON.parse(file.report)]));
  assert.deepEqual(byGroup.get('valid').findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.deepEqual(
    byGroup.get('needs_evidence').findings.map((f) => f.finding_id).sort(),
    ['FND-LOW-001', 'FND-MED-001'],
  );
  assert.equal(byGroup.has('validated'), false);
  assert.equal(byGroup.has('false_positive'), false); // empty groups are not written
});

test('split is deterministic across runs', () => {
  const source = generatedReport(FIVE);
  const first = splitReport(source, { groupBy: 'severity' });
  const second = splitReport(source, { groupBy: 'severity' });
  assert.deepEqual(second, first);
});

test('unknown --by fails naming both allowed values', () => {
  const source = generatedReport(ALL);
  assert.throws(
    () => splitReport(source, { groupBy: 'asset' }),
    (error) => {
      assert.match(error.message, /REPORT_SPLIT_INVALID_GROUP_BY/);
      assert.match(error.message, /severity/);
      assert.match(error.message, /verdict/);
      return true;
    },
  );
  assert.throws(() => splitReport(source, {}), /REPORT_SPLIT_INVALID_GROUP_BY/);
});

test('malformed inputs fail with the shared reader’s named errors', () => {
  const source = generatedReport(ALL);
  assert.throws(() => splitReport(null, { groupBy: 'severity' }), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => splitReport({ findings: [] }, { groupBy: 'severity' }), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => splitReport({ report_id: 'RPT-A' }, { groupBy: 'severity' }), /REPORT_DIFF_INVALID_REPORT/);
  const dup = generatedReport([MED, MED]);
  assert.throws(() => splitReport(dup, { groupBy: 'severity' }), /REPORT_DIFF_DUPLICATE_FINDING_ID/);
});

test('an empty report fails as empty, not as a zero-group split', () => {
  const empty = { report_id: 'RPT-A', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [] };
  assert.throws(() => splitReport(empty, { groupBy: 'severity' }), /REPORT_SPLIT_EMPTY/);
});

test('a finding that fails the strict check fails the split', () => {
  const source = generatedReport(ALL);
  source.findings[0].severity = 'low'; // CRIT still scores 9.8: band mismatch
  assert.throws(
    () => splitReport(source, { groupBy: 'severity' }),
    (error) => {
      assert.match(error.message, /REPORT_SPLIT_INVALID_FINDING/);
      assert.match(error.message, /FND-CRIT-001/);
      return true;
    },
  );
});

test('no generated_at anywhere fails instead of inventing a timestamp', () => {
  const noCreated = (finding) => {
    const copy = clone(finding);
    delete copy.created_at;
    return copy;
  };
  const source = { report_id: 'RPT-A', program_name: PROGRAM, findings: [noCreated(MED)] };
  assert.throws(() => splitReport(source, { groupBy: 'severity' }), /REPORT_SPLIT_NO_GENERATED_AT/);
});

test('generated_at falls back to the newest finding created_at in the group', () => {
  const source = generatedReport([CRIT, MED]);
  delete source.generated_at;
  const split = splitReport(source, { groupBy: 'severity' });
  for (const file of split.files) {
    assert.equal(JSON.parse(file.report).generated_at, '2026-11-26T00:00:00.000Z');
  }
});

test('the other report goldens do not move', () => {
  const markdown = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'markdown' });
  const json = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf');
});

test('CLI: stdout lists only the written paths, summaries go to stderr', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outDir]);
  const lines = stdout.trim().split('\n');
  assert.deepEqual(lines, [
    path.join(outDir, 'RPT-f4341c7c301c-critical.json'),
    path.join(outDir, 'RPT-dfe972674eb8-medium.json'),
    path.join(outDir, 'RPT-e70c87e276a9-low.json'),
  ]);
  assert.equal(stderr, [
    `critical: 1 finding -> ${path.join(outDir, 'RPT-f4341c7c301c-critical.json')}`,
    `medium: 1 finding -> ${path.join(outDir, 'RPT-dfe972674eb8-medium.json')}`,
    `low: 1 finding -> ${path.join(outDir, 'RPT-e70c87e276a9-low.json')}`,
    '',
  ].join('\n'));
  for (const line of lines) {
    assert.equal(JSON.parse(fs.readFileSync(line, 'utf8')).split.group_by, 'severity');
    assert.equal(fs.statSync(line).mode & 0o777, 0o600);
  }
});

test('CLI: --out-dir is created with mode 0700', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'nested', 'out');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outDir]);
  assert.equal(fs.statSync(outDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(dir, 'nested')).mode & 0o777, 0o700);
});

test('CLI: split twice into two dirs gives byte-identical files', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const outA = path.join(dir, 'a');
  const outB = path.join(dir, 'b');
  await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outA]);
  await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outB]);
  const names = fs.readdirSync(outA).sort();
  assert.deepEqual(names, fs.readdirSync(outB).sort());
  for (const name of names) {
    assert.equal(fs.readFileSync(path.join(outA, name), 'utf8'), fs.readFileSync(path.join(outB, name), 'utf8'));
  }
});

test('CLI: non-empty --out-dir refuses without --force and writes nothing', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  const keepPath = path.join(outDir, 'keep.txt');
  fs.mkdirSync(outDir);
  fs.writeFileSync(keepPath, 'keep me\n');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outDir]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_SPLIT_OUT_DIR_NOT_EMPTY/);
      return true;
    },
  );
  assert.deepEqual(fs.readdirSync(outDir), ['keep.txt']);
  assert.equal(fs.readFileSync(keepPath, 'utf8'), 'keep me\n');
});

test('CLI: --force overwrites only the files this split writes', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  const keepPath = path.join(outDir, 'keep.txt');
  const stalePath = path.join(outDir, 'RPT-f4341c7c301c-critical.json');
  fs.mkdirSync(outDir);
  fs.writeFileSync(keepPath, 'keep me\n');
  fs.writeFileSync(stalePath, 'stale\n');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outDir, '--force']);
  assert.equal(fs.readFileSync(keepPath, 'utf8'), 'keep me\n');
  assert.notEqual(fs.readFileSync(stalePath, 'utf8'), 'stale\n');
  assert.equal(JSON.parse(fs.readFileSync(stalePath, 'utf8')).report_id, 'RPT-f4341c7c301c');
  assert.equal(stdout.trim().split('\n').length, 3);
});

test('CLI: --out-dir inside the skill dir or the state dir is refused', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const insideSkill = path.join(SKILL_DIR, 'tmp-split-test');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', insideSkill]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_SPLIT_OUT_DIR_FORBIDDEN/);
      return true;
    },
  );
  assert.equal(fs.existsSync(insideSkill), false);
  const insideState = path.join(STATE_DIR, 'tmp-split-test');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', insideState]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_SPLIT_OUT_DIR_FORBIDDEN/);
      return true;
    },
  );
  assert.equal(fs.existsSync(insideState), false);
});

test('CLI: unknown --by, missing flags, and malformed/symlinked inputs fail with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'asset', '--out-dir', outDir]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_SPLIT_INVALID_GROUP_BY/);
      return true;
    },
  );
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--out-dir', outDir]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /requires --by/);
      return true;
    },
  );
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /requires --out-dir/);
      return true;
    },
  );
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /report split requires a report file/);
      return true;
    },
  );
  fs.writeFileSync(inPath, '{not json');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'severity', '--out-dir', outDir]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  assert.equal(fs.existsSync(outDir), false); // a bad input never creates the dir
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const linkPath = path.join(dir, 'link.json');
  fs.symlinkSync(inPath, linkPath);
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'split', linkPath, '--by', 'severity', '--out-dir', outDir]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI: the input file is read-only (bytes and mtime unchanged)', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  const content = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  fs.writeFileSync(inPath, content);
  const before = fs.statSync(inPath);
  await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'verdict', '--out-dir', outDir]);
  const after = fs.statSync(inPath);
  assert.equal(fs.readFileSync(inPath, 'utf8'), content);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test('CLI: each written file passes report validate cleanly', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-split-');
  const inPath = path.join(dir, 'in.json');
  const outDir = path.join(dir, 'out');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'report', 'split', inPath, '--by', 'verdict', '--out-dir', outDir]);
  for (const filePath of stdout.trim().split('\n')) {
    const { stdout: validation } = await execFileAsync(process.execPath, [CLI, 'report', 'validate', filePath]);
    assert.match(validation, /Report Validation — VALID/);
    assert.match(validation, /\(verified\)/);
  }
});
