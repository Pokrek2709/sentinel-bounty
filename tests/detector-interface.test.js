// Pluggable detector interface (round 51, Phase 5): the contract
// a finding detector must satisfy, the built-in stub as reference
// implementation, and a safe loader for custom detector modules.
// Fixtures only; no real detector, no scanner, no network, no live
// target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  runDetectorOnRecords,
  validateDetectorResult,
  stubDetector,
  runDetector,
  getDetector,
  loadDetector,
} = require('../src/detection/detector');
const { runStubDetector } = require('../src/detection/stub-detector');
const { validateFinding, dedupeFindings } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateModeSync } = require('./helpers/private-mode');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

function fixturePath(name) {
  return path.join(__dirname, 'fixtures', name);
}

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(fixturePath(name), 'utf8'));
}

function baseRaw(overrides) {
  return {
    finding_id: 'F-001',
    title: 'Reflected cross-site scripting in search parameter',
    vulnerability_type: 'Cross-Site Scripting',
    description: 'The search parameter reflects input without encoding.',
    steps_to_reproduce: '1. Open the lab search page.\n2. Enter <script>alert(1)</script>.',
    impact: 'An attacker could execute script in a victim session.',
    remediation: 'Encode all reflected output.',
    cvss_score: 8.2,
    ...overrides,
  };
}

test('stub detector on a single raw record: one normalized finding, severity derived, tool recorded', () => {
  const result = stubDetector(baseRaw({ tool: 'lab-probe' }), DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  assert.deepEqual(result.errors, []);
  const finding = result.findings[0];
  assert.equal(finding.finding_id, 'F-001');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cvss_score, 8.2);
  assert.equal(finding.discovery_tool, 'lab-probe');
  assert.equal(finding.session_id, 'sess-1');
});

test('stub detector on a batch record: findings per good result, bad result counted in skipped', () => {
  const batch = {
    tool: 'stub-scanner-fixture',
    results: [
      baseRaw({ finding_id: 'B-001' }),
      baseRaw({ finding_id: 'B-002', vulnerability_type: 'SQL Injection', cvss_score: 9.0 }),
      baseRaw({ finding_id: 'B-003', title: '' }),
    ],
  };
  const result = stubDetector(batch, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.deepEqual(result.findings.map((finding) => finding.finding_id), ['B-001', 'B-002']);
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /title/);
  assert.equal(result.findings[0].discovery_tool, 'stub-scanner-fixture');
  assert.equal(result.findings[1].severity, 'critical');
});

test('stub detector throws a named error on a non-object input', () => {
  assert.throws(() => stubDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => stubDetector('not an object', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => stubDetector([baseRaw()], DEFAULTS), /DETECTOR_INVALID_INPUT/);
});

test('stub detector counts a record missing its ids in skipped when no defaults are given', () => {
  const result = stubDetector(baseRaw(), {});
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped, 1);
  assert.match(result.errors[0], /session_id/);
});

test('validateDetectorResult accepts a valid envelope and returns normalized copies', () => {
  const envelope = {
    findings: [baseRaw({ session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1', extra_unknown_field: 'dropped' })],
    skipped: 1,
    errors: ['missing or empty required field: title'],
  };
  const validated = validateDetectorResult(envelope);
  assert.equal(validated.findings.length, 1);
  assert.equal(validated.findings[0].severity, 'high');
  assert.equal('extra_unknown_field' in validated.findings[0], false, 'unknown fields are dropped by re-normalization');
  assert.equal(validated.skipped, 1);
  assert.deepEqual(validated.errors, ['missing or empty required field: title']);
  assert.notEqual(validated.errors, envelope.errors, 'errors are copied, not shared');
});

test('validateDetectorResult rejects every malformed envelope with DETECTOR_INVALID_RESULT', () => {
  assert.throws(() => validateDetectorResult(null), /DETECTOR_INVALID_RESULT/);
  assert.throws(() => validateDetectorResult({ findings: {}, skipped: 0, errors: [] }), /DETECTOR_INVALID_RESULT/);
  assert.throws(() => validateDetectorResult({ findings: [], skipped: -1, errors: [] }), /DETECTOR_INVALID_RESULT/);
  assert.throws(() => validateDetectorResult({ findings: [], skipped: 1.5, errors: [] }), /DETECTOR_INVALID_RESULT/);
  assert.throws(() => validateDetectorResult({ findings: [], skipped: 0, errors: 'none' }), /DETECTOR_INVALID_RESULT/);
  assert.throws(() => validateDetectorResult({ findings: [], skipped: 0, errors: [42] }), /DETECTOR_INVALID_RESULT/);
  assert.throws(
    () => validateDetectorResult({ findings: [baseRaw()], skipped: 0, errors: [] }),
    /DETECTOR_INVALID_RESULT: finding at index 0/,
    'a finding without session/target/asset ids fails re-normalization',
  );
  assert.throws(
    () => validateDetectorResult(Promise.resolve({ findings: [], skipped: 0, errors: [] })),
    /DETECTOR_INVALID_RESULT: detector must return a result synchronously/,
  );
});

test('runDetectorOnRecords forces the batch tool as discovery_tool and never aborts on a bad record', () => {
  const result = runDetectorOnRecords(
    [baseRaw({ finding_id: 'R-001', tool: 'per-result-tool' }), baseRaw({ finding_id: 'R-002', title: '' })],
    'batch-tool',
    DEFAULTS,
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
});

test('getDetector resolves stub, inline functions, and null; anything else throws', () => {
  assert.equal(getDetector('stub').source, 'stub');
  assert.equal(typeof getDetector('stub').detector, 'function');
  const inline = () => ({ findings: [], skipped: 0, errors: [] });
  assert.equal(getDetector(inline).source, 'inline');
  assert.equal(getDetector(inline).detector, inline);
  assert.equal(getDetector(null), null);
  assert.equal(getDetector(undefined), null);
  assert.throws(() => getDetector(42), /DETECTOR_INVALID_DETECTOR/);
});

test('loadDetector loads the class fixture and it produces findings only for its class', () => {
  const resolved = loadDetector('tests/fixtures/detector-class.js');
  assert.equal(resolved.source, 'detector-class.js');
  const xss = runDetector(resolved.detector, baseRaw({ tool: 'class-fixture' }), DEFAULTS);
  assert.equal(xss.findings.length, 1);
  assert.equal(xss.findings[0].discovery_tool, 'class-fixture');
  const sqli = runDetector(resolved.detector, baseRaw({ vulnerability_type: 'SQL Injection' }), DEFAULTS);
  assert.equal(sqli.findings.length, 0);
  assert.equal(sqli.skipped, 0);
});

test('loadDetector refuses a missing file, a malformed module, and a non-file path', () => {
  assert.throws(() => loadDetector('tests/fixtures/does-not-exist.js'), /DETECTOR_NOT_FOUND/);
  assert.throws(() => loadDetector('tests/fixtures/detector-malformed.js'), /DETECTOR_INVALID_MODULE/);
  assert.throws(() => loadDetector('tests/fixtures'), /DETECTOR_NOT_A_FILE/);
});

test('loadDetector refuses an absolute path outside the skill directory', () => {
  assert.throws(() => loadDetector('/tmp/detector-outside.js'), /DETECTOR_PATH_OUTSIDE_SKILL/);
  assert.throws(() => loadDetector('../outside-detector.js'), /DETECTOR_PATH_OUTSIDE_SKILL/);
});

test('loadDetector refuses a symlinked detector file and a symlinked parent directory', async (t) => {
  const linkPath = path.join(__dirname, 'fixtures', 'detector-link.js');
  const linkDir = path.join(__dirname, 'fixtures', 'detector-linkdir');
  const outside = await makeTempDir(t, 'sentinel-detector-outside-');
  try {
    fs.copyFileSync(path.join(__dirname, 'fixtures', 'detector-class.js'), path.join(outside, 'detector-class.js'));
    fs.symlinkSync(path.join(__dirname, 'fixtures', 'detector-class.js'), linkPath);
    assert.throws(() => loadDetector('tests/fixtures/detector-link.js'), /DETECTOR_SYMLINK_REFUSED/);
    fs.symlinkSync(outside, linkDir);
    assert.throws(() => loadDetector('tests/fixtures/detector-linkdir/detector-class.js'), /DETECTOR_SYMLINK_REFUSED/);
  } finally {
    fs.rmSync(linkPath, { force: true });
    fs.rmSync(linkDir, { force: true });
  }
});

test('loadDetector refuses a module whose require fails', () => {
  // A module that throws at require time is a load failure, not a
  // detector: write it into a temp dir inside the skill tree so
  // the path check passes, then remove it.
  const badPath = path.join(__dirname, 'fixtures', 'detector-throws-on-load.js');
  fs.writeFileSync(badPath, "'use strict';\nthrow new Error('boom at require time');\n");
  try {
    assert.throws(() => loadDetector('tests/fixtures/detector-throws-on-load.js'), /DETECTOR_LOAD_FAILED/);
  } finally {
    fs.rmSync(badPath, { force: true });
  }
});

test('runDetector records a throwing detector as an error envelope, never a crash', () => {
  const throwing = () => { throw new Error('detector blew up'); };
  const result = runDetector(throwing, baseRaw(), DEFAULTS);
  assert.deepEqual(result.findings, []);
  assert.equal(result.skipped, 0);
  assert.match(result.errors[0], /detector blew up/);
  assert.match(result.error, /detector blew up/);
});

test('runDetector records a detector returning an invalid result as an error envelope', () => {
  const bad = () => ({ findings: 'not an array', skipped: 0, errors: [] });
  const result = runDetector(bad, baseRaw(), DEFAULTS);
  assert.deepEqual(result.findings, []);
  assert.match(result.error, /DETECTOR_INVALID_RESULT/);
  const asyncDetector = () => Promise.resolve({ findings: [], skipped: 0, errors: [] });
  const asyncResult = runDetector(asyncDetector, baseRaw(), DEFAULTS);
  assert.deepEqual(asyncResult.findings, []);
  assert.match(asyncResult.error, /synchronously/);
});

test('runDetector refuses a non-function detector', () => {
  assert.throws(() => runDetector('stub', baseRaw(), DEFAULTS), /DETECTOR_INVALID_DETECTOR/);
});

test('a mutating detector cannot touch the caller input (defensive copy)', () => {
  const mutating = (input) => {
    input.finding_id = 'MUTATED';
    input.vulnerability_type = 'Mutated Type';
    return { findings: [], skipped: 0, errors: [] };
  };
  const input = baseRaw();
  runDetector(mutating, input, DEFAULTS);
  assert.equal(input.finding_id, 'F-001');
  assert.equal(input.vulnerability_type, 'Cross-Site Scripting');
});

test('refactored runStubDetector still returns the identical round-31 results', () => {
  const result = runStubDetector(fixturePath('stub-scanner-output.json'), DEFAULTS);
  assert.equal(result.tool, 'stub-scanner-fixture');
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /title/);
  assert.deepEqual(result.findings.map((finding) => finding.finding_id), ['STUB-001', 'STUB-002']);
});

test('detect -> validate -> dedupe -> report end to end over the stub fixture', () => {
  const fixture = loadFixture('stub-scanner-output.json');
  const result = runDetector(stubDetector, fixture, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  for (const finding of result.findings) {
    assert.equal(validateFinding(finding).verdict, 'needs_evidence');
  }
  const deduped = dedupeFindings(result.findings);
  assert.equal(deduped.groups.length, 2);
  assert.equal(deduped.duplicates, 0);
  const markdown = generateReport(result.findings, { programName: 'Lab Program', generatedAt: '2026-11-26T06:00:00+07:00' });
  assert.match(markdown, /\| medium \| 2 \|/);
  assert.match(markdown, /\| total \| 2 \|/);
});

test('CLI detect with the stub over the fixture: JSON output, findings consumable by the validator', async (t) => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'stub', '--input', fixturePath('stub-scanner-output.json'),
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1',
  ]);
  const output = JSON.parse(stdout);
  assert.equal(output.detector, 'stub');
  assert.equal(output.findings.length, 2);
  assert.equal(output.skipped, 1);
  assert.equal(output.errors.length, 1);
  assert.equal('error' in output, false);
  for (const finding of output.findings) {
    assert.equal(validateFinding(finding).verdict, 'needs_evidence');
  }
});

test('CLI detect writes findings to --out with mode 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-detector-cli-');
  const outPath = path.join(directory, 'findings.json');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--input', fixturePath('stub-scanner-output.json'),
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1', '--out', outPath,
  ]);
  assert.match(stdout, /Findings written to/);
  const output = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  assert.equal(output.findings.length, 2);
  assertPrivateModeSync(outPath, 0o600);
});

test('CLI detect with a bad detector path fails cleanly and writes no --out file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-detector-cli-');
  const outPath = path.join(directory, 'findings.json');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'detect', '--detector', 'tests/fixtures/does-not-exist.js', '--input', fixturePath('stub-scanner-output.json'),
      '--out', outPath,
    ]),
    /DETECTOR_NOT_FOUND/,
  );
  assert.equal(fs.existsSync(outPath), false, 'no output file on a failed detect');
});

test('CLI detect requires --input', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'detect', '--detector', 'stub']),
    /detect requires --input/,
  );
});

test('CLI help names every registered built-in detector (round 99)', async () => {
  // Round 95 found the detect comment block never described the fifth
  // detector (insecure-transport): the registry and the help had
  // drifted silently. This test cross-checks the two sides: every id
  // getDetector resolves by name must appear in the CLI help. A new
  // detector must be added to the usage line (and its comment block)
  // or this test fails — that is the point.
  const detectorSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'detection', 'detector.js'), 'utf8');
  const registered = [...new Set([...detectorSource.matchAll(/if \(spec === '([a-z0-9-]+)'\)/g)].map((m) => m[1]))];
  assert.ok(registered.length >= 7, `expected at least 7 registered detector ids, got ${registered.join(', ')}`);
  let stderr = '';
  try {
    await execFileAsync(process.execPath, [CLI], { timeout: 10_000 });
    assert.fail('expected the CLI with no command to print usage and exit non-zero');
  } catch (error) {
    stderr = error.stderr || '';
  }
  assert.match(stderr, /^Usage:/m);
  for (const id of registered) assert.ok(stderr.includes(id), `CLI help does not name detector ${id}`);
});
