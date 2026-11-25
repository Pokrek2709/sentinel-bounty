const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { normalizeRawFinding, severityForScore } = require('../src/detection/normalized-record');
const { runStubDetector } = require('../src/detection/stub-detector');

const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

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

test('severityForScore follows the cvss-calc severity_ratings bands', () => {
  assert.equal(severityForScore(10.0), 'critical');
  assert.equal(severityForScore(9.0), 'critical');
  assert.equal(severityForScore(8.9), 'high');
  assert.equal(severityForScore(7.0), 'high');
  assert.equal(severityForScore(6.9), 'medium');
  assert.equal(severityForScore(4.0), 'medium');
  assert.equal(severityForScore(3.9), 'low');
  assert.equal(severityForScore(0.1), 'low');
  assert.equal(severityForScore(0.0), 'informational');
});

test('normalize happy path: string steps, derived severity, defaults applied', () => {
  const record = normalizeRawFinding(baseRaw(), DEFAULTS);
  assert.equal(record.severity, 'high');
  assert.equal(record.cvss_score, 8.2);
  assert.deepEqual(record.steps_to_reproduce, [
    '1. Open the lab search page.',
    '2. Enter <script>alert(1)</script>.',
  ]);
  assert.equal(record.validation_status, 'detected');
  assert.equal(record.confidence, 'potential');
  assert.equal(record.session_id, 'sess-1');
  assert.equal(record.target_id, 'tgt-1');
  assert.equal(record.asset_id, 'ast-1');
  // No tool in the raw input: discovery_tool stays absent, never invented.
  assert.equal('discovery_tool' in record, false);
});

test('normalize accepts array steps and an explicit severity matching the score', () => {
  const record = normalizeRawFinding(
    baseRaw({
      severity: 'high',
      steps_to_reproduce: ['Step one.', '  Step two.  ', ''],
      confidence: 'confirmed',
      validation_status: 'needs_review',
      cwe_id: 'CWE-79',
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      references: ['https://example.invalid/lab/xss'],
    }),
    DEFAULTS,
  );
  assert.equal(record.severity, 'high');
  assert.deepEqual(record.steps_to_reproduce, ['Step one.', 'Step two.']);
  assert.equal(record.confidence, 'confirmed');
  assert.equal(record.validation_status, 'needs_review');
  assert.equal(record.cwe_id, 'CWE-79');
  assert.equal(record.discovery_tool, undefined);
});

test('normalize prefers raw session/target/asset ids over defaults', () => {
  const record = normalizeRawFinding(
    baseRaw({ session_id: 'sess-raw', target_id: 'tgt-raw', asset_id: 'ast-raw' }),
    DEFAULTS,
  );
  assert.equal(record.session_id, 'sess-raw');
  assert.equal(record.target_id, 'tgt-raw');
  assert.equal(record.asset_id, 'ast-raw');
});

test('normalize records discovery_tool from the raw tool field', () => {
  const record = normalizeRawFinding(baseRaw({ tool: 'some-detector' }), DEFAULTS);
  assert.equal(record.discovery_tool, 'some-detector');
});

test('normalize throws naming a missing required field', () => {
  const raw = baseRaw();
  delete raw.title;
  assert.throws(() => normalizeRawFinding(raw, DEFAULTS), /title/);
});

test('normalize throws when a required field is an empty string', () => {
  assert.throws(() => normalizeRawFinding(baseRaw({ description: '   ' }), DEFAULTS), /description/);
});

test('normalize throws when session_id is missing from raw and defaults', () => {
  assert.throws(
    () => normalizeRawFinding(baseRaw(), { target_id: 'tgt-1', asset_id: 'ast-1' }),
    /session_id/,
  );
});

test('normalize throws on a severity/cvss_score mismatch', () => {
  assert.throws(
    () => normalizeRawFinding(baseRaw({ severity: 'low' }), DEFAULTS),
    /severity mismatch/,
  );
});

test('normalize throws when neither severity nor cvss_score is present', () => {
  const raw = baseRaw();
  delete raw.cvss_score;
  assert.throws(() => normalizeRawFinding(raw, DEFAULTS), /severity/);
});

test('normalize throws on a bad steps_to_reproduce type', () => {
  assert.throws(
    () => normalizeRawFinding(baseRaw({ steps_to_reproduce: 42 }), DEFAULTS),
    /steps_to_reproduce/,
  );
  assert.throws(
    () => normalizeRawFinding(baseRaw({ steps_to_reproduce: ['ok', 7] }), DEFAULTS),
    /steps_to_reproduce/,
  );
});

test('normalize drops unknown keys and returns only schema fields', () => {
  const record = normalizeRawFinding(baseRaw({ extra_field: 'nope', foobar: 123 }), DEFAULTS);
  assert.equal('extra_field' in record, false);
  assert.equal('foobar' in record, false);
  assert.deepEqual(Object.keys(record).sort(), [
    'asset_id',
    'confidence',
    'cvss_score',
    'description',
    'finding_id',
    'impact',
    'remediation',
    'session_id',
    'severity',
    'steps_to_reproduce',
    'target_id',
    'title',
    'validation_status',
    'vulnerability_type',
  ]);
});

test('stub detector end-to-end: 2 good + 1 bad result', () => {
  const fixturePath = path.join(__dirname, 'fixtures', 'stub-scanner-output.json');
  const result = runStubDetector(fixturePath, DEFAULTS);
  assert.equal(result.tool, 'stub-scanner-fixture');
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /title/);
  assert.equal(result.findings[0].finding_id, 'STUB-001');
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[1].finding_id, 'STUB-002');
  assert.equal(result.findings[1].severity, 'medium');
  for (const finding of result.findings) {
    assert.equal(finding.discovery_tool, 'stub-scanner-fixture');
    assert.equal(finding.session_id, 'sess-1');
  }
});

test('stub detector on an empty fixture returns no findings and no errors', () => {
  const fixturePath = path.join(__dirname, 'fixtures', 'stub-scanner-empty.json');
  const result = runStubDetector(fixturePath, DEFAULTS);
  assert.equal(result.tool, 'stub-scanner-fixture');
  assert.deepEqual(result.findings, []);
  assert.equal(result.skipped, 0);
  assert.deepEqual(result.errors, []);
});

test('stub detector with a missing fixture file throws a clear error', () => {
  const fixturePath = path.join(__dirname, 'fixtures', 'does-not-exist.json');
  assert.throws(() => runStubDetector(fixturePath, DEFAULTS), /not found or unreadable/);
  assert.throws(() => runStubDetector(fixturePath, DEFAULTS), /does-not-exist\.json/);
});
