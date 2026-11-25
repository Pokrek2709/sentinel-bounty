// CVSS 3.1 base-vector parser + scorer (round 36, Phase 6).
//
// Known scores below are the FIRST specification's own worked examples
// and the FIRST calculator's published values — they are the oracle,
// not values fitted to this implementation. No network is used: the
// vectors and scores are written out literally in this file.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { parseCvssVector, computeBaseScore, severityForScore, scoreCvssVector, resolveCvss, roundUp } = require('../src/analysis/cvss');
const { validateFinding } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.json`), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// Known public CVSS 3.1 base vectors and their scores.
const KNOWN_VECTORS = [
  // The specification's canonical maximum: network, low complexity,
  // no privileges, no interaction, scope unchanged, full CIA impact.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, severity: 'critical' },
  // Same impact with scope changed: the 1.08 multiplier caps at 10.0.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', score: 10.0, severity: 'critical' },
  // The specification's scope-changed worked example (partial impact,
  // user interaction required).
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', score: 6.1, severity: 'medium' },
  // Adjacent-network, low privileges, full impact, scope unchanged.
  { vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', score: 7.8, severity: 'high' },
  // Network, low privileges, full impact, scope unchanged.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', score: 8.8, severity: 'high' },
  // Scope-changed with low privileges: exercises the changed PR table
  // (PR:L is 0.68 changed, 0.62 unchanged) — 9.9, not 9.8.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', score: 9.9, severity: 'critical' },
  // No impact at all: ISCBase is 0, so the score is 0.0.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', score: 0.0, severity: 'informational' },
  // The lab fixture's own vector (tests/fixtures/confirmed-full.json):
  // confidentiality-only impact, scope unchanged — 7.5 high.
  { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5, severity: 'high' },
];

test('known CVSS 3.1 vectors score exactly (FIRST worked examples)', () => {
  for (const { vector, score, severity } of KNOWN_VECTORS) {
    const result = scoreCvssVector(vector);
    assert.equal(result.score, score, vector);
    assert.equal(result.severity, severity, vector);
    assert.deepEqual(result.metrics, {
      AV: vector.split('/')[1].split(':')[1],
      AC: vector.split('/')[2].split(':')[1],
      PR: vector.split('/')[3].split(':')[1],
      UI: vector.split('/')[4].split(':')[1],
      S: vector.split('/')[5].split(':')[1],
      C: vector.split('/')[6].split(':')[1],
      I: vector.split('/')[7].split(':')[1],
      A: vector.split('/')[8].split(':')[1],
    });
  }
});

test('parseCvssVector returns the eight base metrics', () => {
  assert.deepEqual(parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), {
    AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
  });
});

test('computeBaseScore agrees with scoreCvssVector on parsed metrics', () => {
  const metrics = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
  assert.equal(computeBaseScore(metrics), 6.1);
});

test('roundUp: the FIRST rule — smallest one-decimal number >= input', () => {
  assert.equal(roundUp(4.02), 4.1);
  assert.equal(roundUp(4.05), 4.1);
  assert.equal(roundUp(4.0), 4.0);
  assert.equal(roundUp(0), 0);
  assert.equal(roundUp(10), 10);
  // Float noise must not round a score up: 6.9000000001 stays 6.9.
  assert.equal(roundUp(6.9000000001), 6.9);
  assert.equal(roundUp(9.800000000000001), 9.8);
});

test('malformed vectors fail with a named code (not a partial parse)', () => {
  const cases = [
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_INVALID_PREFIX'],
    ['cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_INVALID_PREFIX'],
    ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_UNKNOWN_VALUE'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H', 'CVSS_UNKNOWN_VALUE'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', 'CVSS_MISSING_METRIC'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:A', 'CVSS_DUPLICATE_METRIC'],
    ['CVSS:3.1/XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_UNKNOWN_METRIC'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/', 'CVSS_MALFORMED_PART'],
    ['CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS_MALFORMED_PART'],
    // Temporal/environmental parts are now ACCEPTED (round 38) — see
    // tests/cvss-temporal-environmental.test.js for their own
    // malformed cases. Unknown keys are still rejected, not dropped.
    ['', 'CVSS_EMPTY_VECTOR'],
    ['   ', 'CVSS_EMPTY_VECTOR'],
  ];
  for (const [vector, code] of cases) {
    assert.throws(() => parseCvssVector(vector), (error) => {
      assert.equal(error.code, code, vector);
      assert.ok(error.message.startsWith('invalid cvss_vector: '), vector);
      return true;
    }, vector);
  }
  for (const notAString of [42, null, undefined, { AV: 'N' }]) {
    assert.throws(() => parseCvssVector(notAString), (error) => {
      assert.equal(error.code, 'CVSS_INVALID_TYPE');
      return true;
    }, String(notAString));
  }
});

test('severityForScore uses the shared band table (no second table)', () => {
  assert.equal(severityForScore(9.8), 'critical');
  assert.equal(severityForScore(7.5), 'high');
  assert.equal(severityForScore(6.1), 'medium');
  assert.equal(severityForScore(0.0), 'informational');
  assert.equal(severityForScore('9.8'), null);
  assert.equal(severityForScore(NaN), null);
});

test('resolveCvss: declared score wins when valid; vector derives when missing', () => {
  const declared = resolveCvss({ cvss_score: 7.5, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' });
  assert.equal(declared.effectiveScore, 7.5);
  assert.equal(declared.vectorScore, 7.5);
  assert.equal(declared.error, null);

  const derived = resolveCvss({ cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' });
  assert.equal(derived.effectiveScore, 7.5);
  assert.equal(derived.vectorScore, 7.5);
  assert.equal(derived.error, null);

  const neither = resolveCvss({});
  assert.equal(neither.effectiveScore, null);
  assert.equal(neither.vectorScore, null);
  assert.equal(neither.error, null);

  // Empty-string vector is absent, not an error.
  const empty = resolveCvss({ cvss_vector: '' });
  assert.equal(empty.error, null);
  assert.equal(empty.effectiveScore, null);
});

test('resolveCvss: vector disagreeing with the declared score fails', () => {
  const result = resolveCvss({
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  });
  assert.match(result.error, /cvss_vector\/cvss_score mismatch: vector computes to 7\.5 but cvss_score is 9\.8/);
  assert.equal(result.effectiveScore, 9.8);
});

test('resolveCvss: malformed vector is an error, never a mismatch', () => {
  const result = resolveCvss({ cvss_score: 7.5, cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' });
  assert.match(result.error, /invalid cvss_vector: expected prefix "CVSS:3\.1"/);
  assert.equal(result.vectorScore, null);
  assert.equal(result.effectiveScore, 7.5);
});

test('resolveCvss: non-string vector is an error', () => {
  const result = resolveCvss({ cvss_vector: 42 });
  assert.match(result.error, /invalid cvss_vector: expected a string, got number/);
});

// Validator wiring: the confirmed-full fixture already carries a vector
// computing to 7.5 with a declared 7.5 and severity high — it stays
// valid, and the vector alone now carries the check.
test('validator: vector-only finding is valid when severity matches the derived score', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.cvss_score;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'valid');
});

test('validator: vector-only finding with a wrong severity reports the mismatch', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.cvss_score;
  finding.severity = 'critical';
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('severity/cvss mismatch'));
});

test('validator: vector disagreeing with the declared score fails by name', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_score = 9.8;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.some((reason) => reason.startsWith('cvss_vector/cvss_score mismatch:')));
});

test('validator: malformed vector fails by name', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.some((reason) => reason.startsWith('invalid cvss_vector:')));
});

test('validator: false_positive still wins over a bad vector', () => {
  const finding = clone(loadFixture('false-positive'));
  finding.cvss_vector = 'not-a-vector';
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'false_positive');
});

// Generator wiring: a vector-only finding renders with the derived
// score instead of "Not scored".
test('generator: vector-only finding renders with the derived score', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.cvss_score;
  const markdown = generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(markdown, /- \*\*CVSS:\*\* 7\.5 \(CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:N\/A:N\)/);
  const json = JSON.parse(generateReport([finding], {
    programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', format: 'json',
  }));
  assert.equal(json.findings[0].cvss_score, 7.5);
});

test('generator: vector disagreeing with the declared score throws', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_score = 9.8;
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /cvss_vector\/cvss_score mismatch: vector computes to 7\.5 but cvss_score is 9\.8/,
  );
});

test('generator: malformed vector throws', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N';
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /has invalid cvss_vector: missing metric\(s\): A/,
  );
});

test('generator: vector-only finding with a wrong severity throws the mismatch', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.cvss_score;
  finding.severity = 'critical';
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /severity\/score mismatch: severity is "critical" but cvss_vector \(computed score 7\.5\) maps to "high"/,
  );
});
