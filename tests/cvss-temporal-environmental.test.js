// CVSS 3.1 temporal + environmental metrics (round 38, Phase 6).
//
// Expected scores below are hand-computed from the FIRST CVSS v3.1
// specification's formulas and cross-checked with an independent
// throwaway computation (a direct transcription of the formulas,
// /tmp/r38-expected.js — not the module under test). No network
// oracle was consulted: the FIRST calculator was not reachable from
// this lab, so these are formula-derived values, not values copied
// from the calculator; the doc (docs/cvss-temporal-environmental-v1.md)
// says so explicitly. Every value in this file was produced by both
// the hand derivation in the test comments and the independent script.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  parseCvssVector,
  computeTemporalScore,
  computeEnvironmentalScore,
  scoreCvssVector,
  resolveCvss,
} = require('../src/analysis/cvss');
const { validateFinding } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.json`), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const MAX_U = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; // base 9.8
const MID_C = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'; // base 6.1
const ZERO = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'; // base 0.0

// Temporal: Roundup(BaseScore x E x RL x RC).
// 9.8 x 0.94 (P) x 0.95 (O) x 1.00 (C) = 8.7514 -> 8.8.
// 6.1 x 0.91 (U) x 0.97 (W) x 0.96 (R) = 5.1690912 -> 5.2.
const KNOWN_TEMPORAL = [
  { vector: `${MAX_U}/E:P/RL:O/RC:C`, score: 8.8 },
  { vector: `${MID_C}/E:U/RL:W/RC:R`, score: 5.2 },
  { vector: `${MAX_U}/E:H/RL:U/RC:C`, score: 9.8 }, // all factors 1.00
  { vector: `${MAX_U}/E:F`, score: 9.6 }, // 9.8 x 0.97 = 9.506 -> 9.6
  { vector: `${MAX_U}/RL:T`, score: 9.5 }, // 9.8 x 0.96 = 9.408 -> 9.5
];

test('known temporal scores (FIRST formula, hand-derived + cross-checked)', () => {
  for (const { vector, score } of KNOWN_TEMPORAL) {
    const result = scoreCvssVector(vector);
    assert.equal(result.temporalScore, score, vector);
    assert.equal(result.score, vector.startsWith(MID_C) ? 6.1 : 9.8, vector);
  }
});

test('temporal score is null when the vector carries no temporal metrics', () => {
  for (const vector of [MAX_U, MID_C, ZERO]) {
    const result = scoreCvssVector(vector);
    assert.equal(result.temporalScore, null, vector);
  }
  // An explicit X counts as present: the score is computed (and
  // collapses to the base score).
  const allX = scoreCvssVector(`${MAX_U}/E:X/RL:X/RC:X`);
  assert.equal(allX.temporalScore, 9.8);
});

test('computeTemporalScore collapses to the base score on base-only metrics', () => {
  assert.equal(computeTemporalScore(9.8, parseCvssVector(MAX_U)), 9.8);
});

test('computeTemporalScore agrees with scoreCvssVector', () => {
  const metrics = parseCvssVector(`${MAX_U}/E:P/RL:O/RC:C`);
  assert.equal(computeTemporalScore(9.8, metrics), 8.8);
  assert.equal(computeTemporalScore(9.8, parseCvssVector(MAX_U)), 9.8);
});

// Environmental. Hand derivations (independent script agrees):
// - MAX_U + CR:L/IR:L/AR:L: ModifiedISCBase = 1 - 0.72^3 = 0.626752;
//   ModifiedImpact = 6.42 x 0.626752 = 4.02374784; exploitability
//   3.887042775; sum 7.910790615 -> Roundup 8.0.
// - MAX_U + CR:H/IR:H/AR:H: ModifiedISCBase capped at 0.915;
//   ModifiedImpact = 5.8743; sum 9.761342775 -> 9.8.
// - MID_C + CR:H/IR:H/AR:H: ModifiedISCBase = 0.5511;
//   ModifiedImpact = 3.925946; exploitability 2.83525473; sum
//   6.761201 x 1.08 = 7.302097 -> 7.4.
// - MAX_U + MAV:P: exploitability falls to 0.9145983; impact
//   5.87311872; sum 6.787717 -> 6.8.
// - MAX_U + MS:C: scope flips to changed; ModifiedImpact 6.047216;
//   sum 9.934259 x 1.08 -> capped at 10.0.
const KNOWN_ENVIRONMENTAL = [
  { vector: `${MAX_U}/CR:L/IR:L/AR:L`, score: 8.0 },
  { vector: `${MAX_U}/CR:H/IR:H/AR:H`, score: 9.8 },
  { vector: `${MID_C}/CR:H/IR:H/AR:H`, score: 7.4 },
  { vector: `${MAX_U}/MAV:P`, score: 6.8 },
  { vector: `${MAX_U}/MS:C`, score: 10.0 },
  // Double Roundup: inner modified base 8.0, then x 0.94 x 0.95 =
  // 7.144 -> 7.2 (not 7.1: the inner Roundup happens first).
  { vector: `${MAX_U}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`, score: 7.2 },
];

test('known environmental scores (FIRST formula, hand-derived + cross-checked)', () => {
  for (const { vector, score } of KNOWN_ENVIRONMENTAL) {
    const result = scoreCvssVector(vector);
    assert.equal(result.environmentalScore, score, vector);
  }
});

test('environmental score is null when the vector carries no environmental metrics', () => {
  for (const vector of [MAX_U, MID_C, ZERO]) {
    const result = scoreCvssVector(vector);
    assert.equal(result.environmentalScore, null, vector);
  }
  // An explicit X counts as present: the score is computed (and
  // collapses to the base score).
  const allX = scoreCvssVector(`${MAX_U}/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X`);
  assert.equal(allX.environmentalScore, 9.8);
});

test('computeEnvironmentalScore collapses to the base score on base-only metrics', () => {
  assert.equal(computeEnvironmentalScore(parseCvssVector(MAX_U)), 9.8);
});

test('Not Defined fallback: MAV:X behaves exactly like no MAV at all', () => {
  const withX = scoreCvssVector(`${MAX_U}/MAV:X/CR:L`);
  const without = scoreCvssVector(`${MAX_U}/CR:L`);
  assert.equal(withX.environmentalScore, without.environmentalScore);
  // CR:L only (IR/AR at X = 1.00): ModifiedISCBase = 1 - 0.72 x 0.44
  // x 0.44 = 0.860608; impact 5.5251; sum with exploitability
  // 9.412146 -> 9.5. (8.0 is the all-three-low value, not this one.)
  assert.equal(withX.environmentalScore, 9.5);
});

test('environmental score is 0.0 when the modified impact is 0', () => {
  assert.equal(scoreCvssVector(`${ZERO}/CR:H/IR:H/AR:H`).environmentalScore, 0.0);
  assert.equal(scoreCvssVector(`${ZERO}/E:P/RL:O/RC:C`).temporalScore, 0.0);
});

test('computeEnvironmentalScore agrees with scoreCvssVector', () => {
  const metrics = parseCvssVector(`${MAX_U}/CR:L/IR:L/AR:L`);
  assert.equal(computeEnvironmentalScore(metrics), 8.0);
  assert.equal(computeEnvironmentalScore(parseCvssVector(MAX_U)), 9.8);
});

test('scoreCvssVector returns base, temporal, and environmental scores together', () => {
  const result = scoreCvssVector(`${MAX_U}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`);
  assert.equal(result.score, 9.8);
  assert.equal(result.severity, 'critical');
  assert.equal(result.temporalScore, 8.8);
  assert.equal(result.environmentalScore, 7.2);
  assert.equal(result.metrics.E, 'P');
  assert.equal(result.metrics.CR, 'L');
  assert.equal(result.metrics.MAV, undefined); // absent metric stays absent
});

// Base regression: the round-36 known vectors still score exactly.
test('base regression: round-36 known vectors score exactly', () => {
  const known = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
  ];
  for (const [vector, score] of known) {
    const result = scoreCvssVector(vector);
    assert.equal(result.score, score, vector);
    // Base-only vectors carry no temporal/environmental metrics, so
    // those scores are null (not fabricated from all-X).
    assert.equal(result.temporalScore, null, vector);
    assert.equal(result.environmentalScore, null, vector);
  }
});

test('malformed temporal/environmental metrics fail with a named code', () => {
  const cases = [
    [`${MAX_U}/E:Z`, 'CVSS_UNKNOWN_VALUE'],
    [`${MAX_U}/E:P/E:F`, 'CVSS_DUPLICATE_METRIC'],
    [`${MAX_U}/XX:P`, 'CVSS_UNKNOWN_METRIC'],
    [`${MAX_U}/E:p`, 'CVSS_MALFORMED_PART'],
    [`${MAX_U}/CR:Q`, 'CVSS_UNKNOWN_VALUE'],
    [`${MAX_U}/MS:X/MS:C`, 'CVSS_DUPLICATE_METRIC'],
    [`${MAX_U}/MAV:Z`, 'CVSS_UNKNOWN_VALUE'],
    // Temporal-only vector: the eight base metrics are still required.
    ['CVSS:3.1/E:P/RL:O/RC:C', 'CVSS_MISSING_METRIC'],
  ];
  for (const [vector, code] of cases) {
    assert.throws(() => parseCvssVector(vector), (error) => {
      assert.equal(error.code, code, vector);
      assert.ok(error.message.startsWith('invalid cvss_vector: '), vector);
      return true;
    }, vector);
  }
});

// resolveCvss: declared temporal/environmental scores must agree.
test('resolveCvss: matching declared temporal/environmental scores pass', () => {
  const result = resolveCvss({
    cvss_vector: `${MAX_U}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`,
    cvss_temporal_score: 8.8,
    cvss_environmental_score: 7.2,
  });
  assert.equal(result.error, null);
  assert.equal(result.temporalError, null);
  assert.equal(result.environmentalError, null);
  assert.equal(result.temporalScore, 8.8);
  assert.equal(result.environmentalScore, 7.2);
  assert.equal(result.effectiveScore, 9.8); // derived base score (no declared score)
});

test('resolveCvss: mismatched declared temporal score fails by name', () => {
  const result = resolveCvss({
    cvss_vector: `${MAX_U}/E:P/RL:O/RC:C`,
    cvss_temporal_score: 9.8,
  });
  assert.match(result.temporalError, /cvss_vector\/cvss_temporal_score mismatch: vector computes to 8\.8 but cvss_temporal_score is 9\.8/);
  assert.equal(result.error, null);
  assert.equal(result.environmentalError, null);
});

test('resolveCvss: mismatched declared environmental score fails by name', () => {
  const result = resolveCvss({
    cvss_vector: `${MAX_U}/CR:L/IR:L/AR:L`,
    cvss_environmental_score: 9.8,
  });
  assert.match(result.environmentalError, /cvss_vector\/cvss_environmental_score mismatch: vector computes to 8 but cvss_environmental_score is 9\.8/);
  assert.equal(result.error, null);
  assert.equal(result.temporalError, null);
});

test('resolveCvss: invalid declared temporal/environmental scores are left to the callers', () => {
  const result = resolveCvss({
    cvss_vector: `${MAX_U}/E:P/RL:O/RC:C`,
    cvss_temporal_score: 11,
    cvss_environmental_score: 'high',
  });
  assert.equal(result.temporalError, null);
  assert.equal(result.environmentalError, null);
  assert.equal(result.temporalScore, 8.8);
  // The vector carries no environmental metrics, so no environmental
  // score is computed — the invalid declared value is left to the
  // callers, which report it as invalid.
  assert.equal(result.environmentalScore, null);
});

// Validator wiring: the confirmed-full fixture vector is
// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (base 7.5).
// With E:P/RL:O/RC:C the temporal score is 6.7; with CR:L/IR:L/AR:L
// the environmental score is 5.7 (5.1 with both).
const FIXTURE_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';

test('validator: vector with temporal/environmental metrics and matching declared scores is valid', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`;
  finding.cvss_temporal_score = 6.7;
  finding.cvss_environmental_score = 5.1;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'valid');
});

test('validator: vector-only finding with temporal/environmental metrics is valid', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'valid');
});

test('validator: mismatched declared temporal score fails by name', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C`;
  finding.cvss_temporal_score = 7.5;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.some((reason) => reason.startsWith('cvss_vector/cvss_temporal_score mismatch:')));
});

test('validator: mismatched declared environmental score fails by name', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/CR:L/IR:L/AR:L`;
  finding.cvss_environmental_score = 7.5;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.some((reason) => reason.startsWith('cvss_vector/cvss_environmental_score mismatch:')));
});

test('validator: invalid declared temporal/environmental scores are reported as invalid', () => {
  const temporal = clone(loadFixture('confirmed-full'));
  temporal.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C`;
  temporal.cvss_temporal_score = 11;
  const temporalResult = validateFinding(temporal);
  assert.equal(temporalResult.verdict, 'needs_evidence');
  assert.ok(temporalResult.reasons.includes('invalid cvss_temporal_score'));

  const environmental = clone(loadFixture('confirmed-full'));
  environmental.cvss_vector = `${FIXTURE_VECTOR}/CR:L/IR:L/AR:L`;
  environmental.cvss_environmental_score = 'high';
  const environmentalResult = validateFinding(environmental);
  assert.equal(environmentalResult.verdict, 'needs_evidence');
  assert.ok(environmentalResult.reasons.includes('invalid cvss_environmental_score'));
});

test('validator: severity is still checked against the BASE score, not temporal/environmental', () => {
  const finding = clone(loadFixture('confirmed-full'));
  // Temporal 6.7 and environmental 5.7 are both medium, but the base
  // score is 7.5 (high) — the severity stays high and the finding
  // stays valid.
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`;
  finding.severity = 'high';
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'valid');
});

// Generator wiring: vector-only finding renders all three derived scores.
test('generator: vector-only finding renders derived temporal/environmental scores', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`;
  const markdown = generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(markdown, /- \*\*CVSS:\*\* 7\.5 \(CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:N\/A:N\/E:P\/RL:O\/RC:C\/CR:L\/IR:L\/AR:L\)/);
  assert.match(markdown, /- \*\*CVSS temporal:\*\* 6\.7/);
  assert.match(markdown, /- \*\*CVSS environmental:\*\* 5\.1/);
  const json = JSON.parse(generateReport([finding], {
    programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', format: 'json',
  }));
  assert.equal(json.findings[0].cvss_score, 7.5);
  assert.equal(json.findings[0].cvss_temporal_score, 6.7);
  assert.equal(json.findings[0].cvss_environmental_score, 5.1);
});

test('generator: finding without temporal/environmental data renders no extra lines', () => {
  const finding = clone(loadFixture('confirmed-full'));
  const markdown = generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.doesNotMatch(markdown, /CVSS temporal/);
  assert.doesNotMatch(markdown, /CVSS environmental/);
});

test('generator: mismatched declared temporal score throws', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C`;
  finding.cvss_temporal_score = 7.5;
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /cvss_vector\/cvss_temporal_score mismatch: vector computes to 6\.7 but cvss_temporal_score is 7\.5/,
  );
});

test('generator: mismatched declared environmental score throws', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/CR:L/IR:L/AR:L`;
  finding.cvss_environmental_score = 7.5;
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /cvss_vector\/cvss_environmental_score mismatch: vector computes to 5\.7 but cvss_environmental_score is 7\.5/,
  );
});

test('generator: invalid declared environmental score throws', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_environmental_score = 11;
  assert.throws(
    () => generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    /has invalid cvss_environmental_score: 11/,
  );
});

test('generator: template renders derived temporal/environmental scores', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.cvss_vector = `${FIXTURE_VECTOR}/E:P/RL:O/RC:C/CR:L/IR:L/AR:L`;
  const markdown = generateReport([finding], {
    programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z', template: 'immunefi',
  });
  assert.match(markdown, /- \*\*CVSS temporal:\*\* 6\.7/);
  assert.match(markdown, /- \*\*CVSS environmental:\*\* 5\.1/);
});
