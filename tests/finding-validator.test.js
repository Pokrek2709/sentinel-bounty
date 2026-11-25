const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { validateFinding, dedupeFindings, evidenceChecklist, rootCauseKey } = require('../src/analysis/validator');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.json`), 'utf8'));
}

function clone(finding) {
  return JSON.parse(JSON.stringify(finding));
}

test('confirmed finding with complete evidence is valid', () => {
  const result = validateFinding(loadFixture('confirmed-full'));
  assert.equal(result.verdict, 'valid');
  assert.equal(result.reasons.length, 1);
});

test('confirmed finding missing proof_of_concept needs evidence naming it', () => {
  const result = validateFinding(loadFixture('confirmed-missing-poc'));
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['missing proof_of_concept']);
});

test('confirmed finding missing evidence needs evidence naming it', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.evidence;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['missing evidence']);
});

test('confirmed finding with empty steps_to_reproduce needs evidence naming it', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.steps_to_reproduce = [];
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['missing steps_to_reproduce']);
});

test('potential finding with partial evidence needs evidence', () => {
  const result = validateFinding(loadFixture('potential'));
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('missing proof_of_concept'));
  assert.ok(result.reasons.includes('missing evidence'));
});

test('potential finding with complete evidence is valid and says so', () => {
  const result = validateFinding(loadFixture('potential-full'));
  assert.equal(result.verdict, 'valid');
  assert.ok(result.reasons[0].includes('potential but fully evidenced'));
});

test('false_positive confidence is a false positive', () => {
  const result = validateFinding(loadFixture('false-positive'));
  assert.equal(result.verdict, 'false_positive');
  assert.ok(result.reasons[0].includes('confidence field says'));
});

test('needs_manual_review confidence needs evidence for manual review', () => {
  const finding = clone(loadFixture('confirmed-full'));
  finding.confidence = 'needs_manual_review';
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['manual review required']);
});

test('finding missing a required field needs evidence naming the field', () => {
  const finding = clone(loadFixture('confirmed-full'));
  delete finding.impact;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['missing required field: impact']);
});

test('severity disagreeing with cvss_score needs evidence and is not re-labelled', () => {
  const result = validateFinding(loadFixture('severity-mismatch'));
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('severity/cvss mismatch'));
  assert.equal(result.reasons.length, 1);
});

test('severity/cvss band edges agree (9.0 critical, 8.9 high, 0.0 informational)', () => {
  const base = clone(loadFixture('confirmed-full'));
  // This test measures score banding only, so the vector is removed:
  // the fixture's vector computes to 7.5 and would disagree with
  // every overridden score below.
  delete base.cvss_vector;
  assert.equal(validateFinding({ ...base, severity: 'critical', cvss_score: 9.0 }).verdict, 'valid');
  assert.equal(validateFinding({ ...base, severity: 'high', cvss_score: 8.9 }).verdict, 'valid');
  assert.equal(validateFinding({ ...base, severity: 'informational', cvss_score: 0.0 }).verdict, 'valid');
  assert.equal(validateFinding({ ...base, severity: 'low', cvss_score: 3.9 }).verdict, 'valid');
  assert.equal(validateFinding({ ...base, severity: 'low', cvss_score: 4.0 }).verdict, 'needs_evidence');
});

test('validator never throws on a malformed finding', () => {
  for (const malformed of [null, undefined, {}, 'not a finding', 42, [], true]) {
    const result = validateFinding(malformed);
    assert.equal(result.verdict, 'needs_evidence');
    assert.ok(result.reasons.some((reason) => reason.startsWith('missing required field:')));
  }
});

test('dedupe groups the duplicate pair and keeps distinct findings apart', () => {
  const dupA = loadFixture('duplicate-a');
  const dupB = loadFixture('duplicate-b');
  const other = loadFixture('confirmed-full');
  const result = dedupeFindings([dupA, dupB, other]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 1);
  const dupGroup = result.groups.find((group) => group.findings.length === 2);
  assert.deepEqual(
    dupGroup.findings.map((finding) => finding.finding_id),
    ['F-R31-DUP-A', 'F-R31-DUP-B'],
  );
  // The pair dedupes despite different casing and spacing in the first step.
  assert.ok(dupGroup.key.endsWith('navigate to https://lab.local/search?q=<script>alert(1)</script>'));
});

test('dedupe uses the (no-steps) key part when steps are missing', () => {
  const first = clone(loadFixture('potential'));
  const second = clone(loadFixture('potential'));
  first.steps_to_reproduce = [];
  delete second.steps_to_reproduce;
  // steps_to_reproduce is a required field, but dedupe must not throw on it.
  const result = dedupeFindings([first, second]);
  assert.equal(result.groups.length, 1);
  assert.equal(result.duplicates, 1);
  assert.ok(result.groups[0].key.endsWith('|(no-steps)'));
  assert.deepEqual(dedupeFindings([]), { groups: [], duplicates: 0 });
  assert.deepEqual(dedupeFindings(null), { groups: [], duplicates: 0 });
});

test('checklist reports every item present for a full finding', () => {
  // confirmed-full is Stored Cross-Site Scripting, so it gets the XSS
  // per-class list (round 40): the generic three plus response_log as
  // required, then the generic recommended items plus request_log.
  const checklist = evidenceChecklist(loadFixture('confirmed-full'));
  assert.deepEqual(
    checklist.map((entry) => entry.item),
    ['proof_of_concept', 'evidence', 'steps_to_reproduce', 'response_log', 'impact', 'remediation', 'cwe_id', 'cvss_vector', 'request_log'],
  );
  assert.ok(checklist.every((entry) => entry.present === true));
});

test('checklist reports present/false correctly for a minimal finding', () => {
  // confirmed-missing-poc is Reflected Cross-Site Scripting: the XSS
  // per-class list. Its evidence carries a request and a response, so
  // request_log and response_log are present; proof_of_concept,
  // cwe_id, and cvss_vector are absent.
  const checklist = evidenceChecklist(loadFixture('confirmed-missing-poc'));
  assert.deepEqual(checklist, [
    { item: 'proof_of_concept', present: false },
    { item: 'evidence', present: true },
    { item: 'steps_to_reproduce', present: true },
    { item: 'response_log', present: true },
    { item: 'impact', present: true },
    { item: 'remediation', present: true },
    { item: 'cwe_id', present: false },
    { item: 'cvss_vector', present: false },
    { item: 'request_log', present: true },
  ]);
});

test('checklist never omits an item, even for a malformed finding', () => {
  const checklist = evidenceChecklist(null);
  assert.equal(checklist.length, 7);
  assert.ok(checklist.every((entry) => entry.present === false));
});

// --- Round 32 hardening: edge cases the original 17 tests did not cover. ---

test('validator never throws on empty-string and exotic non-object inputs', () => {
  for (const malformed of ['', () => {}, Symbol('finding'), 10n]) {
    const result = validateFinding(malformed);
    assert.equal(result.verdict, 'needs_evidence');
    assert.ok(result.reasons.some((reason) => reason.startsWith('missing required field:')));
  }
});

test('unknown severity needs evidence naming the severity, not a mismatch', () => {
  const base = clone(loadFixture('confirmed-full'));
  for (const severity of ['CRITICAL', 'unknown', '']) {
    const result = validateFinding({ ...base, severity });
    assert.equal(result.verdict, 'needs_evidence');
    assert.deepEqual(result.reasons, [`unknown severity: ${severity}`]);
  }
});

test('unknown severity with an unbandable cvss_score does not slip through as valid', () => {
  // Before round 32 this was 'valid': bandForScore(11) is null, so the
  // mismatch check passed and nothing else objected — while the report
  // generator rejects the severity outright.
  const base = clone(loadFixture('confirmed-full'));
  const result = validateFinding({ ...base, severity: 'unknown', cvss_score: 11 });
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['unknown severity: unknown']);
});

test('false_positive still beats an unknown severity', () => {
  const base = clone(loadFixture('confirmed-full'));
  assert.equal(
    validateFinding({ ...base, severity: 'unknown', confidence: 'false_positive' }).verdict,
    'false_positive',
  );
  assert.deepEqual(
    validateFinding({ ...base, severity: 'unknown', confidence: 'needs_manual_review' }).reasons,
    ['manual review required'],
  );
});

test('present-but-invalid cvss_score needs evidence naming it', () => {
  const base = clone(loadFixture('confirmed-full'));
  for (const cvssScore of ['8.2', NaN, Infinity, 11, -1]) {
    const result = validateFinding({ ...base, cvss_score: cvssScore });
    assert.equal(result.verdict, 'needs_evidence');
    assert.ok(result.reasons.includes('invalid cvss_score'), `cvss_score=${String(cvssScore)}`);
  }
});

test('missing cvss_score stays unchecked', () => {
  const withoutScore = clone(loadFixture('confirmed-full'));
  delete withoutScore.cvss_score;
  assert.equal(validateFinding(withoutScore).verdict, 'valid');
  const nullScore = clone(loadFixture('confirmed-full'));
  nullScore.cvss_score = null;
  assert.equal(validateFinding(nullScore).verdict, 'valid');
});

test('steps_to_reproduce as a non-array does not throw and needs evidence naming it', () => {
  const base = clone(loadFixture('confirmed-full'));
  for (const steps of ['do the thing', '', 42]) {
    const result = validateFinding({ ...base, steps_to_reproduce: steps });
    assert.equal(result.verdict, 'needs_evidence');
    assert.ok(result.reasons.includes('missing steps_to_reproduce'));
  }
});

test('dedupe does not throw on null, undefined and non-object items', () => {
  const dupA = loadFixture('duplicate-a');
  const result = dedupeFindings([dupA, null, 'x', undefined]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 2);
  const junkGroup = result.groups.find((group) => group.key === '||(no-steps)');
  assert.deepEqual(junkGroup.findings, [null, 'x', undefined]);
});

test('dedupe collapses tabs and newlines inside the first step', () => {
  const tabbed = clone(loadFixture('duplicate-a'));
  const newlined = clone(loadFixture('duplicate-a'));
  tabbed.steps_to_reproduce = ['Navigate\tto https://lab.local/search?q=<script>alert(1)</script>'];
  newlined.steps_to_reproduce = ['Navigate\nto  https://lab.local/search?q=<script>alert(1)</script>'];
  assert.equal(rootCauseKey(tabbed), rootCauseKey(newlined));
  const result = dedupeFindings([tabbed, newlined]);
  assert.equal(result.groups.length, 1);
  assert.equal(result.duplicates, 1);
});

test('dedupe groups findings whose vulnerability_type differs only by case or spacing', () => {
  const first = clone(loadFixture('duplicate-a'));
  const second = clone(loadFixture('duplicate-a'));
  first.vulnerability_type = 'Cross-Site Scripting';
  second.vulnerability_type = '  cross-site scripting  ';
  assert.equal(rootCauseKey(first), rootCauseKey(second));
  const result = dedupeFindings([first, second]);
  assert.equal(result.groups.length, 1);
  assert.equal(result.duplicates, 1);
});

test('dedupe keeps findings apart when asset_id differs only by case', () => {
  const first = clone(loadFixture('duplicate-a'));
  const second = clone(loadFixture('duplicate-a'));
  first.asset_id = 'lab-asset-01';
  second.asset_id = 'Lab-Asset-01';
  const result = dedupeFindings([first, second]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 0);
});

test('checklist returns all 7 items as not present for an array input', () => {
  const checklist = evidenceChecklist([]);
  assert.equal(checklist.length, 7);
  assert.deepEqual(
    checklist.map((entry) => entry.item),
    ['proof_of_concept', 'evidence', 'steps_to_reproduce', 'impact', 'remediation', 'cwe_id', 'cvss_vector'],
  );
  assert.ok(checklist.every((entry) => entry.present === false));
});

test('non-string confidence needs evidence as unknown confidence', () => {
  const base = clone(loadFixture('confirmed-full'));
  assert.deepEqual(
    validateFinding({ ...base, confidence: 42 }),
    { verdict: 'needs_evidence', reasons: ['unknown confidence: 42'] },
  );
  assert.deepEqual(
    validateFinding({ ...base, confidence: true }),
    { verdict: 'needs_evidence', reasons: ['unknown confidence: true'] },
  );
});
