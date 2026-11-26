// Per-class evidence checklists (round 40, extended in round 57): the
// validator resolves a finding's vulnerability_type to one of twelve
// classes in knowledge/evidence-checklists.json and enforces that
// class's required evidence items; unknown types fall back to the
// generic checklist.
//
// Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  validateFinding,
  evidenceChecklist,
  evidenceChecklistForClass,
  loadEvidenceChecklists,
  resolveEvidenceClass,
} = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.json`), 'utf8'));
}

function clone(finding) {
  return JSON.parse(JSON.stringify(finding));
}

// The twelve classes, each with its fully-evidenced fixture. XSS reuses
// the round-31 confirmed-full fixture (Stored Cross-Site Scripting).
const CLASS_FIXTURES = [
  ['cross-site scripting', 'confirmed-full'],
  ['sql injection', 'class-sqli-full'],
  ['server-side request forgery', 'class-ssrf-full'],
  ['broken access control', 'class-bac-full'],
  ['authentication bypass', 'class-authbypass-full'],
  ['cross-site request forgery', 'class-csrf-full'],
  ['reentrancy', 'class-reentrancy-full'],
  ['information disclosure', 'class-infodisclosure-full'],
  ['xml external entity', 'class-xxe-full'],
  ['insecure deserialization', 'class-deserialization-full'],
  ['path traversal', 'class-pathtraversal-full'],
  ['business logic flaw', 'class-businesslogic-full'],
];

// The class-specific required item each class adds beyond the generic
// three (proof_of_concept, evidence, steps_to_reproduce), and the
// evidence subfield that proves it.
const CLASS_EXTRA = {
  'cross-site scripting': ['response_log', 'response'],
  'sql injection': ['response_log', 'response'],
  'server-side request forgery': ['request_log', 'request'],
  'broken access control': ['response_log', 'response'],
  'authentication bypass': ['response_log', 'response'],
  'cross-site request forgery': ['request_log', 'request'],
  reentrancy: ['evidence_notes', 'notes'],
  'information disclosure': ['response_log', 'response'],
  'xml external entity': ['response_log', 'response'],
  'insecure deserialization': ['evidence_notes', 'notes'],
  'path traversal': ['response_log', 'response'],
  'business logic flaw': ['evidence_notes', 'notes'],
};

test('spec loads with twelve classes and the generic fallback', () => {
  const spec = loadEvidenceChecklists();
  assert.equal(spec.version, 1);
  assert.equal(spec.classes.length, 12);
  assert.deepEqual(spec.generic.required, ['proof_of_concept', 'evidence', 'steps_to_reproduce']);
  assert.deepEqual(spec.generic.recommended, ['impact', 'remediation', 'cwe_id', 'cvss_vector']);
  assert.deepEqual(
    spec.classes.map((entry) => entry.id),
    [
      'cross-site scripting',
      'sql injection',
      'server-side request forgery',
      'broken access control',
      'authentication bypass',
      'cross-site request forgery',
      'reentrancy',
      'information disclosure',
      'xml external entity',
      'insecure deserialization',
      'path traversal',
      'business logic flaw',
    ],
  );
  for (const entry of spec.classes) {
    assert.ok(entry.required.includes('proof_of_concept'), `${entry.id} requires proof_of_concept`);
    assert.ok(entry.required.includes('evidence'), `${entry.id} requires evidence`);
    assert.ok(entry.required.includes('steps_to_reproduce'), `${entry.id} requires steps_to_reproduce`);
  }
});

test('class resolution normalizes case, spacing, and substrings', () => {
  assert.equal(resolveEvidenceClass('  CROSS-SITE SCRIPTING  ').id, 'cross-site scripting');
  assert.equal(resolveEvidenceClass('Stored Cross-Site Scripting').id, 'cross-site scripting');
  assert.equal(resolveEvidenceClass('xss').id, 'cross-site scripting');
  assert.equal(resolveEvidenceClass('Reflected XSS').id, 'cross-site scripting');
  assert.equal(resolveEvidenceClass('sqli').id, 'sql injection');
  assert.equal(resolveEvidenceClass('SSRF').id, 'server-side request forgery');
  assert.equal(resolveEvidenceClass('idor').id, 'broken access control');
  assert.equal(resolveEvidenceClass('auth bypass').id, 'authentication bypass');
  assert.equal(resolveEvidenceClass('CSRF').id, 'cross-site request forgery');
  assert.equal(resolveEvidenceClass('Re-Entrancy').id, 'reentrancy');
  assert.equal(resolveEvidenceClass('infoleak').id, 'information disclosure');
  assert.equal(resolveEvidenceClass('XXE').id, 'xml external entity');
  assert.equal(resolveEvidenceClass('XML External Entity Injection').id, 'xml external entity');
  assert.equal(resolveEvidenceClass('Insecure Deserialization').id, 'insecure deserialization');
  assert.equal(resolveEvidenceClass('Unsafe Deserialization').id, 'insecure deserialization');
  assert.equal(resolveEvidenceClass('Path Traversal').id, 'path traversal');
  assert.equal(resolveEvidenceClass('Directory Traversal').id, 'path traversal');
  assert.equal(resolveEvidenceClass('traversal').id, 'path traversal');
  assert.equal(resolveEvidenceClass('Business Logic Flaw').id, 'business logic flaw');
  assert.equal(resolveEvidenceClass('Business-Logic Bypass').id, 'business logic flaw');
  assert.equal(resolveEvidenceClass('logic flaw').id, 'business logic flaw');
  assert.equal(resolveEvidenceClass('Open Redirect'), null);
  assert.equal(resolveEvidenceClass('Missing Authentication'), null);
  assert.equal(resolveEvidenceClass(''), null);
  assert.equal(resolveEvidenceClass(null), null);
  assert.equal(resolveEvidenceClass(42), null);
});

test('every class fixture validates with its class checklist', () => {
  for (const [classId, fixtureName] of CLASS_FIXTURES) {
    const finding = loadFixture(fixtureName);
    const resolved = evidenceChecklistForClass(finding);
    assert.equal(resolved.classId, classId, `${fixtureName} resolves to ${classId}`);
    assert.ok(resolved.items.every((entry) => entry.present === true), `${fixtureName} has every checklist item present`);
    const result = validateFinding(finding);
    assert.equal(result.verdict, 'valid', `${fixtureName} (${classId}) should be valid, got ${JSON.stringify(result)}`);
  }
});

test('every class fixture fails when its class-specific item is stripped', () => {
  for (const [classId, fixtureName] of CLASS_FIXTURES) {
    const [extraItem, subfield] = CLASS_EXTRA[classId];
    const finding = clone(loadFixture(fixtureName));
    for (const entry of finding.evidence) delete entry[subfield];
    const result = validateFinding(finding);
    assert.equal(result.verdict, 'needs_evidence', `${fixtureName} without ${extraItem} should need evidence`);
    assert.ok(
      result.reasons.includes(`missing ${extraItem} (required for ${classId})`),
      `${fixtureName} reasons should name ${extraItem}, got ${JSON.stringify(result.reasons)}`,
    );
    // The generic reasons stay exact: no duplicate for the stripped subfield.
    assert.ok(!result.reasons.includes('missing evidence'), `${fixtureName} must not also claim missing evidence`);
  }
});

test('new classes do not steal matches from the existing eight', () => {
  // File order is precedence: a type containing both an old alias and a
  // new alias still resolves to the old class.
  assert.equal(resolveEvidenceClass('SQL Injection').id, 'sql injection');
  assert.equal(resolveEvidenceClass('Stored Cross-Site Scripting').id, 'cross-site scripting');
  assert.equal(resolveEvidenceClass('SSRF via XML').id, 'server-side request forgery');
  assert.equal(resolveEvidenceClass('SQL Injection via path traversal').id, 'sql injection');
  // And the new classes win only when no old alias is present.
  assert.equal(resolveEvidenceClass('Traversal in File Download').id, 'path traversal');
  assert.equal(resolveEvidenceClass('XXE in upload').id, 'xml external entity');
  assert.equal(resolveEvidenceClass('Deserialization gadget chain').id, 'insecure deserialization');
  assert.equal(resolveEvidenceClass('Coupon stacking logic flaw').id, 'business logic flaw');
});

test('SSRF requires both the request and the response', () => {
  const finding = clone(loadFixture('class-ssrf-full'));
  for (const entry of finding.evidence) delete entry.response;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('missing response_log (required for server-side request forgery)'));
  assert.ok(!result.reasons.includes('missing request_log (required for server-side request forgery)'));
});

test('XXE requires both the request and the response', () => {
  const finding = clone(loadFixture('class-xxe-full'));
  for (const entry of finding.evidence) delete entry.response;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('missing response_log (required for xml external entity)'));
  assert.ok(!result.reasons.includes('missing request_log (required for xml external entity)'));
});

test('path traversal requires both the request and the response', () => {
  const finding = clone(loadFixture('class-pathtraversal-full'));
  for (const entry of finding.evidence) delete entry.request;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('missing request_log (required for path traversal)'));
  assert.ok(!result.reasons.includes('missing response_log (required for path traversal)'));
});

test('a missing evidence array reports only missing evidence, not its derived items', () => {
  const finding = clone(loadFixture('class-sqli-full'));
  delete finding.evidence;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.deepEqual(result.reasons, ['missing evidence']);
});

test('unknown class falls back to the generic seven-item checklist', () => {
  const finding = loadFixture('potential-full'); // Open Redirect: no class.
  const resolved = evidenceChecklistForClass(finding);
  assert.equal(resolved.classId, 'generic');
  assert.deepEqual(
    resolved.items.map((entry) => entry.item),
    ['proof_of_concept', 'evidence', 'steps_to_reproduce', 'impact', 'remediation', 'cwe_id', 'cvss_vector'],
  );
  assert.ok(resolved.items.every((entry) => entry.present === true));
  // The generic verdict rules are unchanged: fully evidenced potential stays valid.
  assert.equal(validateFinding(finding).verdict, 'valid');
});

test('evidenceChecklist returns the per-class list with required flags stripped', () => {
  const checklist = evidenceChecklist(loadFixture('class-csrf-full'));
  assert.deepEqual(
    checklist.map((entry) => entry.item),
    ['proof_of_concept', 'evidence', 'steps_to_reproduce', 'request_log', 'impact', 'remediation', 'cwe_id', 'cvss_vector', 'response_log', 'evidence_notes'],
  );
  assert.ok(checklist.every((entry) => entry.present === true));
  assert.ok(checklist.every((entry) => Object.keys(entry).length === 2), 'entries carry only item and present');
});

test('checklist marks required vs recommended and present vs missing', () => {
  const finding = clone(loadFixture('class-reentrancy-full'));
  for (const entry of finding.evidence) delete entry.notes;
  const resolved = evidenceChecklistForClass(finding);
  assert.equal(resolved.classId, 'reentrancy');
  const notes = resolved.items.find((entry) => entry.item === 'evidence_notes');
  assert.deepEqual(notes, { item: 'evidence_notes', present: false, required: true });
  const response = resolved.items.find((entry) => entry.item === 'response_log');
  assert.deepEqual(response, { item: 'response_log', present: true, required: false });
});

test('loader throws on a missing, malformed, or bad-item spec', () => {
  assert.throws(() => loadEvidenceChecklists('/tmp/does-not-exist-r40.json'), /Unable to load evidence checklists/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-checklists-'));
  try {
    const malformed = path.join(directory, 'malformed.json');
    fs.writeFileSync(malformed, '{not json');
    assert.throws(() => loadEvidenceChecklists(malformed), /Unable to load evidence checklists/);
    const badItem = path.join(directory, 'bad-item.json');
    fs.writeFileSync(badItem, JSON.stringify({
      version: 1,
      generic: { required: ['proof_of_concept'], recommended: [] },
      classes: [{ id: 'x', match: ['x'], required: ['no_such_item'], recommended: [] }],
    }));
    assert.throws(() => loadEvidenceChecklists(badItem), /unknown checklist item/);
    const duplicate = path.join(directory, 'duplicate.json');
    fs.writeFileSync(duplicate, JSON.stringify({
      version: 1,
      generic: { required: ['proof_of_concept'], recommended: [] },
      classes: [{ id: 'x', match: ['x'], required: ['proof_of_concept'], recommended: ['proof_of_concept'] }],
    }));
    assert.throws(() => loadEvidenceChecklists(duplicate), /lists an item twice/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('false_positive still wins over a missing class-required item', () => {
  const finding = clone(loadFixture('class-sqli-full'));
  finding.confidence = 'false_positive';
  for (const entry of finding.evidence) delete entry.response;
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'false_positive');
});

test('generator renders the per-class checklist in Markdown, missing items marked', () => {
  const finding = clone(loadFixture('class-csrf-full'));
  for (const entry of finding.evidence) delete entry.request;
  const report = generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(report, /### Evidence Checklist/);
  assert.match(report, /Class: Cross-Site Request Forgery \(CSRF\)/);
  assert.match(report, /- \[ \] request_log \(required\) — missing/);
  assert.match(report, /- \[x\] proof_of_concept \(required\)/);
  assert.match(report, /- \[x\] response_log \(recommended\)/);
  // Determinism: the checklist rendering is byte-identical across runs.
  assert.equal(
    generateReport([finding], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' }),
    report,
  );
});

test('generator attaches the checklist to each finding in JSON', () => {
  const parsed = JSON.parse(generateReport([loadFixture('class-ssrf-full')], {
    programName: 'Lab Program',
    generatedAt: '2026-11-26T02:00:00.000Z',
    format: 'json',
  }));
  const checklist = parsed.findings[0].evidence_checklist;
  assert.equal(checklist.classId, 'server-side request forgery');
  assert.equal(checklist.label, 'Server-Side Request Forgery (SSRF)');
  assert.deepEqual(
    checklist.items.map((entry) => entry.item),
    ['proof_of_concept', 'evidence', 'steps_to_reproduce', 'request_log', 'response_log', 'impact', 'remediation', 'cwe_id', 'cvss_vector', 'evidence_notes'],
  );
  assert.ok(checklist.items.every((entry) => entry.present === true));
  assert.ok(checklist.items.find((entry) => entry.item === 'request_log').required);
  assert.ok(!checklist.items.find((entry) => entry.item === 'evidence_notes').required);
});

test('generator names the generic fallback in Markdown for an unmatched class', () => {
  const report = generateReport([loadFixture('potential-full')], { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' });
  assert.match(report, /Class: Generic \(no class match\) — the vulnerability type matched no class, so the generic checklist applies/);
  assert.match(report, /- \[x\] proof_of_concept \(required\)/);
});

test('generator renders the four new classes in Markdown and JSON', () => {
  const NEW_CLASSES = [
    ['class-xxe-full', 'XML External Entity (XXE)', ['request_log', 'response_log']],
    ['class-deserialization-full', 'Insecure Deserialization', ['evidence_notes']],
    ['class-pathtraversal-full', 'Path Traversal', ['request_log', 'response_log']],
    ['class-businesslogic-full', 'Business Logic Flaw', ['evidence_notes']],
  ];
  for (const [fixtureName, label, extraRequired] of NEW_CLASSES) {
    const finding = loadFixture(fixtureName);
    const options = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };
    const markdown = generateReport([finding], options);
    assert.match(markdown, new RegExp(`Class: ${label.replace(/[()]/g, '\\$&')}`), `${fixtureName} Markdown names its class`);
    for (const item of extraRequired) {
      assert.match(markdown, new RegExp(`- \\[x\\] ${item} \\(required\\)`), `${fixtureName} Markdown marks ${item} required and present`);
    }
    const parsed = JSON.parse(generateReport([finding], { ...options, format: 'json' }));
    const checklist = parsed.findings[0].evidence_checklist;
    assert.equal(checklist.label, label, `${fixtureName} JSON label`);
    for (const item of extraRequired) {
      const entry = checklist.items.find((row) => row.item === item);
      assert.ok(entry, `${fixtureName} JSON carries ${item}`);
      assert.equal(entry.present, true, `${fixtureName} JSON ${item} present`);
      assert.equal(entry.required, true, `${fixtureName} JSON ${item} required`);
    }
  }
});
