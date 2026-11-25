// Conservative semantic dedup (round 48): a second dedup pass after the
// exact-key dedup, over that pass's representatives. Two findings merge
// ONLY when all four hold: same normalized vulnerability_type, same
// asset_id, same CVSS base vector AND same severity (or, when neither
// carries a vector, the same severity band), and at least one shared
// evidence entry. Anything looser — fuzzy text similarity, same type +
// asset without shared evidence — is out of scope by design.
//
// Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  validateFinding,
  dedupeFindings,
  semanticDedupeFindings,
  semanticallyDuplicates,
} = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.json`), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// A pair that SHOULD merge: same type (case differs), same asset, same
// vector, same severity, and one shared evidence entry — but different
// first reproduction steps, so the exact-key dedup does NOT merge them.
function mergeablePair() {
  const sharedEntry = loadFixture('confirmed-full').evidence[0];
  const first = clone(loadFixture('confirmed-full'));
  first.finding_id = 'F-SEM-A';
  const second = clone(loadFixture('confirmed-full'));
  second.finding_id = 'F-SEM-B';
  second.vulnerability_type = 'stored cross-site scripting';
  second.steps_to_reproduce = [
    'Post a comment with an <img onerror> payload on https://lab.local/comments',
    'Reload the comments page as another lab user',
  ];
  second.evidence = [
    sharedEntry,
    { request: 'GET https://lab.local/comments', response: '200 OK, stored <img> tag rendered', notes: 'Second lab run' },
  ];
  second.references = ['https://example.test/lab/stored-xss', 'https://example.test/lab/stored-xss-2'];
  return [first, second];
}

test('semantic dedup merges the pair: union evidence, highest score, merged_from', () => {
  const [first, second] = mergeablePair();
  assert.equal(semanticallyDuplicates(first, second), true);
  const result = semanticDedupeFindings([first, second]);
  assert.equal(result.groups.length, 1);
  assert.equal(result.duplicates, 1);
  const group = result.groups[0];
  assert.deepEqual(group.findings.map((finding) => finding.finding_id), ['F-SEM-A', 'F-SEM-B']);
  const merged = group.merged;
  assert.equal(merged.finding_id, 'F-SEM-A');
  assert.deepEqual(merged.merged_from, ['F-SEM-A', 'F-SEM-B']);
  // Evidence union: the shared entry once, plus the second run's entry.
  assert.equal(merged.evidence.length, 2);
  assert.equal(merged.evidence[0].request, 'POST https://lab.local/comments');
  assert.equal(merged.evidence[1].request, 'GET https://lab.local/comments');
  // Steps union: both step lists, exact-string dedup (the shared
  // 'Reload the comments page as another lab user' step appears once).
  assert.equal(merged.steps_to_reproduce.length, 4);
  assert.deepEqual(merged.references, ['https://example.test/lab/stored-xss', 'https://example.test/lab/stored-xss-2']);
  // Same vector, so the merged score is the vector-computed score.
  assert.equal(merged.cvss_score, 7.5);
  assert.equal(merged.cvss_vector, first.cvss_vector);
  // The merged finding still validates as valid.
  assert.equal(validateFinding(merged).verdict, 'valid');
});

test('semantic dedup does NOT merge when the base vector differs', () => {
  const [first, second] = mergeablePair();
  // Same severity band (high) and shared evidence, but a different
  // base vector: PR:L + C:H/I:H/A:H computes to 8.8, still high.
  second.cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
  second.cvss_score = 8.8;
  assert.equal(semanticallyDuplicates(first, second), false);
  const result = semanticDedupeFindings([first, second]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 0);
  assert.equal(result.groups[0].merged.finding_id, 'F-SEM-A');
  assert.equal(result.groups[0].merged.merged_from, undefined);
});

test('semantic dedup does NOT merge when the asset differs', () => {
  const [first, second] = mergeablePair();
  second.asset_id = 'lab-asset-02';
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup does NOT merge when no evidence entry is shared', () => {
  const [first, second] = mergeablePair();
  second.evidence = [
    { request: 'GET https://lab.local/other', response: '200 OK', notes: 'Unrelated lab run' },
  ];
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup does NOT merge when the vulnerability type differs', () => {
  const [first, second] = mergeablePair();
  second.vulnerability_type = 'SQL Injection';
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup does NOT merge when the severity differs', () => {
  const [first, second] = mergeablePair();
  second.severity = 'medium';
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup merges the no-vector pair on shared severity band, score is the max declared', () => {
  const [first, second] = mergeablePair();
  delete first.cvss_vector;
  delete second.cvss_vector;
  first.cvss_score = 7.5;
  second.cvss_score = 8.8;
  assert.equal(semanticallyDuplicates(first, second), true);
  const result = semanticDedupeFindings([first, second]);
  assert.equal(result.groups.length, 1);
  assert.equal(result.groups[0].merged.cvss_score, 8.8);
  assert.equal(result.groups[0].merged.cvss_vector, undefined);
  assert.equal(validateFinding(result.groups[0].merged).verdict, 'valid');
});

test('semantic dedup does NOT merge a vector finding with a vector-less one', () => {
  const [first, second] = mergeablePair();
  delete second.cvss_vector;
  second.cvss_score = 7.5;
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup does NOT merge when one vector is malformed', () => {
  const [first, second] = mergeablePair();
  second.cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N';
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup does NOT merge on an empty evidence entry alone', () => {
  const [first, second] = mergeablePair();
  first.evidence = [{}];
  second.evidence = [{}];
  assert.equal(semanticallyDuplicates(first, second), false);
  assert.equal(semanticDedupeFindings([first, second]).groups.length, 2);
});

test('semantic dedup handles non-array and empty input like the exact dedup', () => {
  assert.deepEqual(semanticDedupeFindings([]), { groups: [], duplicates: 0 });
  assert.deepEqual(semanticDedupeFindings(null), { groups: [], duplicates: 0 });
  assert.deepEqual(semanticDedupeFindings(undefined), { groups: [], duplicates: 0 });
});

test('semantic dedup is greedy on the representative, not transitive-closure', () => {
  const [first, second] = mergeablePair();
  // A third finding matches the SECOND member's steps/evidence profile
  // but not the representative's: it shares evidence with the second
  // only through an entry the representative does not carry.
  const third = clone(second);
  third.finding_id = 'F-SEM-C';
  third.evidence = [
    { request: 'GET https://lab.local/comments', response: '200 OK, stored <img> tag rendered', notes: 'Second lab run' },
    { request: 'POST https://lab.local/comments/2', response: '200 OK', notes: 'Third lab run' },
  ];
  third.steps_to_reproduce = ['A completely different first step'];
  // third shares the second run's evidence entry with second, but the
  // representative (first) carries only the shared POST entry — which
  // third does NOT carry. So third does not match the representative.
  assert.equal(semanticallyDuplicates(first, third), false);
  assert.equal(semanticallyDuplicates(second, third), true);
  const result = semanticDedupeFindings([first, second, third]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 1);
  assert.deepEqual(result.groups[0].findings.map((finding) => finding.finding_id), ['F-SEM-A', 'F-SEM-B']);
  assert.deepEqual(result.groups[1].findings.map((finding) => finding.finding_id), ['F-SEM-C']);
});

test('generator renders merged_from in Markdown, JSON, and HTML', () => {
  const [first, second] = mergeablePair();
  const merged = semanticDedupeFindings([first, second]).groups[0].merged;
  const options = { programName: 'Lab Program', generatedAt: '2026-11-26T05:55:00+07:00' };
  const markdown = generateReport([merged], options);
  assert.match(markdown, /- \*\*Merged from:\*\* F-SEM-A, F-SEM-B/);
  const json = JSON.parse(generateReport([merged], { ...options, format: 'json' }));
  assert.deepEqual(json.findings[0].merged_from, ['F-SEM-A', 'F-SEM-B']);
  assert.deepEqual(json.groups[0].findings[0].merged_from, ['F-SEM-A', 'F-SEM-B']);
  const html = generateReport([merged], { ...options, format: 'html' });
  assert.match(html, /<dt>Merged from<\/dt><dd>F-SEM-A, F-SEM-B<\/dd>/);
  // A singleton renders no merged-from line anywhere.
  const plain = generateReport([first], options);
  assert.doesNotMatch(plain, /Merged from/);
  assert.doesNotMatch(generateReport([first], { ...options, format: 'html' }), /Merged from/);
  assert.equal(JSON.parse(generateReport([first], { ...options, format: 'json' })).findings[0].merged_from, undefined);
});

test('exact dedup still runs first and is unchanged by the semantic pass', () => {
  const dupA = loadFixture('duplicate-a');
  const dupB = loadFixture('duplicate-b');
  const other = loadFixture('confirmed-full');
  const exact = dedupeFindings([dupA, dupB, other]);
  assert.equal(exact.groups.length, 2);
  assert.equal(exact.duplicates, 1);
  const representatives = exact.groups.map((group) => group.findings[0]);
  const semantic = semanticDedupeFindings(representatives);
  assert.equal(semantic.groups.length, 2);
  assert.equal(semantic.duplicates, 0);
  assert.deepEqual(
    semantic.groups.map((group) => group.merged.finding_id),
    ['F-R31-DUP-A', 'F-R31-CONFIRMED-FULL'],
  );
});
