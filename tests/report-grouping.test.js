// Report grouping by asset (round 42): findings render grouped by
// asset_id, groups ordered by asset_id ascending, findings inside a
// group by severity then finding_id. Fixtures only; no scanner, no
// network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport, groupFindingsByAsset } = require('../src/report/generator');
const { validateFinding, dedupeFindings } = require('../src/analysis/validator');
const { runStubDetector } = require('../src/detection/stub-detector');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(finding) {
  return JSON.parse(JSON.stringify(finding));
}

test('groupFindingsByAsset orders groups by asset_id and findings by severity then id', () => {
  const array = loadFixture('report-findings-array.json');
  const [critical, medium, low] = array;
  // Deliberately feed low before medium inside one asset, and put the
  // critical finding on the alphabetically-last asset, so input order
  // proves nothing and the grouped order must come from the sorter.
  const input = [
    { ...clone(low), asset_id: 'beta-app' },
    { ...clone(medium), asset_id: 'beta-app' },
    { ...clone(critical), asset_id: 'alpha-app' },
  ];
  const before = JSON.stringify(input);
  const groups = groupFindingsByAsset(input);
  assert.equal(JSON.stringify(input), before, 'grouping must not mutate its input');
  assert.deepEqual(groups.map((group) => group.asset_id), ['alpha-app', 'beta-app']);
  assert.deepEqual(groups[0].findings.map((finding) => finding.finding_id), ['FND-CRIT-001']);
  assert.deepEqual(groups[1].findings.map((finding) => finding.finding_id), ['FND-MED-001', 'FND-LOW-001']);
});

test('groupFindingsByAsset maps missing, empty, whitespace, and non-string asset_id to unassigned', () => {
  const base = loadFixture('report-critical.json');
  const variants = [
    clone(base),
    { ...clone(base), asset_id: '' },
    { ...clone(base), asset_id: '   ' },
    { ...clone(base), asset_id: 42 },
  ];
  delete variants[0].asset_id;
  const groups = groupFindingsByAsset(variants);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].asset_id, 'unassigned');
  assert.equal(groups[0].findings.length, 4);
});

test('groupFindingsByAsset rejects a non-array input', () => {
  assert.throws(() => groupFindingsByAsset('not-an-array'), /expects an array/);
});

test('markdown groups findings by asset with a global finding number', () => {
  const array = loadFixture('report-findings-array.json');
  const [critical, medium, low] = array;
  const input = [
    { ...clone(critical), asset_id: 'zeta-app' },
    { ...clone(medium), asset_id: 'alpha-app' },
    { ...clone(low), asset_id: 'alpha-app' },
  ];
  const markdown = generateReport(input, OPTIONS);
  const assetAlpha = markdown.indexOf('## Asset: alpha-app');
  const assetZeta = markdown.indexOf('## Asset: zeta-app');
  assert.ok(assetAlpha !== -1 && assetZeta !== -1, 'both asset sections are present');
  assert.ok(assetAlpha < assetZeta, 'alpha-app group renders before zeta-app');
  assert.match(markdown, /## Asset: alpha-app — 2 findings \(critical: 0, high: 0, medium: 1, low: 1, informational: 0\)/);
  assert.match(markdown, /## Asset: zeta-app — 1 finding \(critical: 1, high: 0, medium: 0, low: 0, informational: 0\)/);
  // Global numbering follows grouped order, not input order: the
  // critical finding (input #1) renders last, as finding 3.
  const first = markdown.indexOf('## 1. Verbose error messages disclose internal paths [MEDIUM]');
  const second = markdown.indexOf('## 2. robots.txt discloses administrative path [LOW]');
  const third = markdown.indexOf('## 3. SQL injection in login username parameter [CRITICAL]');
  assert.ok(first !== -1 && second !== -1 && third !== -1, 'all three findings render with global numbers');
  assert.ok(first < second && second < third, 'finding numbers follow grouped order');
});

test('single-finding report keeps its content and only gains the group header', () => {
  const finding = loadFixture('report-critical.json');
  const markdown = generateReport([finding], OPTIONS);
  assert.match(markdown, /## Asset: lab-app\/login — 1 finding \(critical: 1, high: 0, medium: 0, low: 0, informational: 0\)/);
  assert.match(markdown, /## 1\. SQL injection in login username parameter \[CRITICAL\]/);
  const parsed = JSON.parse(generateReport([finding], { ...OPTIONS, format: 'json' }));
  assert.equal(parsed.groups.length, 1);
  assert.equal(parsed.groups[0].asset_id, 'lab-app/login');
  assert.equal(parsed.groups[0].findings_count, 1);
  assert.deepEqual(parsed.groups[0].findings_summary, { critical: 1, high: 0, medium: 0, low: 0, informational: 0, total: 1 });
  assert.equal(parsed.findings.length, 1);
});

test('grouping is deterministic across input orders', () => {
  const array = loadFixture('report-findings-array.json');
  const [critical, medium, low] = array;
  const reordered = [
    { ...clone(critical), asset_id: 'zeta-app' },
    { ...clone(medium), asset_id: 'alpha-app' },
    { ...clone(low), asset_id: 'alpha-app' },
  ];
  const shuffled = [reordered[2], reordered[0], reordered[1]];
  assert.equal(generateReport(reordered, OPTIONS), generateReport(shuffled, OPTIONS));
  assert.equal(
    generateReport(reordered, { ...OPTIONS, format: 'json' }),
    generateReport(shuffled, { ...OPTIONS, format: 'json' }),
  );
});

test('grouping never changes a finding verdict', () => {
  const array = loadFixture('report-findings-array.json');
  const before = array.map((finding) => validateFinding(finding).verdict);
  const grouped = groupFindingsByAsset(array);
  const after = grouped.flatMap((group) => group.findings).map((finding) => validateFinding(finding).verdict);
  assert.deepEqual(after.sort(), before.sort());
});

test('JSON output carries groups alongside the flat findings array', () => {
  const parsed = JSON.parse(generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'json' }));
  assert.deepEqual(parsed.groups.map((group) => group.asset_id), ['lab-app/login', 'lab-app/profile', 'lab-app/robots']);
  for (const group of parsed.groups) {
    assert.equal(group.findings_count, 1);
    assert.equal(group.findings.length, 1);
    assert.ok(group.findings[0].evidence_checklist, 'grouped findings carry the evidence checklist');
    assert.equal(group.findings_summary.total, 1);
  }
  // The flat array stays for backward compatibility, in grouped order.
  assert.deepEqual(parsed.findings.map((finding) => finding.finding_id), ['FND-CRIT-001', 'FND-MED-001', 'FND-LOW-001']);
  assert.equal(parsed.findings[0].finding_id, 'FND-CRIT-001');
});

test('dedupe runs before grouping: report over the deduped set groups by asset', () => {
  const result = runStubDetector(path.join(__dirname, 'fixtures', 'stub-scanner-mixed.json'), {
    session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1',
  });
  const deduped = dedupeFindings(result.findings);
  const dedupedFindings = deduped.groups.map((group) => group.findings[0]);
  const parsed = JSON.parse(generateReport(dedupedFindings, { ...OPTIONS, format: 'json' }));
  assert.equal(parsed.groups.length, 1);
  assert.equal(parsed.groups[0].asset_id, 'ast-1');
  // MIX-001 high (8.2), MIX-006 high (7.5), MIX-003 low (2.0): severity
  // first, then finding_id inside the high pair.
  assert.deepEqual(parsed.findings.map((finding) => finding.finding_id), ['MIX-001', 'MIX-006', 'MIX-003']);
  assert.deepEqual(parsed.groups[0].findings_summary, { critical: 0, high: 2, medium: 0, low: 1, informational: 0, total: 3 });
});

test('platform-template JSON keeps its flat shape (no groups)', () => {
  const finding = loadFixture('report-critical.json');
  const parsed = JSON.parse(generateReport([finding], { ...OPTIONS, format: 'json', template: 'immunefi' }));
  assert.equal(parsed.template, 'immunefi');
  assert.equal(parsed.findings.length, 1);
  assert.ok(!('groups' in parsed), 'template JSON omits groups');
});

test('CLI report renders asset sections in grouped order', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
  ]);
  const login = stdout.indexOf('## Asset: lab-app/login');
  const profile = stdout.indexOf('## Asset: lab-app/profile');
  const robots = stdout.indexOf('## Asset: lab-app/robots');
  assert.ok(login !== -1 && profile !== -1 && robots !== -1, 'all three asset sections are present');
  assert.ok(login < profile && profile < robots, 'asset sections render in asset_id order');
});
