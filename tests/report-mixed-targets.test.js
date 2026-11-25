// Mixed-target grouping with explicit opt-in (round 49, Phase 7).
// By default a report covering more than one distinct target_id is
// refused (REPORT_MIXED_TARGETS_REFUSED); the operator opts in with
// --allow-mixed-targets, and the report then groups by target first,
// then by asset within each target, stating the full target list in
// its header (Markdown, JSON, and HTML). Fixtures only; no scanner,
// no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport, groupFindingsByTarget } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(finding) {
  return JSON.parse(JSON.stringify(finding));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// Two validated findings on two distinct targets. confirmed-full is
// target local-lab / asset lab-asset-01 (high); potential-full is
// target local-lab / asset lab-asset-02 (medium) — retargeted here to
// local-lab-2 so the pair is genuinely mixed.
function mixedFindings() {
  const first = clone(loadFixture('confirmed-full.json'));
  const second = clone(loadFixture('potential-full.json'));
  second.target_id = 'local-lab-2';
  return [first, second];
}

test('groupFindingsByTarget orders targets ascending and nests asset groups', () => {
  const input = mixedFindings().reverse();
  const before = JSON.stringify(input);
  const targetGroups = groupFindingsByTarget(input);
  assert.equal(JSON.stringify(input), before, 'grouping must not mutate its input');
  assert.deepEqual(targetGroups.map((targetGroup) => targetGroup.target_id), ['local-lab', 'local-lab-2']);
  assert.deepEqual(targetGroups[0].groups.map((group) => group.asset_id), ['lab-asset-01']);
  assert.deepEqual(targetGroups[1].groups.map((group) => group.asset_id), ['lab-asset-02']);
  assert.deepEqual(targetGroups[0].groups[0].findings.map((finding) => finding.finding_id), ['F-R31-CONFIRMED-FULL']);
});

test('groupFindingsByTarget maps a missing target_id to the unassigned target', () => {
  const finding = clone(loadFixture('report-critical.json'));
  delete finding.target_id;
  const targetGroups = groupFindingsByTarget([finding]);
  assert.equal(targetGroups.length, 1);
  assert.equal(targetGroups[0].target_id, 'unassigned');
});

test('mixed-target input is refused by default with a named error', () => {
  assert.throws(
    () => generateReport(mixedFindings(), OPTIONS),
    (error) => {
      assert.match(error.message, /REPORT_MIXED_TARGETS_REFUSED/);
      assert.match(error.message, /local-lab/);
      assert.match(error.message, /local-lab-2/);
      assert.match(error.message, /--allow-mixed-targets/);
      return true;
    },
  );
});

test('mixed-target input with the opt-in groups by target then asset in Markdown', () => {
  const markdown = generateReport(mixedFindings().reverse(), { ...OPTIONS, allowMixedTargets: true });
  assert.match(markdown, /This report covers multiple targets: local-lab, local-lab-2\./);
  const targetOne = markdown.indexOf('## Target: local-lab\n');
  const targetTwo = markdown.indexOf('## Target: local-lab-2\n');
  assert.ok(targetOne !== -1 && targetTwo !== -1, 'both target sections are present');
  assert.ok(targetOne < targetTwo, 'target sections render in target_id order');
  const assetOne = markdown.indexOf('### Asset: lab-asset-01');
  const assetTwo = markdown.indexOf('### Asset: lab-asset-02');
  assert.ok(assetOne !== -1 && assetTwo !== -1, 'both asset subsections are present');
  assert.ok(targetOne < assetOne && assetOne < targetTwo && targetTwo < assetTwo, 'asset subsections nest under their target');
  // '### Asset:' contains '## Asset:' as a substring, so anchor the
  // check at a line start: no top-level asset section in
  // multi-target mode.
  assert.ok(!markdown.includes('\n## Asset:'), 'no top-level asset section in multi-target mode');
  // Finding numbers stay global across targets.
  assert.match(markdown, /## 1\. .*\[HIGH\]/);
  assert.match(markdown, /## 2\. .*\[MEDIUM\]/);
});

test('mixed-target input with the opt-in lists targets in JSON', () => {
  const parsed = JSON.parse(generateReport(mixedFindings().reverse(), { ...OPTIONS, format: 'json', allowMixedTargets: true }));
  assert.deepEqual(parsed.target_ids, ['local-lab', 'local-lab-2']);
  assert.equal(parsed.mixed_targets, true);
  // schemas/report.schema.json still requires target_id: in a
  // multi-target report it holds the first target in sorted order.
  assert.equal(parsed.target_id, 'local-lab');
  assert.deepEqual(parsed.groups.map((group) => [group.target_id, group.asset_id]), [
    ['local-lab', 'lab-asset-01'],
    ['local-lab-2', 'lab-asset-02'],
  ]);
  assert.deepEqual(parsed.findings.map((finding) => finding.finding_id), ['F-R31-CONFIRMED-FULL', 'F-R31-POTENTIAL-FULL']);
});

test('mixed-target input with the opt-in lists targets in HTML', () => {
  const html = generateReport(mixedFindings(), { ...OPTIONS, format: 'html', allowMixedTargets: true });
  assert.match(html, /<p>This report covers multiple targets: local-lab, local-lab-2<\/p>/);
  const targetOne = html.indexOf('<h2>Target: local-lab</h2>');
  const targetTwo = html.indexOf('<h2>Target: local-lab-2</h2>');
  assert.ok(targetOne !== -1 && targetTwo !== -1, 'both target headings are present');
  assert.ok(targetOne < targetTwo, 'target headings render in target_id order');
  assert.match(html, /<h3>Asset: lab-asset-01/);
  assert.match(html, /<h3>Asset: lab-asset-02/);
});

test('single-target output is unchanged by the mixed-target work (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  const html = generateReport(findings, { ...OPTIONS, format: 'html' });
  // Hashes captured from the pre-change generator (round 44, commit
  // 57bfb19): adding the mixed-target refusal and opt-in must not
  // move a byte of the single-target output.
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
  assert.ok(!markdown.includes('This report covers multiple targets'), 'no multi-target line in single-target mode');
  assert.ok(!html.includes('<h2>Target:'), 'no target heading in single-target mode');
  assert.ok(!('target_ids' in JSON.parse(json)), 'no target_ids in single-target JSON');
  assert.ok(!('mixed_targets' in JSON.parse(json)), 'no mixed_targets in single-target JSON');
});

test('mixed-target output is deterministic across input orderings', () => {
  const forward = mixedFindings();
  const reversed = mixedFindings().reverse();
  const opts = { ...OPTIONS, allowMixedTargets: true };
  assert.equal(
    sha256(generateReport(forward, opts)),
    sha256(generateReport(reversed, opts)),
    'markdown byte-identical across input orderings',
  );
  assert.equal(
    sha256(generateReport(forward, { ...opts, format: 'json' })),
    sha256(generateReport(reversed, { ...opts, format: 'json' })),
    'json byte-identical across input orderings',
  );
  assert.equal(
    sha256(generateReport(forward, { ...opts, format: 'html' })),
    sha256(generateReport(reversed, { ...opts, format: 'html' })),
    'html byte-identical across input orderings',
  );
});

test('a template with mixed-target input is refused as mixed-target, not as a template', () => {
  assert.throws(
    () => generateReport(mixedFindings(), { ...OPTIONS, template: 'immunefi' }),
    /REPORT_MIXED_TARGETS_REFUSED/,
    'the input-set refusal runs before the template branch',
  );
  // Same-target pair + template still fails as a template (one
  // finding per report), not as a mixed-target refusal.
  const sameTarget = [clone(loadFixture('confirmed-full.json')), clone(loadFixture('potential-full.json'))];
  assert.throws(
    () => generateReport(sameTarget, { ...OPTIONS, template: 'immunefi' }),
    /renders one finding per report/,
  );
});

test('CLI report refuses mixed-target input by default and writes no file', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-r49-');
  const outPath = path.join(dir, 'report.md');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'mixed-target-findings.json'),
      '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z', '--out', outPath,
    ]),
    (error) => {
      assert.equal(error.code, 1, 'exit code 1');
      assert.match(error.stderr, /REPORT_MIXED_TARGETS_REFUSED/);
      return true;
    },
  );
  assert.ok(!fs.existsSync(outPath), 'a refused report writes no output file');
});

test('CLI report with --allow-mixed-targets renders target sections', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-r49-');
  const outPath = path.join(dir, 'report.md');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'mixed-target-findings.json'),
    '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
    '--out', outPath, '--allow-mixed-targets',
  ]);
  assert.match(stdout, /Report written to/);
  const written = fs.readFileSync(outPath, 'utf8');
  assert.match(written, /This report covers multiple targets: local-lab, local-lab-2\./);
  assert.match(written, /## Target: local-lab\n/);
  assert.match(written, /## Target: local-lab-2\n/);
  assert.match(written, /### Asset: lab-asset-01/);
});
