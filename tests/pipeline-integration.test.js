// Pipeline integration (round 32): stub detector -> validator -> dedupe ->
// report generator, all in-process, plus the CLI failure path for a
// report that must never be half-written.
//
// Fixtures only; no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { runStubDetector } = require('../src/detection/stub-detector');
const { validateFinding, dedupeFindings } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');

const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };
const GENERATED_AT = '2026-11-26T02:50:00+07:00';
const PROGRAM = 'Lab Program';
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function fixturePath(name) {
  return path.join(__dirname, 'fixtures', name);
}

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(fixturePath(name), 'utf8'));
}

test('pipeline round-31 driver cases: stub -> validate -> dedupe -> deterministic report', () => {
  const result = runStubDetector(fixturePath('stub-scanner-output.json'), DEFAULTS);
  assert.equal(result.tool, 'stub-scanner-fixture');
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /title/);
  assert.deepEqual(
    result.findings.map((finding) => finding.finding_id),
    ['STUB-001', 'STUB-002'],
  );

  for (const finding of result.findings) {
    assert.equal(validateFinding(finding).verdict, 'needs_evidence');
  }

  const deduped = dedupeFindings(result.findings);
  assert.equal(deduped.groups.length, 2);
  assert.equal(deduped.duplicates, 0);

  const options = { programName: PROGRAM, generatedAt: GENERATED_AT };
  const markdown = generateReport(result.findings, options);
  assert.match(markdown, /\| critical \| 0 \|/);
  assert.match(markdown, /\| high \| 1 \|/);
  assert.match(markdown, /\| medium \| 1 \|/);
  assert.match(markdown, /\| total \| 2 \|/);

  const json = generateReport(result.findings, { ...options, format: 'json' });
  const parsed = JSON.parse(json);
  assert.deepEqual(parsed.findings_summary, {
    critical: 0,
    high: 1,
    medium: 1,
    low: 0,
    informational: 0,
    total: 2,
  });
  assert.equal(parsed.program_name, PROGRAM);
  assert.equal(parsed.generated_at, GENERATED_AT);

  // Determinism: the same input produces byte-identical output.
  assert.equal(generateReport(result.findings, options), markdown);
  assert.equal(generateReport(result.findings, { ...options, format: 'json' }), json);
});

test('pipeline mixed fixture: XSS pair dedupes, verdicts, report over the deduped set', () => {
  const result = runStubDetector(fixturePath('stub-scanner-mixed.json'), DEFAULTS);
  assert.equal(result.tool, 'stub-scanner-mixed');
  assert.equal(result.findings.length, 4);
  assert.equal(result.skipped, 2);
  assert.equal(result.errors.length, 2);
  assert.ok(result.errors.some((error) => /impact/.test(error)), 'one skip names impact');
  assert.ok(
    result.errors.some((error) => /severity mismatch/.test(error)),
    'one skip names the severity mismatch',
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.finding_id),
    ['MIX-001', 'MIX-002', 'MIX-003', 'MIX-006'],
  );

  const deduped = dedupeFindings(result.findings);
  assert.equal(deduped.groups.length, 3);
  assert.equal(deduped.duplicates, 1);
  const xssGroup = deduped.groups.find((group) => group.findings.length === 2);
  assert.ok(xssGroup, 'the MIX-001/MIX-002 group has exactly 2 findings');
  assert.deepEqual(
    xssGroup.findings.map((finding) => finding.finding_id),
    ['MIX-001', 'MIX-002'],
  );

  const verdictById = new Map(
    result.findings.map((finding) => [finding.finding_id, validateFinding(finding).verdict]),
  );
  assert.equal(verdictById.get('MIX-001'), 'needs_evidence');
  assert.equal(verdictById.get('MIX-002'), 'needs_evidence');
  assert.equal(verdictById.get('MIX-003'), 'false_positive');
  assert.equal(verdictById.get('MIX-006'), 'valid');

  // Report over the deduped set: first finding of each group, in group order.
  const dedupedFindings = deduped.groups.map((group) => group.findings[0]);
  assert.deepEqual(
    dedupedFindings.map((finding) => finding.finding_id),
    ['MIX-001', 'MIX-003', 'MIX-006'],
  );
  const options = { programName: PROGRAM, generatedAt: GENERATED_AT };
  const markdown = generateReport(dedupedFindings, options);
  assert.match(markdown, /\| high \| 2 \|/);
  assert.match(markdown, /\| low \| 1 \|/);
  assert.match(markdown, /\| total \| 3 \|/);
  // The generator renders what it is given, including the false-positive
  // finding; excluding it is a policy decision for a later round.
  assert.match(markdown, /Reflected XSS in search box/);
  assert.match(markdown, /Login status endpoint reachable without credentials/);
  assert.match(markdown, /Verbose error discloses stack trace/);
  const parsed = JSON.parse(generateReport(dedupedFindings, { ...options, format: 'json' }));
  assert.deepEqual(parsed.findings_summary, {
    critical: 0,
    high: 2,
    medium: 0,
    low: 1,
    informational: 0,
    total: 3,
  });
});

test('CLI report with a missing-field finding fails with no half-written output', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-pipeline-'));
  try {
    const output = path.join(directory, 'out.md');
    let caught = null;
    try {
      execFileSync(process.execPath, [
        CLI, 'report', '--finding', fixturePath('report-incomplete.json'), '--out', output,
      ]);
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, 'execFileSync must throw on the non-zero exit');
    assert.notEqual(caught.status, 0);
    const combined = `${String(caught.stderr || '')}\n${String(caught.stdout || '')}`;
    assert.match(combined, /impact/);
    assert.match(combined, /remediation/);
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('severity-mismatch fixture: generator throws, validator flags the mismatch', () => {
  const finding = loadFixture('severity-mismatch.json');
  assert.throws(
    () => generateReport([finding], { programName: 'Lab', generatedAt: GENERATED_AT }),
    /mismatch/,
  );
  const result = validateFinding(finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.ok(result.reasons.includes('severity/cvss mismatch'));
});
