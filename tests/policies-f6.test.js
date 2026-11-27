// F6 policies (round 90): the open policy questions from
// rounds 48/50/67, decided by the user on 2026-11-28
// (~01:03 WIB) and implemented as executable policy in
// src/analysis/policies.js. These tests pin the decisions:
// a future change must change the constants AND the doc,
// not slip past silently.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const {
  SEMANTIC_DEDUP_MODE,
  FALSE_POSITIVE_REPORTING,
  AI_VERDICT_OVERRIDE,
  DETECTION_AUTO_RUN,
  DETECTOR_ASYNC,
  excludeFalsePositives,
} = require('../src/analysis/policies');
const { semanticDedupeFindings, validateFinding } = require('../src/analysis/validator');
const { runDetector } = require('../src/detection/detector');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const ALL = loadFixture('report-findings-array.json');
const CRIT = ALL[0];
const MED = ALL[1];
const PROGRAM = 'Lab Program';
const GENERATED_AT = '2026-11-26T02:00:00.000Z';

test('the policy constants are the user-approved decisions', () => {
  assert.equal(SEMANTIC_DEDUP_MODE, 'conservative');
  assert.equal(FALSE_POSITIVE_REPORTING, 'exclude-from-reports');
  assert.equal(AI_VERDICT_OVERRIDE, false);
  assert.equal(DETECTION_AUTO_RUN, false);
  assert.equal(DETECTOR_ASYNC, false);
});

test('semantic dedup stays conservative: same type + asset + vector WITHOUT shared evidence does not merge', () => {
  const a = clone(CRIT);
  const b = clone(CRIT);
  b.finding_id = 'FND-CRIT-002';
  b.evidence = [{ notes: 'A different observation, no shared entry.' }];
  b.steps_to_reproduce = ['A different first step.'];
  const result = semanticDedupeFindings([a, b]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 0);
});

test('semantic dedup stays conservative: different severity does not merge', () => {
  const a = clone(CRIT);
  const b = clone(CRIT);
  b.finding_id = 'FND-CRIT-002';
  b.severity = 'high';
  b.cvss_score = 7.5;
  const result = semanticDedupeFindings([a, b]);
  assert.equal(result.groups.length, 2);
  assert.equal(result.duplicates, 0);
});

test('excludeFalsePositives excludes only rule-verdict false_positive findings', () => {
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const ne = clone(MED);
  ne.confidence = 'potential';
  const { kept, excluded } = excludeFalsePositives([CRIT, fp, ne]);
  assert.deepEqual(kept.map((f) => f.finding_id), ['FND-CRIT-001', 'FND-MED-001']);
  assert.deepEqual(excluded.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.equal(excluded[0], fp);
});

test('excludeFalsePositives keeps findings that fail the strict check (never masks a defect)', () => {
  const broken = clone(CRIT);
  broken.severity = 'low'; // CRIT scores 9.8: band mismatch, strict check fails
  const { kept, excluded } = excludeFalsePositives([broken]);
  assert.equal(kept.length, 1);
  assert.equal(excluded.length, 0);
  // ... and the generator still throws on it, as today.
  assert.throws(() => generateReport([broken], { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
});

test('AI verdict never overrides the rule verdict, in either direction', () => {
  const disagreeing = () => ({ verdict: 'false_positive', confidence: 1, reasons: ['model disagrees'] });
  const agreeing = () => ({ verdict: 'valid', confidence: 1, reasons: ['model agrees'] });
  const valid = validateFinding(CRIT, { verifier: disagreeing });
  assert.equal(valid.verdict, 'valid');
  assert.equal(valid.aiVerdict.verdict, 'false_positive');
  const unevidenced = clone(MED);
  unevidenced.evidence = [];
  const needs = validateFinding(unevidenced, { verifier: agreeing });
  assert.equal(needs.verdict, 'needs_evidence');
  assert.equal(needs.aiVerdict.verdict, 'valid');
});

test('an async detector is refused, never awaited', () => {
  const asyncDetector = async () => ({ findings: [], skipped: 0, errors: [] });
  const result = runDetector(asyncDetector, clone(CRIT), {});
  assert.deepEqual(result.findings, []);
  assert.equal(result.skipped, 0);
  assert.match(result.errors[0], /DETECTOR_INVALID_RESULT/);
  assert.match(result.error, /synchronously/);
});

test('CLI: a false_positive finding is excluded by default, with a stderr note', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-default-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([CRIT, fp]));
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
  ]);
  const parsed = JSON.parse(stdout);
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  // Round 96: the note carries the policy version, so a run's
  // enforcement is auditable from its own output.
  assert.equal(stderr, 'Excluded 1 false_positive finding from the report (policy F6 v1.0.0; use --include-false-positives to keep them).\n');
});

test('CLI: --include-false-positives keeps the finding and says nothing', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-flag-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([CRIT, fp]));
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
    '--include-false-positives',
  ]);
  const parsed = JSON.parse(stdout);
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001', 'FND-CRIT-001']);
  assert.equal(stderr, '');
});

test('CLI: when every finding is false_positive the command fails closed', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-all-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([fp]));
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--findings', inPath, '--format', 'json',
      '--program', PROGRAM, '--generated-at', GENERATED_AT,
    ]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_ALL_FINDINGS_FALSE_POSITIVE/);
      return true;
    },
  );
});

test('CLI: an empty findings array still renders the header-only CSV (round 90 regression)', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-empty-');
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, '[]', 'utf8');
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'csv',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
  ]);
  assert.equal(stdout.trim(), 'finding_id,target_id,asset_id,severity,cvss_base_score,cvss_temporal_score,cvss_environmental_score,verdict,evidence_checklist,merged_from,ai_verdict');
  assert.doesNotMatch(stderr, /REPORT_ALL_FINDINGS_FALSE_POSITIVE/);
});
