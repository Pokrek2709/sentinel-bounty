// F6 policy enforcement (round 96): the round-90 decisions
// were constants and a library pass, but no operator path
// applied the semantic dedup — `sentinel report` rendered
// duplicate findings, and a report with two identical findings
// failed its own `report validate` with
// REPORT_VALIDATE_DUPLICATE_FINDING_ID. These tests pin the
// round-96 wiring: `enforceReportPolicies` (false-positive
// exclusion first, then conservative semantic dedup, never
// across rule verdicts) is the single enforcement entry point
// for report generation from raw findings, `sentinel policy`
// names the active version, and the detect -> report chain
// enforces the policies end to end, including the round-95
// AST detector (`tainted-deserialize`).
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const {
  POLICY_VERSION,
  getPolicySummary,
  enforceReportPolicies,
} = require('../src/analysis/policies');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const CLASS_VERIFIER = path.join(__dirname, 'fixtures', 'ai-verifier-class.js');

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

test('the policy version is 1.0.0 and the summary names the five decisions', () => {
  assert.equal(POLICY_VERSION, '1.0.0');
  assert.deepEqual(getPolicySummary(), {
    version: '1.0.0',
    decisions: {
      semanticDedupMode: 'conservative',
      falsePositiveReporting: 'exclude-from-reports',
      aiVerdictOverride: false,
      detectionAutoRun: false,
      detectorAsync: false,
    },
  });
});

test('enforceReportPolicies merges identical findings at report time', () => {
  const a = clone(CRIT);
  const b = clone(CRIT);
  const { kept, excluded, duplicates } = enforceReportPolicies([a, b]);
  assert.equal(kept.length, 1);
  assert.equal(excluded.length, 0);
  assert.equal(duplicates, 1);
  // merged_from is an id SET: the two members share one id.
  assert.deepEqual(kept[0].merged_from, ['FND-CRIT-001']);
  assert.equal(kept[0].finding_id, 'FND-CRIT-001');
});

test('enforceReportPolicies excludes first: a valid finding never absorbs a false_positive twin', () => {
  // The pair WOULD merge if dedup ran first (same type, asset,
  // vector, severity, shared evidence — the rule does not look
  // at confidence), so the order is the only thing protecting
  // the valid finding from absorbing the FP triage.
  const valid = clone(CRIT);
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const { kept, excluded, duplicates } = enforceReportPolicies([valid, fp]);
  assert.deepEqual(kept.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.equal(kept[0].confidence, 'confirmed');
  assert.equal(excluded.length, 1);
  assert.equal(excluded[0], fp);
  assert.equal(duplicates, 0);
});

test('enforceReportPolicies never merges across rule verdicts, even with the opt-in flag', () => {
  const valid = clone(CRIT);
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const { kept, excluded, duplicates } = enforceReportPolicies([valid, fp], { includeFalsePositives: true });
  assert.equal(kept.length, 2);
  assert.equal(excluded.length, 0);
  assert.equal(duplicates, 0);
  assert.deepEqual(kept.map((f) => f.confidence), ['confirmed', 'false_positive']);
});

test('enforceReportPolicies merges identical false_positive findings among themselves with the flag', () => {
  const a = clone(CRIT);
  a.confidence = 'false_positive';
  const b = clone(CRIT);
  b.confidence = 'false_positive';
  const { kept, excluded, duplicates } = enforceReportPolicies([a, b], { includeFalsePositives: true });
  assert.equal(kept.length, 1);
  assert.equal(kept[0].confidence, 'false_positive');
  assert.equal(excluded.length, 0);
  assert.equal(duplicates, 1);
});

test('enforceReportPolicies passes strict-check failures through untouched', () => {
  const broken = clone(CRIT);
  broken.severity = 'low'; // CRIT scores 9.8: band mismatch, strict check fails
  const { kept, excluded, duplicates } = enforceReportPolicies([broken, clone(CRIT)]);
  assert.equal(kept.length, 2);
  assert.equal(excluded.length, 0);
  assert.equal(duplicates, 0);
  assert.equal(kept[0], broken);
  // ... and the generator still throws on it, as today.
  assert.throws(() => generateReport(kept, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
});

test('enforceReportPolicies keeps input order for findings that do not merge', () => {
  const { kept, duplicates } = enforceReportPolicies([clone(MED), clone(CRIT)]);
  assert.deepEqual(kept.map((f) => f.finding_id), ['FND-MED-001', 'FND-CRIT-001']);
  assert.equal(duplicates, 0);
});

test('enforceReportPolicies handles an empty array', () => {
  assert.deepEqual(enforceReportPolicies([]), { kept: [], excluded: [], duplicates: 0 });
});

test('structured (AST-shape) evidence merges on identical entries and never on empty ones', () => {
  const astEntry = {
    type: 'ast-call', sink: 'yaml.load', kind: 'tainted-arg',
    line: 1, column: 28, call: 'yaml.load',
    taint: { source: "parameter 'd' of function 'parse'", chain: ["parameter 'd' of function 'parse'"] },
  };
  // A well-formed finding (strict check must pass for a rule
  // verdict; a malformed finding passes through dedup untouched).
  const base = clone(CRIT);
  base.vulnerability_type = 'insecure deserialization';
  base.evidence = [astEntry];
  const twin = clone(base);
  assert.equal(enforceReportPolicies([clone(base), twin]).duplicates, 1);
  const moved = clone(base);
  moved.evidence = [{ ...astEntry, line: 5 }];
  assert.equal(enforceReportPolicies([clone(base), moved]).duplicates, 0);
  const empty = clone(base);
  empty.evidence = [{}];
  const emptyTwin = clone(empty);
  assert.equal(enforceReportPolicies([empty, emptyTwin]).duplicates, 0);
});

test('CLI: duplicate findings merge at report generation, and the produced report validates', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-dedup-cli-');
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([clone(CRIT), clone(CRIT)]));
  const outPath = path.join(dir, 'report.json');
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT, '--out', outPath,
  ]);
  assert.match(stdout, /Report written to/);
  assert.equal(stderr, 'Merged 1 duplicate finding (policy F6 v1.0.0, conservative semantic dedup).\n');
  const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  assert.equal(parsed.findings.length, 1);
  assert.deepEqual(parsed.findings[0].merged_from, ['FND-CRIT-001']);
  const validated = await execFileAsync(process.execPath, [CLI, 'report', 'validate', outPath]);
  assert.match(validated.stdout, /Report Validation — VALID/);
});

test('CLI: all-false_positive findings with duplicates still fail closed', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-dup-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([fp, clone(fp)]));
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--findings', inPath, '--format', 'json',
      '--program', PROGRAM, '--generated-at', GENERATED_AT,
    ]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_ALL_FINDINGS_FALSE_POSITIVE/);
      assert.doesNotMatch(error.stderr, /Merged/);
      return true;
    },
  );
});

test('CLI: --include-false-positives merges identical FP findings and says so', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-dedup-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([fp, clone(fp)]));
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
    '--include-false-positives',
  ]);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].confidence, 'false_positive');
  assert.equal(stderr, 'Merged 1 duplicate finding (policy F6 v1.0.0, conservative semantic dedup).\n');
});

test('CLI: a valid finding and its false_positive twin do not merge', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-fp-nomerge-');
  const fp = clone(CRIT);
  fp.confidence = 'false_positive';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([clone(CRIT), fp]));
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
  ]);
  const parsed = JSON.parse(stdout);
  assert.deepEqual(parsed.findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.equal(stderr, 'Excluded 1 false_positive finding from the report (policy F6 v1.0.0; use --include-false-positives to keep them).\n');
});

test('CLI: sentinel policy prints the version and the five decisions', async () => {
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'policy']);
  assert.equal(stderr, '');
  assert.match(stdout, /Sentinel policy F6 v1\.0\.0/);
  assert.match(stdout, /semantic dedup: conservative/);
  assert.match(stdout, /false positives: exclude-from-reports/);
  assert.match(stdout, /AI verdict: advisory only/);
  assert.match(stdout, /detection auto-run: no/);
  assert.match(stdout, /detectors: synchronous only/);
  const json = await execFileAsync(process.execPath, [CLI, 'policy', '--json']);
  assert.deepEqual(JSON.parse(json.stdout), getPolicySummary());
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'policy', '--bogus']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /Unknown option: --bogus/);
      return true;
    },
  );
});

test('CLI end to end: detect stays raw, report enforces the policies (tainted-deserialize)', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-ast-e2e-');
  const record = {
    content: 'function parse(d) { return yaml.load(d); }',
    session_id: 's1', target_id: 't1', asset_id: 'a1',
  };
  const batchPath = path.join(dir, 'batch.json');
  fs.writeFileSync(batchPath, JSON.stringify({ tool: 'lab', results: [record, clone(record)] }));
  const detectedPath = path.join(dir, 'detected.json');
  await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'tainted-deserialize',
    '--input', batchPath, '--out', detectedPath,
  ]);
  const detected = JSON.parse(fs.readFileSync(detectedPath, 'utf8'));
  // detect is a finding source: the two identical records yield
  // two findings with the same deterministic id, unmerged.
  assert.equal(detected.findings.length, 2);
  assert.equal(detected.findings[0].finding_id, detected.findings[1].finding_id);
  const findingsPath = path.join(dir, 'findings.json');
  fs.writeFileSync(findingsPath, JSON.stringify(detected.findings));
  const outPath = path.join(dir, 'report.json');
  const { stderr } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', findingsPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT, '--out', outPath,
  ]);
  assert.equal(stderr, 'Merged 1 duplicate finding (policy F6 v1.0.0, conservative semantic dedup).\n');
  const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  assert.equal(parsed.findings.length, 1);
  assert.deepEqual(parsed.findings[0].merged_from, [detected.findings[0].finding_id]);
  const validated = await execFileAsync(process.execPath, [CLI, 'report', 'validate', outPath]);
  assert.match(validated.stdout, /Report Validation — VALID/);
});

test('CLI: an AI verdict that disagrees never governs exclusion', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-f6-ai-cli-');
  // Rule-valid finding, AI says false_positive (fixture verifier
  // rejects the CSRF class): the finding is KEPT, with the
  // disagreeing AI verdict recorded as advisory.
  const csrf = clone(CRIT);
  csrf.vulnerability_type = 'Cross-Site Request Forgery';
  const inPath = path.join(dir, 'findings.json');
  fs.writeFileSync(inPath, JSON.stringify([csrf]));
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
    '--verifier', CLASS_VERIFIER,
  ]);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].ai_verdict.verdict, 'false_positive');
  // Rule-false_positive finding, AI says valid (fixture verifier
  // confirms the XSS class): still EXCLUDED — the rule governs.
  const fpXss = clone(CRIT);
  fpXss.confidence = 'false_positive';
  fpXss.vulnerability_type = 'Cross-Site Scripting';
  const inPath2 = path.join(dir, 'findings2.json');
  fs.writeFileSync(inPath2, JSON.stringify([clone(CRIT), fpXss]));
  const kept = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', inPath2, '--format', 'json',
    '--program', PROGRAM, '--generated-at', GENERATED_AT,
    '--verifier', CLASS_VERIFIER,
  ]);
  const parsed2 = JSON.parse(kept.stdout);
  assert.deepEqual(parsed2.findings.map((f) => f.finding_id), ['FND-CRIT-001']);
  assert.match(kept.stderr, /Excluded 1 false_positive finding/);
});
