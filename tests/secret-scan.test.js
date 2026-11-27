// First real detector (round 86, Phase 5): secret-scan scans
// operator-supplied local text for well-known credential formats
// and reports one finding per distinct secret — never the full
// secret itself. No network, no scanner, no target, no liveness
// check: every finding is confidence `potential`.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  secretScanDetector,
  PATTERNS,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  redactMatch,
  findingIdFor,
} = require('../src/detection/secret-scan');
const { getDetector, runDetector } = require('../src/detection/detector');
const { validateFinding, dedupeFindings, evidenceChecklistForClass } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

// Test secrets are syntactically valid formats only; none of them
// is a live credential (random filler after the fixed prefix).
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GITHUB_TOKEN = `ghp_${'a'.repeat(36)}`;
const GITHUB_FINE_TOKEN = `github_pat_${'b'.repeat(82)}`;
const SLACK_TOKEN = 'xoxb-123456789012-ABCDEFGHIJ';
const PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----';

function scan(content, defaults = DEFAULTS, extra = {}) {
  return secretScanDetector({ content, ...extra }, defaults);
}

function assertNoFullSecret(finding, secret) {
  const serialized = JSON.stringify(finding);
  assert.equal(serialized.includes(secret), false, `finding leaks the full secret: ${secret}`);
}

test('secret-scan: an AWS access key ID yields one high-severity information-disclosure finding', () => {
  const result = scan(`config line\nkey=${AWS_KEY}\nend`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'information disclosure');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.confidence, 'potential');
  assert.equal(finding.discovery_tool, 'secret-scan');
  assert.equal(finding.cwe_id, 'CWE-200');
  assert.equal(finding.evidence[0].pattern, 'aws-access-key-id');
  assert.equal(finding.evidence[0].line, 2);
  assert.equal(finding.proof_of_concept, 'Matched aws-access-key-id at line 2: AKIA****MPLE');
  assertNoFullSecret(finding, AWS_KEY);
  assert.match(finding.description, /line 2/);
});

test('secret-scan: each pattern family is detected with its own pattern id', () => {
  const cases = [
    [GITHUB_TOKEN, 'github-classic-token'],
    [GITHUB_FINE_TOKEN, 'github-fine-grained-token'],
    [SLACK_TOKEN, 'slack-token'],
    [PEM_HEADER, 'private-key-pem'],
  ];
  for (const [secret, patternId] of cases) {
    const result = scan(`prefix ${secret} suffix`);
    assert.equal(result.findings.length, 1, patternId);
    assert.equal(result.findings[0].evidence[0].pattern, patternId);
    // The PEM header is not secret material, so it is carried
    // verbatim by design (asserted below); every other pattern
    // must never leak the full secret.
    if (patternId !== 'private-key-pem') {
      assertNoFullSecret(result.findings[0], secret);
    }
  }
  // The PEM header is not secret material, so it is carried verbatim.
  const pem = scan(PEM_HEADER);
  assert.equal(pem.findings[0].proof_of_concept, `Matched private-key-pem at line 1: ${PEM_HEADER}`);
});

test('secret-scan: line numbers are 1-based and the source label is carried into description and evidence', () => {
  const content = ['first line', 'second line', `token ${GITHUB_TOKEN}`, 'last line'].join('\n');
  const result = scan(content, DEFAULTS, { source: 'lab-notes.txt' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 3);
  assert.equal(result.findings[0].evidence[0].source, 'lab-notes.txt');
  assert.match(result.findings[0].description, /source "lab-notes.txt", line 3/);
});

test('secret-scan: the same secret twice is one finding; two distinct secrets are two findings', () => {
  const repeated = scan(`${AWS_KEY}\n${AWS_KEY}\n${AWS_KEY}`);
  assert.equal(repeated.findings.length, 1, 'same value deduped within a record');
  const otherKey = 'AKIAZZZZZZZZZZZZZZZZ';
  const distinct = scan(`${AWS_KEY}\n${otherKey}`);
  assert.equal(distinct.findings.length, 2, 'distinct values are distinct findings');
  assert.notEqual(distinct.findings[0].finding_id, distinct.findings[1].finding_id);
});

test('secret-scan: finding_id is deterministic per secret and stable across runs', () => {
  const first = scan(AWS_KEY);
  const second = scan(`other text ${AWS_KEY} here`);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.equal(first.findings[0].finding_id, findingIdFor('aws-access-key-id', AWS_KEY));
  assert.match(first.findings[0].finding_id, /^secret-scan-[0-9a-f]{16}$/);
});

test('secret-scan: a record without usable content is skipped, never thrown; a non-object input throws', () => {
  for (const bad of [{}, { content: '' }, { content: '   ' }, { content: 42 }]) {
    const result = secretScanDetector(bad, DEFAULTS);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 1);
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /content/);
  }
  assert.throws(() => secretScanDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => secretScanDetector('not an object', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => secretScanDetector([{}], DEFAULTS), /DETECTOR_INVALID_INPUT/);
});

test('secret-scan: a record missing its ids is skipped without defaults and filled from defaults', () => {
  const noDefaults = secretScanDetector({ content: AWS_KEY }, {});
  assert.equal(noDefaults.findings.length, 0);
  assert.equal(noDefaults.skipped, 1);
  assert.match(noDefaults.errors[0], /session_id|target_id|asset_id/);
  const withDefaults = secretScanDetector({ content: AWS_KEY }, DEFAULTS);
  assert.equal(withDefaults.findings.length, 1);
  assert.equal(withDefaults.findings[0].session_id, 'sess-1');
  assert.equal(withDefaults.findings[0].target_id, 'tgt-1');
  assert.equal(withDefaults.findings[0].asset_id, 'ast-1');
  const perRecord = secretScanDetector(
    { content: AWS_KEY, session_id: 's-9', target_id: 't-9', asset_id: 'a-9' },
    DEFAULTS,
  );
  assert.equal(perRecord.findings[0].session_id, 's-9', 'record ids win over defaults');
});

test('secret-scan: oversized content is skipped, not scanned', () => {
  const big = secretScanDetector({ content: `x${' '.repeat(MAX_CONTENT_CHARS)}` }, DEFAULTS);
  assert.equal(big.findings.length, 0);
  assert.equal(big.skipped, 1);
  assert.match(big.errors[0], /exceeds the 1000000 character limit/);
});

test('secret-scan: the per-record cap truncates visibly, never silently', () => {
  const keys = [];
  for (let index = 0; index < MAX_FINDINGS_PER_RECORD + 5; index += 1) {
    // Distinct 16-char suffixes keep every key a distinct value.
    keys.push(`AKIA${String(index).padStart(16, '0')}`);
  }
  const result = scan(keys.join('\n'));
  assert.equal(result.findings.length, MAX_FINDINGS_PER_RECORD);
  assert.equal(result.skipped, 0);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /5 additional matches truncated/);
  assert.match(result.errors[0], /first 100 reported/);
});

test('secret-scan: batch records follow the stub convention — batch tool is authoritative, bad results skipped', () => {
  const batch = {
    tool: 'lab-capture',
    results: [
      { content: AWS_KEY },
      { content: '' },
      { content: GITHUB_TOKEN },
    ],
  };
  const result = secretScanDetector(batch, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.findings[0].discovery_tool, 'lab-capture');
  assert.equal(result.findings[1].discovery_tool, 'lab-capture');
  assert.throws(
    () => secretScanDetector({ tool: '  ', results: [{ content: AWS_KEY }] }, DEFAULTS),
    /DETECTOR_INVALID_INPUT: batch tool must be a non-empty string/,
  );
});

test('secret-scan: getDetector resolves the built-in name and runDetector validates its envelope', () => {
  const resolved = getDetector('secret-scan');
  assert.equal(resolved.source, 'secret-scan');
  assert.equal(typeof resolved.detector, 'function');
  const result = runDetector(resolved.detector, { content: AWS_KEY }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal('error' in result, false);
});

test('secret-scan: findings validate as needs_evidence and carry the information-disclosure checklist', () => {
  const result = scan(`leaked: ${AWS_KEY}`);
  const finding = result.findings[0];
  const verdict = validateFinding(finding);
  assert.equal(verdict.verdict, 'needs_evidence', 'no response_log yet — the operator must add the distribution evidence');
  const checklist = evidenceChecklistForClass(finding);
  assert.equal(checklist.classId, 'information disclosure');
  assert.equal(checklist.items.find((item) => item.item === 'response_log').present, false);
  assert.equal(checklist.items.find((item) => item.item === 'proof_of_concept').present, true);
  const deduped = dedupeFindings([finding, finding]);
  assert.equal(deduped.groups.length, 1, 'the same secret dedupes to one finding');
  assert.equal(deduped.duplicates, 1);
});

test('secret-scan: detect -> validate -> report end to end, JSON carries the evidence checklist', () => {
  const result = runDetector(secretScanDetector, { content: `a\n${SLACK_TOKEN}\n${AWS_KEY}` }, DEFAULTS);
  assert.equal(result.findings.length, 2);
  const json = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
    format: 'json',
  });
  const report = JSON.parse(json);
  assert.equal(report.findings.length, 2);
  for (const finding of report.findings) {
    assert.equal(finding.evidence_checklist.classId, 'information disclosure');
    assertNoFullSecret(finding, SLACK_TOKEN);
    assertNoFullSecret(finding, AWS_KEY);
  }
  const markdown = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
  });
  assert.match(markdown, /information disclosure/i);
  assert.equal(markdown.includes(SLACK_TOKEN), false, 'markdown never carries the full secret');
});

test('secret-scan: redactMatch keeps first 4 and last 4, masks the middle', () => {
  assert.equal(redactMatch('aws-access-key-id', AWS_KEY), 'AKIA****MPLE');
  assert.equal(redactMatch('github-classic-token', GITHUB_TOKEN), 'ghp_****aaaa');
  assert.equal(redactMatch('private-key-pem', PEM_HEADER), PEM_HEADER);
});

test('CLI detect with secret-scan over a local record: JSON output, detector named, no full secret', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-secret-scan-cli-');
  const inputPath = path.join(directory, 'record.json');
  fs.writeFileSync(inputPath, JSON.stringify({ content: `notes\n${AWS_KEY}\n`, source: 'lab.txt' }), 'utf8');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'secret-scan', '--input', inputPath,
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1',
  ]);
  const output = JSON.parse(stdout);
  assert.equal(output.detector, 'secret-scan');
  assert.equal(output.findings.length, 1);
  assert.equal(output.skipped, 0);
  assert.equal('error' in output, false);
  assert.equal(output.findings[0].evidence[0].source, 'lab.txt');
  assert.equal(JSON.stringify(output).includes(AWS_KEY), false, 'CLI output never carries the full secret');
});

test('secret-scan: patterns are the strict fixed formats — lookalikes do not match', () => {
  const lookalikes = [
    'AKIAIOSFODNN7EXAMPL', // 19 chars, one short
    'akiaIOSFODNN7EXAMPLE', // lowercase prefix
    'ghp_short', // far too short for a token
    'xox-1234567890', // xox- without a valid scope letter
    '-----BEGIN CERTIFICATE-----', // not a private key header
  ];
  for (const lookalike of lookalikes) {
    const result = scan(lookalike);
    assert.equal(result.findings.length, 0, lookalike);
  }
  assert.equal(PATTERNS.length, 5, 'the documented pattern set');
});
