// Fifth real detector (round 90, Phase 5): insecure-transport
// scans operator-supplied local text for insecure-transport
// call sites (cleartext http:// URLs with a non-loopback host,
// and TLS verification switched off) and reports one finding
// per distinct call site — never executing the code it scans.
// A finding carries only the matched text, and for a URL only
// scheme + host (never path, query, or userinfo). No network,
// no scanner, no target: every finding is confidence
// `potential`.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  insecureTransportDetector,
  PATTERNS,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
  isLoopbackHost,
} = require('../src/detection/insecure-transport');
const { getDetector, runDetector } = require('../src/detection/detector');
const { validateFinding, dedupeFindings, evidenceChecklistForClass } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

// Test code excerpts only; no snippet here is executed by the
// detector or the tests — the detector matches text.
const HTTP_URL = 'fetch("http://api.example.com/v1/data?key=abc")';
const TLS_OFF = 'rejectUnauthorized: false';

function scan(content, defaults = DEFAULTS, extra = {}) {
  return insecureTransportDetector({ content, ...extra }, defaults);
}

test('insecure-transport: a cleartext URL yields one medium-severity cleartext-transmission finding, host only', () => {
  const result = scan(`const a = 1\n${HTTP_URL}\nend`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'cleartext transmission');
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.confidence, 'potential');
  assert.equal(finding.discovery_tool, 'insecure-transport');
  assert.equal(finding.cwe_id, 'CWE-319');
  assert.equal(finding.evidence[0].pattern, 'cleartext-http');
  assert.equal(finding.evidence[0].line, 2);
  assert.equal(finding.evidence[0].column, 8);
  // Only scheme + host: the path and query never reach the finding.
  assert.equal(finding.evidence[0].match, 'http://api.example.com');
  assert.equal(finding.proof_of_concept, 'Matched cleartext-http at line 2, column 8: http://api.example.com');
  assert.match(finding.description, /line 2, column 8/);
  // Cleartext transmission has no dedicated evidence class, so
  // the validator resolves it to the generic checklist — whose
  // required items (proof_of_concept, evidence,
  // steps_to_reproduce) the finding already carries.
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  assert.equal(validateFinding(finding).verdict, 'valid');
});

test('insecure-transport: each pattern family is detected with its own pattern id, class, and severity', () => {
  const cases = [
    ['fetch("http://api.example.com:8080/v1")', 'cleartext-http', 'cleartext transmission', 'medium', 'CWE-319'],
    ['const u = "http://example.com./docs"', 'cleartext-http', 'cleartext transmission', 'medium', 'CWE-319'],
    ['const u = "http://[2001:db8::1]/api"', 'cleartext-http', 'cleartext transmission', 'medium', 'CWE-319'],
    ['rejectUnauthorized: false', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['rejectUnauthorized = false', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['requests.get(url, verify=False)', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['session.verify = False', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['ctx.check_hostname = False', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['ssl._create_unverified_context()', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
    ['ctx.verify_mode = CERT_NONE', 'tls-verify-disabled', 'improper certificate validation', 'high', 'CWE-295'],
  ];
  for (const [code, patternId, vulnType, severity, cwe] of cases) {
    const result = scan(`prefix ${code} suffix`);
    assert.equal(result.findings.length, 1, patternId);
    const finding = result.findings[0];
    assert.equal(finding.evidence[0].pattern, patternId);
    assert.equal(finding.vulnerability_type, vulnType);
    assert.equal(finding.severity, severity);
    assert.equal(finding.cwe_id, cwe);
  }
});

test('insecure-transport: a URL with userinfo never leaks credentials into the finding', () => {
  const result = scan('fetch("http://admin:s3cret@internal.example.com/api?token=abc123")');
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.evidence[0].match, 'http://internal.example.com');
  const serialized = JSON.stringify(finding);
  assert.ok(!serialized.includes('s3cret'), 'password must not appear in the finding');
  assert.ok(!serialized.includes('abc123'), 'query token must not appear in the finding');
  assert.ok(!serialized.includes('admin:'), 'username must not appear in the finding');
});

test('insecure-transport: loopback hosts never match', () => {
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('LOCALHOST'), true);
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('127.9.8.7'), true);
  assert.equal(isLoopbackHost('[::1]'), true);
  assert.equal(isLoopbackHost('::1'), true);
  assert.equal(isLoopbackHost('example.com'), false);
  assert.equal(isLoopbackHost('10.0.0.1'), false);
  for (const url of [
    'fetch("http://localhost:3000/api")',
    'fetch("http://127.0.0.1:8080/api")',
    'fetch("http://[::1]/api")',
    'const u = "http://localhost/docs"',
  ]) {
    assert.equal(scan(url).findings.length, 0, url);
  }
});

test('insecure-transport: line numbers are 1-based and the source label is carried into description and evidence', () => {
  const content = ['first line', 'second line', `run ${HTTP_URL}`, 'last line'].join('\n');
  const result = scan(content, DEFAULTS, { source: 'lab-code.js' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 3);
  assert.equal(result.findings[0].evidence[0].column, 12);
  assert.equal(result.findings[0].evidence[0].source, 'lab-code.js');
  assert.match(result.findings[0].description, /source "lab-code.js", line 3, column 12/);
});

test('insecure-transport: identity is per call site (pattern, line, column, match)', () => {
  const twoUrls = scan('http://a.example.com/x http://b.example.com/y');
  assert.equal(twoUrls.findings.length, 2, 'two URLs on one line are two findings');
  assert.equal(twoUrls.findings[0].evidence[0].column, 1);
  assert.notEqual(twoUrls.findings[0].finding_id, twoUrls.findings[1].finding_id);
  const twoLines = scan('http://a.example.com/x\nhttp://a.example.com/x');
  assert.equal(twoLines.findings.length, 2, 'same URL on two lines is two call sites');
  assert.notEqual(twoLines.findings[0].finding_id, twoLines.findings[1].finding_id);
  const mixed = scan('http://a.example.com/x; verify=False');
  assert.equal(mixed.findings.length, 2, 'different patterns on one line are distinct findings');
});

test('insecure-transport: finding ids are deterministic per call site', () => {
  const a = scan(HTTP_URL);
  const b = scan(HTTP_URL);
  assert.equal(a.findings[0].finding_id, b.findings[0].finding_id);
  assert.equal(
    a.findings[0].finding_id,
    findingIdFor('cleartext-http', 1, 8, 'http://api.example.com'),
  );
});

test('insecure-transport: skipped-record handling and oversized-content refusal', () => {
  assert.equal(scan('').skipped, 1);
  assert.equal(scan('').findings.length, 0);
  assert.equal(scan('   ').skipped, 1);
  assert.equal(scan('x'.repeat(MAX_CONTENT_CHARS + 1)).skipped, 1);
  assert.throws(() => insecureTransportDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => insecureTransportDetector('nope', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => insecureTransportDetector([], DEFAULTS), /DETECTOR_INVALID_INPUT/);
  const badBatch = insecureTransportDetector({ tool: 't', results: [{ content: HTTP_URL }, { nope: true }] }, DEFAULTS);
  assert.equal(badBatch.findings.length, 1);
  assert.equal(badBatch.skipped, 1);
});

test('insecure-transport: the per-record cap truncates visibly, never silently', () => {
  const lines = Array.from({ length: MAX_FINDINGS_PER_RECORD + 5 }, (_, i) => `http://host${i}.example.com/x`);
  const result = scan(lines.join('\n'));
  assert.equal(result.findings.length, MAX_FINDINGS_PER_RECORD);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /5 additional matches truncated/);
});

test('insecure-transport: batch convention forces the batch tool as discovery_tool', () => {
  const result = insecureTransportDetector({ tool: 'batch-tool', results: [{ content: HTTP_URL }] }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'batch-tool');
  const noTool = insecureTransportDetector({ results: [{ content: HTTP_URL }] }, DEFAULTS);
  assert.equal(noTool.findings[0].discovery_tool, 'insecure-transport');
});

test('insecure-transport: getDetector resolves the built-in name and runDetector validates the envelope', () => {
  const resolved = getDetector('insecure-transport');
  assert.equal(resolved.source, 'insecure-transport');
  const result = runDetector(resolved.detector, { content: TLS_OFF }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].pattern, 'tls-verify-disabled');
  assert.throws(() => getDetector('no-such-detector'), /DETECTOR_/);
});

test('insecure-transport: validate -> dedupe -> report end to end', () => {
  const result = scan(`${HTTP_URL}\n${TLS_OFF}`);
  assert.equal(result.findings.length, 2);
  for (const finding of result.findings) {
    assert.equal(validateFinding(finding).verdict, 'valid');
    assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  }
  const deduped = dedupeFindings(result.findings);
  assert.equal(deduped.groups.length, 2);
  const json = generateReport(result.findings, { programName: 'Lab', generatedAt: '2026-11-26T02:00:00.000Z', format: 'json' });
  const parsed = JSON.parse(json);
  assert.deepEqual(parsed.findings.map((f) => f.evidence_checklist.classId), ['generic', 'generic']);
  const markdown = generateReport(result.findings, { programName: 'Lab', generatedAt: '2026-11-26T02:00:00.000Z', format: 'markdown' });
  assert.match(markdown, /cleartext transmission/);
  assert.match(markdown, /improper certificate validation/);
});

test('insecure-transport: CLI over a local record, no credential leak', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-insecure-transport-');
  const record = {
    content: 'fetch("http://admin:s3cret@internal.example.com/api?token=abc123")\nverify=False',
    session_id: 'sess-1',
    target_id: 'tgt-1',
    asset_id: 'ast-1',
  };
  const inPath = path.join(dir, 'record.json');
  fs.writeFileSync(inPath, JSON.stringify(record));
  const { stdout, stderr } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'insecure-transport', '--input', inPath,
  ]);
  const envelope = JSON.parse(stdout);
  assert.equal(envelope.findings.length, 2);
  assert.equal(envelope.skipped, 0);
  assert.ok(!stdout.includes('s3cret'), 'detect stdout must not contain the password');
  assert.ok(!stdout.includes('abc123'), 'detect stdout must not contain the query token');
  assert.equal(stderr, '');
  const findingsPath = path.join(dir, 'findings.json');
  fs.writeFileSync(findingsPath, JSON.stringify(envelope.findings));
  const report = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', findingsPath, '--format', 'summary',
    '--program', 'Lab', '--generated-at', '2026-11-26T02:00:00.000Z',
  ]);
  assert.match(report.stdout, /Findings: 2 total/);
  assert.match(report.stdout, /high: 1/);
  assert.match(report.stdout, /medium: 1/);
  assert.ok(!report.stdout.includes('s3cret'), 'report must not contain the password');
});

test('insecure-transport: lookalikes that must NOT match', () => {
  const cases = [
    'fetch("https://api.example.com/v1")',
    'fetch("http://localhost:3000/api")',
    'fetch("http://127.0.0.1/api")',
    'const u = "http://"',
    'requests.get(url, verify=True)',
    'session.verify = True',
    'rejectUnauthorized: true',
    'ctx.check_hostname = True',
    'ctx.verify_mode = CERT_REQUIRED',
    'if (mode == CERT_NONE) { }',
    'const verify = getFlag()',
  ];
  for (const code of cases) {
    const result = scan(code);
    assert.equal(result.findings.length, 0, code);
  }
});
