// Fourth real detector (round 89, Phase 5): hardcoded-credential
// scans operator-supplied local text for credential-named
// variables assigned a quoted string literal (password, API key,
// secret/token — CWE-798) and reports one finding per distinct
// assignment site — never carrying the literal value itself
// (the finding shows `<name><operator> "****"`), never executing
// the code it scans. No network, no scanner, no target: every
// finding is confidence `potential`.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  hardcodedCredentialDetector,
  PATTERNS,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('../src/detection/hardcoded-credential');
const { getDetector, runDetector } = require('../src/detection/detector');
const { validateFinding, dedupeFindings, evidenceChecklistForClass } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

// Test code excerpts only; the literals below are obviously fake
// values ('hunter2', 'test-secret-123') and no snippet here is
// executed by the detector or the tests — the detector matches
// assignment text and masks the literal before building a finding.
const PASSWORD_ASSIGN = 'password = "hunter2"';
const API_KEY_ASSIGN = 'api_key = "test-key-123"';
const SECRET_ASSIGN = 'client_secret = "test-secret-123"';

function scan(content, defaults = DEFAULTS, extra = {}) {
  return hardcodedCredentialDetector({ content, ...extra }, defaults);
}

test('hardcoded-credential: a password assignment yields one high-severity finding with the literal masked', () => {
  const result = scan(`const a = 1\n${PASSWORD_ASSIGN}\nend`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'use of hard-coded credentials');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.confidence, 'potential');
  assert.equal(finding.discovery_tool, 'hardcoded-credential');
  assert.equal(finding.cwe_id, 'CWE-798');
  assert.equal(finding.evidence[0].pattern, 'hardcoded-password');
  assert.equal(finding.evidence[0].line, 2);
  assert.equal(finding.evidence[0].column, 1);
  assert.equal(finding.evidence[0].match, 'password = "****"');
  assert.equal(finding.proof_of_concept, 'Matched hardcoded-password at line 2, column 1: password = "****"');
  assert.match(finding.description, /line 2, column 1/);
  // The literal must appear nowhere in the finding — not in the
  // match, the proof of concept, the description, or any field.
  assert.equal(JSON.stringify(finding).includes('hunter2'), false, 'the secret value never leaks into a finding');
  // 'use of hard-coded credentials' has no dedicated evidence
  // class, so the validator resolves it to the generic
  // checklist — whose required items (proof_of_concept,
  // evidence, steps_to_reproduce) the finding already carries.
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  assert.equal(validateFinding(finding).verdict, 'valid');
});

test('hardcoded-credential: each pattern family is detected with its own pattern id, class, and severity', () => {
  const cases = [
    [API_KEY_ASSIGN, 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    [SECRET_ASSIGN, 'hardcoded-secret', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['apiKey = "test-key-123"', 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['API_KEY = "test-key-123"', 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['access_key = "test-key-123"', 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['secret_key = "test-secret-123"', 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['secretKey = "test-secret-123"', 'hardcoded-api-key', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['token = "test-token-123"', 'hardcoded-secret', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['accessToken = "test-token-123"', 'hardcoded-secret', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['auth_token = "test-token-123"', 'hardcoded-secret', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['passwd = "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['pwd = "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['PASSWORD = "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['user_password = "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['userPassword = "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['{"password": "hunter2"}', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
    ['password := "hunter2"', 'hardcoded-password', 'use of hard-coded credentials', 'high', 'CWE-798'],
  ];
  for (const [code, patternId, vulnType, severity, cwe] of cases) {
    const result = scan(`prefix ${code} suffix`);
    assert.equal(result.findings.length, 1, patternId);
    const finding = result.findings[0];
    assert.equal(finding.evidence[0].pattern, patternId);
    assert.equal(finding.vulnerability_type, vulnType);
    assert.equal(finding.severity, severity);
    assert.equal(finding.cwe_id, cwe);
    assert.equal(JSON.stringify(finding).includes('hunter2'), false, 'no literal leaks');
    assert.equal(JSON.stringify(finding).includes('test-key-123'), false, 'no literal leaks');
    assert.equal(JSON.stringify(finding).includes('test-secret-123'), false, 'no literal leaks');
    assert.equal(JSON.stringify(finding).includes('test-token-123'), false, 'no literal leaks');
  }
});

test('hardcoded-credential: line numbers are 1-based and the source label is carried into description and evidence', () => {
  const content = ['first line', 'second line', `run ${PASSWORD_ASSIGN}`, 'last line'].join('\n');
  const result = scan(content, DEFAULTS, { source: 'lab-code.py' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 3);
  assert.equal(result.findings[0].evidence[0].column, 5);
  assert.equal(result.findings[0].evidence[0].source, 'lab-code.py');
  assert.match(result.findings[0].description, /source "lab-code.py", line 3, column 5/);
});

test('hardcoded-credential: identity is per assignment site (pattern, line, column, masked match) — two assignments on one line are two findings', () => {
  const two = scan('password = "a"; password = "b"; password = "a"');
  assert.equal(two.findings.length, 3, 'three assignment sites at three columns, even with a repeated literal');
  assert.equal(two.findings[0].evidence[0].column, 1);
  assert.equal(two.findings[1].evidence[0].column, 17);
  assert.equal(two.findings[2].evidence[0].column, 33);
  // The masked match is the same for all three, but the column
  // differs, so each site is its own finding.
  assert.notEqual(two.findings[0].finding_id, two.findings[1].finding_id, 'different column is a different finding');
  assert.notEqual(two.findings[0].finding_id, two.findings[2].finding_id, 'different column is a different finding even with the same literal');
  const twoLines = scan('password = "a"\npassword = "a"');
  assert.equal(twoLines.findings.length, 2, 'same assignment text on two lines is two sites');
  assert.notEqual(twoLines.findings[0].finding_id, twoLines.findings[1].finding_id);
  const mixed = scan('password = "a"; api_key = "b"');
  assert.equal(mixed.findings.length, 2, 'different patterns on one line are distinct findings');
});

test('hardcoded-credential: finding_id is deterministic per assignment site and stable across runs', () => {
  const first = scan(PASSWORD_ASSIGN);
  const second = scan(PASSWORD_ASSIGN);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.equal(first.findings[0].finding_id, findingIdFor('hardcoded-password', 1, 1, 'password = "****"'));
  assert.match(first.findings[0].finding_id, /^hardcoded-credential-[0-9a-f]{16}$/);
  const otherLine = scan(`line one\n${PASSWORD_ASSIGN}`);
  assert.notEqual(first.findings[0].finding_id, otherLine.findings[0].finding_id, 'line is part of the identity');
  const otherColumn = scan(`  ${PASSWORD_ASSIGN}`);
  assert.notEqual(first.findings[0].finding_id, otherColumn.findings[0].finding_id, 'column is part of the identity');
  // The id hashes the MASKED match: two different literals at
  // the same site produce the same id, by design — the secret
  // value is not part of the identity.
  const otherLiteral = scan('password = "different-value"');
  assert.equal(first.findings[0].finding_id, otherLiteral.findings[0].finding_id, 'the literal value is not part of the identity');
});

test('hardcoded-credential: a record without usable content is skipped, never thrown; a non-object input throws', () => {
  for (const bad of [{}, { content: '' }, { content: '   ' }, { content: 42 }]) {
    const result = hardcodedCredentialDetector(bad, DEFAULTS);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 1);
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /content/);
  }
  assert.throws(() => hardcodedCredentialDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => hardcodedCredentialDetector('not an object', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => hardcodedCredentialDetector([{}], DEFAULTS), /DETECTOR_INVALID_INPUT/);
});

test('hardcoded-credential: a record missing its ids is skipped without defaults and filled from defaults', () => {
  const noDefaults = hardcodedCredentialDetector({ content: PASSWORD_ASSIGN }, {});
  assert.equal(noDefaults.findings.length, 0);
  assert.equal(noDefaults.skipped, 1);
  assert.match(noDefaults.errors[0], /session_id|target_id|asset_id/);
  const withDefaults = hardcodedCredentialDetector({ content: PASSWORD_ASSIGN }, DEFAULTS);
  assert.equal(withDefaults.findings.length, 1);
  assert.equal(withDefaults.findings[0].session_id, 'sess-1');
  assert.equal(withDefaults.findings[0].target_id, 'tgt-1');
  assert.equal(withDefaults.findings[0].asset_id, 'ast-1');
  const perRecord = hardcodedCredentialDetector(
    { content: PASSWORD_ASSIGN, session_id: 's-9', target_id: 't-9', asset_id: 'a-9' },
    DEFAULTS,
  );
  assert.equal(perRecord.findings[0].session_id, 's-9', 'record ids win over defaults');
});

test('hardcoded-credential: oversized content is skipped, not scanned', () => {
  const big = hardcodedCredentialDetector({ content: `x${' '.repeat(MAX_CONTENT_CHARS)}` }, DEFAULTS);
  assert.equal(big.findings.length, 0);
  assert.equal(big.skipped, 1);
  assert.match(big.errors[0], /exceeds the 1000000 character limit/);
});

test('hardcoded-credential: the per-record cap truncates visibly, never silently', () => {
  const lines = [];
  for (let index = 0; index < MAX_FINDINGS_PER_RECORD + 5; index += 1) {
    // Same assignment text on a new line is a new site, so 105
    // lines give 105 findings before the cap.
    lines.push(`password = "value${index}"`);
  }
  const result = scan(lines.join('\n'));
  assert.equal(result.findings.length, MAX_FINDINGS_PER_RECORD);
  assert.equal(result.skipped, 0);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /5 additional matches truncated/);
  assert.match(result.errors[0], /first 100 reported/);
});

test('hardcoded-credential: batch records follow the stub convention — batch tool is authoritative, bad results skipped', () => {
  const batch = {
    tool: 'lab-capture',
    results: [
      { content: PASSWORD_ASSIGN },
      { content: '' },
      { content: API_KEY_ASSIGN },
    ],
  };
  const result = hardcodedCredentialDetector(batch, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.findings[0].discovery_tool, 'lab-capture');
  assert.equal(result.findings[1].discovery_tool, 'lab-capture');
  assert.throws(
    () => hardcodedCredentialDetector({ tool: '  ', results: [{ content: PASSWORD_ASSIGN }] }, DEFAULTS),
    /DETECTOR_INVALID_INPUT: batch tool must be a non-empty string/,
  );
});

test('hardcoded-credential: getDetector resolves the built-in name and runDetector validates its envelope', () => {
  const resolved = getDetector('hardcoded-credential');
  assert.equal(resolved.source, 'hardcoded-credential');
  assert.equal(typeof resolved.detector, 'function');
  const result = runDetector(resolved.detector, { content: PASSWORD_ASSIGN }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal('error' in result, false);
});

test('hardcoded-credential: findings validate as valid under the generic checklist and dedupe by assignment site', () => {
  const finding = scan(PASSWORD_ASSIGN).findings[0];
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  assert.equal(validateFinding(finding).verdict, 'valid', 'the generic checklist requires only poc, evidence, and steps — all carried');
  const apiKey = scan(API_KEY_ASSIGN).findings[0];
  assert.equal(validateFinding(apiKey).verdict, 'valid');
  assert.match(apiKey.description, /never carries a secret value/);
  const deduped = dedupeFindings([finding, finding]);
  assert.equal(deduped.groups.length, 1, 'the same assignment site dedupes to one finding');
  assert.equal(deduped.duplicates, 1);
});

test('hardcoded-credential: detect -> validate -> report end to end, JSON carries the generic checklist', () => {
  const result = runDetector(hardcodedCredentialDetector, { content: `a\n${PASSWORD_ASSIGN}\n${SECRET_ASSIGN}` }, DEFAULTS);
  assert.equal(result.findings.length, 2);
  const json = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-28T00:00:00+07:00',
    format: 'json',
  });
  const report = JSON.parse(json);
  assert.equal(report.findings.length, 2);
  const byPattern = {};
  for (const finding of report.findings) {
    byPattern[finding.evidence[0].pattern] = finding.evidence_checklist.classId;
  }
  assert.equal(byPattern['hardcoded-password'], 'generic');
  assert.equal(byPattern['hardcoded-secret'], 'generic');
  const markdown = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-28T00:00:00+07:00',
  });
  assert.match(markdown, /hard-coded credentials/i);
  // No literal survives into any rendered format.
  assert.equal(json.includes('hunter2'), false, 'no literal in the JSON report');
  assert.equal(markdown.includes('hunter2'), false, 'no literal in the Markdown report');
  assert.equal(json.includes('test-secret-123'), false, 'no literal in the JSON report');
});

test('CLI detect with hardcoded-credential over a local record: JSON output, detector named, literal masked, code never executed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-hardcoded-credential-cli-');
  const inputPath = path.join(directory, 'record.json');
  fs.writeFileSync(inputPath, JSON.stringify({ content: `notes\n${PASSWORD_ASSIGN}\n${API_KEY_ASSIGN}\n`, source: 'lab.py' }), 'utf8');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'hardcoded-credential', '--input', inputPath,
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1',
  ]);
  const output = JSON.parse(stdout);
  assert.equal(output.detector, 'hardcoded-credential');
  assert.equal(output.findings.length, 2);
  assert.equal(output.skipped, 0);
  assert.equal('error' in output, false);
  assert.equal(output.findings[0].evidence[0].source, 'lab.py');
  assert.equal(stdout.includes('hunter2'), false, 'the CLI output never carries the literal');
  assert.equal(stdout.includes('test-key-123'), false, 'the CLI output never carries the literal');
});

test('hardcoded-credential: patterns are strict assignment syntax — lookalikes do not match', () => {
  const lookalikes = [
    'password == "hunter2"', // comparison, not assignment
    'password === "hunter2"', // strict comparison
    'password != "hunter2"', // comparison
    'password = ""', // empty literal is not a credential
    'password = process.env.PASSWORD', // env read, not a literal
    'password = getPassword()', // function call, not a literal
    'password = 123', // number, not a string literal
    'password = null', // no literal
    'passwordHash = "abc"', // a hash, not the password itself
    'password_hash = "abc"', // a hash, not the password itself
    'password2 = "abc"', // suffixed variant — out of scope by design
    'password_confirmation = "abc"', // suffixed variant — out of scope by design
    'bypass = "strict"', // 'pass' alone is not a credential name (collides with bypass)
    'pass = "abc"', // bare 'pass' excluded — collides with 'bypass'
    'secretary = "x"', // 'secret' inside a longer word
    'secretKey = "abc"', // the one deliberate exception: secretKey IS a key name — it matches hardcoded-api-key, checked separately below
    'tokenize(data)', // 'token' inside a longer word
    'myToken = getToken()', // no literal assigned
    'api_keys = "abc"', // plural — not a single key name
    'password = `hunter2`', // backtick template literal — out of scope by design
    'password=abc123', // unquoted .env-style value — out of scope by design
  ];
  for (const lookalike of lookalikes) {
    const result = scan(lookalike);
    // The secretKey line is the one deliberate exception: it
    // matches hardcoded-api-key (secret_key/secretKey are key
    // names), so it is checked separately.
    if (lookalike.startsWith('secretKey =')) {
      assert.equal(result.findings.length, 1, lookalike);
      assert.equal(result.findings[0].evidence[0].pattern, 'hardcoded-api-key');
      continue;
    }
    assert.equal(result.findings.length, 0, lookalike);
  }
  assert.equal(PATTERNS.length, 3, 'the documented pattern set');
});
