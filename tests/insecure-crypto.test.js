// Third real detector (round 88, Phase 5): insecure-crypto scans
// operator-supplied local text for weak-cryptography call sites
// (MD5/SHA-1 hashes, ECB mode, DES/3DES/RC4 ciphers, Node's
// deprecated createCipher()/createDecipher(), Math.random() /
// random.random()) and reports one finding per distinct call
// site — never executing the code it scans. No network, no
// scanner, no target: every finding is confidence `potential`.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  insecureCryptoDetector,
  PATTERNS,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('../src/detection/insecure-crypto');
const { getDetector, runDetector } = require('../src/detection/detector');
const { validateFinding, dedupeFindings, evidenceChecklistForClass } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

// Test code excerpts only; no snippet here is executed by the
// detector or the tests — the detector matches call text.
const MD5_CALL = "hashlib.md5(data).hexdigest()";
const SHA1_CALL = 'crypto.createHash("sha1").update(data)';
const ECB_CALL = 'Cipher.getInstance("AES/ECB/PKCS5Padding")';
const DES_CALL = 'Cipher.getInstance("DES/CBC/PKCS5Padding")';
const DEPRECATED_CALL = "crypto.createCipher('aes-128-cbc', password)";
const RANDOM_CALL = 'const token = Math.random().toString(36)';

function scan(content, defaults = DEFAULTS, extra = {}) {
  return insecureCryptoDetector({ content, ...extra }, defaults);
}

test('insecure-crypto: an MD5 call yields one medium-severity cryptographic-failure finding', () => {
  const result = scan(`const a = 1\n${MD5_CALL}\nend`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'cryptographic failure');
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.confidence, 'potential');
  assert.equal(finding.discovery_tool, 'insecure-crypto');
  assert.equal(finding.cwe_id, 'CWE-327');
  assert.equal(finding.evidence[0].pattern, 'weak-hash-md5');
  assert.equal(finding.evidence[0].line, 2);
  assert.equal(finding.evidence[0].column, 1);
  assert.equal(finding.evidence[0].match, 'hashlib.md5(');
  assert.equal(finding.proof_of_concept, 'Matched weak-hash-md5 at line 2, column 1: hashlib.md5(');
  assert.match(finding.description, /line 2, column 1/);
  // Cryptographic failure has no dedicated evidence class, so
  // the validator resolves it to the generic checklist — whose
  // required items (proof_of_concept, evidence,
  // steps_to_reproduce) the finding already carries.
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  assert.equal(validateFinding(finding).verdict, 'valid');
});

test('insecure-crypto: each pattern family is detected with its own pattern id, class, and severity', () => {
  const cases = [
    [SHA1_CALL, 'weak-hash-sha1', 'cryptographic failure', 'medium', 'CWE-327'],
    [ECB_CALL, 'ecb-mode', 'cryptographic failure', 'medium', 'CWE-327'],
    [DES_CALL, 'weak-cipher-des-rc4', 'cryptographic failure', 'high', 'CWE-327'],
    ["crypto.createCipheriv('des-ede3-cbc', key, iv)", 'weak-cipher-des-rc4', 'cryptographic failure', 'high', 'CWE-327'],
    ["crypto.createCipheriv('rc4', key, null)", 'weak-cipher-des-rc4', 'cryptographic failure', 'high', 'CWE-327'],
    ['ARC4.new(key)', 'weak-cipher-des-rc4', 'cryptographic failure', 'high', 'CWE-327'],
    [DEPRECATED_CALL, 'deprecated-cipher', 'cryptographic failure', 'medium', 'CWE-327'],
    ["crypto.createDecipher('aes-128-cbc', password)", 'deprecated-cipher', 'cryptographic failure', 'medium', 'CWE-327'],
    [RANDOM_CALL, 'insecure-random', 'cryptographic failure', 'medium', 'CWE-338'],
    ['token = random.random()', 'insecure-random', 'cryptographic failure', 'medium', 'CWE-338'],
    ["hashlib.new('md5', data)", 'weak-hash-md5', 'cryptographic failure', 'medium', 'CWE-327'],
    ['MessageDigest.getInstance("SHA-1")', 'weak-hash-sha1', 'cryptographic failure', 'medium', 'CWE-327'],
    ["crypto.createCipheriv('aes-128-ecb', key, iv)", 'ecb-mode', 'cryptographic failure', 'medium', 'CWE-327'],
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

test('insecure-crypto: line numbers are 1-based and the source label is carried into description and evidence', () => {
  const content = ['first line', 'second line', `run ${MD5_CALL}`, 'last line'].join('\n');
  const result = scan(content, DEFAULTS, { source: 'lab-code.py' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 3);
  assert.equal(result.findings[0].evidence[0].column, 5);
  assert.equal(result.findings[0].evidence[0].source, 'lab-code.py');
  assert.match(result.findings[0].description, /source "lab-code.py", line 3, column 5/);
});

test('insecure-crypto: identity is per call site (pattern, line, column, match) — two md5() calls on one line are two findings', () => {
  const twoCalls = scan(`md5(a); md5(b); md5(a)`);
  assert.equal(twoCalls.findings.length, 3, 'three call sites at three columns, even with repeated text');
  assert.equal(twoCalls.findings[0].evidence[0].column, 1);
  assert.equal(twoCalls.findings[1].evidence[0].column, 9);
  assert.equal(twoCalls.findings[2].evidence[0].column, 17);
  const twoLines = scan(`md5(a)\nmd5(a)`);
  assert.equal(twoLines.findings.length, 2, 'same call text on two lines is two code sites');
  assert.notEqual(twoLines.findings[0].finding_id, twoLines.findings[1].finding_id);
  const mixed = scan(`md5(a); sha1(b)`);
  assert.equal(mixed.findings.length, 2, 'different patterns on one line are distinct findings');
});

test('insecure-crypto: DES in ECB mode is two distinct weaknesses — one finding per pattern', () => {
  const result = scan('Cipher.getInstance("DES/ECB/PKCS5Padding")');
  assert.equal(result.findings.length, 2, 'a weak cipher in a weak mode is two findings, not one');
  const patterns = result.findings.map((finding) => finding.evidence[0].pattern).sort();
  assert.deepEqual(patterns, ['ecb-mode', 'weak-cipher-des-rc4']);
});

test('insecure-crypto: finding_id is deterministic per call site and stable across runs', () => {
  const first = scan(MD5_CALL);
  const second = scan(MD5_CALL);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.equal(first.findings[0].finding_id, findingIdFor('weak-hash-md5', 1, 1, 'hashlib.md5('));
  assert.match(first.findings[0].finding_id, /^insecure-crypto-[0-9a-f]{16}$/);
  const otherLine = scan(`line one\n${MD5_CALL}`);
  assert.notEqual(first.findings[0].finding_id, otherLine.findings[0].finding_id, 'line is part of the identity');
  const otherColumn = scan(`  ${MD5_CALL}`);
  assert.notEqual(first.findings[0].finding_id, otherColumn.findings[0].finding_id, 'column is part of the identity');
});

test('insecure-crypto: a record without usable content is skipped, never thrown; a non-object input throws', () => {
  for (const bad of [{}, { content: '' }, { content: '   ' }, { content: 42 }]) {
    const result = insecureCryptoDetector(bad, DEFAULTS);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 1);
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /content/);
  }
  assert.throws(() => insecureCryptoDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => insecureCryptoDetector('not an object', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => insecureCryptoDetector([{}], DEFAULTS), /DETECTOR_INVALID_INPUT/);
});

test('insecure-crypto: a record missing its ids is skipped without defaults and filled from defaults', () => {
  const noDefaults = insecureCryptoDetector({ content: MD5_CALL }, {});
  assert.equal(noDefaults.findings.length, 0);
  assert.equal(noDefaults.skipped, 1);
  assert.match(noDefaults.errors[0], /session_id|target_id|asset_id/);
  const withDefaults = insecureCryptoDetector({ content: MD5_CALL }, DEFAULTS);
  assert.equal(withDefaults.findings.length, 1);
  assert.equal(withDefaults.findings[0].session_id, 'sess-1');
  assert.equal(withDefaults.findings[0].target_id, 'tgt-1');
  assert.equal(withDefaults.findings[0].asset_id, 'ast-1');
  const perRecord = insecureCryptoDetector(
    { content: MD5_CALL, session_id: 's-9', target_id: 't-9', asset_id: 'a-9' },
    DEFAULTS,
  );
  assert.equal(perRecord.findings[0].session_id, 's-9', 'record ids win over defaults');
});

test('insecure-crypto: oversized content is skipped, not scanned', () => {
  const big = insecureCryptoDetector({ content: `x${' '.repeat(MAX_CONTENT_CHARS)}` }, DEFAULTS);
  assert.equal(big.findings.length, 0);
  assert.equal(big.skipped, 1);
  assert.match(big.errors[0], /exceeds the 1000000 character limit/);
});

test('insecure-crypto: the per-record cap truncates visibly, never silently', () => {
  const lines = [];
  for (let index = 0; index < MAX_FINDINGS_PER_RECORD + 5; index += 1) {
    lines.push(`md5(x${index})`);
  }
  const result = scan(lines.join('\n'));
  assert.equal(result.findings.length, MAX_FINDINGS_PER_RECORD);
  assert.equal(result.skipped, 0);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /5 additional matches truncated/);
  assert.match(result.errors[0], /first 100 reported/);
});

test('insecure-crypto: batch records follow the stub convention — batch tool is authoritative, bad results skipped', () => {
  const batch = {
    tool: 'lab-capture',
    results: [
      { content: MD5_CALL },
      { content: '' },
      { content: DES_CALL },
    ],
  };
  const result = insecureCryptoDetector(batch, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.findings[0].discovery_tool, 'lab-capture');
  assert.equal(result.findings[1].discovery_tool, 'lab-capture');
  assert.throws(
    () => insecureCryptoDetector({ tool: '  ', results: [{ content: MD5_CALL }] }, DEFAULTS),
    /DETECTOR_INVALID_INPUT: batch tool must be a non-empty string/,
  );
});

test('insecure-crypto: getDetector resolves the built-in name and runDetector validates its envelope', () => {
  const resolved = getDetector('insecure-crypto');
  assert.equal(resolved.source, 'insecure-crypto');
  assert.equal(typeof resolved.detector, 'function');
  const result = runDetector(resolved.detector, { content: MD5_CALL }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal('error' in result, false);
});

test('insecure-crypto: findings validate as valid under the generic checklist and dedupe by call site', () => {
  const finding = scan(MD5_CALL).findings[0];
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
  assert.equal(validateFinding(finding).verdict, 'valid', 'the generic checklist requires only poc, evidence, and steps — all carried');
  const random = scan(RANDOM_CALL).findings[0];
  assert.equal(validateFinding(random).verdict, 'valid');
  assert.match(random.description, /only a weakness when its output feeds a secret/);
  const deduped = dedupeFindings([finding, finding]);
  assert.equal(deduped.groups.length, 1, 'the same call site dedupes to one finding');
  assert.equal(deduped.duplicates, 1);
});

test('insecure-crypto: detect -> validate -> report end to end, JSON carries the generic checklist', () => {
  const result = runDetector(insecureCryptoDetector, { content: `a\n${MD5_CALL}\n${DES_CALL}` }, DEFAULTS);
  assert.equal(result.findings.length, 2);
  const json = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
    format: 'json',
  });
  const report = JSON.parse(json);
  assert.equal(report.findings.length, 2);
  const byPattern = {};
  for (const finding of report.findings) {
    byPattern[finding.evidence[0].pattern] = finding.evidence_checklist.classId;
  }
  assert.equal(byPattern['weak-hash-md5'], 'generic');
  assert.equal(byPattern['weak-cipher-des-rc4'], 'generic');
  const markdown = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
  });
  assert.match(markdown, /cryptographic failure/i);
});

test('CLI detect with insecure-crypto over a local record: JSON output, detector named, code never executed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-insecure-crypto-cli-');
  const inputPath = path.join(directory, 'record.json');
  fs.writeFileSync(inputPath, JSON.stringify({ content: `notes\n${MD5_CALL}\n${DES_CALL}\n`, source: 'lab.py' }), 'utf8');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'insecure-crypto', '--input', inputPath,
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1',
  ]);
  const output = JSON.parse(stdout);
  assert.equal(output.detector, 'insecure-crypto');
  assert.equal(output.findings.length, 2);
  assert.equal(output.skipped, 0);
  assert.equal('error' in output, false);
  assert.equal(output.findings[0].evidence[0].source, 'lab.py');
});

test('insecure-crypto: patterns are strict call-site syntax — lookalikes do not match', () => {
  const lookalikes = [
    'md5sum(file)', // md5 followed by 'sum', not '('
    'md5Hex(data)', // md5 followed by 'Hex', not '('
    'getMd5(data)', // 'Md5' — capital M, case-sensitive by design
    'MD5(data)', // uppercase — case-sensitive by design
    'sha1sum(file)', // sha1 followed by 'sum'
    'sha256(data)', // sha256 is not sha1
    "createHash('sha256')", // strong hash — the string is sha256, not sha1
    'SHA1(data)', // uppercase — case-sensitive by design
    'Cipher.getInstance("AES/GCM/NoPadding")', // strong mode, no ECB
    "crypto.createCipheriv('aes-256-gcm', key, iv)", // strong mode
    'const ecb = 1', // ECB as a bare identifier, not a mode selection
    'AESECB', // no slash — not a mode string
    "crypto.createCipheriv('des-ede3-cbc', key, iv)", // 3DES — matches weak-cipher, NOT ecb
    'crypto.createCipheriv(key, iv)', // createCipheriv without a cipher name
    'Math.randomInt(10)', // random followed by 'Int', not '('
    'random.randint(1, 10)', // randint, not random(
    'random.choice(items)', // choice, not random(
    'secrets.token_hex(16)', // the safe generator — must not match
    'crypto.randomBytes(16)', // the safe generator — must not match
    'random(data)', // bare random( — no Math./random. prefix
  ];
  for (const lookalike of lookalikes) {
    const result = scan(lookalike);
    // The des-ede3-cbc line is the one deliberate exception: it
    // matches weak-cipher-des-rc4, so it is checked separately.
    if (lookalike.startsWith("crypto.createCipheriv('des-ede3")) {
      assert.equal(result.findings.length, 1, lookalike);
      assert.equal(result.findings[0].evidence[0].pattern, 'weak-cipher-des-rc4');
      continue;
    }
    assert.equal(result.findings.length, 0, lookalike);
  }
  assert.equal(PATTERNS.length, 6, 'the documented pattern set');
});
