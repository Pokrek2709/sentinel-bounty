// Pluggable AI-verdict interface (round 50, Phase 6): the contract a
// model-based finding verifier must satisfy, the built-in stub, and a
// safe loader for custom verifier modules. The AI verdict is
// ADVISORY ONLY — the rule-based verdict never changes because of
// it. Fixtures only; no model call, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  stubVerifier,
  validateAiVerdictResult,
  runVerifier,
  getVerifier,
  loadVerifier,
  attachAiVerdict,
} = require('../src/analysis/ai-verdict');
const { validateFinding } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

test('stub verifier always returns needs_evidence with confidence 0', () => {
  const result = stubVerifier(loadFixture('confirmed-full.json'));
  assert.deepEqual(result, { verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] });
});

test('stub verifier never claims valid or false_positive, even for a fully-evidenced finding', () => {
  const result = stubVerifier(loadFixture('confirmed-full.json'));
  assert.notEqual(result.verdict, 'valid');
  assert.notEqual(result.verdict, 'false_positive');
});

test('validateAiVerdictResult accepts a valid result and returns a normalized copy', () => {
  const reasons = ['model saw the PoC'];
  const result = validateAiVerdictResult({ verdict: 'valid', confidence: 0.9, reasons });
  assert.deepEqual(result, { verdict: 'valid', confidence: 0.9, reasons: ['model saw the PoC'] });
  assert.notEqual(result.reasons, reasons, 'reasons are copied, not shared');
});

test('validateAiVerdictResult rejects a Promise return, an unknown verdict, and bad confidence or reasons', () => {
  assert.throws(() => validateAiVerdictResult(Promise.resolve({ verdict: 'valid', confidence: 1, reasons: [] })), /AI_VERDICT_INVALID_RESULT: verifier must return a result synchronously/);
  assert.throws(() => validateAiVerdictResult(null), /AI_VERDICT_INVALID_RESULT: verifier result must be an object/);
  assert.throws(() => validateAiVerdictResult([]), /AI_VERDICT_INVALID_RESULT: verifier result must be an object/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'maybe', confidence: 0.5, reasons: [] }), /verdict must be one of valid, false_positive, needs_evidence/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'valid', confidence: 1.5, reasons: [] }), /confidence must be a finite number in \[0, 1\]/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'valid', confidence: Number.NaN, reasons: [] }), /confidence must be a finite number in \[0, 1\]/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'valid', confidence: '0.9', reasons: [] }), /confidence must be a finite number in \[0, 1\]/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'valid', confidence: 0.5, reasons: 'yes' }), /reasons must be an array of strings/);
  assert.throws(() => validateAiVerdictResult({ verdict: 'valid', confidence: 0.5, reasons: [42] }), /reasons must be an array of strings/);
});

test('runVerifier records a custom verifier verdict', () => {
  const finding = loadFixture('confirmed-full.json');
  const result = runVerifier(() => ({ verdict: 'valid', confidence: 0.9, reasons: ['model agrees'] }), finding);
  assert.deepEqual(result, { verdict: 'valid', confidence: 0.9, reasons: ['model agrees'] });
  assert.equal(result.error, undefined, 'a clean run carries no error field');
});

test('runVerifier catches a throwing verifier and records the failure without throwing', () => {
  const finding = loadFixture('confirmed-full.json');
  const result = runVerifier(() => { throw new Error('model endpoint down'); }, finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.equal(result.confidence, 0);
  assert.equal(result.error, 'model endpoint down');
  assert.ok(result.reasons[0].includes('ai verifier error: model endpoint down'));
});

test('runVerifier catches an invalid-shape return and records the failure without throwing', () => {
  const finding = loadFixture('confirmed-full.json');
  const result = runVerifier(() => ({ verdict: 'valid', confidence: 2, reasons: [] }), finding);
  assert.equal(result.verdict, 'needs_evidence');
  assert.equal(result.confidence, 0);
  assert.match(result.error, /AI_VERDICT_INVALID_RESULT/);
});

test('runVerifier passes a defensive copy: a mutating verifier cannot change the finding', () => {
  const finding = loadFixture('confirmed-full.json');
  const before = JSON.stringify(finding);
  runVerifier((input) => {
    input.title = 'MUTATED';
    input.evidence = [];
    return { verdict: 'valid', confidence: 1, reasons: [] };
  }, finding);
  assert.equal(JSON.stringify(finding), before, 'the original finding is untouched');
});

test('getVerifier resolves stub, an inline function, and null; rejects anything else', () => {
  assert.deepEqual(getVerifier('stub'), { verifier: stubVerifier, source: 'stub' });
  const fn = () => ({ verdict: 'valid', confidence: 1, reasons: [] });
  assert.deepEqual(getVerifier(fn), { verifier: fn, source: 'inline' });
  assert.equal(getVerifier(undefined), null);
  assert.equal(getVerifier(null), null);
  assert.throws(() => getVerifier(42), /AI_VERDICT_INVALID_VERIFIER/);
});

test('loadVerifier loads the fixture class verifier and it answers per class', () => {
  const { verifier, source } = loadVerifier('tests/fixtures/ai-verifier-class.js');
  assert.equal(source, 'ai-verifier-class.js');
  assert.deepEqual(runVerifier(verifier, loadFixture('confirmed-full.json')), { verdict: 'valid', confidence: 0.9, reasons: ['fixture: XSS class confirmed by model'] });
  assert.deepEqual(runVerifier(verifier, loadFixture('class-csrf-full.json')), { verdict: 'false_positive', confidence: 0.8, reasons: ['fixture: CSRF class rejected by model'] });
  assert.deepEqual(runVerifier(verifier, loadFixture('class-ssrf-full.json')), { verdict: 'needs_evidence', confidence: 0.5, reasons: ['fixture: unknown class, model abstains'] });
});

test('loadVerifier refuses a malformed module, a missing file, and a path outside the skill directory', () => {
  assert.throws(() => loadVerifier('tests/fixtures/ai-verifier-malformed.js'), /AI_VERDICT_INVALID_MODULE/);
  assert.throws(() => loadVerifier('tests/fixtures/no-such-verifier.js'), /AI_VERDICT_NOT_FOUND/);
  assert.throws(() => loadVerifier('/etc/passwd'), /AI_VERDICT_PATH_OUTSIDE_SKILL/);
  assert.throws(() => loadVerifier('../../outside.js'), /AI_VERDICT_PATH_OUTSIDE_SKILL/);
});

test('loadVerifier refuses a symlinked verifier file and a symlinked parent directory', async (t) => {
  const linkPath = path.join(__dirname, 'fixtures', 'ai-verifier-link.js');
  const linkDir = path.join(__dirname, 'fixtures', 'ai-verifier-linkdir');
  const outside = await makeTempDir(t, 'sentinel-ai-verdict-outside-');
  try {
    fs.copyFileSync(path.join(__dirname, 'fixtures', 'ai-verifier-class.js'), path.join(outside, 'ai-verifier-class.js'));
    // Round 81: symlink creation needs privileges that are not
    // guaranteed on every platform (Windows runners included) —
    // same guard as backup-restore.test.js: skip, do not fail.
    try {
      fs.symlinkSync(path.join(__dirname, 'fixtures', 'ai-verifier-class.js'), linkPath);
    } catch (error) {
      t.skip(`symlink unavailable: ${error.code || error.message}`);
      return;
    }
    assert.throws(() => loadVerifier('tests/fixtures/ai-verifier-link.js'), /AI_VERDICT_SYMLINK_REFUSED/);
    try {
      fs.symlinkSync(outside, linkDir);
    } catch (error) {
      t.skip(`symlink unavailable: ${error.code || error.message}`);
      return;
    }
    assert.throws(() => loadVerifier('tests/fixtures/ai-verifier-linkdir/ai-verifier-class.js'), /AI_VERDICT_SYMLINK_REFUSED/);
  } finally {
    fs.rmSync(linkPath, { force: true });
    fs.rmSync(linkDir, { force: true });
  }
});

test('attachAiVerdict returns a copy with ai_verdict and ai_verdict_source; no verifier means no change', () => {
  const finding = loadFixture('confirmed-full.json');
  assert.equal(attachAiVerdict(finding, null), finding, 'no verifier: same reference back');
  const attached = attachAiVerdict(finding, { verifier: stubVerifier, source: 'stub' });
  assert.notEqual(attached, finding, 'a copy is returned');
  assert.deepEqual(attached.ai_verdict, { verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] });
  assert.equal(attached.ai_verdict_source, 'stub');
  assert.equal(finding.ai_verdict, undefined, 'the original finding is untouched');
});

test('validateFinding with a disagreeing verifier: the rule verdict stands', () => {
  const disagreeing = () => ({ verdict: 'false_positive', confidence: 1, reasons: ['model disagrees'] });
  const valid = validateFinding(loadFixture('confirmed-full.json'), { verifier: disagreeing });
  assert.equal(valid.verdict, 'valid', 'the rule verdict is not overridden by the AI verdict');
  assert.equal(valid.aiVerdict.verdict, 'false_positive');
  assert.equal(valid.aiVerdictSource, 'inline');

  const agreeing = () => ({ verdict: 'valid', confidence: 1, reasons: ['model agrees'] });
  const incomplete = validateFinding(loadFixture('potential.json'), { verifier: agreeing });
  assert.equal(incomplete.verdict, 'needs_evidence', 'a valid AI verdict cannot rescue an unevidenced finding');
  assert.equal(incomplete.aiVerdict.verdict, 'valid');
});

test('validateFinding with the stub records needs_evidence and source stub', () => {
  const result = validateFinding(loadFixture('confirmed-full.json'), { verifier: 'stub' });
  assert.equal(result.verdict, 'valid');
  assert.deepEqual(result.aiVerdict, { verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] });
  assert.equal(result.aiVerdictSource, 'stub');
});

test('validateFinding without a verifier returns no aiVerdict field', () => {
  const result = validateFinding(loadFixture('confirmed-full.json'));
  assert.equal(result.verdict, 'valid');
  assert.equal(result.aiVerdict, undefined);
  assert.equal(result.aiVerdictSource, undefined);
});

test('validateFinding with an invalid verifier option records a verifier failure and never throws', () => {
  const result = validateFinding(loadFixture('confirmed-full.json'), { verifier: 42 });
  assert.equal(result.verdict, 'valid');
  assert.equal(result.aiVerdict.verdict, 'needs_evidence');
  assert.match(result.aiVerdict.error, /AI_VERDICT_INVALID_VERIFIER/);
  assert.equal(result.aiVerdictSource, 'invalid');
});

test('generateReport with the stub renders the advisory AI verdict in Markdown, JSON, and HTML', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, { ...OPTIONS, verifier: 'stub' });
  assert.match(markdown, /AI verdict \(advisory\):\*\* needs_evidence \(confidence 0, source: stub\) — no AI model configured/);
  const json = JSON.parse(generateReport(findings, { ...OPTIONS, format: 'json', verifier: 'stub' }));
  for (const finding of json.findings) {
    assert.deepEqual(finding.ai_verdict, { verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] });
    assert.equal(finding.ai_verdict_source, 'stub');
  }
  const html = generateReport(findings, { ...OPTIONS, format: 'html', verifier: 'stub' });
  assert.match(html, /AI verdict \(advisory\)<\/dt><dd>needs_evidence \(confidence 0, source: stub\) — no AI model configured<\/dd>/);
});

test('generateReport with the fixture class verifier renders per-class AI verdicts', () => {
  const findings = [loadFixture('confirmed-full.json'), loadFixture('class-csrf-full.json')];
  const markdown = generateReport(findings, { ...OPTIONS, verifier: 'tests/fixtures/ai-verifier-class.js' });
  assert.match(markdown, /AI verdict \(advisory\):\*\* valid \(confidence 0\.9, source: ai-verifier-class\.js\) — fixture: XSS class confirmed by model/);
  assert.match(markdown, /AI verdict \(advisory\):\*\* false_positive \(confidence 0\.8, source: ai-verifier-class\.js\) — fixture: CSRF class rejected by model/);
});

test('generateReport without a verifier is byte-identical to the pre-round-50 output (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  // Hashes captured from the pre-change generator (round 43, commit
  // c3bec85): adding the verifier interface must not move a byte of
  // the output when no verifier is configured.
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
});

test('generateReport renders a throwing verifier as a recorded error, never a crash', () => {
  const throwing = () => { throw new Error('model exploded'); };
  const markdown = generateReport([loadFixture('confirmed-full.json')], { ...OPTIONS, verifier: throwing });
  assert.match(markdown, /AI verdict \(advisory\):\*\* needs_evidence \(confidence 0, source: inline\) — ai verifier error: model exploded/);
});

test('CLI report --verifier stub writes the advisory line; a bad verifier path fails cleanly with no file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-ai-verdict-cli-');
  const output = path.join(directory, 'report.md');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'confirmed-full.json'),
    '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
    '--verifier', 'stub', '--out', output,
  ]);
  assert.match(stdout, /Report written to/);
  assert.match(fs.readFileSync(output, 'utf8'), /AI verdict \(advisory\):\*\* needs_evidence \(confidence 0, source: stub\)/);
  const badOutput = path.join(directory, 'bad.md');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'confirmed-full.json'),
      '--verifier', 'tests/fixtures/no-such-verifier.js', '--out', badOutput,
    ]),
    (error) => {
      assert.match(error.stderr, /AI_VERDICT_NOT_FOUND/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(badOutput), false, 'a failed verifier load writes no file');
});
