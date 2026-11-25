// Scope-decision explainability (round 52, Phase 3).
// `sentinel check-scope --explain` prints the ordered rule trail behind a
// decision (which rule matched, from which policy source, and what would
// change the outcome); `--explain --json` carries the same trail as
// structured data. Plain (non-explain) output is byte-identical to the
// pre-round output. Explainability only observes the decision logic —
// every decision here is asserted identical to evaluate(). Fixtures only;
// no scanner, no network, no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { TargetRegistry, evaluateTargetRequestWithTrail, normalizeTarget, renderScopeExplanationText } = require('../src/scope/target-registry');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const TARGET_FILE = path.resolve(__dirname, '..', 'examples', 'local-target.example.json');

function target(overrides = {}) {
  return {
    target_id: 'local-lab',
    program_name: 'Local test fixture',
    authorization_reference: 'LOCAL-LAB-ONLY',
    allowed_domains: ['example.test', '*.example.test'],
    excluded_domains: ['admin.example.test'],
    excluded_paths: ['/account/remove'],
    ...overrides,
  };
}

function explained(overrides = {}, url = 'https://app.example.test/docs') {
  const registry = new TargetRegistry();
  registry.register(target(overrides));
  return registry.explain('local-lab', url, { targetFile: TARGET_FILE });
}

function rule(explanation, ruleId) {
  return explanation.rules.find((entry) => entry.rule === ruleId);
}

// The pre-round plain output for the in-scope case, captured before this
// round (baseline run, 2026-11-26). Plain output must stay byte-identical.
const PLAIN_IN_SCOPE_GOLDEN = `{
  "targetId": "local-lab",
  "authorizationStatus": "declared_not_verified",
  "decision": {
    "allowed": true,
    "reason": "IN_SCOPE",
    "hostname": "app.example.test",
    "path": "/docs",
    "pattern": "*.example.test"
  },
  "safety": "No network request was made."
}
`;

test('in-scope explanation names IN_SCOPE as the deciding rule and evaluates all six rules', () => {
  const explanation = explained();
  assert.equal(explanation.decidingRule, 'IN_SCOPE');
  assert.equal(explanation.decision.allowed, true);
  assert.equal(explanation.decision.reason, 'IN_SCOPE');
  assert.deepEqual(explanation.rules.map((entry) => entry.rule), [
    'TARGET_REGISTERED', 'URL_VALID', 'EXCLUDED_DOMAIN', 'ALLOWED_DOMAIN', 'EXCLUDED_PATH', 'IN_SCOPE',
  ]);
  assert.ok(explanation.rules.every((entry) => entry.evaluated));
  assert.deepEqual(explanation.rules.filter((entry) => entry.matched).map((entry) => entry.rule), ['IN_SCOPE']);
  assert.equal(rule(explanation, 'ALLOWED_DOMAIN').detail.pattern, '*.example.test');
  assert.equal(explanation.suggestion, 'No change needed — the request is in scope.');
});

test('excluded-domain explanation names EXCLUDED_DOMAIN and short-circuits the later rules', () => {
  const explanation = explained({}, 'https://admin.example.test/');
  assert.equal(explanation.decidingRule, 'EXCLUDED_DOMAIN');
  assert.equal(explanation.decision.reason, 'EXCLUDED_DOMAIN');
  assert.equal(rule(explanation, 'EXCLUDED_DOMAIN').detail.pattern, 'admin.example.test');
  assert.match(rule(explanation, 'EXCLUDED_DOMAIN').source, /target file: .* \(excluded_domains\)/);
  assert.match(explanation.suggestion, /Remove "admin\.example\.test" from excluded_domains/);
  assert.equal(rule(explanation, 'ALLOWED_DOMAIN').evaluated, false);
  assert.equal(rule(explanation, 'EXCLUDED_PATH').evaluated, false);
  assert.equal(rule(explanation, 'IN_SCOPE').evaluated, false);
  assert.ok(explanation.rules.filter((entry) => entry.evaluated).every((entry) => !entry.matched || entry.rule === 'EXCLUDED_DOMAIN'));
});

test('out-of-scope host explanation names ALLOWED_DOMAIN and suggests adding the host', () => {
  const explanation = explained({}, 'https://outside.test/');
  assert.equal(explanation.decidingRule, 'ALLOWED_DOMAIN');
  assert.equal(explanation.decision.reason, 'HOST_OUT_OF_SCOPE');
  assert.match(explanation.suggestion, /Add "outside\.test" \(or a matching wildcard\) to allowed_domains/);
  assert.equal(rule(explanation, 'EXCLUDED_PATH').evaluated, false);
  assert.equal(rule(explanation, 'IN_SCOPE').evaluated, false);
});

test('built-in default excluded path cites the built-in source and suggests the override', () => {
  const explanation = explained({}, 'https://app.example.test/logout');
  assert.equal(explanation.decidingRule, 'EXCLUDED_PATH');
  assert.equal(explanation.decision.reason, 'EXCLUDED_PATH');
  assert.match(rule(explanation, 'EXCLUDED_PATH').source, /built-in default: .*DEFAULT_EXCLUDED_PATHS/);
  // Round 54 changed the policy: the built-in defaults CAN now be
  // overridden per target via `default_excluded_paths`, so the
  // suggestion names the override instead of "cannot be un-excluded".
  assert.match(explanation.suggestion, /built-in policy default.*declare "default_excluded_paths"/);
});

test('configured excluded path cites the target file and suggests removing it', () => {
  const explanation = explained({}, 'https://app.example.test/account/remove/history');
  assert.equal(explanation.decidingRule, 'EXCLUDED_PATH');
  assert.match(rule(explanation, 'EXCLUDED_PATH').source, /target file: .* \(excluded_paths\)/);
  assert.match(explanation.suggestion, /Remove "\/account\/remove" from excluded_paths/);
});

test('invalid URL explanation names URL_VALID and keeps the parse error as detail', () => {
  const explanation = explained({}, 'https://user:pass@example.test/');
  assert.equal(explanation.decidingRule, 'URL_VALID');
  assert.equal(explanation.decision.reason, 'INVALID_URL');
  assert.match(rule(explanation, 'URL_VALID').detail.error, /credentials/);
  assert.match(explanation.suggestion, /Fix the request URL/);
  assert.equal(rule(explanation, 'EXCLUDED_DOMAIN').evaluated, false);
});

test('unregistered target explanation names TARGET_REGISTERED and evaluates nothing else', () => {
  const registry = new TargetRegistry();
  const explanation = registry.explain('missing', 'https://example.test/', { targetFile: TARGET_FILE });
  assert.equal(explanation.decidingRule, 'TARGET_REGISTERED');
  assert.equal(explanation.decision.reason, 'TARGET_NOT_REGISTERED');
  assert.match(explanation.suggestion, /Register the target first/);
  assert.equal(explanation.rules.filter((entry) => entry.evaluated).length, 1);
});

test('explain() decisions are identical to evaluate() across the whole matrix', () => {
  const registry = new TargetRegistry();
  registry.register(target());
  const urls = [
    'https://example.test/docs',
    'https://app.example.test/docs',
    'https://outside.test/',
    'https://admin.example.test/',
    'https://v2.admin.example.test/',
    'https://app.example.test/logout',
    'https://app.example.test/logout%2Fsession',
    'https://app.example.test/account/remove/history',
    'https://user:pass@example.test/',
    'https://127.0.0.1/',
    'not-a-url',
  ];
  for (const url of urls) {
    const explanation = registry.explain('local-lab', url, { targetFile: TARGET_FILE });
    assert.deepEqual(explanation.decision, registry.evaluate('local-lab', url), url);
    const direct = evaluateTargetRequestWithTrail(normalizeTarget(target()), url);
    assert.deepEqual(direct.decision, registry.evaluate('local-lab', url), url);
  }
});

test('text rendering names the deciding rule and suggestion and is deterministic', () => {
  const explanation = explained({}, 'https://outside.test/');
  const first = renderScopeExplanationText(explanation);
  const second = renderScopeExplanationText(explanation);
  assert.equal(first, second);
  assert.match(first, /Decision: HOST_OUT_OF_SCOPE \(denied\)/);
  assert.match(first, /4\. ALLOWED_DOMAIN: DECIDED \(deny\)/);
  assert.match(first, /5\. EXCLUDED_PATH: not evaluated/);
  assert.match(first, /Deciding rule: ALLOWED_DOMAIN/);
  assert.match(first, /Suggestion: Add "outside\.test"/);
});

test('CLI plain output is byte-identical to the pre-round golden', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'check-scope', '--target', TARGET_FILE, '--url', 'https://app.example.test/docs',
  ]);
  assert.equal(stdout, PLAIN_IN_SCOPE_GOLDEN);
});

test('CLI --explain prints the text trail with the deciding rule and suggestion', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'check-scope', '--target', TARGET_FILE, '--url', 'https://outside.test/', '--explain',
  ]);
  assert.match(stdout, /Decision: HOST_OUT_OF_SCOPE \(denied\)/);
  assert.match(stdout, /Deciding rule: ALLOWED_DOMAIN/);
  assert.match(stdout, /Suggestion: Add "outside\.test"/);
  assert.match(stdout, /Policy source: .*local-target\.example\.json/);
});

test('CLI --explain --json carries the same trail as structured data and is deterministic', async () => {
  const args = [CLI, 'check-scope', '--target', TARGET_FILE, '--url', 'https://app.example.test/docs', '--explain', '--json'];
  const first = await execFileAsync(process.execPath, args);
  const second = await execFileAsync(process.execPath, args);
  assert.equal(first.stdout, second.stdout);
  const parsed = JSON.parse(first.stdout);
  assert.equal(parsed.decision.reason, 'IN_SCOPE');
  assert.equal(parsed.explanation.decidingRule, 'IN_SCOPE');
  assert.equal(parsed.explanation.rules.length, 6);
  assert.deepEqual(parsed.explanation.rules.map((entry) => entry.rule), [
    'TARGET_REGISTERED', 'URL_VALID', 'EXCLUDED_DOMAIN', 'ALLOWED_DOMAIN', 'EXCLUDED_PATH', 'IN_SCOPE',
  ]);
  assert.equal(parsed.explanation.suggestion, 'No change needed — the request is in scope.');
  assert.equal(parsed.explanation.source.targetFile, TARGET_FILE);
});

test('CLI --json alone is the same as plain output', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'check-scope', '--target', TARGET_FILE, '--url', 'https://app.example.test/docs', '--json',
  ]);
  assert.equal(stdout, PLAIN_IN_SCOPE_GOLDEN);
});

test('CLI corrupt or missing target file fails cleanly with a named error and no trail', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-r52-');
  const corrupt = path.join(dir, 'corrupt.json');
  fs.writeFileSync(corrupt, '{not json');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'check-scope', '--target', corrupt, '--url', 'https://example.test/', '--explain']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /Invalid JSON in /);
      assert.equal(error.stdout, '');
      return true;
    },
  );
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'check-scope', '--target', path.join(dir, 'missing.json'), '--url', 'https://example.test/', '--explain']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /Cannot read /);
      assert.equal(error.stdout, '');
      return true;
    },
  );
});
