// Scope list + overridable default excluded paths (round 54, Phase 3).
//
// `sentinel scope list` reads the persistent store from round 53 and
// reports every target (sorted by target_id) with its validation status
// and, when `--url` is given, its scope decision for that URL. The
// target file's `default_excluded_paths` field replaces the built-in
// default excluded paths (`DEFAULT_EXCLUDED_PATHS`) for that target
// only; absent it keeps the built-ins, and an invalid value fails
// loudly with no silent fallback. Fixtures only; no scanner, no
// network, no live target. The real state directory is never touched —
// every test uses its own temp state dir.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { makeTempDir } = require('./helpers/temp-dir');
const {
  DEFAULT_EXCLUDED_PATHS,
  TargetRegistry,
  normalizeTarget,
  evaluateTargetRequest,
} = require('../src/scope/target-registry');
const {
  ScopeStoreError,
  listScopeTargets,
  storePathFor,
} = require('../src/scope/target-store');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

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

async function runCli(args) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function parse(stdout) {
  return JSON.parse(stdout);
}

async function writeTargetFile(directory, contents, name = 'target.json') {
  const file = path.join(directory, name);
  await fs.writeFile(file, typeof contents === 'string' ? contents : `${JSON.stringify(contents, null, 2)}\n`, { mode: 0o600 });
  return file;
}

async function writeStoreFile(directory, targets) {
  const storePath = path.join(directory, 'scope-targets.json');
  await fs.mkdir(directory, { recursive: true });
  await fs.writeFile(storePath, `${JSON.stringify({ schema_version: 1, targets }, null, 2)}\n`, { mode: 0o600 });
  return storePath;
}

test('default_excluded_paths: absent keeps the built-ins, present replaces them, invalid fails', () => {
  const absent = normalizeTarget(target());
  assert.deepEqual(absent.defaultExcludedPaths, [...DEFAULT_EXCLUDED_PATHS]);
  assert.equal(absent.defaultExcludedPathsOverridden, false);
  assert.ok(absent.excludedPaths.includes('/logout'));
  assert.ok(absent.excludedPaths.includes('/account/remove'));

  const empty = normalizeTarget(target({ default_excluded_paths: [] }));
  assert.deepEqual(empty.defaultExcludedPaths, []);
  assert.equal(empty.defaultExcludedPathsOverridden, true);
  assert.ok(!empty.excludedPaths.includes('/logout'));
  assert.ok(empty.excludedPaths.includes('/account/remove'));

  const custom = normalizeTarget(target({ default_excluded_paths: ['/custom', '/logout'] }));
  assert.deepEqual(custom.defaultExcludedPaths, ['/custom', '/logout']);
  assert.equal(custom.defaultExcludedPathsOverridden, true);
  assert.ok(custom.excludedPaths.includes('/custom'));
  assert.ok(!custom.excludedPaths.includes('/signout'));

  assert.throws(() => normalizeTarget(target({ default_excluded_paths: 'not-an-array' })), /default_excluded_paths must be an array/);
  assert.throws(() => normalizeTarget(target({ default_excluded_paths: ['logout'] })), /must be an absolute path/);
  assert.throws(() => normalizeTarget(target({ default_excluded_paths: ['/a?b=1'] })), /must be an absolute path/);
});

test('override is honored by evaluate and the decision object shape is unchanged', () => {
  const empty = normalizeTarget(target({ default_excluded_paths: [] }));
  assert.deepEqual(
    evaluateTargetRequest(empty, 'https://app.example.test/logout'),
    { allowed: true, reason: 'IN_SCOPE', hostname: 'app.example.test', path: '/logout', pattern: '*.example.test' },
  );

  const custom = normalizeTarget(target({ default_excluded_paths: ['/custom'] }));
  assert.deepEqual(
    evaluateTargetRequest(custom, 'https://app.example.test/custom'),
    { allowed: false, reason: 'EXCLUDED_PATH', hostname: 'app.example.test', path: '/custom', pattern: '/custom' },
  );
  assert.deepEqual(
    evaluateTargetRequest(custom, 'https://app.example.test/logout'),
    { allowed: true, reason: 'IN_SCOPE', hostname: 'app.example.test', path: '/logout', pattern: '*.example.test' },
  );

  // The built-in default still denies without an override.
  assert.deepEqual(
    evaluateTargetRequest(normalizeTarget(target()), 'https://app.example.test/logout'),
    { allowed: false, reason: 'EXCLUDED_PATH', hostname: 'app.example.test', path: '/logout', pattern: '/logout' },
  );
});

test('explain cites the override source and suggests removing it; built-in cites the built-in and suggests the override', () => {
  const registry = new TargetRegistry();
  registry.register(target({ target_id: 'custom-defaults', default_excluded_paths: ['/custom'] }));
  const overridden = registry.explain('custom-defaults', 'https://app.example.test/custom', { targetFile: 'target.json' });
  assert.equal(overridden.decidingRule, 'EXCLUDED_PATH');
  const overriddenRule = overridden.rules.find((entry) => entry.rule === 'EXCLUDED_PATH');
  assert.match(overriddenRule.source, /target file: target\.json \(default_excluded_paths\)/);
  assert.match(overridden.suggestion, /Remove "\/custom" from default_excluded_paths/);

  registry.register(target());
  const builtin = registry.explain('local-lab', 'https://app.example.test/logout', { targetFile: 'target.json' });
  const builtinRule = builtin.rules.find((entry) => entry.rule === 'EXCLUDED_PATH');
  assert.match(builtinRule.source, /built-in default: .*DEFAULT_EXCLUDED_PATHS/);
  assert.match(builtin.suggestion, /declare "default_excluded_paths"/);
});

test('listScopeTargets: empty store, sorted targets, decisions with --url, invalid entries reported not hidden', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-list-');
  const storePath = path.join(directory, 'scope-targets.json');

  assert.deepEqual(await listScopeTargets(storePath), { store: storePath, count: 0, targets: [] });

  const zeta = target({ target_id: 'zeta', allowed_domains: ['zeta.test'] });
  const alpha = target({ target_id: 'alpha', allowed_domains: ['alpha.test'] });
  const broken = target({ target_id: 'broken', allowed_domains: [] });
  const noId = { program_name: 'No id at all', allowed_domains: ['example.test'] };
  await writeStoreFile(directory, [zeta, broken, alpha, noId]);

  const listed = await listScopeTargets(storePath);
  assert.equal(listed.count, 4);
  assert.deepEqual(listed.targets.map((entry) => entry.targetId), ['alpha', 'broken', 'zeta', null]);
  assert.equal(listed.targets[0].valid, true);
  assert.equal(listed.targets[0].decision, null);
  assert.deepEqual(listed.targets[0].allowedDomains, ['alpha.test']);
  assert.equal(listed.targets[1].valid, false);
  assert.match(listed.targets[1].error, /allowed_domains must contain at least one domain/);
  assert.equal(listed.targets[1].decision, null);
  assert.equal(listed.targets[3].targetId, null);
  assert.equal(listed.targets[3].valid, false);

  const withUrl = await listScopeTargets(storePath, { url: 'https://alpha.test/docs' });
  assert.equal(withUrl.targets[0].decision.reason, 'IN_SCOPE');
  assert.equal(withUrl.targets[2].decision.reason, 'HOST_OUT_OF_SCOPE');
  assert.equal(withUrl.targets[1].decision, null);

  // Determinism: the same store listed twice is byte-identical, and a
  // store written in the opposite order lists identically (sorted).
  assert.equal(JSON.stringify(await listScopeTargets(storePath)), JSON.stringify(listed));
  await writeStoreFile(directory, [alpha, zeta, broken, noId]);
  assert.equal(JSON.stringify(await listScopeTargets(storePath)), JSON.stringify(listed));
});

test('listScopeTargets: invalid URL and damaged store shape fail loudly', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-list-');
  const storePath = path.join(directory, 'scope-targets.json');
  await writeStoreFile(directory, [target()]);

  await assert.rejects(
    listScopeTargets(storePath, { url: 'https://user:pass@example.test/' }),
    (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_LIST_INVALID_URL',
  );
  await assert.rejects(
    listScopeTargets(storePath, { url: 'not a url' }),
    (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_LIST_INVALID_URL',
  );

  await fs.writeFile(storePath, JSON.stringify({ schema_version: 99, targets: [] }), { mode: 0o600 });
  await assert.rejects(
    listScopeTargets(storePath),
    (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_STORE_UNSUPPORTED_SCHEMA',
  );

  await fs.writeFile(storePath, '{ corrupt json', { mode: 0o600 });
  await assert.rejects(
    listScopeTargets(storePath),
    (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_STORE_CORRUPT',
  );
});

test('CLI scope list: empty store, text and JSON, --url decisions, mutual exclusion', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-list-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = storePathFor(stateDirectory);

  const empty = await runCli(['scope', 'list', '--state-dir', stateDirectory]);
  assert.equal(empty.code, 0, empty.stderr);
  assert.match(empty.stdout, /No scope targets in .*scope-targets\.json/);

  const emptyJson = await runCli(['scope', 'list', '--state-dir', stateDirectory, '--json']);
  assert.equal(emptyJson.code, 0, emptyJson.stderr);
  assert.deepEqual(parse(emptyJson.stdout), { store: storePath, count: 0, targets: [] });

  assert.equal((await runCli(['scope', 'add', await writeTargetFile(directory, target({ target_id: 'beta' })), '--state-dir', stateDirectory])).code, 0);
  assert.equal((await runCli(['scope', 'add', await writeTargetFile(directory, target({ target_id: 'alpha', allowed_domains: ['alpha.test'] }), 'alpha.json'), '--state-dir', stateDirectory])).code, 0);

  const listed = await runCli(['scope', 'list', '--state-dir', stateDirectory]);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, /Scope targets in .* \(2\):/);
  assert.ok(listed.stdout.indexOf('alpha |') < listed.stdout.indexOf('beta |'), 'sorted by target_id');
  assert.match(listed.stdout, /decision: —/);

  const withUrl = await runCli(['scope', 'list', '--state-dir', stateDirectory, '--url', 'https://alpha.test/docs']);
  assert.equal(withUrl.code, 0, withUrl.stderr);
  assert.match(withUrl.stdout, /alpha \| valid \| decision: IN_SCOPE/);
  assert.match(withUrl.stdout, /beta \| valid \| decision: HOST_OUT_OF_SCOPE/);

  const firstJson = await runCli(['scope', 'list', '--state-dir', stateDirectory, '--json']);
  const secondJson = await runCli(['scope', 'list', '--state-dir', stateDirectory, '--json']);
  assert.equal(firstJson.stdout, secondJson.stdout);
  assert.equal(parse(firstJson.stdout).count, 2);
  assert.deepEqual(parse(firstJson.stdout).targets.map((entry) => entry.targetId), ['alpha', 'beta']);

  const both = await runCli(['scope', 'list', '--state-dir', stateDirectory, '--store', storePath]);
  assert.equal(both.code, 1);
  assert.match(both.stderr, /mutually exclusive/);

  const byStore = await runCli(['scope', 'list', '--store', storePath, '--json']);
  assert.equal(byStore.code, 0, byStore.stderr);
  assert.equal(parse(byStore.stdout).count, 2);
});

test('CLI scope list refuses a symlinked store and works while the kill-switch is armed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-list-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');
  await fs.mkdir(stateDirectory, { recursive: true });
  const planted = await writeTargetFile(directory, '{"planted":true}', 'planted.json');
  await fs.symlink(planted, storePath);

  const refused = await runCli(['scope', 'list', '--state-dir', stateDirectory]);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /SCOPE_STORE_SYMLINK_REFUSED/);
  assert.equal(await fs.readFile(planted, 'utf8'), '{"planted":true}');

  await fs.unlink(storePath);
  assert.equal((await runCli(['scope', 'add', await writeTargetFile(directory, target()), '--state-dir', stateDirectory])).code, 0);

  const triggered = await runCli(['kill-switch', 'trigger', '--actor', 'tester', '--reason', 'lab stop', '--state-dir', stateDirectory]);
  assert.equal(triggered.code, 0, triggered.stderr);
  // Read-only: list needs no kill-switch guard and still works armed.
  const listed = await runCli(['scope', 'list', '--state-dir', stateDirectory]);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, /local-lab \| valid/);
});

test('CLI: scope add refuses a target with an invalid default_excluded_paths, check-scope honors the override', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-list-');
  const stateDirectory = path.join(directory, 'state');

  const bad = await writeTargetFile(directory, target({ default_excluded_paths: 'nope' }));
  const addResult = await runCli(['scope', 'add', bad, '--state-dir', stateDirectory]);
  assert.equal(addResult.code, 1);
  assert.match(addResult.stderr, /SCOPE_TARGET_INVALID/);

  const overridden = await writeTargetFile(directory, target({ target_id: 'no-defaults', default_excluded_paths: [] }), 'no-defaults.json');
  const decided = await runCli(['check-scope', '--target', overridden, '--url', 'https://app.example.test/logout']);
  assert.equal(decided.code, 0, decided.stderr);
  assert.equal(parse(decided.stdout).decision.reason, 'IN_SCOPE');

  const explained = await runCli(['check-scope', '--target', overridden, '--url', 'https://app.example.test/logout', '--explain']);
  assert.equal(explained.code, 0, explained.stderr);
  assert.match(explained.stdout, /Deciding rule: IN_SCOPE/);
});
