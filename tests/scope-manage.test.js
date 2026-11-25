// Scope target management (round 53, Phase 3).
//
// `sentinel scope add <target.json>` / `sentinel scope remove <target-id>`
// manage the persistent store `<state-dir>/scope-targets.json`; `sentinel
// check-scope --store <store-file> --target-id <id>` resolves a target
// from that store. Fixtures only; no scanner, no network, no live
// target. The real state directory is never touched — every test uses
// its own temp state dir.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { makeTempDir } = require('./helpers/temp-dir');
const {
  ScopeStoreError,
  loadScopeTargets,
  addScopeTarget,
  removeScopeTarget,
  findScopeTarget,
} = require('../src/scope/target-store');

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

async function auditEvents(stateDirectory) {
  let text = '';
  try {
    text = await fs.readFile(path.join(stateDirectory, 'audit.jsonl'), 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

async function writeTargetFile(directory, contents, name = 'target.json') {
  const file = path.join(directory, name);
  await fs.writeFile(file, typeof contents === 'string' ? contents : `${JSON.stringify(contents, null, 2)}\n`, { mode: 0o600 });
  return file;
}

test('scope add stores the target, audits it, and check-scope --store resolves it', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');

  const added = await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory]);
  assert.equal(added.code, 0, added.stderr);
  assert.deepEqual(parse(added.stdout), {
    added: true,
    targetId: 'local-lab',
    store: storePath,
    auditLogged: true,
  });

  const stored = JSON.parse(await fs.readFile(storePath, 'utf8'));
  assert.equal(stored.schema_version, 1);
  assert.equal(stored.targets.length, 1);
  assert.equal(stored.targets[0].target_id, 'local-lab');
  assert.equal((await fs.stat(storePath)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(stateDirectory)).mode & 0o777, 0o700);
  const events = await auditEvents(stateDirectory);
  assert.equal(events.filter((event) => event.event === 'SCOPE_TARGET_ADDED').length, 1);
  assert.equal(events.find((event) => event.event === 'SCOPE_TARGET_ADDED').details.targetId, 'local-lab');

  const decided = await runCli(['check-scope', '--store', storePath, '--target-id', 'local-lab', '--url', 'https://app.example.test/docs']);
  assert.equal(decided.code, 0, decided.stderr);
  assert.equal(parse(decided.stdout).decision.reason, 'IN_SCOPE');

  const explained = await runCli(['check-scope', '--store', storePath, '--target-id', 'local-lab', '--url', 'https://app.example.test/docs', '--explain']);
  assert.equal(explained.code, 0, explained.stderr);
  assert.match(explained.stdout, /Deciding rule: IN_SCOPE/);
  assert.match(explained.stdout, /Policy source: .*scope-targets\.json/);
});

test('scope add of an already-present target is an idempotent no-op', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');

  assert.equal((await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory])).code, 0);
  const before = await fs.readFile(storePath, 'utf8');
  const duplicate = await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory]);
  assert.equal(duplicate.code, 0, duplicate.stderr);
  assert.deepEqual(parse(duplicate.stdout), {
    added: false,
    alreadyPresent: true,
    targetId: 'local-lab',
    store: storePath,
  });
  assert.equal(await fs.readFile(storePath, 'utf8'), before);
  const events = await auditEvents(stateDirectory);
  assert.equal(events.filter((event) => event.event === 'SCOPE_TARGET_ADDED').length, 1);
});

test('scope add refuses an invalid target and writes nothing', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const badTarget = await writeTargetFile(directory, target({ allowed_domains: [] }));
  const result = await runCli(['scope', 'add', badTarget, '--state-dir', stateDirectory]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /SCOPE_TARGET_INVALID/);
  await assert.rejects(fs.stat(path.join(stateDirectory, 'scope-targets.json')), /ENOENT/);

  const malformed = await writeTargetFile(directory, '{ not json', 'malformed.json');
  const malformedResult = await runCli(['scope', 'add', malformed, '--state-dir', stateDirectory]);
  assert.equal(malformedResult.code, 1);
  assert.match(malformedResult.stderr, /SCOPE_TARGET_INVALID/);
});

test('scope remove deletes the target, audits it, and check-scope flips back', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');

  assert.equal((await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory])).code, 0);
  const removed = await runCli(['scope', 'remove', 'local-lab', '--state-dir', stateDirectory]);
  assert.equal(removed.code, 0, removed.stderr);
  assert.deepEqual(parse(removed.stdout), {
    removed: true,
    targetId: 'local-lab',
    store: storePath,
    auditLogged: true,
  });
  assert.deepEqual(JSON.parse(await fs.readFile(storePath, 'utf8')).targets, []);
  const events = await auditEvents(stateDirectory);
  assert.equal(events.filter((event) => event.event === 'SCOPE_TARGET_REMOVED').length, 1);

  const decided = await runCli(['check-scope', '--store', storePath, '--target-id', 'local-lab', '--url', 'https://app.example.test/docs']);
  assert.equal(decided.code, 1);
  assert.match(decided.stderr, /SCOPE_TARGET_NOT_FOUND/);
});

test('scope remove of an absent target fails cleanly and writes nothing', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');

  assert.equal((await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory])).code, 0);
  const before = await fs.readFile(storePath, 'utf8');
  const result = await runCli(['scope', 'remove', 'no-such-target', '--state-dir', stateDirectory]);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /SCOPE_TARGET_NOT_FOUND/);
  assert.equal(await fs.readFile(storePath, 'utf8'), before);
  const events = await auditEvents(stateDirectory);
  assert.equal(events.filter((event) => event.event === 'SCOPE_TARGET_REMOVED').length, 0);
});

test('a symlinked or corrupt store file is refused, never written through', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');
  await fs.mkdir(stateDirectory, { recursive: true });
  const linkTarget = await writeTargetFile(directory, '{"planted":true}', 'planted.json');
  await fs.symlink(linkTarget, storePath);

  const addResult = await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory]);
  assert.equal(addResult.code, 1);
  assert.match(addResult.stderr, /SCOPE_STORE_SYMLINK_REFUSED/);
  assert.equal(await fs.readFile(linkTarget, 'utf8'), '{"planted":true}');

  const removeResult = await runCli(['scope', 'remove', 'local-lab', '--state-dir', stateDirectory]);
  assert.equal(removeResult.code, 1);
  assert.match(removeResult.stderr, /SCOPE_STORE_SYMLINK_REFUSED/);

  await fs.unlink(storePath);
  await fs.writeFile(storePath, '{ corrupt json', { mode: 0o600 });
  const corruptAdd = await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory]);
  assert.equal(corruptAdd.code, 1);
  assert.match(corruptAdd.stderr, /SCOPE_STORE_CORRUPT/);
  const corruptRemove = await runCli(['scope', 'remove', 'local-lab', '--state-dir', stateDirectory]);
  assert.equal(corruptRemove.code, 1);
  assert.match(corruptRemove.stderr, /SCOPE_STORE_CORRUPT/);
});

test('an armed kill-switch refuses both scope commands', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');

  const triggered = await runCli(['kill-switch', 'trigger', '--actor', 'tester', '--reason', 'lab stop', '--state-dir', stateDirectory]);
  assert.equal(triggered.code, 0, triggered.stderr);
  assert.equal(parse(triggered.stdout).triggered, true);

  const addResult = await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory]);
  assert.equal(addResult.code, 1);
  assert.equal(parse(addResult.stdout).reason, 'SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE');
  assert.equal(parse(addResult.stdout).added, false);
  await assert.rejects(fs.stat(storePath), /ENOENT/);

  const removeResult = await runCli(['scope', 'remove', 'local-lab', '--state-dir', stateDirectory]);
  assert.equal(removeResult.code, 1);
  assert.equal(parse(removeResult.stdout).reason, 'SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE');
  assert.equal(parse(removeResult.stdout).removed, false);
});

test('check-scope refuses --store together with --target, and requires --target-id', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const stateDirectory = path.join(directory, 'state');
  const storePath = path.join(stateDirectory, 'scope-targets.json');
  assert.equal((await runCli(['scope', 'add', TARGET_FILE, '--state-dir', stateDirectory])).code, 0);

  const both = await runCli(['check-scope', '--store', storePath, '--target', TARGET_FILE, '--target-id', 'local-lab', '--url', 'https://app.example.test/docs']);
  assert.equal(both.code, 1);
  assert.match(both.stderr, /mutually exclusive/);

  const missingId = await runCli(['check-scope', '--store', storePath, '--url', 'https://app.example.test/docs']);
  assert.equal(missingId.code, 1);
  assert.match(missingId.stderr, /requires --target-id/);

  const absent = await runCli(['check-scope', '--store', storePath, '--target-id', 'no-such-target', '--url', 'https://app.example.test/docs']);
  assert.equal(absent.code, 1);
  assert.match(absent.stderr, /SCOPE_TARGET_NOT_FOUND/);
});

test('scope commands reject missing actions and values', async (t) => {
  const noAction = await runCli(['scope']);
  assert.equal(noAction.code, 1);
  assert.match(noAction.stderr, /scope requires an action/);

  const unknownAction = await runCli(['scope', 'list']);
  assert.equal(unknownAction.code, 1);
  assert.match(unknownAction.stderr, /scope requires an action/);

  const noValue = await runCli(['scope', 'add']);
  assert.equal(noValue.code, 1);
  assert.match(noValue.stderr, /scope add requires a <target\.json> file/);

  const noId = await runCli(['scope', 'remove']);
  assert.equal(noId.code, 1);
  assert.match(noId.stderr, /scope remove requires a <target-id>/);
});

test('store module: missing file is empty, bad schema and bad entries fail loudly', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-scope-');
  const storePath = path.join(directory, 'scope-targets.json');

  assert.deepEqual(await loadScopeTargets(storePath), { schema_version: 1, targets: [] });
  assert.equal(await findScopeTarget(storePath, 'local-lab'), null);

  await fs.writeFile(storePath, JSON.stringify({ schema_version: 99, targets: [] }), { mode: 0o600 });
  await assert.rejects(loadScopeTargets(storePath), (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_STORE_UNSUPPORTED_SCHEMA');

  await fs.writeFile(storePath, JSON.stringify({ schema_version: 1, targets: [target({ allowed_domains: [] })] }), { mode: 0o600 });
  await assert.rejects(loadScopeTargets(storePath), (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_TARGET_INVALID');

  await fs.writeFile(storePath, JSON.stringify({ schema_version: 1, targets: [target()] }), { mode: 0o600 });
  assert.equal((await findScopeTarget(storePath, 'local-lab')).target_id, 'local-lab');
  assert.equal((await addScopeTarget(storePath, target())).added, false);
  assert.equal((await addScopeTarget(storePath, target())).alreadyPresent, true);
  assert.equal((await removeScopeTarget(storePath, 'local-lab')).removed, true);
  await assert.rejects(removeScopeTarget(storePath, 'local-lab'), (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_TARGET_NOT_FOUND');
  await assert.rejects(addScopeTarget(storePath, target({ allowed_domains: [] })), (error) => error instanceof ScopeStoreError && error.code === 'SCOPE_TARGET_INVALID');
});
