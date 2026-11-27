// Pre-push gate tests (round 99).
//
// The changelog rule pins the round-94 lesson: a CHANGELOG entry that
// misses its code commit and lands as a follow-up (683169c) is a
// silent gap — the rule requires the entry in the SAME commit. The
// rule is tested here against scratch git repos (via the
// SENTINEL_PRE_PUSH_REPO_ROOT test seam) so the assertions do not
// depend on this repo's own history, plus one assertion against the
// real repo: the previous commit must itself satisfy the rule.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const { makeTempDir } = require('./helpers/temp-dir');
const {
  touchesCode, commitNeedsChangelog, checkCommits, resolveRange, runChangelogCheck, main,
} = require('../scripts/pre-push-check.cjs');

test('changelog rule: code commits need CHANGELOG.md in the same commit', () => {
  assert.equal(commitNeedsChangelog(['src/foo.js']), true);
  assert.equal(commitNeedsChangelog(['bin/sentinel.js']), true);
  assert.equal(commitNeedsChangelog(['tests/foo.test.js']), true);
  assert.equal(commitNeedsChangelog(['scripts/pre-push-check.cjs']), true);
  assert.equal(commitNeedsChangelog(['.github/workflows/ci-guards.yml']), true);
  assert.equal(commitNeedsChangelog(['package.json']), true);
  assert.equal(commitNeedsChangelog(['src/foo.js', 'CHANGELOG.md']), false);
  assert.equal(commitNeedsChangelog(['docs/foo.md']), false);
  assert.equal(commitNeedsChangelog(['CHANGELOG.md']), false);
  assert.equal(commitNeedsChangelog([]), false);
  assert.equal(touchesCode(['docs/foo.md']), false);
});

test('changelog rule: checkCommits reports only the offending commits', () => {
  const { failures } = checkCommits([
    { sha: 'aaa', files: ['src/a.js'] },
    { sha: 'bbb', files: ['src/b.js', 'CHANGELOG.md'] },
    { sha: 'ccc', files: ['docs/c.md'] },
  ]);
  assert.deepEqual(failures.map((failure) => failure.sha), ['aaa']);
});

test('resolveRange: empty and all-zero starts fall back to HEAD~1..HEAD', () => {
  assert.equal(resolveRange(undefined), 'HEAD~1..HEAD');
  assert.equal(resolveRange(''), 'HEAD~1..HEAD');
  assert.equal(resolveRange('0000000000000000000000000000000000000000..abc1234'), 'HEAD~1..HEAD');
  assert.equal(resolveRange('abc1234..def5678'), 'abc1234..def5678');
});

async function git(cwd, ...args) {
  await execFileAsync('git', args, { cwd, timeout: 10_000 });
}

async function makeRepo(t) {
  const dir = await makeTempDir(t, 'sentinel-prepush-');
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'test@example.test');
  await git(dir, 'config', 'user.name', 'Pre-push Test');
  // An initial commit, so HEAD~1 resolves for the ranges below.
  await commitFile(dir, 'README.md', '# Test repo\n', 'initial commit');
  return dir;
}

async function commitFile(dir, relPath, content, message) {
  const target = path.join(dir, relPath);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, content);
  await git(dir, 'add', relPath);
  await git(dir, 'commit', '-q', '-m', message);
  const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: dir });
  return stdout.trim();
}

test('changelog rule against a scratch repo: code-only commit fails, CHANGELOG commit passes', async (t) => {
  const dir = await makeRepo(t);
  const sha1 = await commitFile(dir, 'src/foo.js', "'use strict';\n", 'code without changelog');
  let result = runChangelogCheck('HEAD~1..HEAD', { repoRoot: dir });
  assert.equal(result.ok, false);
  assert.deepEqual(result.failures.map((failure) => failure.sha), [sha1]);

  await commitFile(dir, 'CHANGELOG.md', '# Changelog\n', 'changelog entry');
  result = runChangelogCheck('HEAD~1..HEAD', { repoRoot: dir });
  assert.equal(result.ok, true);
  assert.deepEqual(result.failures, []);

  // The range covering both commits still fails: the rule is per
  // commit, and the first commit never gained its entry.
  result = runChangelogCheck('HEAD~2..HEAD', { repoRoot: dir });
  assert.equal(result.ok, false);
  assert.deepEqual(result.failures.map((failure) => failure.sha), [sha1]);
});

test('changelog rule against a scratch repo: docs-only commit passes', async (t) => {
  const dir = await makeRepo(t);
  await commitFile(dir, 'docs/note.md', '# Note\n', 'docs only');
  const result = runChangelogCheck('HEAD~1..HEAD', { repoRoot: dir });
  assert.equal(result.ok, true);
});

test('changelog rule: unresolvable range warns locally and throws in CI mode', async (t) => {
  const dir = await makeRepo(t);
  await commitFile(dir, 'src/foo.js', "'use strict';\n", 'only commit');
  const warned = runChangelogCheck('HEAD~5..HEAD', { repoRoot: dir });
  assert.equal(warned.skipped, true);
  assert.equal(warned.ok, true);
  assert.throws(() => runChangelogCheck('HEAD~5..HEAD', { strict: true, repoRoot: dir }), (error) => error.code === 'GIT_RANGE_FAILED');
});

test('pre-push main: --help exits 0, unknown flag exits 2', async () => {
  const writes = [];
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk) => { writes.push(String(chunk)); return true; };
  process.stderr.write = (chunk) => { writes.push(String(chunk)); return true; };
  try {
    assert.equal(main(['--help']), 0);
    assert.equal(main(['--bogus-flag']), 2);
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }
  assert.match(writes.join(''), /Usage: node scripts\/pre-push-check\.cjs/);
});

test('pre-push changelog rule: the real repo previous commit satisfies it', () => {
  const result = runChangelogCheck('HEAD~1..HEAD');
  assert.equal(result.ok, true, `previous commit fails the changelog rule: ${JSON.stringify(result.failures)}`);
});
