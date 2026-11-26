const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { scanPendingPromises, scanText, normalizeRelativePath } = require('./helpers/pending-promise-scanner');

const REPO_ROOT = path.resolve(__dirname, '..');

test('the real tree has no unallowlisted fire-and-forget promise', async () => {
  const allowlist = JSON.parse(await fs.readFile(path.join(__dirname, 'pending-promise-allowlist.json'), 'utf8'));
  const { violations, stale } = await scanPendingPromises(REPO_ROOT, allowlist);
  assert.deepEqual(violations, [], `unallowlisted fire-and-forget promise sites: ${JSON.stringify(violations, null, 2)}`);
  assert.deepEqual(stale, [], `stale allowlist entries (no matching code left): ${JSON.stringify(stale, null, 2)}`);
});

test('the scanner flags a bare unregister(), an async executor, and an unallowlisted .then()', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-promise-guard-');
  try {
    await fs.mkdir(path.join(directory, 'src'));
    await fs.mkdir(path.join(directory, 'bin'));
    await fs.writeFile(path.join(directory, 'src', 'a.js'), [
      'async function run(registration) {',
      '  unregister();',
      '  await unregister();',
      '  const p = new Promise(async (resolve) => resolve(1));',
      '  Promise.resolve(1).then(() => 2);',
      '}',
      '',
    ].join('\n'));
    await fs.writeFile(path.join(directory, 'bin', 'b.js'), 'void finishRun(1);\n');
    const { violations, stale } = await scanPendingPromises(directory, []);
    assert.deepEqual(violations.map((entry) => entry.kind), ['bare-unregister', 'async-executor', 'then']);
    assert.deepEqual(stale, []);
    // The awaited unregister(), the `void finishRun(...)` call, and
    // the definition forms must NOT be flagged.
    assert.equal(violations.some((entry) => entry.text.includes('await unregister')), false);
    assert.equal(violations.some((entry) => entry.kind === 'bare-finish-run'), false);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('an allowlist entry excuses its occurrence and goes stale when the code moves on', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-promise-guard-allow-');
  try {
    await fs.mkdir(path.join(directory, 'src'));
    await fs.mkdir(path.join(directory, 'bin'));
    await fs.writeFile(path.join(directory, 'src', 'a.js'), 'Promise.resolve(1).then(() => 2, () => 3);\n');
    const allowlist = [{ file: 'src/a.js', kind: 'then', substring: 'Promise.resolve(1).then(', reason: 'test excuse' }];
    assert.deepEqual((await scanPendingPromises(directory, allowlist)).violations, []);
    assert.deepEqual((await scanPendingPromises(directory, allowlist)).stale, []);
    await fs.writeFile(path.join(directory, 'src', 'a.js'), 'Promise.resolve(1);\n');
    assert.deepEqual((await scanPendingPromises(directory, allowlist)).stale, allowlist);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('normalizeRelativePath folds Windows backslashes to the allowlist forward-slash spelling', () => {
  // Round 83, Windows run 54: path.relative yields backslashes on
  // Windows, so no allowlist entry (forward slashes) ever matched.
  // The allowlist comparison itself is exercised by the real-tree test
  // on the Windows runner; this pins the folding with an explicit
  // Windows separator, plus the no-op on the current platform.
  assert.equal(normalizeRelativePath('src\\execution\\controlled-wrapper.js', '\\'), 'src/execution/controlled-wrapper.js');
  assert.equal(normalizeRelativePath('bin\\sentinel.js', '\\'), 'bin/sentinel.js');
  assert.equal(normalizeRelativePath('src/execution/controlled-wrapper.js'), 'src/execution/controlled-wrapper.js');
});

test('scanText ignores commented-out code', () => {
  const occurrences = scanText('src/a.js', [
    '// unregister();',
    'const x = 1; // Promise.resolve(1).then(() => 2);',
    '/* setInterval(async () => {}) */',
    'await unregister();',
  ].join('\n'));
  assert.deepEqual(occurrences, []);
});
