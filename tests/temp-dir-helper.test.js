'use strict';

// Tests for the shared temp-dir helper (round 46, Phase 8).
//
// Proves a temp dir is removed when its test ends — after a passing
// test, and after a FAILING test (the leak that filled /tmp in rounds
// 39 and 45). Top-level tests in a file run sequentially in
// declaration order, so the second test can assert the first test's
// dir is gone. The failing-test proof runs a generated fixture in a
// child `node --test` process so the failure cannot fail this suite.
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);

let dirFromPassingTest;

test('helper: temp dir exists during its test and is removed after it', async (t) => {
  dirFromPassingTest = await makeTempDir(t, 'sentinel-helper-pass-');
  assert.equal((await fs.stat(dirFromPassingTest)).isDirectory(), true);
});

test('helper: the previous test temp dir is gone', async () => {
  await assert.rejects(fs.stat(dirFromPassingTest), /ENOENT/);
});

test('helper: temp dir is removed even when its test fails', async (t) => {
  const fixtureDir = await makeTempDir(t, 'sentinel-helper-fail-fixture-');
  const fixture = path.join(fixtureDir, 'failing.test.js');
  const marker = path.join(fixtureDir, 'dir.txt');
  const helperPath = path.resolve(__dirname, 'helpers', 'temp-dir.js');
  await fs.writeFile(fixture, `'use strict';
const test = require('node:test');
const fs = require('node:fs');
const { makeTempDir } = require(${JSON.stringify(helperPath)});
test('deliberately failing test', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-helper-fail-');
  fs.writeFileSync(${JSON.stringify(marker)}, dir, 'utf8');
  throw new Error('deliberate failure');
});
`, 'utf8');
  let code = 0;
  // node:test refuses to run recursively inside a test file
  // ("run() is being called recursively ... skipping running files"),
  // detected via NODE_TEST_CONTEXT / NODE_TEST_WORKER_ID. Scrub both
  // so the child is a fresh, ordinary test run.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  delete env.NODE_TEST_WORKER_ID;
  try {
    await execFileAsync(process.execPath, ['--test', fixture], { windowsHide: true, env });
  } catch (error) {
    code = error.code;
  }
  assert.notEqual(code, 0, 'fixture run must fail');
  const dir = await fs.readFile(marker, 'utf8');
  await assert.rejects(fs.stat(dir), /ENOENT/, 'failing test temp dir must be removed');
});
