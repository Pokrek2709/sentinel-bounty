// CI guards guard (round 99).
//
// The ci-guards workflow (.github/workflows/ci-guards.yml) is
// load-bearing — it runs the suite, the Windows simulation, and the
// changelog rule on every push — but a YAML workflow is only checked
// by GitHub when it runs, so a typo in a job name or a step command
// would fail silently until the next push. These tests pin the
// workflow's shape from the repo side: the job exists, it runs on
// Linux, every guard step is present, and no step references the
// /tmp preload the VM wipes on restart (round 95 rebuilt it
// mid-round). YAML validity itself is proven by the workflow running
// on push; these tests pin the content GitHub would run.
//
// The Windows workflow is pinned here too, in one place: round 99
// adds guards, it does not change windows-test.yml, and this test
// fails if that file stops running the suite on windows-latest.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const REPO_ROOT = path.resolve(__dirname, '..');
const GUARDS_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'ci-guards.yml');
const WINDOWS_WORKFLOW = path.join(REPO_ROOT, '.github', 'workflows', 'windows-test.yml');

test('ci-guards workflow exists and runs the suite, the simulation, verify-install, and the changelog rule', () => {
  const content = fs.readFileSync(GUARDS_WORKFLOW, 'utf8');
  assert.match(content, /^name: ci-guards$/m);
  assert.match(content, /^  ci-guards:$/m);
  assert.match(content, /runs-on: ubuntu-latest/);
  assert.match(content, /fetch-depth: 0/);
  assert.match(content, /run: npm test/);
  assert.match(content, /run: node --test --require \.\/scripts\/fake-win32\.cjs/);
  assert.match(content, /run: node bin\/sentinel\.js verify-install/);
  assert.match(content, /run: node scripts\/pre-push-check\.cjs --changelog-only --range/);
  assert.doesNotMatch(content, /\/tmp\/fake-win32/);
});

test('windows-test workflow still runs the suite on windows-latest', () => {
  const content = fs.readFileSync(WINDOWS_WORKFLOW, 'utf8');
  assert.match(content, /runs-on: windows-latest/);
  assert.match(content, /run: npm test/);
});
