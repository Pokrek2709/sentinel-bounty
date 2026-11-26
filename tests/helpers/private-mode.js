'use strict';

// Private-mode assertions that work on every platform (round 81).
//
// The problem: POSIX permission bits do not exist on Windows.
// Node reports every regular file as 0666 and every directory as
// 0777 there, and `fs.chmod` is a no-op except for the read-only
// bit. So `stat().mode & 0o777 === 0o600` — asserted in ~20 places
// across the suite — can NEVER pass on Windows, and that is why the
// `windows-test` workflow failed on all 53 runs since round 28.
// The writers still pass `mode: 0o600`/`0o700` at creation time;
// on Windows that option is simply ignored by the OS.
//
// The fix: on POSIX, assert the exact mode bits (unchanged
// behavior — the privacy guarantee). On Windows, assert what the
// platform CAN guarantee: the entry exists and is the expected
// kind (a regular file for 0600, a directory for 0700). The
// privacy guarantee there is the OS ACL, which Node cannot
// observe — so the assertion says exactly that instead of
// pretending to check mode bits. This is the same precedent as
// `persistent-kill-switch.test.js`, which already guards its mode
// assertion with `process.platform !== 'win32'`.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { posixModesApply } = require('../../src/policy/state-permissions');

function expectedKind(expectedMode) {
  if (expectedMode === 0o600) return 'file';
  if (expectedMode === 0o700) return 'directory';
  throw new Error(`assertPrivateMode: unsupported expected mode 0o${expectedMode.toString(8)} (only 0o600 files and 0o700 directories)`);
}

function assertPrivateModeSync(target, expectedMode, message) {
  const stat = fs.statSync(target);
  if (posixModesApply()) {
    assert.equal(stat.mode & 0o777, expectedMode, message);
    return;
  }
  // Windows: no POSIX mode bits to check. The entry must exist
  // and be the expected kind; anything else is a real failure.
  const kind = expectedKind(expectedMode);
  if (kind === 'file') {
    assert.ok(stat.isFile(), message || `expected ${target} to be a regular file`);
  } else {
    assert.ok(stat.isDirectory(), message || `expected ${target} to be a directory`);
  }
}

async function assertPrivateMode(target, expectedMode, message) {
  const stat = await fs.promises.stat(target);
  if (posixModesApply()) {
    assert.equal(stat.mode & 0o777, expectedMode, message);
    return;
  }
  const kind = expectedKind(expectedMode);
  if (kind === 'file') {
    assert.ok(stat.isFile(), message || `expected ${target} to be a regular file`);
  } else {
    assert.ok(stat.isDirectory(), message || `expected ${target} to be a directory`);
  }
}

module.exports = { assertPrivateMode, assertPrivateModeSync, posixModesApply };
