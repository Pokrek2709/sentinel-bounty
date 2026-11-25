const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { closeAndRemoveLock } = require('../src/policy/lock-file');

test('closeAndRemoveLock removes the lock file even when close() throws, and the close error propagates', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-lock-file-');
  try {
    const lockFile = path.join(directory, 'x.lock');
    await fs.writeFile(lockFile, 'locked');
    const closeError = new Error('EBADF');
    const handle = { close: async () => { throw closeError; } };
    await assert.rejects(closeAndRemoveLock(handle, lockFile), (error) => error === closeError);
    await assert.rejects(fs.stat(lockFile), (error) => error.code === 'ENOENT');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('closeAndRemoveLock removes the lock file on the clean path and swallows a missing file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-lock-file-');
  try {
    const lockFile = path.join(directory, 'x.lock');
    await fs.writeFile(lockFile, 'locked');
    let closed = false;
    await closeAndRemoveLock({ close: async () => { closed = true; } }, lockFile);
    assert.equal(closed, true);
    await assert.rejects(fs.stat(lockFile), (error) => error.code === 'ENOENT');
    // A lock file that is already gone is not an error.
    await closeAndRemoveLock({ close: async () => {} }, lockFile);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('closeAndRemoveLock surfaces a non-ENOENT removal failure', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-lock-file-');
  try {
    const lockFile = path.join(directory, 'x.lock');
    await fs.mkdir(lockFile);
    // unlink() on a directory fails (EISDIR/EPERM by platform), never ENOENT.
    await assert.rejects(
      closeAndRemoveLock({ close: async () => {} }, lockFile),
      (error) => error.code !== 'ENOENT',
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
