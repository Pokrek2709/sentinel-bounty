const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  classifyStorageError,
  classifyRotationLockError,
  classifyTokenFileError,
  classifyStateReadError,
  isCorruptStateError,
  hasNonDirectoryAncestor,
  classifyEnoentPathError,
} = require('../src/policy/storage-errors');

function fakeError(code) {
  const error = new Error(`${code}: fake`);
  error.code = code;
  return error;
}

test('classifyStorageError maps the state-lock taxonomy', () => {
  assert.equal(classifyStorageError(fakeError('EACCES')), 'KILL_SWITCH_STATE_PERMISSION_DENIED');
  assert.equal(classifyStorageError(fakeError('EPERM')), 'KILL_SWITCH_STATE_PERMISSION_DENIED');
  assert.equal(classifyStorageError(fakeError('ENOSPC')), 'KILL_SWITCH_STATE_UNAVAILABLE');
  assert.equal(classifyStorageError(fakeError('EDQUOT')), 'KILL_SWITCH_STATE_UNAVAILABLE');
  assert.equal(classifyStorageError(fakeError('ENOTDIR')), 'KILL_SWITCH_STATE_PATH_INVALID');
  assert.equal(classifyStorageError(fakeError('EEXIST')), null);
  assert.equal(classifyStorageError(fakeError('ENOENT')), null);
  assert.equal(classifyStorageError(new Error('no code')), null);
  assert.equal(classifyStorageError(null), null);
});

test('classifyRotationLockError maps the rotation-lock taxonomy', () => {
  assert.equal(classifyRotationLockError(fakeError('EACCES')), 'RESET_TOKEN_ROTATION_PERMISSION_DENIED');
  assert.equal(classifyRotationLockError(fakeError('EPERM')), 'RESET_TOKEN_ROTATION_PERMISSION_DENIED');
  assert.equal(classifyRotationLockError(fakeError('ENOSPC')), 'RESET_TOKEN_ROTATION_UNAVAILABLE');
  assert.equal(classifyRotationLockError(fakeError('EDQUOT')), 'RESET_TOKEN_ROTATION_UNAVAILABLE');
  assert.equal(classifyRotationLockError(fakeError('ENOTDIR')), 'RESET_TOKEN_ROTATION_PATH_INVALID');
  assert.equal(classifyRotationLockError(fakeError('EEXIST')), null);
  assert.equal(classifyRotationLockError(fakeError('ENOENT')), null);
  assert.equal(classifyRotationLockError(new Error('no code')), null);
  assert.equal(classifyRotationLockError(undefined), null);
});

test('classifyTokenFileError maps digest-read failures', () => {
  assert.equal(classifyTokenFileError(fakeError('EACCES')), 'RESET_TOKEN_FILE_PERMISSION_DENIED');
  assert.equal(classifyTokenFileError(fakeError('EPERM')), 'RESET_TOKEN_FILE_PERMISSION_DENIED');
  assert.equal(classifyTokenFileError(fakeError('ENOTDIR')), 'RESET_TOKEN_FILE_PATH_INVALID');
  assert.equal(classifyTokenFileError(fakeError('ENOSPC')), null);
  assert.equal(classifyTokenFileError(fakeError('ENOENT')), null);
  assert.equal(classifyTokenFileError(new SyntaxError('bad json')), null);
});

test('classifyStateReadError maps state-read failures', () => {
  assert.equal(classifyStateReadError(fakeError('EACCES')), 'KILL_SWITCH_STATE_PERMISSION_DENIED');
  assert.equal(classifyStateReadError(fakeError('EPERM')), 'KILL_SWITCH_STATE_PERMISSION_DENIED');
  assert.equal(classifyStateReadError(fakeError('ENOTDIR')), 'KILL_SWITCH_STATE_PATH_INVALID');
  assert.equal(classifyStateReadError(fakeError('ENOSPC')), 'KILL_SWITCH_STATE_UNAVAILABLE');
  assert.equal(classifyStateReadError(fakeError('EDQUOT')), 'KILL_SWITCH_STATE_UNAVAILABLE');
  assert.equal(classifyStateReadError(fakeError('EEXIST')), null);
  assert.equal(classifyStateReadError(fakeError('ENOENT')), null);
});

test('isCorruptStateError detects unparseable or wrong-shape state', () => {
  assert.equal(isCorruptStateError(new SyntaxError('Unexpected token')), true);
  assert.equal(isCorruptStateError(new Error('Invalid kill-switch state.')), true);
  assert.equal(isCorruptStateError(new Error('KILL_SWITCH_STATE_CORRUPT')), false);
  assert.equal(isCorruptStateError(fakeError('EACCES')), false);
});

test('classifyEnoentPathError maps a Windows-style ENOENT through a file parent to the caller path-invalid code', async (t) => {
  // Round 85: round 83 fixed only the digest-read path. The other
  // classifiers (state-lock, state-read, rotation-lock, audit-log)
  // still return null for ENOENT, so on Windows — where a path
  // through a file yields ENOENT, not ENOTDIR — they misclassify.
  // The helper is the shared disambiguation: a synthetic ENOENT
  // (the exact code Windows reports) plus a real file parent must
  // yield the caller's path-invalid code, while a genuinely missing
  // path must stay null ("missing", not "invalid").
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-storage-errors-'));
  t.after(async () => {
    await fs.rm(directory, { recursive: true, force: true });
  });
  const notADir = path.join(directory, 'notadir');
  await fs.writeFile(notADir, 'I am a regular file, not a directory');
  // Windows-style ENOENT under a file parent: invalid path.
  assert.equal(
    await classifyEnoentPathError(fakeError('ENOENT'), path.join(notADir, 'state', 'kill-switch.json'), 'KILL_SWITCH_STATE_PATH_INVALID'),
    'KILL_SWITCH_STATE_PATH_INVALID',
  );
  assert.equal(
    await classifyEnoentPathError(fakeError('ENOENT'), path.join(notADir, 'audit.jsonl'), 'AUDIT_LOG_PATH_INVALID'),
    'AUDIT_LOG_PATH_INVALID',
  );
  // Genuinely missing below a real directory: still missing, not invalid.
  assert.equal(
    await classifyEnoentPathError(fakeError('ENOENT'), path.join(directory, 'state', 'kill-switch.json'), 'KILL_SWITCH_STATE_PATH_INVALID'),
    null,
  );
  // Non-ENOENT errors are never the helper's business.
  assert.equal(
    await classifyEnoentPathError(fakeError('ENOTDIR'), path.join(notADir, 'state', 'kill-switch.json'), 'KILL_SWITCH_STATE_PATH_INVALID'),
    null,
  );
  assert.equal(
    await classifyEnoentPathError(fakeError('EACCES'), path.join(notADir, 'state', 'kill-switch.json'), 'KILL_SWITCH_STATE_PATH_INVALID'),
    null,
  );
  assert.equal(await classifyEnoentPathError(new Error('no code'), path.join(notADir, 'x'), 'KILL_SWITCH_STATE_PATH_INVALID'), null);
  assert.equal(await classifyEnoentPathError(null, path.join(notADir, 'x'), 'KILL_SWITCH_STATE_PATH_INVALID'), null);
});

test('hasNonDirectoryAncestor distinguishes a file parent from a genuinely missing file', async (t) => {
  // Round 83, Windows run 54: on Windows a path through a file yields
  // ENOENT, not ENOTDIR, so the rotate/revoke tests degraded to
  // "unauthorized" instead of reporting RESET_TOKEN_FILE_PATH_INVALID.
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-storage-errors-'));
  t.after(async () => {
    await fs.rm(directory, { recursive: true, force: true });
  });
  // A file as a parent component: the path can never resolve.
  const notADir = path.join(directory, 'notadir');
  await fs.writeFile(notADir, 'I am a regular file, not a directory');
  assert.equal(await hasNonDirectoryAncestor(path.join(notADir, 'digest', 'operator-reset-token.sha256')), true);
  // Genuinely missing below a real directory: no file ancestor.
  assert.equal(await hasNonDirectoryAncestor(path.join(directory, 'digest', 'operator-reset-token.sha256')), false);
  // An existing file itself has no non-directory ancestor.
  assert.equal(await hasNonDirectoryAncestor(notADir), false);
  // A path below an existing directory is genuinely missing.
  await fs.mkdir(path.join(directory, 'realdir'));
  assert.equal(await hasNonDirectoryAncestor(path.join(directory, 'realdir', 'missing.json')), false);
});
