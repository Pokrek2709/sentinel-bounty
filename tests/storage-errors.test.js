const assert = require('node:assert/strict');
const test = require('node:test');
const {
  classifyStorageError,
  classifyRotationLockError,
  classifyTokenFileError,
  classifyStateReadError,
  isCorruptStateError,
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
