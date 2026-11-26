// Shared filesystem-error taxonomy for the operator-facing error codes.
// Every classifier returns the error code, or null when the error is not a
// classified storage failure (callers rethrow it raw). Error messages carry
// only the code, never a path, token, or digest value.
//
// - EEXIST is NOT classified here: a live lock is a locked error only after
//   the retry timeout, decided by the caller.
// - EACCES/EPERM: the operator cannot access the storage location at all.
// - ENOSPC/EDQUOT: the disk/quota is exhausted.
// - ENOTDIR: a path component is not a directory.
//
// Windows caveat (round 83): on Windows a path through a file does NOT
// yield ENOTDIR — the OS reports the path as not found (ENOENT) — so an
// ENOENT alone cannot tell "file missing" apart from "a parent is a
// file". hasNonDirectoryAncestor() makes that distinction by walking
// the ancestors: it exists for exactly that ENOENT disambiguation and
// is only consulted when the error code is ENOENT.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

// True when some ancestor of filePath exists and is not a directory
// (a regular file, a symlink to one, ...): traversing through it can
// never succeed, so an ENOENT for filePath means the path is invalid,
// not merely absent. False when an existing directory ancestor is
// found first (the missing part is genuinely absent) or the walk cannot
// tell (permission failure, root reached). Follows symlinks, so a
// symlink to a directory counts as a directory — traversal through it
// works — while a symlink to a file counts as a file.
async function hasNonDirectoryAncestor(filePath) {
  let dir = path.dirname(filePath);
  for (;;) {
    let stat = null;
    try {
      stat = await fs.stat(dir);
    } catch (error) {
      // ENOENT (Windows: also the code for a path through a file) and
      // ENOTDIR (POSIX: a component above is not a directory) both
      // mean "keep walking up to find the offending ancestor".
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') return false;
      const parent = path.dirname(dir);
      if (parent === dir) return false;
      dir = parent;
      continue;
    }
    return !stat.isDirectory();
  }
}

function classifyStorageError(error) {
  if (!error || typeof error.code !== 'string') return null;
  if (['ENOSPC', 'EDQUOT'].includes(error.code)) return 'KILL_SWITCH_STATE_UNAVAILABLE';
  if (['EACCES', 'EPERM'].includes(error.code)) return 'KILL_SWITCH_STATE_PERMISSION_DENIED';
  if (error.code === 'ENOTDIR') return 'KILL_SWITCH_STATE_PATH_INVALID';
  return null;
}

// Rotation-lock failures use the RESET_TOKEN_ROTATION_* namespace so they
// stay distinct from state-lock failures (RESET_TOKEN_ROTATION_LOCKED is
// the pre-existing live-lock code).
function classifyRotationLockError(error) {
  if (!error || typeof error.code !== 'string') return null;
  if (['EACCES', 'EPERM'].includes(error.code)) return 'RESET_TOKEN_ROTATION_PERMISSION_DENIED';
  if (['ENOSPC', 'EDQUOT'].includes(error.code)) return 'RESET_TOKEN_ROTATION_UNAVAILABLE';
  if (error.code === 'ENOTDIR') return 'RESET_TOKEN_ROTATION_PATH_INVALID';
  return null;
}

// Digest-file (operator reset-token hash file) access failures. A
// permission/path failure reading the digest is not an authorization
// failure, and must not be reported as one.
function classifyTokenFileError(error) {
  if (!error || typeof error.code !== 'string') return null;
  if (['EACCES', 'EPERM'].includes(error.code)) return 'RESET_TOKEN_FILE_PERMISSION_DENIED';
  if (error.code === 'ENOTDIR') return 'RESET_TOKEN_FILE_PATH_INVALID';
  return null;
}

// State-file read failures. A JSON parse failure or an invalid shape is a
// corrupt state, not a filesystem error, so it is classified by the caller
// through isCorruptStateError() instead.
function classifyStateReadError(error) {
  if (!error || typeof error.code !== 'string') return null;
  if (['EACCES', 'EPERM'].includes(error.code)) return 'KILL_SWITCH_STATE_PERMISSION_DENIED';
  if (error.code === 'ENOTDIR') return 'KILL_SWITCH_STATE_PATH_INVALID';
  if (['ENOSPC', 'EDQUOT'].includes(error.code)) return 'KILL_SWITCH_STATE_UNAVAILABLE';
  return null;
}

// A state file that cannot be parsed, or parses to the wrong shape, is
// corrupt. This covers JSON.parse SyntaxErrors and the 'Invalid
// kill-switch state.' shape rejection.
function isCorruptStateError(error) {
  return error instanceof SyntaxError || (error instanceof Error && error.message === 'Invalid kill-switch state.');
}

module.exports = { classifyStorageError, classifyRotationLockError, classifyTokenFileError, classifyStateReadError, isCorruptStateError, hasNonDirectoryAncestor };
