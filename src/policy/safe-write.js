// Symlink-refusing file writes (Phase 8 hardening, round 34).
//
// Every CLI output path takes its destination from an operator flag
// (--out, --output, --probe-dir), so a bare `path.resolve` is not itself
// a traversal bug: the operator chose the path. The real hazard is a
// PLANTED symlink at a predictable output path: `fs.writeFile` follows
// symlinks, so attacker-influenced report content (a finding's
// description is untrusted data) would be written to the link target —
// e.g. a shell startup file — instead of the intended report file.
//
// This helper refuses to write through a symlink at the exact target
// path: an lstat pre-check catches the common case on all platforms,
// and O_NOFOLLOW closes the check-then-write race on POSIX (it is
// ignored on Windows, where the lstat is the protection). Parent path
// components are still the operator's own path and are not checked.
'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');

async function writeFileRefusingSymlink(filePath, content, { encoding = 'utf8', mode = 0o600 } = {}) {
  let stat = null;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && stat.isSymbolicLink()) {
    throw new Error(`Refusing to write through a symbolic link: ${filePath}`);
  }
  if (stat && stat.isDirectory()) {
    throw new Error(`Refusing to write to a directory: ${filePath}`);
  }
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC
    | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
  let handle;
  try {
    handle = await fs.open(filePath, flags, mode);
  } catch (error) {
    if (error.code === 'ELOOP') throw new Error(`Refusing to write through a symbolic link: ${filePath}`);
    throw error;
  }
  try {
    await handle.writeFile(content, { encoding });
    await handle.chmod(mode);
  } finally {
    await handle.close();
  }
}

module.exports = { writeFileRefusingSymlink };
