// Lock-file close + removal (Phase 8 hardening, round 47).
//
// Two call sites close a lock file and then remove it — the audit
// log's #withLock and the CLI's token-rotation lock — and both had
// the same latent wart: `await handle.close()` in a `finally` whose
// next line removes the lock file. If close() throws (EBADF, EIO),
// the removal is skipped and the stale lock stays behind; the next
// acquirer then fails with AUDIT_LOG_LOCKED /
// RESET_TOKEN_ROTATION_LOCKED until the 60 s stale-lock reaper
// removes it. The failure mode is rare (close() almost never throws),
// but the fix is one helper: close first, remove the lock file in a
// `finally` so removal always runs. If close() throws, its error
// propagates AFTER the removal; if the removal itself throws a
// non-ENOENT error, that error replaces it (both are storage errors
// and the removal failure is the more actionable one).
'use strict';

const fs = require('node:fs/promises');

async function closeAndRemoveLock(handle, lockFile) {
  try {
    await handle.close();
  } finally {
    await fs.unlink(lockFile).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

module.exports = { closeAndRemoveLock };
