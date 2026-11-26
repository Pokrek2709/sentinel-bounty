const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { ensurePrivateDir } = require('../policy/state-permissions');
const { closeAndRemoveLock } = require('../policy/lock-file');
const { classifyEnoentPathError } = require('../policy/storage-errors');
const { readRetentionPolicyLenient } = require('./audit-retention');

const MAX_RECORD_BYTES = 32 * 1024;
const MAX_LOG_BYTES = 10 * 1024 * 1024;
const DEFAULT_ROTATION_BYTES = 8 * 1024 * 1024;
const DEFAULT_RETENTION_COUNT = 3;
const DEFAULT_STALE_LOCK_MS = 60_000;

// Hash-chain format, version 1 (round 43). Every record appended after
// this round carries chainVersion, prevHash, and hash:
//   hash = SHA-256(JSON.stringify({
//     chainVersion: 1, version, event, eventId, recordedAt, details,
//     prevHash }))
// with keys in exactly that order (insertion order is preserved by
// JSON.stringify and by JSON.parse, so an independent checker that
// rebuilds the object in the same order reproduces the hash). The
// details hashed are the REDACTED details actually stored, never the
// caller's raw values. The first chained record of a fresh chain uses
// GENESIS_PREV_HASH as its prevHash. Verification checks internal
// consistency only (see verifyChain): it does NOT enforce that the
// first retained chained record chains from genesis, because rotation
// retention legitimately drops the oldest records — a dropped prefix
// is indistinguishable from a deleted one. See docs/audit-integrity-v1.md.
const CHAIN_VERSION = 1;
const GENESIS_PREV_HASH = '0'.repeat(64);

function computeAuditRecordHash(record) {
  const canonical = {
    chainVersion: CHAIN_VERSION,
    version: record.version,
    event: record.event,
    eventId: record.eventId,
    recordedAt: record.recordedAt,
    details: record.details,
    prevHash: record.prevHash,
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function requireAbsoluteOutside(file, skillDirectory, field) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) throw new TypeError(`${field} must be an absolute path.`);
  if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path.');
  const relative = path.relative(path.resolve(skillDirectory), path.resolve(file));
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) throw new TypeError(`${field} must be outside the skill directory.`);
}

// Classify a filesystem error from an audit lock/storage operation into the
// operator-facing audit error taxonomy. Same shape as the kill-switch state
// classifier in src/policy/persistent-kill-switch.js, with AUDIT_LOG_*
// codes: EEXIST is NOT classified here (a live audit lock is
// AUDIT_LOG_LOCKED only after the retry timeout, decided by the caller).
function classifyAuditStorageError(error) {
  if (!error || typeof error.code !== 'string') return null;
  if (['ENOSPC', 'EDQUOT'].includes(error.code)) return 'AUDIT_LOG_STORAGE_UNAVAILABLE';
  if (['EACCES', 'EPERM'].includes(error.code)) return 'AUDIT_LOG_PERMISSION_DENIED';
  if (error.code === 'ENOTDIR') return 'AUDIT_LOG_PATH_INVALID';
  return null;
}

function redact(value, key = '') {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (/authorization|cookie|password|secret|token|api[-_]?key/i.test(key)) return '[REDACTED]';
    // Only strings that look like URLs (scheme://...) go through the
    // URL parser: a Windows absolute path such as `C:\Users\...`
    // parses as a URL with scheme `c`, and toString() lowercases the
    // scheme, which silently corrupts the stored path (Windows run 54:
    // audit-retention store reported as `c:\...` instead of `C:\...`).
    // Credentials live in the authority component, which requires
    // `//`, so gating on `://` keeps the credential stripping while
    // leaving plain paths byte-identical.
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value)) {
      try {
        const parsed = new URL(value);
        parsed.username = '';
        parsed.password = '';
        return parsed.toString();
      } catch {
        // Not a parseable URL after all: fall through to the length cap.
      }
    }
    return value.length > 4_000 ? `${value.slice(0, 4_000)}…` : value;
  }
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => redact(entry, key));
  if (typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100).map(([childKey, childValue]) => [childKey, redact(childValue, childKey)]));
  return value;
}

class AuditLog {
  #logFile;
  #lockFile;
  #clock;
  #lockTimeoutMs;
  #lockRetryMs;
  #staleLockMs;
  #rotationBytes;
  #retentionCount;

  constructor({ logFile, skillDirectory, clock = () => Date.now(), lockTimeoutMs = 5_000, lockRetryMs = 25, staleLockMs = DEFAULT_STALE_LOCK_MS, rotationBytes = DEFAULT_ROTATION_BYTES, retentionCount = DEFAULT_RETENTION_COUNT } = {}) {
    requireAbsoluteOutside(logFile, skillDirectory, 'logFile');
    if (typeof clock !== 'function') throw new TypeError('clock must be a function.');
    if (![lockTimeoutMs, lockRetryMs, staleLockMs, rotationBytes, retentionCount].every((value) => Number.isInteger(value) && value >= 0)) throw new TypeError('Audit timing and retention values must be non-negative integers.');
    if (rotationBytes < 1 || rotationBytes > MAX_LOG_BYTES) throw new RangeError(`rotationBytes must be between 1 and ${MAX_LOG_BYTES}.`);
    if (retentionCount < 1) throw new RangeError('retentionCount must be at least 1.');
    this.#logFile = logFile;
    this.#lockFile = `${logFile}.lock`;
    this.#clock = clock;
    this.#lockTimeoutMs = lockTimeoutMs;
    this.#lockRetryMs = lockRetryMs;
    this.#staleLockMs = staleLockMs;
    this.#rotationBytes = rotationBytes;
    this.#retentionCount = retentionCount;
  }

  async #withLock(operation) {
    try {
      // ensurePrivateDir (round 45): mkdir({ recursive, mode })
      // alone never chmods a directory that already exists.
      await ensurePrivateDir(path.dirname(this.#logFile));
    } catch (error) {
      const classified = classifyAuditStorageError(error)
        || await classifyEnoentPathError(error, path.dirname(this.#logFile), 'AUDIT_LOG_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
    const started = this.#clock();
    let lock;
    while (!lock) {
      try {
        lock = await fs.open(this.#lockFile, 'wx', 0o600);
      } catch (error) {
        if (lock) {
          await lock.close();
          lock = undefined;
          await fs.unlink(this.#lockFile).catch((unlinkError) => { if (unlinkError.code !== 'ENOENT') throw unlinkError; });
        }
        const classified = classifyAuditStorageError(error)
          || await classifyEnoentPathError(error, this.#lockFile, 'AUDIT_LOG_PATH_INVALID');
        if (classified) throw new Error(classified);
        if (error.code !== 'EEXIST' || this.#clock() - started >= this.#lockTimeoutMs) throw new Error('AUDIT_LOG_LOCKED');
        try {
          const stat = await fs.stat(this.#lockFile);
          if (this.#clock() - stat.mtimeMs >= this.#staleLockMs) await fs.unlink(this.#lockFile);
        } catch (statError) {
          const statClassified = classifyAuditStorageError(statError)
            || await classifyEnoentPathError(statError, this.#lockFile, 'AUDIT_LOG_PATH_INVALID');
          if (statClassified) throw new Error(statClassified);
          if (statError.code !== 'ENOENT') throw statError;
        }
        await new Promise((resolve) => setTimeout(resolve, this.#lockRetryMs));
      }
    }
    try {
      await this.#cleanupTemporaryFiles();
      return await operation();
    } finally {
      // Round 47: close() throwing used to skip the lock removal and
      // leave a stale lock behind for up to 60 s. closeAndRemoveLock
      // removes the file even when close() throws.
      await closeAndRemoveLock(lock, this.#lockFile);
    }
  }

  async #cleanupTemporaryFiles() {
    let entries;
    try {
      entries = await fs.readdir(path.dirname(this.#logFile));
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    const escapedBase = path.basename(this.#logFile).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const temporaryPattern = new RegExp(`^${escapedBase}\\.\\d+\\.[0-9a-f-]{36}\\.(?:health\\.)?tmp$`);
    for (const entry of entries.filter((name) => temporaryPattern.test(name))) {
      const candidate = path.join(path.dirname(this.#logFile), entry);
      try {
        if ((await fs.lstat(candidate)).isFile()) await fs.unlink(candidate);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
  }

  async #rotateUnlocked() {
    for (let index = this.#retentionCount - 1; index >= 1; index -= 1) {
      await fs.rename(`${this.#logFile}.${index}`, `${this.#logFile}.${index + 1}`).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
    await fs.rename(this.#logFile, `${this.#logFile}.1`).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }

  // The retained set parsed into records, grouped by file, in chain
  // order (archives oldest first, then the active log). Unparseable
  // lines and non-object lines are skipped here — they are garbage the
  // chain walk reports separately (verifyChain /
  // verifyChainPerRecord), and they carry no recordedAt/hash a prune
  // plan could cite. Called only while the lock is held.
  async #readRetainedRecordsUnlocked(activeText) {
    const parseLines = (text) => text.split('\n').filter(Boolean).map((line) => {
      try {
        const parsed = JSON.parse(line);
        return parsed && typeof parsed === 'object' ? parsed : null;
      } catch {
        return null;
      }
    }).filter((parsed) => parsed !== null);
    const archives = new Map();
    for (let index = this.#retentionCount; index >= 1; index -= 1) {
      let text = '';
      try {
        text = await fs.readFile(`${this.#logFile}.${index}`, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      archives.set(index, parseLines(text));
    }
    return { active: parseLines(activeText), archives };
  }

  // Retention plan (round 62). Called only from append(), only when a
  // rotation is about to happen, and only while the lock is held.
  // Returns null when there is no policy (absent, corrupt, or
  // symlinked — read leniently so a damaged policy file can never
  // block audit appends) or when the policy prunes nothing. Otherwise
  // returns the prune plan for THIS rotation:
  //   { prunedCount, prunedFirstRecordedAt, prunedLastRecordedAt,
  //     lastPrunedHash, maxArchives, maxRecords,
  //     deleteArchiveIndices, truncateActiveLines }
  //
  // What leaves the retained set in this rotation, in chain order:
  // - the oldest archive, dropped by the rotation itself (round 37:
  //   the archive at index retentionCount falls off when everything
  //   shifts). With a policy set this drop is anchored too — the anchor
  //   is a complete account of what left the retained set in this
  //   rotation. Without a policy the drop stays exactly as before:
  //   silent, no anchor.
  // - archives beyond max_archives (post-rotation index), when set.
  // - the oldest lines of the rotated-in active log (.1), when
  //   max_records is set and the retained total still exceeds it.
  // The anchor itself (+1 record) and the incoming record (+1) count
  // toward the retained total. The anchor is written to the NEW active
  // log together with the incoming record — never into .1 — so
  // truncation of .1 can remove every old active record: with
  // max_records = 1 the retained set can bottom out at 2 records
  // (anchor + incoming), documented in docs/audit-retention-v1.md, not
  // silently violated.
  async #planRetentionPruneUnlocked(activeText) {
    const policy = await readRetentionPolicyLenient(path.dirname(this.#logFile));
    if (!policy) return null;
    const { active, archives } = await this.#readRetainedRecordsUnlocked(activeText);
    const retentionCount = this.#retentionCount;
    // Post-rotation, archive .k (pre-rotation) sits at index k+1; the
    // pre-rotation archive at index retentionCount falls off.
    const droppedByRotation = archives.get(retentionCount) || [];
    const prunedByMaxArchives = [];
    const deleteArchiveIndices = [];
    if (policy.max_archives !== null) {
      for (let index = policy.max_archives + 1; index <= retentionCount; index += 1) {
        deleteArchiveIndices.push(index);
      }
      // Pre-rotation .k lands at post-rotation index k+1, so it is
      // policy-pruned exactly when k+1 > max_archives, i.e. k >=
      // max_archives (k ranges 1..retentionCount-1; k =
      // retentionCount is the rotation drop, counted separately).
      // Collected oldest first (highest k first): the pruned list is
      // used in chain order for the anchor's first/last timestamps and
      // last-pruned hash, so the order matters.
      for (let k = retentionCount - 1; k >= policy.max_archives; k -= 1) {
        prunedByMaxArchives.push(...(archives.get(k) || []));
      }
    }
    // Kept archives after the policy: pre-rotation .k survives when
    // k+1 <= max_archives (or when no max_archives is set).
    let keptArchiveRecords = 0;
    for (let k = 1; k <= retentionCount - 1; k += 1) {
      if (policy.max_archives === null || k + 1 <= policy.max_archives) {
        keptArchiveRecords += (archives.get(k) || []).length;
      }
    }
    // Retained total after rotation + archive pruning: active records
    // + anchor + incoming record + kept archives.
    let truncateActiveLines = 0;
    if (policy.max_records !== null) {
      const retained = active.length + 2 + keptArchiveRecords;
      if (retained > policy.max_records) {
        truncateActiveLines = Math.min(retained - policy.max_records, active.length);
      }
    }
    const prunedByMaxRecords = active.slice(0, truncateActiveLines);
    const prunedInOrder = [...droppedByRotation, ...prunedByMaxArchives, ...prunedByMaxRecords];
    if (prunedInOrder.length === 0) return null;
    const firstWithTimestamp = prunedInOrder.find((record) => typeof record.recordedAt === 'string');
    const lastWithTimestamp = [...prunedInOrder].reverse().find((record) => typeof record.recordedAt === 'string');
    const lastWithHash = [...prunedInOrder].reverse().find((record) => typeof record.hash === 'string' && /^[a-f0-9]{64}$/.test(record.hash));
    return Object.freeze({
      prunedCount: prunedInOrder.length,
      prunedFirstRecordedAt: firstWithTimestamp ? firstWithTimestamp.recordedAt : null,
      prunedLastRecordedAt: lastWithTimestamp ? lastWithTimestamp.recordedAt : null,
      lastPrunedHash: lastWithHash ? lastWithHash.hash : null,
      maxArchives: policy.max_archives,
      maxRecords: policy.max_records,
      deleteArchiveIndices: Object.freeze(deleteArchiveIndices),
      truncateActiveLines,
    });
  }

  // Executes a retention plan AFTER #rotateUnlocked() has run: deletes
  // the archives beyond max_archives and truncates the oldest lines of
  // the rotated-in active log (.1). Called only while the lock is held.
  // The anchor lives in the NEW active log, not in .1, so
  // front-truncation of .1 can remove every old active record;
  // truncateActiveLines was capped at the pre-rotation active count.
  async #enforceRetentionPruneUnlocked(plan) {
    for (const index of plan.deleteArchiveIndices) {
      await fs.unlink(`${this.#logFile}.${index}`).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
    if (plan.truncateActiveLines > 0) {
      const archiveOne = `${this.#logFile}.1`;
      const text = await fs.readFile(archiveOne, 'utf8');
      const lines = text.split('\n').filter(Boolean);
      const kept = lines.slice(plan.truncateActiveLines);
      const temporary = `${this.#logFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
      let renamed = false;
      try {
        await fs.writeFile(temporary, kept.length > 0 ? `${kept.join('\n')}\n` : '', { encoding: 'utf8', mode: 0o600 });
        await fs.chmod(temporary, 0o600);
        await fs.rename(temporary, archiveOne);
        renamed = true;
        await fs.chmod(archiveOne, 0o600);
      } finally {
        if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      }
    }
  }

  // The newest parseable record, newest file first (active log, then
  // .1, .2, …). The first parseable record decides: a chained record
  // returns its hash; a legacy record returns GENESIS_PREV_HASH,
  // because chaining started after the last legacy record was written,
  // so no chained record can exist anywhere older. Unparseable lines
  // are skipped (a garbage tail must not stop the writer from chaining
  // onto the last good record — verification still reports the garbage
  // line). Called only while the lock is held.
  async #chainTailUnlocked() {
    const files = [this.#logFile];
    for (let index = 1; index <= this.#retentionCount; index += 1) files.push(`${this.#logFile}.${index}`);
    for (const file of files) {
      let text = '';
      try {
        text = await fs.readFile(file, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        continue;
      }
      const lines = text.split('\n').filter(Boolean);
      for (let index = lines.length - 1; index >= 0; index -= 1) {
        let parsed;
        try {
          parsed = JSON.parse(lines[index]);
        } catch {
          continue;
        }
        if (!parsed || typeof parsed !== 'object') continue;
        if (typeof parsed.hash === 'string' && /^[a-f0-9]{64}$/.test(parsed.hash)) return parsed.hash;
        return GENESIS_PREV_HASH;
      }
    }
    return GENESIS_PREV_HASH;
  }

  async append(event, details = {}) {
    if (typeof event !== 'string' || event.trim() === '') throw new TypeError('event must be a non-empty string.');
    const record = {
      chainVersion: CHAIN_VERSION,
      version: 1,
      event: event.trim(),
      eventId: crypto.randomUUID(),
      recordedAt: new Date(this.#clock()).toISOString(),
      details: redact(details),
    };
    // Size pre-check before the lock: prevHash and hash are always 64
    // hex characters, so the byte length is identical whatever the real
    // tail hash turns out to be.
    const probeLine = `${JSON.stringify({ ...record, prevHash: GENESIS_PREV_HASH, hash: GENESIS_PREV_HASH })}\n`;
    if (Buffer.byteLength(probeLine) > MAX_RECORD_BYTES) throw new RangeError('Audit record exceeds the maximum size.');
    let written = null;
    await this.#withLock(async () => {
      // The prevHash is resolved under the lock, so no concurrent
      // append can interleave a record between the tail read and this
      // write. The stored line and the returned record are the same
      // object: callers can recompute the hash from the return value.
      const prevHash = await this.#chainTailUnlocked();
      written = { ...record, prevHash, hash: computeAuditRecordHash({ ...record, prevHash }) };
      const chainedLine = `${JSON.stringify(written)}\n`;
      let existing = '';
      try {
        existing = await fs.readFile(this.#logFile, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      let next = `${existing}${chainedLine}`;
      if (Buffer.byteLength(next) > this.#rotationBytes) {
        // Retention (round 62): when rotation runs and a policy is set,
        // the prune is RECORDED, not silent. The plan is computed from
        // the pre-rotation retained set; when it prunes anything, an
        // AUDIT_LOG_PRUNED anchor record is written to the NEW active
        // log together with the incoming record (one atomic temp-file
        // write, so there is no window where the anchor exists but the
        // prune did not happen). The anchor chains from the old tail
        // and the incoming record chains from the anchor, so the chain
        // stays verifiable after the prune. A policy that prunes
        // nothing writes no anchor and rotates exactly as before.
        const prunePlan = await this.#planRetentionPruneUnlocked(existing);
        let anchorLine = '';
        if (prunePlan) {
          const anchor = {
            chainVersion: CHAIN_VERSION,
            version: 1,
            event: 'AUDIT_LOG_PRUNED',
            eventId: crypto.randomUUID(),
            // Stamped with the incoming record's time, not the clock:
            // the anchor precedes the incoming record in chain order,
            // so stamping it later would make recordedAt non-monotonic
            // along the chain (an auditor reading the log in order
            // would see a later timestamp before an earlier one, and a
            // later prune's first/last timestamps could invert).
            recordedAt: record.recordedAt,
            details: redact({
              prunedCount: prunePlan.prunedCount,
              prunedFirstRecordedAt: prunePlan.prunedFirstRecordedAt,
              prunedLastRecordedAt: prunePlan.prunedLastRecordedAt,
              lastPrunedHash: prunePlan.lastPrunedHash,
              maxArchives: prunePlan.maxArchives,
              maxRecords: prunePlan.maxRecords,
            }),
          };
          const anchorWithChain = { ...anchor, prevHash, hash: computeAuditRecordHash({ ...anchor, prevHash }) };
          anchorLine = `${JSON.stringify(anchorWithChain)}\n`;
          // The incoming record now chains from the anchor, not from
          // the old tail.
          written = { ...record, prevHash: anchorWithChain.hash, hash: computeAuditRecordHash({ ...record, prevHash: anchorWithChain.hash }) };
        }
        await this.#rotateUnlocked();
        next = `${anchorLine}${JSON.stringify(written)}\n`;
        if (prunePlan) await this.#enforceRetentionPruneUnlocked(prunePlan);
      }
      if (Buffer.byteLength(next) > MAX_LOG_BYTES) throw new RangeError('Audit record exceeds the maximum size.');
      const temporary = `${this.#logFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
      let renamed = false;
      try {
        await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
        await fs.chmod(temporary, 0o600);
        await fs.rename(temporary, this.#logFile);
        renamed = true;
        await fs.chmod(this.#logFile, 0o600);
      } finally {
        if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      }
    });
    return Object.freeze(written);
  }

  async healthCheck({ additionalBytes = 0 } = {}) {
    if (!Number.isInteger(additionalBytes) || additionalBytes < 0) throw new TypeError('additionalBytes must be a non-negative integer.');
    try {
      await this.#withLock(async () => {
        let existing = '';
        try {
          const stat = await fs.lstat(this.#logFile);
          if (!stat.isFile()) throw new Error('AUDIT_LOG_INVALID');
          existing = await fs.readFile(this.#logFile, 'utf8');
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        for (const line of existing.split('\n').filter(Boolean)) {
          try {
            const parsed = JSON.parse(line);
            if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') throw new Error('AUDIT_LOG_CORRUPT');
          } catch (error) {
            if (error.message === 'AUDIT_LOG_CORRUPT') throw error;
            throw new Error('AUDIT_LOG_CORRUPT');
          }
        }
        // Archives are validated too (round 37): a corrupt rotated file
        // is REPORTED as AUDIT_LOG_ARCHIVE_CORRUPT, never silently
        // dropped. Only archives 1..retentionCount are checked — the
        // rotation itself never creates more, so a stray file beyond
        // retention is out of scope for this check (see
        // docs/backup-restore-v1.md). The healthy case is unchanged:
        // valid archives keep the result { healthy: true }.
        for (let index = 1; index <= this.#retentionCount; index += 1) {
          const archive = `${this.#logFile}.${index}`;
          let archiveText = '';
          try {
            const archiveStat = await fs.lstat(archive);
            if (!archiveStat.isFile()) throw new Error('AUDIT_LOG_ARCHIVE_CORRUPT');
            archiveText = await fs.readFile(archive, 'utf8');
          } catch (error) {
            if (error.code === 'ENOENT') continue;
            if (error.message === 'AUDIT_LOG_ARCHIVE_CORRUPT') throw error;
            throw new Error('AUDIT_LOG_ARCHIVE_CORRUPT');
          }
          for (const line of archiveText.split('\n').filter(Boolean)) {
            try {
              const parsed = JSON.parse(line);
              if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') throw new Error('AUDIT_LOG_ARCHIVE_CORRUPT');
            } catch (error) {
              if (error.message === 'AUDIT_LOG_ARCHIVE_CORRUPT') throw error;
              throw new Error('AUDIT_LOG_ARCHIVE_CORRUPT');
            }
          }
        }
        const temporary = `${this.#logFile}.${process.pid}.${crypto.randomUUID()}.health.tmp`;
        try {
          await fs.writeFile(temporary, '0'.repeat(Buffer.byteLength(existing) + 2 * 1024 + additionalBytes), { encoding: 'utf8', mode: 0o600 });
        } finally {
          await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
        }
      });
      return Object.freeze({ healthy: true });
    } catch (error) {
      if (error.message === 'AUDIT_LOG_LOCKED') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_LOCKED' });
      if (error.message === 'AUDIT_LOG_PERMISSION_DENIED') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_PERMISSION_DENIED' });
      if (error.message === 'AUDIT_LOG_PATH_INVALID') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_PATH_INVALID' });
      if (error.message === 'AUDIT_LOG_STORAGE_UNAVAILABLE' || ['ENOSPC', 'EDQUOT'].includes(error.code)) return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_STORAGE_UNAVAILABLE' });
      if (error.message === 'AUDIT_LOG_CORRUPT') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_CORRUPT' });
      if (error.message === 'AUDIT_LOG_ARCHIVE_CORRUPT') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_ARCHIVE_CORRUPT' });
      if (error.message === 'AUDIT_LOG_INVALID') return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_INVALID' });
      return Object.freeze({ healthy: false, reason: 'AUDIT_LOG_UNAVAILABLE' });
    }
  }

  async readEvents() {
    return Object.freeze(await this.#withLock(async () => {
      let existing = '';
      try {
        existing = await fs.readFile(this.#logFile, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      return existing.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    }));
  }

  // Active log PLUS rotated archives, oldest first (.N … .1, then the
  // active log). This is the complete record set: rotation never drops a
  // record, it only moves it. readEvents() stays active-log-only by
  // design — callers that need history (revoke-token recovery, audits)
  // use this method instead. Like readEvents(), a corrupt line throws
  // rather than being skipped; use healthCheck() to REPORT corruption
  // (AUDIT_LOG_CORRUPT / AUDIT_LOG_ARCHIVE_CORRUPT) instead of throwing.
  async readAllEvents() {
    return Object.freeze(await this.#withLock(async () => {
      const events = [];
      for (let index = this.#retentionCount; index >= 1; index -= 1) {
        let archived = '';
        try {
          archived = await fs.readFile(`${this.#logFile}.${index}`, 'utf8');
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        events.push(...archived.split('\n').filter(Boolean).map((line) => JSON.parse(line)));
      }
      let existing = '';
      try {
        existing = await fs.readFile(this.#logFile, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      events.push(...existing.split('\n').filter(Boolean).map((line) => JSON.parse(line)));
      return events;
    }));
  }

  // Every retained line, in chain order (archives oldest first, then
  // the active log), as { file, line, text } where `file` is the
  // basename only (the raw line is never echoed back by callers).
  // Shared by verifyChain() and verifyChainPerRecord().
  async #readChainEntriesUnlocked() {
    const entries = [];
    const files = [];
    for (let index = this.#retentionCount; index >= 1; index -= 1) files.push(`${this.#logFile}.${index}`);
    files.push(this.#logFile);
    for (const file of files) {
      let text = '';
      try {
        text = await fs.readFile(file, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        continue;
      }
      const label = path.basename(file);
      text.split('\n').filter(Boolean).forEach((line, index) => {
        entries.push({ file: label, line: index + 1, text: line });
      });
    }
    return entries;
  }

  // Replay the hash chain over the complete retained set (archives
  // oldest first, then the active log — the same order as
  // readAllEvents()). Returns a frozen result; it never throws for a
  // broken chain, only for storage failures (lock, permission, path),
  // which surface as the classified AUDIT_LOG_* codes.
  //
  // Verification rules (round 43):
  // - Records without a `hash` field are LEGACY (written before
  //   chaining): they must form a contiguous prefix. A legacy record
  //   after a chained one is a break (AUDIT_CHAIN_LEGACY_AFTER_CHAINED).
  // - A chained record's prevHash must equal the previous chained
  //   record's hash (AUDIT_CHAIN_PREV_MISMATCH), and its stored hash
  //   must equal the recomputed hash (AUDIT_CHAIN_HASH_MISMATCH).
  // - A line that is not valid JSONL is a break
  //   (AUDIT_CHAIN_UNPARSEABLE) — structural corruption is reported
  //   here as a chain break; healthCheck() keeps its own
  //   AUDIT_LOG_CORRUPT / AUDIT_LOG_ARCHIVE_CORRUPT codes.
  // - The FIRST chained record's prevHash is accepted as the anchor
  //   and reported as anchorHash: it is NOT required to equal
  //   GENESIS_PREV_HASH, because rotation retention legitimately drops
  //   the oldest records. Consequence, stated honestly: deleting a
  //   leading prefix — or the last record, which has no successor —
  //   is undetectable. The chain detects modification, reordering,
  //   and deletion of any record that still has a successor in the
  //   retained set. An attacker who can rewrite the whole log (and
  //   recompute every hash) is outside this mechanism entirely; the
  //   chain is tamper-EVIDENCE, not tamper-PREVENTION.
  async verifyChain() {
    const broken = (entry, reason, counts) => Object.freeze({
      verified: false,
      totalRecords: counts.totalRecords,
      legacyRecords: counts.legacyRecords,
      chainedRecords: counts.chainedRecords,
      anchorHash: counts.anchorHash,
      // file + line only: the raw line is never echoed back (it can
      // carry long details, and the operator already has the file).
      brokenAt: Object.freeze({ file: entry.file, line: entry.line, reason }),
      reason,
    });
    try {
      return Object.freeze(await this.#withLock(async () => {
        const entries = await this.#readChainEntriesUnlocked();
        const counts = { totalRecords: entries.length, legacyRecords: 0, chainedRecords: 0, anchorHash: null };
        let seenChained = false;
        let expectedPrev = null;
        for (const entry of entries) {
          let parsed;
          try {
            parsed = JSON.parse(entry.text);
          } catch {
            return broken(entry, 'AUDIT_CHAIN_UNPARSEABLE', counts);
          }
          if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') {
            return broken(entry, 'AUDIT_CHAIN_UNPARSEABLE', counts);
          }
          if (typeof parsed.hash !== 'string') {
            if (seenChained) return broken(entry, 'AUDIT_CHAIN_LEGACY_AFTER_CHAINED', counts);
            counts.legacyRecords += 1;
            continue;
          }
          if (!seenChained) {
            seenChained = true;
            counts.anchorHash = typeof parsed.prevHash === 'string' ? parsed.prevHash : null;
            expectedPrev = parsed.prevHash;
          }
          if (typeof parsed.prevHash !== 'string' || parsed.prevHash !== expectedPrev) {
            return broken(entry, 'AUDIT_CHAIN_PREV_MISMATCH', counts);
          }
          if (!/^[a-f0-9]{64}$/.test(parsed.hash) || computeAuditRecordHash(parsed) !== parsed.hash) {
            return broken(entry, 'AUDIT_CHAIN_HASH_MISMATCH', counts);
          }
          counts.chainedRecords += 1;
          expectedPrev = parsed.hash;
        }
        return {
          verified: true,
          totalRecords: counts.totalRecords,
          legacyRecords: counts.legacyRecords,
          chainedRecords: counts.chainedRecords,
          anchorHash: counts.anchorHash,
          brokenAt: null,
          reason: null,
        };
      }));
    } catch (error) {
      if (['AUDIT_LOG_LOCKED', 'AUDIT_LOG_PERMISSION_DENIED', 'AUDIT_LOG_STORAGE_UNAVAILABLE', 'AUDIT_LOG_PATH_INVALID'].includes(error.message)) throw error;
      const classified = classifyAuditStorageError(error)
        || await classifyEnoentPathError(error, this.#logFile, 'AUDIT_LOG_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
  }

  // Per-record chain verification for `sentinel audit export`
  // (round 56). Unlike verifyChain(), which stops at the FIRST break,
  // this walks every retained line and attaches a status to each one,
  // so an auditor can see exactly which records verify and which do
  // not. Status values:
  // - 'verified': a chained record whose prevHash matches the previous
  //   chained record's stored hash and whose stored hash recomputes.
  // - 'legacy': a record without a hash field, in the pre-chain prefix.
  // - 'broken': unparseable, legacy-after-chained, prev mismatch, or
  //   hash mismatch (reason carries the AUDIT_CHAIN_* code).
  // The walk continues past breaks: after a broken chained record the
  // next record is checked against the broken record's STORED hash,
  // because that is what the next record's prevHash references. The
  // summary counts records by status (verifiedRecords /
  // legacyRecords / brokenRecords — counts, not booleans); the
  // top-level `verified` boolean is true exactly when no record is
  // broken. The same honest limits as verifyChain() apply: a deleted
  // leading prefix or last record is undetectable, and a full rewrite
  // with recomputed hashes verifies clean.
  async verifyChainPerRecord() {
    try {
      return Object.freeze(await this.#withLock(async () => {
        const entries = await this.#readChainEntriesUnlocked();
        const records = [];
        const summary = { totalRecords: entries.length, verifiedRecords: 0, legacyRecords: 0, brokenRecords: 0, anchorHash: null, firstRecordedAt: null, lastRecordedAt: null };
        let seenChained = false;
        let expectedPrev = null;
        for (const entry of entries) {
          let parsed;
          try {
            parsed = JSON.parse(entry.text);
          } catch {
            records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'broken', reason: 'AUDIT_CHAIN_UNPARSEABLE' }), record: null }));
            summary.brokenRecords += 1;
            continue;
          }
          if (!parsed || typeof parsed !== 'object' || typeof parsed.event !== 'string') {
            records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'broken', reason: 'AUDIT_CHAIN_UNPARSEABLE' }), record: null }));
            summary.brokenRecords += 1;
            continue;
          }
          if (typeof parsed.recordedAt === 'string') {
            if (summary.firstRecordedAt === null) summary.firstRecordedAt = parsed.recordedAt;
            summary.lastRecordedAt = parsed.recordedAt;
          }
          if (typeof parsed.hash !== 'string') {
            if (seenChained) {
              records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'broken', reason: 'AUDIT_CHAIN_LEGACY_AFTER_CHAINED' }), record: parsed }));
              summary.brokenRecords += 1;
            } else {
              records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'legacy', reason: null }), record: parsed }));
              summary.legacyRecords += 1;
            }
            continue;
          }
          if (!seenChained) {
            seenChained = true;
            summary.anchorHash = typeof parsed.prevHash === 'string' ? parsed.prevHash : null;
            expectedPrev = parsed.prevHash;
          }
          let reason = null;
          if (typeof parsed.prevHash !== 'string' || parsed.prevHash !== expectedPrev) {
            reason = 'AUDIT_CHAIN_PREV_MISMATCH';
          } else if (!/^[a-f0-9]{64}$/.test(parsed.hash) || computeAuditRecordHash(parsed) !== parsed.hash) {
            reason = 'AUDIT_CHAIN_HASH_MISMATCH';
          }
          if (reason) {
            records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'broken', reason }), record: parsed }));
            summary.brokenRecords += 1;
          } else {
            records.push(Object.freeze({ file: entry.file, line: entry.line, chain: Object.freeze({ status: 'verified', reason: null }), record: parsed }));
            summary.verifiedRecords += 1;
          }
          expectedPrev = parsed.hash;
        }
        return { verified: summary.brokenRecords === 0, summary: Object.freeze(summary), records: Object.freeze(records) };
      }));
    } catch (error) {
      if (['AUDIT_LOG_LOCKED', 'AUDIT_LOG_PERMISSION_DENIED', 'AUDIT_LOG_STORAGE_UNAVAILABLE', 'AUDIT_LOG_PATH_INVALID'].includes(error.message)) throw error;
      const classified = classifyAuditStorageError(error)
        || await classifyEnoentPathError(error, this.#logFile, 'AUDIT_LOG_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
  }
}

module.exports = { AuditLog, redact, computeAuditRecordHash, GENESIS_PREV_HASH, CHAIN_VERSION };
