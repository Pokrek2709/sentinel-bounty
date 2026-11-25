const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

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
    try {
      const parsed = new URL(value);
      parsed.username = '';
      parsed.password = '';
      return parsed.toString();
    } catch {
      return value.length > 4_000 ? `${value.slice(0, 4_000)}…` : value;
    }
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
      await fs.mkdir(path.dirname(this.#logFile), { recursive: true, mode: 0o700 });
    } catch (error) {
      const classified = classifyAuditStorageError(error);
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
        const classified = classifyAuditStorageError(error);
        if (classified) throw new Error(classified);
        if (error.code !== 'EEXIST' || this.#clock() - started >= this.#lockTimeoutMs) throw new Error('AUDIT_LOG_LOCKED');
        try {
          const stat = await fs.stat(this.#lockFile);
          if (this.#clock() - stat.mtimeMs >= this.#staleLockMs) await fs.unlink(this.#lockFile);
        } catch (statError) {
          const statClassified = classifyAuditStorageError(statError);
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
      await lock.close();
      await fs.unlink(this.#lockFile).catch((error) => { if (error.code !== 'ENOENT') throw error; });
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
        await this.#rotateUnlocked();
        next = chainedLine;
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
      const classified = classifyAuditStorageError(error);
      if (classified) throw new Error(classified);
      throw error;
    }
  }
}

module.exports = { AuditLog, redact, computeAuditRecordHash, GENESIS_PREV_HASH, CHAIN_VERSION };
