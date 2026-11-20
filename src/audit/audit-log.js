const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const MAX_RECORD_BYTES = 32 * 1024;
const MAX_LOG_BYTES = 10 * 1024 * 1024;
const DEFAULT_ROTATION_BYTES = 8 * 1024 * 1024;
const DEFAULT_RETENTION_COUNT = 3;
const DEFAULT_STALE_LOCK_MS = 60_000;

function requireAbsoluteOutside(file, skillDirectory, field) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) throw new TypeError(`${field} must be an absolute path.`);
  if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path.');
  const relative = path.relative(path.resolve(skillDirectory), path.resolve(file));
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) throw new TypeError(`${field} must be outside the skill directory.`);
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
    await fs.mkdir(path.dirname(this.#logFile), { recursive: true, mode: 0o700 });
    const started = this.#clock();
    let lock;
    while (!lock) {
      try {
        lock = await fs.open(this.#lockFile, 'wx', 0o600);
      } catch (error) {
        if (error.code !== 'EEXIST' || this.#clock() - started >= this.#lockTimeoutMs) throw new Error('AUDIT_LOG_LOCKED');
        try {
          const stat = await fs.stat(this.#lockFile);
          if (this.#clock() - stat.mtimeMs >= this.#staleLockMs) await fs.unlink(this.#lockFile);
        } catch (statError) {
          if (statError.code !== 'ENOENT') throw statError;
        }
        await new Promise((resolve) => setTimeout(resolve, this.#lockRetryMs));
      }
    }
    try {
      return await operation();
    } finally {
      await lock.close();
      await fs.unlink(this.#lockFile).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  async #rotateUnlocked() {
    for (let index = this.#retentionCount - 1; index >= 1; index -= 1) {
      await fs.rename(`${this.#logFile}.${index}`, `${this.#logFile}.${index + 1}`).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
    await fs.rename(this.#logFile, `${this.#logFile}.1`).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }

  async append(event, details = {}) {
    if (typeof event !== 'string' || event.trim() === '') throw new TypeError('event must be a non-empty string.');
    const record = {
      version: 1,
      event: event.trim(),
      eventId: crypto.randomUUID(),
      recordedAt: new Date(this.#clock()).toISOString(),
      details: redact(details),
    };
    const line = `${JSON.stringify(record)}\n`;
    if (Buffer.byteLength(line) > MAX_RECORD_BYTES) throw new RangeError('Audit record exceeds the maximum size.');
    await this.#withLock(async () => {
      let existing = '';
      try {
        existing = await fs.readFile(this.#logFile, 'utf8');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      let next = `${existing}${line}`;
      if (Buffer.byteLength(next) > this.#rotationBytes) {
        await this.#rotateUnlocked();
        next = line;
      }
      if (Buffer.byteLength(next) > MAX_LOG_BYTES) throw new RangeError('Audit record exceeds the maximum size.');
      const temporary = `${this.#logFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
      await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
      await fs.chmod(temporary, 0o600);
      await fs.rename(temporary, this.#logFile);
      await fs.chmod(this.#logFile, 0o600);
    });
    return Object.freeze(record);
  }
}

module.exports = { AuditLog, redact };
