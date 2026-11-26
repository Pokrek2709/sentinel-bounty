const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { classifyStorageError, classifyStateReadError, isCorruptStateError, classifyEnoentPathError } = require('./storage-errors');
const { ensurePrivateDir } = require('./state-permissions');

const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_LOCK_RETRY_MS = 25;
const DEFAULT_STALE_LOCK_MS = 60_000;
const DEFAULT_WORKER_LEASE_MS = 5_000;

function requireString(value, field, maxLength = 500) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    throw new TypeError(`${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

function nowFrom(clock) {
  const value = clock();
  if (!Number.isFinite(value)) throw new TypeError('clock must return milliseconds as a finite number.');
  return value;
}

// Workers recorded in the state file must be objects; anything else (a
// string, number, null, or array) is malformed data from a hand-edited
// file. The locked path prunes such entries; the lockless path drops them
// for exact parity instead of spreading them into phantom workers
// (spreading "x" yields {"0": "x"} with leaseExpired true).
function isWorkerRecord(worker) {
  return worker !== null && typeof worker === 'object' && !Array.isArray(worker);
}

// Pure v1/legacy -> v2 migration, shared by the locked reader (which
// writes the migrated state back) and the lockless parser (in-memory
// only), so the two paths cannot drift apart. Throws
// KILL_SWITCH_STATE_CORRUPT for shapes that are neither v2, v1, nor
// legacy. `now` is injected so the lockless path uses the same clock as
// the locked path.
function migrateKillSwitchState(parsed, now) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('KILL_SWITCH_STATE_CORRUPT');
  if (parsed.version === 2 && typeof parsed.active === 'boolean' && Array.isArray(parsed.workers)) return parsed;
  if (parsed.version === 1 && typeof parsed.active === 'boolean') {
    return { version: 2, active: parsed.active, trigger: parsed.trigger || null, workers: [] };
  }
  if (parsed.version === undefined && typeof parsed.enabled === 'boolean') {
    const timestamp = parsed.updatedAt || parsed.updated_at;
    return {
      version: 2,
      active: parsed.enabled,
      trigger: parsed.enabled ? {
        triggerId: 'legacy-state',
        triggeredBy: 'legacy-state',
        reason: typeof parsed.reason === 'string' && parsed.reason.trim() ? parsed.reason.trim() : 'Migrated legacy kill-switch state',
        triggeredAt: Number.isFinite(Date.parse(timestamp)) ? Date.parse(timestamp) : now,
      } : null,
      workers: [],
    };
  }
  throw new Error('KILL_SWITCH_STATE_CORRUPT');
}

// Classify a filesystem error from a lock/state-storage operation into the
// operator-facing error taxonomy. Lives in storage-errors.js so the
// operator CLI can reuse the same taxonomy for the rotation lock.

class PersistentKillSwitch {
  #stateFile;
  #lockFile;
  #clock;
  #workers = new Map();
  #lockTimeoutMs;
  #lockRetryMs;
  #staleLockMs;
  #workerLeaseMs;
  #resetToken;
  #resetTokenHash;

  constructor({ stateFile, skillDirectory, clock = () => Date.now(), lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS, lockRetryMs = DEFAULT_LOCK_RETRY_MS, staleLockMs = DEFAULT_STALE_LOCK_MS, workerLeaseMs = DEFAULT_WORKER_LEASE_MS, resetToken, resetTokenHash } = {}) {
    if (typeof stateFile !== 'string' || !path.isAbsolute(stateFile)) throw new TypeError('stateFile must be an absolute path.');
    if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path so state placement can be verified.');
    const relativeStatePath = path.relative(path.resolve(skillDirectory), path.resolve(stateFile));
    if (relativeStatePath === '' || (!relativeStatePath.startsWith('..') && !path.isAbsolute(relativeStatePath))) throw new TypeError('stateFile must be outside the skill directory.');
    if (typeof clock !== 'function') throw new TypeError('clock must be a function.');
    if (resetToken !== undefined && resetTokenHash !== undefined) throw new TypeError('Provide resetToken or resetTokenHash, not both.');
    if (resetToken !== undefined && (typeof resetToken !== 'string' || resetToken.length < 16)) throw new TypeError('resetToken must be at least 16 characters and must come from a secure operator channel.');
    if (resetTokenHash !== undefined && (typeof resetTokenHash !== 'string' || !/^[a-f0-9]{64}$/i.test(resetTokenHash))) throw new TypeError('resetTokenHash must be a SHA-256 hex digest.');
    if (![lockTimeoutMs, lockRetryMs, staleLockMs].every((value) => Number.isInteger(value) && value >= 0)) throw new TypeError('lock timing values must be non-negative integers.');
    if (!Number.isInteger(workerLeaseMs) || workerLeaseMs < 1_000) throw new TypeError('workerLeaseMs must be at least 1000ms.');
    this.#stateFile = stateFile;
    this.#lockFile = `${stateFile}.lock`;
    this.#clock = clock;
    this.#lockTimeoutMs = lockTimeoutMs;
    this.#lockRetryMs = lockRetryMs;
    this.#staleLockMs = staleLockMs;
    this.#workerLeaseMs = workerLeaseMs;
    this.#resetToken = resetToken || null;
    this.#resetTokenHash = (resetTokenHash || (resetToken ? crypto.createHash('sha256').update(resetToken).digest('hex') : null))?.toLowerCase() || null;
  }

  async #withLock(operation) {
    try {
      // ensurePrivateDir (round 45) also chmods a directory that
      // already exists: mkdir({ recursive, mode }) alone never does,
      // which is how a state dir created under a permissive umask
      // stayed loose forever.
      await ensurePrivateDir(path.dirname(this.#stateFile));
    } catch (error) {
      const classified = classifyStorageError(error)
        || await classifyEnoentPathError(error, path.dirname(this.#stateFile), 'KILL_SWITCH_STATE_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
    const started = nowFrom(this.#clock);
    let handle;
    while (!handle) {
      try {
        handle = await fs.open(this.#lockFile, 'wx', 0o600);
        await handle.writeFile(JSON.stringify({ pid: process.pid, acquiredAt: nowFrom(this.#clock) }));
      } catch (error) {
        if (handle) {
          await handle.close();
          await fs.unlink(this.#lockFile).catch((unlinkError) => { if (unlinkError.code !== 'ENOENT') throw unlinkError; });
        }
        handle = undefined;
        const classified = classifyStorageError(error)
          || await classifyEnoentPathError(error, this.#lockFile, 'KILL_SWITCH_STATE_PATH_INVALID');
        if (classified) throw new Error(classified);
        if (error.code !== 'EEXIST' || nowFrom(this.#clock) - started >= this.#lockTimeoutMs) throw new Error('KILL_SWITCH_STATE_LOCKED');
        try {
          const stat = await fs.stat(this.#lockFile);
          if (nowFrom(this.#clock) - stat.mtimeMs >= this.#staleLockMs) await fs.unlink(this.#lockFile);
        } catch (statError) {
          const statClassified = classifyStorageError(statError)
            || await classifyEnoentPathError(statError, this.#lockFile, 'KILL_SWITCH_STATE_PATH_INVALID');
          if (statClassified) throw new Error(statClassified);
          if (statError.code !== 'ENOENT') throw statError;
        }
        await new Promise((resolve) => setTimeout(resolve, this.#lockRetryMs));
      }
    }
    try {
      return await operation();
    } finally {
      await handle.close();
      await fs.unlink(this.#lockFile).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  async #writeUnlocked(state) {
    const temporary = `${this.#stateFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let renamed = false;
    try {
      await fs.writeFile(temporary, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
      await fs.chmod(temporary, 0o600);
      await fs.rename(temporary, this.#stateFile);
      renamed = true;
      await fs.chmod(this.#stateFile, 0o600);
    } catch (error) {
      const classified = classifyStorageError(error)
        || await classifyEnoentPathError(error, temporary, 'KILL_SWITCH_STATE_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    } finally {
      if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  async #readUnlocked() {
    try {
      const parsed = JSON.parse(await fs.readFile(this.#stateFile, 'utf8'));
      // v1/legacy migration is shared with the lockless parser (see
      // migrateKillSwitchState): the locked path writes the migrated
      // state back, the lockless path keeps it in memory only.
      const migrated = migrateKillSwitchState(parsed, nowFrom(this.#clock));
      if (parsed.version !== 2) await this.#writeUnlocked(migrated);
      return migrated;
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Windows reports a path through a file as ENOENT, not
        // ENOTDIR: a file parent is a path failure, not "no state yet".
        const invalid = await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
        if (invalid) throw new Error(invalid);
        return { version: 2, active: false, trigger: null, workers: [] };
      }
      const classified = classifyStateReadError(error)
        || await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
      if (classified) throw new Error(classified);
      if (isCorruptStateError(error)) throw new Error('KILL_SWITCH_STATE_CORRUPT');
      throw error;
    }
  }

  // Canonical lockless reader: the single parser for every lockless path.
  // No lock file, no mkdir, no writes. Expired leases are reported, not
  // pruned, and are marked leaseExpired so the operator can tell stale
  // entries apart from live workers.
  async #readSnapshotWithoutLock() {
    let raw;
    try {
      raw = await fs.readFile(this.#stateFile, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Windows reports a path through a file as ENOENT, not
        // ENOTDIR: a file parent is a path failure, not "no state yet".
        const invalid = await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
        if (invalid) throw new Error(invalid);
        return { version: 2, active: false, trigger: null, workers: [] };
      }
      const classified = classifyStateReadError(error)
        || await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
    return this.#parseStateForLocklessRead(raw);
  }

  // Canonical lockless snapshot shape, shared by snapshot()'s fallback and
  // snapshotLockless() so both paths report identically: readMode is the
  // primary marker, lockless/pruned are kept for the ronde-23 shape, and
  // registeredWorkers counts live leases only, matching the locked
  // snapshot() (which prunes before counting).
  #locklessSnapshot(state) {
    const now = nowFrom(this.#clock);
    // Non-object workers are dropped, not spread: lockless must report
    // exactly the same workers the locked path would prune to.
    const workers = state.workers.filter(isWorkerRecord).map((worker) => Object.freeze({ ...worker, leaseExpired: !Number.isFinite(worker.leaseExpiresAt) || worker.leaseExpiresAt <= now }));
    return Object.freeze({
      active: state.active,
      trigger: state.trigger ? Object.freeze({ ...state.trigger }) : null,
      registeredWorkers: workers.filter((worker) => !worker.leaseExpired).length,
      workers: Object.freeze(workers),
      version: state.version,
      readMode: 'LOCKLESS_FALLBACK',
      lockless: true,
      pruned: false,
    });
  }

  #pruneWorkers(state, now = nowFrom(this.#clock)) {
    // A non-object worker (null, string, number, array) is malformed
    // data: drop it here instead of letting Number.isFinite throw on
    // null.leaseExpiresAt. Matches the lockless filter exactly.
    const workers = state.workers.filter((worker) => isWorkerRecord(worker) && Number.isFinite(worker.leaseExpiresAt) && worker.leaseExpiresAt > now);
    return workers.length === state.workers.length ? state : { ...state, workers };
  }

  #operatorMatches(token) {
    if (!this.#resetTokenHash || typeof token !== 'string') return false;
    const presentedHash = crypto.createHash('sha256').update(token).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(presentedHash), Buffer.from(this.#resetTokenHash));
  }

  async assertNotTriggered() {
    const state = await this.#withLock(async () => {
      const current = await this.#readUnlocked();
      const pruned = this.#pruneWorkers(current);
      if (pruned !== current) await this.#writeUnlocked(pruned);
      return pruned;
    });
    return state.active ? Object.freeze({ allowed: false, reason: 'KILL_SWITCH_ACTIVE', trigger: Object.freeze({ ...state.trigger }) }) : Object.freeze({ allowed: true, reason: 'KILL_SWITCH_INACTIVE' });
  }

  async registerWorker({ workerId, cancel }) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    if (typeof cancel !== 'function') throw new TypeError('cancel must be a function.');
    const registration = await this.#withLock(async () => {
      const current = this.#pruneWorkers(await this.#readUnlocked());
      if (current.active) return { registered: false, reason: 'KILL_SWITCH_ACTIVE' };
      if (current.workers.some((worker) => worker.workerId === normalizedWorkerId)) return { registered: false, reason: 'WORKER_ALREADY_REGISTERED' };
      await this.#writeUnlocked({ ...current, workers: [...current.workers, { workerId: normalizedWorkerId, pid: process.pid, leaseExpiresAt: nowFrom(this.#clock) + this.#workerLeaseMs }] });
      return { registered: true };
    });
    if (!registration.registered) return Object.freeze(registration);
    this.#workers.set(normalizedWorkerId, cancel);
    return Object.freeze({ registered: true, unregister: () => this.unregisterWorker(normalizedWorkerId) });
  }

  async heartbeatWorker(workerId) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    if (!this.#workers.has(normalizedWorkerId)) return false;
    return this.#withLock(async () => {
      if (!this.#workers.has(normalizedWorkerId)) return false;
      const current = this.#pruneWorkers(await this.#readUnlocked());
      const workers = current.workers.map((worker) => worker.workerId === normalizedWorkerId ? { ...worker, leaseExpiresAt: nowFrom(this.#clock) + this.#workerLeaseMs } : worker);
      await this.#writeUnlocked({ ...current, workers });
      return true;
    });
  }

  async snapshot() {
    let state;
    try {
      state = await this.#withLock(async () => {
        const current = await this.#readUnlocked();
        const pruned = this.#pruneWorkers(current);
        if (pruned !== current) await this.#writeUnlocked(pruned);
        return pruned;
      });
    } catch (error) {
      if (error.message !== 'KILL_SWITCH_STATE_UNAVAILABLE') throw error;
      return this.#locklessSnapshot(await this.#readSnapshotWithoutLock());
    }
    const workers = state.workers.map((worker) => Object.freeze({ ...worker }));
    return Object.freeze({ active: state.active, trigger: state.trigger ? Object.freeze({ ...state.trigger }) : null, registeredWorkers: workers.length, workers: Object.freeze(workers), version: state.version });
  }

  // Lockless read: no lock file, no mkdir, no writes. Used only when the
  // locked path cannot run (for example a full disk). Returns the same
  // canonical shape as snapshot()'s storage-unavailable fallback.
  async snapshotLockless() {
    let raw;
    try {
      raw = await fs.readFile(this.#stateFile, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Windows reports a path through a file as ENOENT, not
        // ENOTDIR: a file parent is a path failure, not "no state yet".
        const invalid = await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
        if (invalid) throw new Error(invalid);
        return this.#locklessSnapshot({ version: 2, active: false, trigger: null, workers: [] });
      }
      const classified = classifyStateReadError(error)
        || await classifyEnoentPathError(error, this.#stateFile, 'KILL_SWITCH_STATE_PATH_INVALID');
      if (classified) throw new Error(classified);
      throw error;
    }
    return this.#locklessSnapshot(this.#parseStateForLocklessRead(raw));
  }

  #parseStateForLocklessRead(raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error('KILL_SWITCH_STATE_CORRUPT');
    }
    // Same migration as the locked reader; the lockless path never
    // writes the migrated state back.
    return migrateKillSwitchState(parsed, nowFrom(this.#clock));
  }

  async trigger({ triggeredBy, reason }) {
    const trigger = Object.freeze({ triggerId: crypto.randomUUID(), triggeredBy: requireString(triggeredBy, 'triggeredBy', 200), reason: requireString(reason, 'reason'), triggeredAt: nowFrom(this.#clock) });
    const writeResult = await this.#withLock(async () => {
      const state = this.#pruneWorkers(await this.#readUnlocked());
      if (state.active) return { active: true, trigger: state.trigger };
      await this.#writeUnlocked({ version: 2, active: true, trigger, workers: state.workers });
      return { active: false };
    });
    if (writeResult.active) return Object.freeze({ triggered: false, reason: 'KILL_SWITCH_ALREADY_ACTIVE', trigger: writeResult.trigger, cancellations: [] });
    const workers = [...this.#workers.entries()];
    const results = await Promise.allSettled(workers.map(async ([workerId, cancel]) => { await cancel({ reason: 'KILL_SWITCH_ACTIVE', trigger }); return workerId; }));
    return Object.freeze({ triggered: true, trigger, cancellations: Object.freeze(results.map((item, index) => Object.freeze({ workerId: workers[index][0], cancelled: item.status === 'fulfilled', ...(item.status === 'rejected' ? { error: String(item.reason?.message || item.reason) } : {}) }))) });
  }

  async unregisterWorker(workerId) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    const removed = this.#workers.delete(normalizedWorkerId);
    await this.#withLock(async () => {
      const current = this.#pruneWorkers(await this.#readUnlocked());
      await this.#writeUnlocked({ ...current, workers: current.workers.filter((worker) => worker.workerId !== normalizedWorkerId) });
    });
    return removed;
  }

  async reset({ resetBy, resetToken }) {
    requireString(resetBy, 'resetBy', 200);
    if (!this.#operatorMatches(resetToken)) return Object.freeze({ reset: false, reason: 'RESET_OPERATOR_UNAUTHORIZED' });
    return Object.freeze(await this.#withLock(async () => {
      const state = this.#pruneWorkers(await this.#readUnlocked());
      if (state.workers.length > 0) return { reset: false, reason: 'WORKERS_STILL_REGISTERED', registeredWorkers: state.workers.length };
      if (!state.active) return { reset: false, reason: 'KILL_SWITCH_INACTIVE' };
      await this.#writeUnlocked({ version: 2, active: false, trigger: null, workers: [] });
      return { reset: true };
    }));
  }
}

module.exports = { PersistentKillSwitch, DEFAULT_WORKER_LEASE_MS };
