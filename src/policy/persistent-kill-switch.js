const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_LOCK_RETRY_MS = 25;
const DEFAULT_STALE_LOCK_MS = 60_000;

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

class PersistentKillSwitch {
  #stateFile;
  #lockFile;
  #clock;
  #workers = new Map();
  #lockTimeoutMs;
  #lockRetryMs;
  #staleLockMs;

  constructor({
    stateFile,
    skillDirectory,
    clock = () => Date.now(),
    lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
    lockRetryMs = DEFAULT_LOCK_RETRY_MS,
    staleLockMs = DEFAULT_STALE_LOCK_MS,
  } = {}) {
    if (typeof stateFile !== 'string' || !path.isAbsolute(stateFile)) throw new TypeError('stateFile must be an absolute path.');
    if (typeof skillDirectory !== 'string' || !path.isAbsolute(skillDirectory)) throw new TypeError('skillDirectory must be an absolute path so state placement can be verified.');
    const relativeStatePath = path.relative(path.resolve(skillDirectory), path.resolve(stateFile));
    if (relativeStatePath === '' || (!relativeStatePath.startsWith('..') && !path.isAbsolute(relativeStatePath))) {
      throw new TypeError('stateFile must be outside the skill directory.');
    }
    if (typeof clock !== 'function') throw new TypeError('clock must be a function.');
    if (![lockTimeoutMs, lockRetryMs, staleLockMs].every((value) => Number.isInteger(value) && value >= 0)) throw new TypeError('lock timing values must be non-negative integers.');
    this.#stateFile = stateFile;
    this.#lockFile = `${stateFile}.lock`;
    this.#clock = clock;
    this.#lockTimeoutMs = lockTimeoutMs;
    this.#lockRetryMs = lockRetryMs;
    this.#staleLockMs = staleLockMs;
  }

  async #withLock(operation) {
    await fs.mkdir(path.dirname(this.#stateFile), { recursive: true, mode: 0o700 });
    const started = nowFrom(this.#clock);
    let handle;
    while (!handle) {
      try {
        handle = await fs.open(this.#lockFile, 'wx', 0o600);
        await handle.writeFile(JSON.stringify({ pid: process.pid, acquiredAt: nowFrom(this.#clock) }));
      } catch (error) {
        if (handle) await handle.close();
        handle = undefined;
        if (error.code !== 'EEXIST' || nowFrom(this.#clock) - started >= this.#lockTimeoutMs) throw new Error('KILL_SWITCH_STATE_LOCKED');
        try {
          const lockStat = await fs.stat(this.#lockFile);
          if (nowFrom(this.#clock) - lockStat.mtimeMs >= this.#staleLockMs) await fs.unlink(this.#lockFile);
        } catch (statError) {
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

  async #readUnlocked() {
    try {
      const parsed = JSON.parse(await fs.readFile(this.#stateFile, 'utf8'));
      if (parsed.version === 1 && typeof parsed.active === 'boolean') return parsed;
      if (parsed.version === undefined && typeof parsed.enabled === 'boolean') {
        const migrated = {
          version: 1,
          active: parsed.enabled,
          trigger: parsed.enabled ? {
            triggerId: 'legacy-state',
            triggeredBy: 'legacy-state',
            reason: typeof parsed.reason === 'string' && parsed.reason.trim() ? parsed.reason.trim() : 'Migrated legacy kill-switch state',
            triggeredAt: Number.isFinite(Date.parse(parsed.updatedAt)) ? Date.parse(parsed.updatedAt) : nowFrom(this.#clock),
          } : null,
        };
        await this.#writeUnlocked(migrated);
        return migrated;
      }
      throw new Error('Invalid kill-switch state.');
    } catch (error) {
      if (error.code === 'ENOENT') return { version: 1, active: false, trigger: null };
      throw error;
    }
  }

  async #writeUnlocked(state) {
    const temporary = `${this.#stateFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
    await fs.writeFile(temporary, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, this.#stateFile);
    await fs.chmod(this.#stateFile, 0o600);
  }

  async assertNotTriggered() {
    const state = await this.#withLock(() => this.#readUnlocked());
    return state.active
      ? Object.freeze({ allowed: false, reason: 'KILL_SWITCH_ACTIVE', trigger: Object.freeze({ ...state.trigger }) })
      : Object.freeze({ allowed: true, reason: 'KILL_SWITCH_INACTIVE' });
  }

  async registerWorker({ workerId, cancel }) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    if (typeof cancel !== 'function') throw new TypeError('cancel must be a function.');
    const status = await this.assertNotTriggered();
    if (!status.allowed) return Object.freeze({ registered: false, reason: status.reason });
    if (this.#workers.has(normalizedWorkerId)) throw new Error(`Worker is already registered: ${normalizedWorkerId}`);
    this.#workers.set(normalizedWorkerId, cancel);
    const afterRegistration = await this.assertNotTriggered();
    if (!afterRegistration.allowed) {
      this.#workers.delete(normalizedWorkerId);
      return Object.freeze({ registered: false, reason: afterRegistration.reason });
    }
    return Object.freeze({ registered: true, unregister: () => this.#workers.delete(normalizedWorkerId) });
  }

  async trigger({ triggeredBy, reason }) {
    const trigger = Object.freeze({ triggerId: crypto.randomUUID(), triggeredBy: requireString(triggeredBy, 'triggeredBy', 200), reason: requireString(reason, 'reason'), triggeredAt: nowFrom(this.#clock) });
    const writeResult = await this.#withLock(async () => {
      const state = await this.#readUnlocked();
      if (state.active) return { active: true, trigger: state.trigger };
      await this.#writeUnlocked({ version: 1, active: true, trigger });
      return { active: false };
    });
    if (writeResult.active) return Object.freeze({ triggered: false, reason: 'KILL_SWITCH_ALREADY_ACTIVE', trigger: writeResult.trigger, cancellations: [] });
    const workers = [...this.#workers.entries()];
    const results = await Promise.allSettled(workers.map(async ([workerId, cancel]) => { await cancel({ reason: 'KILL_SWITCH_ACTIVE', trigger }); return workerId; }));
    return Object.freeze({ triggered: true, trigger, cancellations: Object.freeze(results.map((item, index) => Object.freeze({ workerId: workers[index][0], cancelled: item.status === 'fulfilled', ...(item.status === 'rejected' ? { error: String(item.reason?.message || item.reason) } : {}) }))) });
  }

  async reset({ resetBy }) {
    requireString(resetBy, 'resetBy', 200);
    if (this.#workers.size > 0) return Object.freeze({ reset: false, reason: 'WORKERS_STILL_REGISTERED', registeredWorkers: this.#workers.size });
    const result = await this.#withLock(async () => {
      const state = await this.#readUnlocked();
      if (!state.active) return { reset: false, reason: 'KILL_SWITCH_INACTIVE' };
      await this.#writeUnlocked({ version: 1, active: false, trigger: null });
      return { reset: true };
    });
    return Object.freeze(result);
  }
}

module.exports = { PersistentKillSwitch };
