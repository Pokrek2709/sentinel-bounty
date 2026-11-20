const crypto = require('node:crypto');

function requireString(value, field, maxLength = 500) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    throw new TypeError(`${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

class KillSwitch {
  #clock;
  #active = false;
  #trigger = null;
  #workers = new Map();
  #history = [];

  constructor({ clock = () => Date.now() } = {}) {
    if (typeof clock !== 'function') throw new TypeError('clock must be a function.');
    this.#clock = clock;
  }

  #now() {
    const now = this.#clock();
    if (!Number.isFinite(now)) throw new TypeError('clock must return milliseconds as a finite number.');
    return now;
  }

  #record(event, detail = {}) {
    this.#history.push(Object.freeze({ event, at: this.#now(), ...detail }));
  }

  snapshot() {
    return Object.freeze({
      active: this.#active,
      trigger: this.#trigger ? Object.freeze({ ...this.#trigger }) : null,
      registeredWorkers: this.#workers.size,
    });
  }

  history() {
    return Object.freeze([...this.#history]);
  }

  assertNotTriggered() {
    if (this.#active) {
      return Object.freeze({ allowed: false, reason: 'KILL_SWITCH_ACTIVE', trigger: Object.freeze({ ...this.#trigger }) });
    }
    return Object.freeze({ allowed: true, reason: 'KILL_SWITCH_INACTIVE' });
  }

  registerWorker({ workerId, cancel }) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    if (typeof cancel !== 'function') throw new TypeError('cancel must be a function.');
    if (this.#workers.has(normalizedWorkerId)) throw new Error(`Worker is already registered: ${normalizedWorkerId}`);
    if (this.#active) {
      this.#record('WORKER_REJECTED', { workerId: normalizedWorkerId, reason: 'KILL_SWITCH_ACTIVE' });
      return Object.freeze({ registered: false, reason: 'KILL_SWITCH_ACTIVE' });
    }
    this.#workers.set(normalizedWorkerId, cancel);
    this.#record('WORKER_REGISTERED', { workerId: normalizedWorkerId });
    return Object.freeze({
      registered: true,
      unregister: () => this.unregisterWorker(normalizedWorkerId),
    });
  }

  unregisterWorker(workerId) {
    const normalizedWorkerId = requireString(workerId, 'workerId', 200);
    const removed = this.#workers.delete(normalizedWorkerId);
    if (removed) this.#record('WORKER_UNREGISTERED', { workerId: normalizedWorkerId });
    return removed;
  }

  async trigger({ triggeredBy, reason }) {
    const trigger = Object.freeze({
      triggerId: crypto.randomUUID(),
      triggeredBy: requireString(triggeredBy, 'triggeredBy', 200),
      reason: requireString(reason, 'reason'),
      triggeredAt: this.#now(),
    });
    if (this.#active) {
      return Object.freeze({ triggered: false, reason: 'KILL_SWITCH_ALREADY_ACTIVE', trigger: this.#trigger, cancellations: [] });
    }

    this.#active = true;
    this.#trigger = trigger;
    this.#record('TRIGGERED', { triggerId: trigger.triggerId });
    const workers = [...this.#workers.entries()];
    const results = await Promise.allSettled(workers.map(async ([workerId, cancel]) => {
      await cancel(Object.freeze({ reason: 'KILL_SWITCH_ACTIVE', trigger }));
      return workerId;
    }));
    const cancellations = results.map((result, index) => Object.freeze({
      workerId: workers[index][0],
      cancelled: result.status === 'fulfilled',
      ...(result.status === 'rejected' ? { error: result.reason instanceof Error ? result.reason.message : String(result.reason) } : {}),
    }));
    this.#record('CANCELLATION_DISPATCHED', { workers: workers.length });
    return Object.freeze({ triggered: true, trigger, cancellations: Object.freeze(cancellations) });
  }

  reset({ resetBy }) {
    if (!this.#active) return Object.freeze({ reset: false, reason: 'KILL_SWITCH_INACTIVE' });
    if (this.#workers.size > 0) {
      return Object.freeze({ reset: false, reason: 'WORKERS_STILL_REGISTERED', registeredWorkers: this.#workers.size });
    }
    const actor = requireString(resetBy, 'resetBy', 200);
    const priorTrigger = this.#trigger;
    this.#active = false;
    this.#trigger = null;
    this.#record('RESET', { resetBy: actor, priorTriggerId: priorTrigger.triggerId });
    return Object.freeze({ reset: true });
  }
}

module.exports = { KillSwitch };
