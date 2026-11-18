const crypto = require('node:crypto');

const DEFAULT_REQUEST_BUDGET = 1_000;
const MAX_REQUEST_BUDGET = 10_000;
const DEFAULT_RPS = 2;
const MAX_BURST = 5;
const MAX_CONCURRENCY = 2;
const SERVER_PRESSURE_STATUSES = new Set([429, 503]);

function assertPositiveFinite(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive finite number.`);
  }
}

function assertPositiveInteger(value, name) {
  if (!Number.isInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive integer.`);
}

function normalizeDomain(domain) {
  if (typeof domain !== 'string' || domain.trim() === '') throw new TypeError('domain must be a non-empty hostname.');
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

class RequestGovernor {
  #clock;
  #ratePerSecond;
  #concurrencyLimit;
  #budgetLimit;
  #used = 0;
  #active = 0;
  #budgetWarningEmitted = false;
  #reservations = new Map();
  #domains = new Map();

  constructor({
    requestsPerSecond = DEFAULT_RPS,
    concurrency = MAX_CONCURRENCY,
    requestBudget = DEFAULT_REQUEST_BUDGET,
    clock = () => Date.now(),
  } = {}) {
    assertPositiveFinite(requestsPerSecond, 'requestsPerSecond');
    assertPositiveInteger(concurrency, 'concurrency');
    assertPositiveInteger(requestBudget, 'requestBudget');
    if (concurrency > MAX_CONCURRENCY) throw new RangeError(`concurrency may not exceed ${MAX_CONCURRENCY}.`);
    if (requestBudget > MAX_REQUEST_BUDGET) throw new RangeError(`requestBudget may not exceed ${MAX_REQUEST_BUDGET}.`);
    if (typeof clock !== 'function') throw new TypeError('clock must be a function.');
    this.#ratePerSecond = requestsPerSecond;
    this.#concurrencyLimit = concurrency;
    this.#budgetLimit = requestBudget;
    this.#clock = clock;
  }

  static fromTarget(target, options = {}) {
    if (!target || typeof target !== 'object') throw new TypeError('target is required.');
    return new RequestGovernor({
      requestsPerSecond: target.rateLimit?.requests_per_second ?? DEFAULT_RPS,
      concurrency: target.rateLimit?.concurrency ?? MAX_CONCURRENCY,
      requestBudget: target.requestBudget ?? DEFAULT_REQUEST_BUDGET,
      ...options,
    });
  }

  #now() {
    const now = this.#clock();
    if (!Number.isFinite(now)) throw new TypeError('clock must return milliseconds as a finite number.');
    return now;
  }

  #stateFor(domain, now) {
    const existing = this.#domains.get(domain);
    if (existing) return existing;
    const state = {
      tokens: MAX_BURST,
      lastRefillAt: now,
      consecutivePressure: 0,
      pausedUntil: 0,
      halted: false,
    };
    this.#domains.set(domain, state);
    return state;
  }

  #refill(state, now) {
    const elapsed = Math.max(0, now - state.lastRefillAt);
    state.tokens = Math.min(MAX_BURST, state.tokens + ((elapsed / 1_000) * this.#ratePerSecond));
    state.lastRefillAt = now;
  }

  acquire(domainInput) {
    const domain = normalizeDomain(domainInput);
    const now = this.#now();
    const state = this.#stateFor(domain, now);
    if (state.halted) return { allowed: false, reason: 'SERVER_PRESSURE_HALT', domain };
    if (now < state.pausedUntil) {
      return { allowed: false, reason: 'SERVER_BACKOFF', domain, retryAfterMs: state.pausedUntil - now };
    }
    if (this.#used >= this.#budgetLimit) return { allowed: false, reason: 'REQUEST_BUDGET_EXHAUSTED', domain };
    if (this.#active >= this.#concurrencyLimit) return { allowed: false, reason: 'CONCURRENCY_LIMIT', domain };

    this.#refill(state, now);
    if (state.tokens < 1) {
      return {
        allowed: false,
        reason: 'RATE_LIMITED',
        domain,
        retryAfterMs: Math.ceil(((1 - state.tokens) / this.#ratePerSecond) * 1_000),
      };
    }

    state.tokens -= 1;
    this.#used += 1;
    this.#active += 1;
    const reservationId = crypto.randomUUID();
    this.#reservations.set(reservationId, domain);
    const warnings = [];
    if (!this.#budgetWarningEmitted && this.#used / this.#budgetLimit >= 0.8) {
      this.#budgetWarningEmitted = true;
      warnings.push('REQUEST_BUDGET_80_PERCENT');
    }
    return {
      allowed: true,
      reason: 'PERMITTED',
      domain,
      reservationId,
      remainingBudget: this.#budgetLimit - this.#used,
      warnings,
    };
  }

  release(reservationId) {
    if (!this.#reservations.delete(reservationId)) return false;
    this.#active -= 1;
    return true;
  }

  recordResponse(domainInput, statusCode) {
    const domain = normalizeDomain(domainInput);
    const now = this.#now();
    const state = this.#stateFor(domain, now);
    if (!SERVER_PRESSURE_STATUSES.has(statusCode)) {
      state.consecutivePressure = 0;
      return { domain, action: 'NONE' };
    }

    state.consecutivePressure += 1;
    const pauseMs = 15_000 * (2 ** (state.consecutivePressure - 1));
    state.pausedUntil = Math.max(state.pausedUntil, now + pauseMs);
    if (state.consecutivePressure >= 3) {
      state.halted = true;
      return { domain, action: 'HALT', reason: 'SERVER_PRESSURE_HALT', consecutivePressure: state.consecutivePressure };
    }
    return { domain, action: 'BACKOFF', pauseMs, consecutivePressure: state.consecutivePressure };
  }

  renewBudget(requestBudget) {
    assertPositiveInteger(requestBudget, 'requestBudget');
    if (requestBudget > MAX_REQUEST_BUDGET) throw new RangeError(`requestBudget may not exceed ${MAX_REQUEST_BUDGET}.`);
    if (requestBudget < this.#used) throw new RangeError('requestBudget may not be less than requests already used.');
    this.#budgetLimit = requestBudget;
    this.#budgetWarningEmitted = this.#used / this.#budgetLimit >= 0.8;
    return this.snapshot();
  }

  snapshot() {
    return Object.freeze({
      requestsUsed: this.#used,
      requestBudget: this.#budgetLimit,
      remainingBudget: this.#budgetLimit - this.#used,
      activeRequests: this.#active,
      concurrencyLimit: this.#concurrencyLimit,
      requestsPerSecond: this.#ratePerSecond,
      maxBurst: MAX_BURST,
    });
  }
}

module.exports = {
  DEFAULT_REQUEST_BUDGET,
  DEFAULT_RPS,
  MAX_BURST,
  MAX_CONCURRENCY,
  MAX_REQUEST_BUDGET,
  RequestGovernor,
};
