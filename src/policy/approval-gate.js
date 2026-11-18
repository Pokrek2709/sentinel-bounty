const crypto = require('node:crypto');

const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1_000;
const MAX_APPROVAL_TTL_MS = 10 * 60 * 1_000;
const MAX_ESTIMATED_REQUESTS = 10_000;

function requireString(value, field, maxLength = 500) {
  if (typeof value !== 'string' || value.trim() === '' || value.trim().length > maxLength) {
    throw new TypeError(`${field} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value.trim();
}

function requireRequestEstimate(value) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_ESTIMATED_REQUESTS) {
    throw new RangeError(`estimatedRequests must be an integer from 1 to ${MAX_ESTIMATED_REQUESTS}.`);
  }
  return value;
}

function requireScopeFingerprint(value) {
  const fingerprint = requireString(value, 'scopeFingerprint', 64).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new TypeError('scopeFingerprint must be a SHA-256 hexadecimal digest.');
  return fingerprint;
}

function immutableRecord(record) {
  return Object.freeze({
    ...record,
    binding: Object.freeze({ ...record.binding }),
  });
}

class ApprovalGate {
  #clock;
  #requests = new Map();
  #approvals = new Map();
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

  #recordEvent(event, request) {
    this.#history.push(Object.freeze({
      event,
      requestId: request.requestId,
      at: this.#now(),
    }));
  }

  #expireIfNeeded(request, now = this.#now()) {
    if (request.status === 'PENDING' || request.status === 'APPROVED') {
      if (now >= request.expiresAt) {
        request.status = 'EXPIRED';
        this.#recordEvent('EXPIRED', request);
      }
    }
    return request;
  }

  request({ targetId, action, estimatedRequests, scopeFingerprint, reason, ttlMs = DEFAULT_APPROVAL_TTL_MS }) {
    if (!Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_APPROVAL_TTL_MS) {
      throw new RangeError(`ttlMs must be an integer from 1 to ${MAX_APPROVAL_TTL_MS}.`);
    }
    const now = this.#now();
    const record = {
      requestId: crypto.randomUUID(),
      approvalId: null,
      status: 'PENDING',
      binding: {
        targetId: requireString(targetId, 'targetId', 200),
        action: requireString(action, 'action', 100),
        estimatedRequests: requireRequestEstimate(estimatedRequests),
        scopeFingerprint: requireScopeFingerprint(scopeFingerprint),
        reason: requireString(reason, 'reason'),
      },
      requestedAt: now,
      expiresAt: now + ttlMs,
      approvedAt: null,
      approvedBy: null,
      consumedAt: null,
    };
    this.#requests.set(record.requestId, record);
    this.#recordEvent('REQUESTED', record);
    return this.get(record.requestId);
  }

  approve(requestId, { approver } = {}) {
    const request = this.#requests.get(requestId);
    if (!request) return { allowed: false, reason: 'APPROVAL_REQUEST_NOT_FOUND' };
    this.#expireIfNeeded(request);
    if (request.status !== 'PENDING') return { allowed: false, reason: `APPROVAL_${request.status}` };
    request.status = 'APPROVED';
    request.approvalId = crypto.randomUUID();
    request.approvedBy = requireString(approver, 'approver', 200);
    request.approvedAt = this.#now();
    this.#approvals.set(request.approvalId, request);
    this.#recordEvent('APPROVED', request);
    return Object.freeze({ allowed: true, approvalId: request.approvalId, request: this.get(requestId) });
  }

  deny(requestId, { approver } = {}) {
    const request = this.#requests.get(requestId);
    if (!request) return { allowed: false, reason: 'APPROVAL_REQUEST_NOT_FOUND' };
    this.#expireIfNeeded(request);
    if (request.status !== 'PENDING') return { allowed: false, reason: `APPROVAL_${request.status}` };
    request.status = 'DENIED';
    request.approvedBy = requireString(approver, 'approver', 200);
    this.#recordEvent('DENIED', request);
    return Object.freeze({ allowed: true, request: this.get(requestId) });
  }

  authorize(approvalId, { targetId, action, estimatedRequests, scopeFingerprint } = {}) {
    const request = this.#approvals.get(approvalId);
    if (!request) return { allowed: false, reason: 'APPROVAL_NOT_FOUND' };
    this.#expireIfNeeded(request);
    if (request.status !== 'APPROVED') return { allowed: false, reason: `APPROVAL_${request.status}` };
    const binding = request.binding;
    if (
      binding.targetId !== targetId
      || binding.action !== action
      || binding.estimatedRequests !== estimatedRequests
      || binding.scopeFingerprint !== scopeFingerprint
    ) {
      return { allowed: false, reason: 'APPROVAL_BINDING_MISMATCH' };
    }
    request.status = 'CONSUMED';
    request.consumedAt = this.#now();
    this.#recordEvent('CONSUMED', request);
    return Object.freeze({ allowed: true, reason: 'APPROVED_AND_CONSUMED', request: this.get(request.requestId) });
  }

  get(requestId) {
    const request = this.#requests.get(requestId);
    if (!request) return null;
    this.#expireIfNeeded(request);
    return immutableRecord(request);
  }

  history() {
    return Object.freeze([...this.#history]);
  }
}

module.exports = {
  ApprovalGate,
  DEFAULT_APPROVAL_TTL_MS,
  MAX_APPROVAL_TTL_MS,
};
