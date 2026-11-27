// Public HTTP adapter (Phase 4 groundwork, round 90): the
// GET-only adapter for PUBLIC targets, behind the same
// activation gate as the local adapter — plus two rules the
// local adapter does not need.
//
// This module is INFRASTRUCTURE, not an execution: it
// implements the adapter and its gate, and no CLI command
// invokes it yet. Nothing in this round runs it against a
// real target: there is no registered target with a
// verified authorization reference, and the tests use a stub
// transport and a stub resolver only (no real socket, no
// real DNS). See docs/public-http-adapter-v1.md.
//
// The gate, in order — the first failing rule decides, the
// rest are never evaluated:
//   1. Kill switch not triggered (assertNotTriggered).
//   2. The URL parses and is http(s) (INVALID_URL).
//   3. The hostname is public: not localhost, not a
//      loopback name (NON_PUBLIC_HOST). IP-literal hosts
//      are refused later by the scope rule (URL_VALID: no
//      IP host), so a public target must be named by
//      domain.
//   4. The caller presents the target's authorization
//      reference and it matches the reference recorded at
//      registration (AUTHORIZATION_REFERENCE_MISMATCH; the
//      values are never logged — audit events carry
//      targetId and url only). An unregistered target
//      fails here as TARGET_NOT_REGISTERED.
//   5. Scope accepts the exact URL (SCOPE_*).
//   6. The target allows the http_probing method
//      (ACTION_NOT_ALLOWED).
//   7. The scope fingerprint matches (SCOPE_FINGERPRINT_MISMATCH).
//   8. Governor acquires a reservation for the hostname
//      (GOVERNOR_*).
//   9. The approval gate authorizes the single-use approval
//      (approval.reason).
//  10. DNS resolution of the hostname, AFTER the approval
//      (the lookup is part of the gated operation, not a
//      pre-gate probe): failure is DNS_RESOLUTION_FAILED;
//      any resolved address that is not public is
//      RESOLVED_NON_PUBLIC_HOST. The approval is consumed
//      by the attempt even when resolution fails — that is
//      the fail-closed cost of a single-use approval, and
//      the governor reservation is released.
//  11. Audit append HTTP_REQUEST_ALLOWED (AUDIT_UNAVAILABLE
//      on failure).
//  12. Worker lease, then the request itself: GET-only,
//      5 s timeout by default, 1 MiB body cap, headers
//      redacted, redirects recorded but NEVER followed,
//      kill-switch polling every 100 ms, cleanup awaited
//      (the unregister discipline of the local adapter,
//      round 47).
//
// Node stdlib only. No CLI invokes this adapter yet.
'use strict';

const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { redact } = require('../audit/audit-log');

function result(allowed, reason, detail = {}) {
  return Object.freeze({ allowed, reason, ...detail });
}

// Is an IPv4 address public (globally routable)? Refuses
// loopback, private (RFC 1918), link-local (incl. the cloud
// metadata address 169.254.169.254), CGNAT, documentation /
// benchmarking / TEST-NET ranges, multicast, and reserved
// space. The check is on the address the hostname resolved
// to — a DNS name that resolves to a private address is an
// SSRF attempt, not a public target.
function isPublicIpv4(address) {
  const parts = address.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  if (a === 0) return false;
  if (a === 10) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && parts[2] === 0) return false;
  if (a === 192 && b === 0 && parts[2] === 2) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && parts[2] === 100) return false;
  if (a === 203 && b === 0 && parts[2] === 113) return false;
  if (a >= 224) return false;
  return true;
}

// Is an IPv6 address public? Refuses loopback, unspecified,
// link-local, unique-local, IPv4-mapped (checked against the
// embedded IPv4 rules), documentation, and multicast.
function isPublicIpv6(address) {
  const lower = address.toLowerCase();
  if (lower === '::1' || lower === '::') return false;
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return false;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return false;
  if (lower.startsWith('ff')) return false;
  if (lower.startsWith('2001:db8')) return false;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPublicIpv4(mapped[1]);
  return true;
}

function isPublicAddress(address) {
  if (typeof address !== 'string' || address === '') return false;
  if (net.isIP(address) === 4) return isPublicIpv4(address);
  if (net.isIP(address) === 6) return isPublicIpv6(address);
  return false;
}

// Is a hostname public by name alone (before DNS)? Refuses
// localhost in any case. IP literals are left to the scope
// rule (URL_VALID refuses IP hosts) and to the resolved-
// address check below.
function isPublicHostname(hostname) {
  return hostname.toLowerCase() !== 'localhost';
}

class PublicHttpAdapter {
  #registry;
  #approvalGate;
  #governor;
  #killSwitch;
  #audit;
  #timeoutMs;
  #maxBodyBytes;
  #pollIntervalMs;
  #requestGet;
  #resolveHost;

  constructor({ registry, approvalGate, governor, killSwitch, auditLog, timeoutMs = 5_000, maxBodyBytes = 1_048_576, pollIntervalMs = 100, requestGet, resolveHost } = {}) {
    if (!registry || typeof registry.evaluate !== 'function' || typeof registry.getScopeFingerprint !== 'function' || typeof registry.getAuthorizationReference !== 'function') throw new TypeError('registry is required.');
    if (!approvalGate || typeof approvalGate.authorize !== 'function') throw new TypeError('approvalGate is required.');
    if (!governor || typeof governor.acquire !== 'function' || typeof governor.release !== 'function') throw new TypeError('governor is required.');
    if (!killSwitch || typeof killSwitch.assertNotTriggered !== 'function' || typeof killSwitch.registerWorker !== 'function') throw new TypeError('killSwitch is required.');
    if (!auditLog || typeof auditLog.append !== 'function') throw new TypeError('auditLog is required.');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('timeoutMs must be a positive integer.');
    if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1) throw new RangeError('maxBodyBytes must be a positive integer.');
    if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 10) throw new RangeError('pollIntervalMs must be at least 10ms.');
    this.#registry = registry;
    this.#approvalGate = approvalGate;
    this.#governor = governor;
    this.#killSwitch = killSwitch;
    this.#audit = auditLog;
    this.#timeoutMs = timeoutMs;
    this.#maxBodyBytes = maxBodyBytes;
    this.#pollIntervalMs = pollIntervalMs;
    this.#requestGet = requestGet || ((requestUrl, callback) => (requestUrl.protocol === 'https:' ? https : http).get(requestUrl, callback));
    this.#resolveHost = resolveHost || ((hostname) => dns.promises.lookup(hostname, { all: true }));
  }

  async get({ targetId, url, authorizationRef, approvalId, estimatedRequests = 1, scopeFingerprint }) {
    const kill = await this.#killSwitch.assertNotTriggered();
    if (!kill.allowed) return result(false, kill.reason);
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return result(false, 'INVALID_URL');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'INVALID_URL' });
      return result(false, 'INVALID_URL');
    }
    if (!isPublicHostname(parsed.hostname)) {
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'NON_PUBLIC_HOST' });
      return result(false, 'NON_PUBLIC_HOST');
    }
    const storedRef = this.#registry.getAuthorizationReference(targetId);
    if (storedRef === null) {
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'TARGET_NOT_REGISTERED' });
      return result(false, 'TARGET_NOT_REGISTERED');
    }
    if (typeof authorizationRef !== 'string' || authorizationRef === '' || authorizationRef !== storedRef) {
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'AUTHORIZATION_REFERENCE_MISMATCH' });
      return result(false, 'AUTHORIZATION_REFERENCE_MISMATCH');
    }
    const scope = this.#registry.evaluate(targetId, parsed.toString());
    if (!scope.allowed) {
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: `SCOPE_${scope.reason}` });
      return result(false, `SCOPE_${scope.reason}`);
    }
    if (!this.#registry.isMethodAllowed(targetId, 'http_probing')) return result(false, 'ACTION_NOT_ALLOWED');
    const fingerprint = this.#registry.getScopeFingerprint(targetId);
    if (scopeFingerprint !== fingerprint) return result(false, 'SCOPE_FINGERPRINT_MISMATCH');
    const reservation = this.#governor.acquire(parsed.hostname);
    if (!reservation.allowed) return result(false, `GOVERNOR_${reservation.reason}`);
    const approval = this.#approvalGate.authorize(approvalId, { targetId, action: 'http_probing', estimatedRequests, scopeFingerprint: fingerprint });
    if (!approval.allowed) {
      this.#governor.release(reservation.reservationId);
      return result(false, approval.reason);
    }
    // DNS resolution happens AFTER the approval: the lookup is
    // part of the gated operation, not a pre-gate probe. The
    // approval is consumed by the attempt even when resolution
    // fails; the governor reservation is released.
    let resolved;
    try {
      resolved = await this.#resolveHost(parsed.hostname);
    } catch {
      this.#governor.release(reservation.reservationId);
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'DNS_RESOLUTION_FAILED' });
      return result(false, 'DNS_RESOLUTION_FAILED');
    }
    const addresses = (Array.isArray(resolved) ? resolved : [resolved])
      .map((entry) => (typeof entry === 'string' ? entry : entry && entry.address))
      .filter((address) => typeof address === 'string');
    if (addresses.length === 0 || addresses.some((address) => !isPublicAddress(address))) {
      this.#governor.release(reservation.reservationId);
      await this.#audit.append('PUBLIC_HTTP_BLOCKED', { targetId, url, reason: 'RESOLVED_NON_PUBLIC_HOST' });
      return result(false, 'RESOLVED_NON_PUBLIC_HOST');
    }
    try {
      await this.#audit.append('PUBLIC_HTTP_REQUEST_ALLOWED', { targetId, url, method: 'GET', estimatedRequests });
    } catch {
      this.#governor.release(reservation.reservationId);
      return result(false, 'AUDIT_UNAVAILABLE');
    }

    let request;
    let timer;
    let poller;
    let settled = false;
    let finishRun;
    const workerId = `public-http-${reservation.reservationId}`;
    // cleanup() is async: unregister() writes the kill-switch state
    // under a lock, and calling it fire-and-forget could strand the
    // worker record until lease expiry (blocking reset() with
    // WORKERS_STILL_REGISTERED) and turn a write rejection into an
    // unhandled rejection — there is no unhandledRejection handler
    // anywhere in src/ or bin/, so Node would crash the process.
    // finishRun therefore awaits cleanup and never rejects: a cleanup
    // failure resolves with the real HTTP result plus
    // unregisterFailed: true, so the outcome stays honest.
    const cleanup = async () => {
      if (timer) clearTimeout(timer);
      if (poller) clearInterval(poller);
      this.#governor.release(reservation.reservationId);
      await unregister();
    };
    let unregister = () => {};
    const run = new Promise((resolve) => {
      const body = [];
      let bytes = 0;
      // Never rejects by construction: cleanup() failures are
      // converted to a resolved value (see cleanup above), so the two
      // synchronous call sites (the 'error' handler and the timeout)
      // may call it with `void` — the guard test enforces that every
      // other call site awaits it.
      finishRun = (value) => {
        if (settled) return Promise.resolve();
        settled = true;
        return Promise.resolve(cleanup()).then(
          () => resolve(value),
          () => resolve({ ...value, unregisterFailed: true }),
        );
      };
      const cancel = async () => {
        try {
          request?.destroy();
        } catch {
          // Already destroyed; the finish below still runs.
        }
        await finishRun(result(false, 'PROCESS_FAILED', { cancellation: 'KILL_SWITCH_ACTIVE' }));
      };
      Promise.resolve(this.#killSwitch.registerWorker({ workerId, cancel })).then((registration) => {
        if (!registration.registered) {
          this.#governor.release(reservation.reservationId);
          void finishRun(result(false, registration.reason));
          return;
        }
        unregister = registration.unregister || (() => {});
        request = this.#requestGet(parsed, (response) => {
          response.setEncoding('utf8');
          response.on('data', (chunk) => {
            bytes += Buffer.byteLength(chunk);
            if (bytes <= this.#maxBodyBytes) body.push(chunk);
          });
          response.once('end', async () => {
            try {
              const pressure = typeof this.#governor.recordResponse === 'function'
                ? this.#governor.recordResponse(parsed.hostname, response.statusCode)
                : { action: 'UNSUPPORTED' };
              await this.#audit.append('PUBLIC_HTTP_RESPONSE', { targetId, url, statusCode: response.statusCode, contentLength: bytes, redirected: [301, 302, 303, 307, 308].includes(response.statusCode), pressureAction: pressure.action });
              const headers = Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key, redact(value, key)]));
              await finishRun(result(true, 'HTTP_COMPLETED', { statusCode: response.statusCode, headers, body: body.join(''), truncated: bytes > this.#maxBodyBytes }));
            } catch {
              await finishRun(result(false, 'AUDIT_UNAVAILABLE'));
            }
          });
        });
        request.once('error', (error) => void finishRun(result(false, 'HTTP_ERROR', { errorCode: error.code || 'HTTP_ERROR' })));
        timer = setTimeout(() => {
          try {
            request.destroy();
          } catch {
            // Already destroyed; the finish below still runs.
          }
          void finishRun(result(false, 'HTTP_TIMEOUT', { timeoutMs: this.#timeoutMs }));
        }, this.#timeoutMs);
        poller = setInterval(async () => {
          if (settled) return;
          try {
            const current = await this.#killSwitch.assertNotTriggered();
            if (!current.allowed) await cancel();
          } catch {
            // cancel() is non-rejecting by construction (finishRun
            // converts cleanup failures to a resolved value and
            // destroy() is guarded above), but a rejection escaping
            // this interval callback would be unhandled and crash the
            // process — there is no unhandledRejection handler. Never
            // let it escape: a second cancel attempt is best-effort.
            try {
              await cancel();
            } catch {
              // Already finishing; the timeout is the backstop.
            }
          }
        }, this.#pollIntervalMs);
      }).catch(() => void finishRun(result(false, 'PROCESS_ERROR')));
    });
    return run;
  }
}

module.exports = { PublicHttpAdapter, isPublicAddress, isPublicHostname };
