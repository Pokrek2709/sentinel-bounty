const http = require('node:http');
const https = require('node:https');
const { redact } = require('../audit/audit-log');

function result(allowed, reason, detail = {}) {
  return Object.freeze({ allowed, reason, ...detail });
}

class LocalHttpAdapter {
  #registry;
  #approvalGate;
  #governor;
  #killSwitch;
  #audit;
  #timeoutMs;
  #maxBodyBytes;
  #pollIntervalMs;
  #requestGet;

  constructor({ registry, approvalGate, governor, killSwitch, auditLog, timeoutMs = 5_000, maxBodyBytes = 1_048_576, pollIntervalMs = 100, requestGet } = {}) {
    if (!registry || typeof registry.evaluate !== 'function' || typeof registry.getScopeFingerprint !== 'function') throw new TypeError('registry is required.');
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
  }

  async get({ targetId, url, approvalId, estimatedRequests = 1, scopeFingerprint }) {
    const kill = await this.#killSwitch.assertNotTriggered();
    if (!kill.allowed) return result(false, kill.reason);
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return result(false, 'INVALID_URL');
    }
    if (parsed.protocol !== 'http:' || parsed.hostname.toLowerCase() !== 'localhost') {
      await this.#audit.append('HTTP_BLOCKED', { targetId, url, reason: 'LOCALHOST_ONLY' });
      return result(false, 'LOCALHOST_ONLY');
    }
    const scope = this.#registry.evaluate(targetId, parsed.toString());
    if (!scope.allowed) {
      await this.#audit.append('HTTP_BLOCKED', { targetId, url, reason: `SCOPE_${scope.reason}` });
      return result(false, `SCOPE_${scope.reason}`);
    }
    if (!this.#registry.isMethodAllowed(targetId, 'http_probing')) return result(false, 'ACTION_NOT_ALLOWED');
    const fingerprint = this.#registry.getScopeFingerprint(targetId);
    if (scopeFingerprint !== fingerprint) return result(false, 'SCOPE_FINGERPRINT_MISMATCH');
    const reservation = this.#governor.acquire('localhost');
    if (!reservation.allowed) return result(false, `GOVERNOR_${reservation.reason}`);
    const approval = this.#approvalGate.authorize(approvalId, { targetId, action: 'http_probing', estimatedRequests, scopeFingerprint: fingerprint });
    if (!approval.allowed) {
      this.#governor.release(reservation.reservationId);
      return result(false, approval.reason);
    }
    try {
      await this.#audit.append('HTTP_REQUEST_ALLOWED', { targetId, url, method: 'GET', estimatedRequests });
    } catch {
      this.#governor.release(reservation.reservationId);
      return result(false, 'AUDIT_UNAVAILABLE');
    }

    let request;
    let timer;
    let poller;
    let settled = false;
    let finishRun;
    const workerId = `http-${reservation.reservationId}`;
    // cleanup() is async: unregister() writes the kill-switch state
    // under a lock, and the first version called it fire-and-forget
    // here. A process that exited right after get() resolved could
    // strand the worker record until lease expiry (blocking reset()
    // with WORKERS_STILL_REGISTERED), and a write rejection became an
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
                ? this.#governor.recordResponse('localhost', response.statusCode)
                : { action: 'UNSUPPORTED' };
              await this.#audit.append('HTTP_RESPONSE', { targetId, url, statusCode: response.statusCode, contentLength: bytes, redirected: [301, 302, 303, 307, 308].includes(response.statusCode), pressureAction: pressure.action });
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

module.exports = { LocalHttpAdapter };
