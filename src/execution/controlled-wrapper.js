const { spawn } = require('node:child_process');

function requireString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw new TypeError(`${field} must be a non-empty string.`);
  return value.trim();
}

function result(allowed, reason, detail = {}) {
  return Object.freeze({ allowed, reason, ...detail });
}

class ControlledExecution {
  #registry;
  #approvalGate;
  #governor;
  #killSwitch;
  #tools;
  #spawnProcess;
  #timeoutMs;
  #cancellationGraceMs;
  #killPollIntervalMs;

  constructor({ registry, approvalGate, governor, killSwitch, tools = {}, spawnProcess = spawn, timeoutMs = 60_000, cancellationGraceMs = 1_000, killPollIntervalMs = 100 } = {}) {
    if (!registry || typeof registry.evaluate !== 'function' || typeof registry.getScopeFingerprint !== 'function') throw new TypeError('registry is required.');
    if (!approvalGate || typeof approvalGate.authorize !== 'function') throw new TypeError('approvalGate is required.');
    if (!governor || typeof governor.acquire !== 'function' || typeof governor.release !== 'function') throw new TypeError('governor is required.');
    if (!killSwitch || typeof killSwitch.assertNotTriggered !== 'function' || typeof killSwitch.registerWorker !== 'function') throw new TypeError('killSwitch is required.');
    if (!tools || typeof tools !== 'object' || Array.isArray(tools)) throw new TypeError('tools must be an object.');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('timeoutMs must be a positive integer.');
    if (!Number.isInteger(cancellationGraceMs) || cancellationGraceMs < 0) throw new RangeError('cancellationGraceMs must be a non-negative integer.');
    if (!Number.isInteger(killPollIntervalMs) || killPollIntervalMs < 10) throw new RangeError('killPollIntervalMs must be an integer of at least 10ms.');
    this.#registry = registry;
    this.#approvalGate = approvalGate;
    this.#governor = governor;
    this.#killSwitch = killSwitch;
    this.#tools = Object.freeze(Object.fromEntries(Object.entries(tools).map(([name, definition]) => {
      requireString(name, 'tool name');
      if (!definition || typeof definition.command !== 'string' || !Array.isArray(definition.args)) throw new TypeError(`Tool ${name} must define a command and fixed args.`);
      if (definition.args.some((arg) => typeof arg !== 'string')) throw new TypeError(`Tool ${name} args must be strings.`);
      return [name, Object.freeze({ command: definition.command, args: Object.freeze([...definition.args]) })];
    })));
    this.#spawnProcess = spawnProcess;
    this.#timeoutMs = timeoutMs;
    this.#cancellationGraceMs = cancellationGraceMs;
    this.#killPollIntervalMs = killPollIntervalMs;
  }

  async execute({ targetId, requestUrl, action, toolName, approvalId, estimatedRequests, scopeFingerprint }) {
    const killStatus = await this.#killSwitch.assertNotTriggered();
    if (!killStatus.allowed) return result(false, killStatus.reason);

    const tool = this.#tools[toolName];
    if (!tool) return result(false, 'TOOL_NOT_ALLOWLISTED', { toolName });
    if (!this.#registry.isMethodAllowed(targetId, action)) return result(false, 'ACTION_NOT_ALLOWED', { action });
    const scope = this.#registry.evaluate(targetId, requestUrl);
    if (!scope.allowed) return result(false, `SCOPE_${scope.reason}`, { scope });
    const expectedFingerprint = this.#registry.getScopeFingerprint(targetId);
    if (scopeFingerprint !== expectedFingerprint) return result(false, 'SCOPE_FINGERPRINT_MISMATCH');

    const reservation = this.#governor.acquire(scope.hostname);
    if (!reservation.allowed) return result(false, `GOVERNOR_${reservation.reason}`, { governor: reservation });

    const approval = this.#approvalGate.authorize(approvalId, {
      targetId,
      action,
      estimatedRequests,
      scopeFingerprint: expectedFingerprint,
    });
    if (!approval.allowed) {
      this.#governor.release(reservation.reservationId);
      return result(false, approval.reason);
    }

    const workerId = `execution-${reservation.reservationId}`;
    let child;
    let timer;
    let killPoller;
    let killCheckInFlight = false;
    let timeoutTriggered = false;
    let settled = false;
    let unregister = () => {};
    const close = () => {
      if (timer) clearTimeout(timer);
      if (killPoller) clearInterval(killPoller);
      this.#governor.release(reservation.reservationId);
      unregister();
    };
    const terminate = async () => {
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      const signalProcessTree = (signal) => {
        if (process.platform !== 'win32' && child.pid) {
          try {
            process.kill(-child.pid, signal);
            return;
          } catch (error) {
            if (!['ESRCH', 'EINVAL'].includes(error.code)) throw error;
          }
        }
        child.kill(signal);
      };
      signalProcessTree('SIGTERM');
      if (this.#cancellationGraceMs === 0) return;
      await new Promise((resolve) => setTimeout(resolve, this.#cancellationGraceMs));
      if (child.exitCode === null && child.signalCode === null) signalProcessTree('SIGKILL');
    };

    const registration = await this.#killSwitch.registerWorker({ workerId, cancel: terminate });
    if (!registration.registered) {
      this.#governor.release(reservation.reservationId);
      return result(false, registration.reason);
    }
    unregister = registration.unregister || (() => {});

    const run = new Promise((resolve) => {
      const output = { stdout: '', stderr: '' };
      const finish = (value) => {
        if (settled) return;
        settled = true;
        close();
        resolve(value);
      };
      try {
        child = this.#spawnProcess(tool.command, tool.args, {
          shell: false,
          windowsHide: true,
          detached: process.platform !== 'win32',
        });
      } catch (error) {
        finish(result(false, 'PROCESS_ERROR', { error: 'Tool process failed to start.', errorCode: error.code || 'SPAWN_FAILED' }));
        return;
      }
      if (typeof child.stdout?.setEncoding === 'function') child.stdout.setEncoding('utf8');
      if (typeof child.stderr?.setEncoding === 'function') child.stderr.setEncoding('utf8');
      child.stdout?.on('data', (chunk) => { output.stdout += chunk; });
      child.stderr?.on('data', (chunk) => { output.stderr += chunk; });
      killPoller = setInterval(async () => {
        if (killCheckInFlight || settled) return;
        killCheckInFlight = true;
        try {
          const currentKillStatus = await this.#killSwitch.assertNotTriggered();
          if (!currentKillStatus.allowed) await terminate();
        } catch {
          // An unreadable kill-switch state is fail-closed: stop the child.
          await terminate();
        } finally {
          killCheckInFlight = false;
        }
      }, this.#killPollIntervalMs);
      child.once('error', (error) => finish(result(false, 'PROCESS_ERROR', { error: 'Tool process failed during execution.', errorCode: error.code || 'PROCESS_ERROR' })));
      child.once('close', (code, signal) => finish(result(
        timeoutTriggered ? false : code === 0,
        timeoutTriggered ? 'EXECUTION_TIMEOUT' : code === 0 ? 'EXECUTED' : 'PROCESS_FAILED',
        {
          exitCode: code,
          signal,
          ...(timeoutTriggered ? { timeoutMs: this.#timeoutMs } : {}),
          stdout: output.stdout,
          stderr: output.stderr,
        },
      )));
      timer = setTimeout(async () => {
        timeoutTriggered = true;
        await terminate();
        finish(result(false, 'EXECUTION_TIMEOUT', { timeoutMs: this.#timeoutMs, stdout: output.stdout, stderr: output.stderr }));
      }, this.#timeoutMs);
    });
    return run;
  }
}

module.exports = { ControlledExecution };
