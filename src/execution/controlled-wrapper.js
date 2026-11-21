const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');

function requireString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw new TypeError(`${field} must be a non-empty string.`);
  return value.trim();
}

function result(allowed, reason, detail = {}) {
  return Object.freeze({ allowed, reason, ...detail });
}

async function collectDescendantPids(rootPid) {
  if (process.platform !== 'linux' || !Number.isInteger(rootPid)) return [];
  const entries = await fs.readdir('/proc', { withFileTypes: true });
  const children = new Map();
  await Promise.all(entries
    .filter((entry) => entry.isDirectory() && /^\d+$/.test(entry.name))
    .map(async (entry) => {
      try {
        const status = await fs.readFile(`/proc/${entry.name}/status`, 'utf8');
        const parentLine = status.split('\n').find((line) => line.startsWith('PPid:'));
        const parentPid = Number(parentLine?.split(/\s+/)[1]);
        const pid = Number(entry.name);
        if (!Number.isInteger(parentPid) || !Number.isInteger(pid)) return;
        const list = children.get(parentPid) || [];
        list.push(pid);
        children.set(parentPid, list);
      } catch (error) {
        if (!['ENOENT', 'EACCES'].includes(error.code)) throw error;
      }
    }));
  const descendants = [];
  const pending = [...(children.get(rootPid) || [])];
  while (pending.length > 0) {
    const pid = pending.shift();
    descendants.push(pid);
    pending.push(...(children.get(pid) || []));
  }
  return descendants;
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
    let cancellationCause = null;
    let settled = false;
    let finishRun = null;
    let unregister = () => {};
    const close = async () => {
      if (timer) clearTimeout(timer);
      if (killPoller) clearInterval(killPoller);
      this.#governor.release(reservation.reservationId);
      await unregister();
    };
    const terminate = async ({ cause = 'CANCEL' } = {}) => {
      if (cause === 'KILL_SWITCH') cancellationCause = 'KILL_SWITCH';
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      const descendantPids = await collectDescendantPids(child.pid);
      const signalProcessTree = (signal) => {
        let groupSignalled = false;
        if (process.platform !== 'win32' && child.pid) {
          try {
            process.kill(-child.pid, signal);
            groupSignalled = true;
          } catch (error) {
            if (!['ESRCH', 'EINVAL'].includes(error.code)) throw error;
          }
        }
        if (!groupSignalled) child.kill(signal);
        for (const pid of descendantPids) {
          try {
            process.kill(pid, signal);
          } catch (error) {
            if (!['ESRCH', 'EPERM'].includes(error.code)) throw error;
          }
        }
      };
      signalProcessTree('SIGTERM');
      if (this.#cancellationGraceMs === 0) return;
      await new Promise((resolve) => setTimeout(resolve, this.#cancellationGraceMs));
      if (child.exitCode === null && child.signalCode === null) signalProcessTree('SIGKILL');
      if (cause === 'KILL_SWITCH' && !settled && finishRun) finishRun(result(false, 'PROCESS_FAILED', { cancellation: 'KILL_SWITCH_ACTIVE' }));
    };

    const registration = await this.#killSwitch.registerWorker({
      workerId,
      cancel: (request = {}) => terminate({ cause: request.reason === 'KILL_SWITCH_ACTIVE' ? 'KILL_SWITCH' : 'CANCEL' }),
    });
    if (!registration.registered) {
      this.#governor.release(reservation.reservationId);
      return result(false, registration.reason);
    }
    unregister = registration.unregister || (() => {});

    // A remote trigger can arrive in the gap between worker registration and
    // child creation. Re-check before spawning so cancellation never permits a
    // process to start after the persistent switch is active.
    const postRegistrationKillStatus = await this.#killSwitch.assertNotTriggered();
    if (!postRegistrationKillStatus.allowed) {
      await unregister();
      this.#governor.release(reservation.reservationId);
      return result(false, 'PROCESS_FAILED', { cancellation: 'KILL_SWITCH_ACTIVE' });
    }

    const run = new Promise((resolve) => {
      const output = { stdout: '', stderr: '' };
      const finish = (value) => {
        if (settled) return;
        settled = true;
        Promise.resolve(close()).then(() => resolve(value), () => resolve(result(false, 'POLICY_ERROR')));
      };
      finishRun = finish;
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
          if (typeof this.#killSwitch.heartbeatWorker === 'function') await this.#killSwitch.heartbeatWorker(workerId);
          const currentKillStatus = await this.#killSwitch.assertNotTriggered();
          if (!currentKillStatus.allowed) await terminate({ cause: 'KILL_SWITCH' });
        } catch {
          // An unreadable kill-switch state is fail-closed: stop the child.
          await terminate({ cause: 'KILL_SWITCH' });
        } finally {
          killCheckInFlight = false;
        }
      }, this.#killPollIntervalMs);
      child.once('error', (error) => finish(result(false, 'PROCESS_ERROR', { error: 'Tool process failed during execution.', errorCode: error.code || 'PROCESS_ERROR' })));
      child.once('close', (code, signal) => finish(result(
        timeoutTriggered ? false : cancellationCause === 'KILL_SWITCH' ? false : code === 0,
        timeoutTriggered ? 'EXECUTION_TIMEOUT' : cancellationCause === 'KILL_SWITCH' ? 'PROCESS_FAILED' : code === 0 ? 'EXECUTED' : 'PROCESS_FAILED',
        {
          exitCode: code,
          signal,
          ...(timeoutTriggered ? { timeoutMs: this.#timeoutMs } : {}),
          ...(cancellationCause === 'KILL_SWITCH' ? { cancellation: 'KILL_SWITCH_ACTIVE' } : {}),
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
