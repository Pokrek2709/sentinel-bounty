const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { ApprovalGate } = require('../src/policy/approval-gate');
const { ControlledExecution } = require('../src/execution/controlled-wrapper');
const { KillSwitch } = require('../src/policy/kill-switch');
const { RequestGovernor } = require('../src/policy/request-governor');
const { TargetRegistry } = require('../src/scope/target-registry');

const FINGERPRINT_PLACEHOLDER = '0'.repeat(64);

function setup({ spawnProcess } = {}) {
  const registry = new TargetRegistry();
  registry.register({
    target_id: 'local-lab', program_name: 'Local lab', authorization_reference: 'LOCAL-LAB',
    allowed_domains: ['example.test'], request_budget: 10,
  });
  const fingerprint = registry.getScopeFingerprint('local-lab');
  const approvalGate = new ApprovalGate({ clock: () => 0 });
  const requested = approvalGate.request({ targetId: 'local-lab', action: 'safe_scanning', estimatedRequests: 1, scopeFingerprint: fingerprint, reason: 'Local lab only' });
  const approved = approvalGate.approve(requested.requestId, { approver: 'local-human' });
  const governor = new RequestGovernor({ requestBudget: 10, clock: () => 0 });
  const killSwitch = new KillSwitch({ clock: () => 0 });
  const wrapper = new ControlledExecution({
    registry, approvalGate, governor, killSwitch,
    tools: { node_version: { command: process.execPath, args: ['--version'] } },
    spawnProcess,
  });
  return { wrapper, killSwitch, fingerprint, approvalId: approved.approvalId };
}

function fakeProcess({ exitCode = 0, stdout = 'ok\n' } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kill = (signal) => {
    child.signalCode = signal;
    child.exitCode = exitCode;
    child.stdout.emit('data', stdout);
    child.emit('close', exitCode, signal);
    return true;
  };
  process.nextTick(() => {
    child.exitCode = exitCode;
    child.stdout.emit('data', stdout);
    child.emit('close', exitCode, null);
  });
  return child;
}

test('refuses unregistered tools and out-of-scope URLs before spawning', async () => {
  let spawned = false;
  const context = setup({ spawnProcess: () => { spawned = true; return fakeProcess(); } });
  const deniedTool = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning', toolName: 'shell', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.equal(deniedTool.reason, 'TOOL_NOT_ALLOWLISTED');
  const deniedScope = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://outside.test/', action: 'safe_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.match(deniedScope.reason, /^SCOPE_/);
  assert.equal(spawned, false);
});

test('refuses an action that the target registration does not allow', async () => {
  let spawned = false;
  const context = setup({ spawnProcess: () => { spawned = true; return fakeProcess(); } });
  const result = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'active_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.deepEqual(result, { allowed: false, reason: 'ACTION_NOT_ALLOWED', action: 'active_scanning' });
  assert.equal(spawned, false);
});

test('releases policy state when spawning the fixed command throws', async () => {
  const context = setup({ spawnProcess: () => { throw new Error('spawn denied'); } });
  const result = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.deepEqual(result, { allowed: false, reason: 'PROCESS_ERROR', error: 'spawn denied' });
  assert.equal(context.killSwitch.snapshot().registeredWorkers, 0);
});

test('requires exact approval and executes one fixed command without a shell', async () => {
  let received;
  const context = setup({ spawnProcess: (command, args, options) => { received = { command, args, options }; return fakeProcess(); } });
  const result = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.equal(result.reason, 'EXECUTED');
  assert.equal(received.options.shell, false);
  assert.equal(received.command, process.execPath);
  assert.deepEqual(received.args, ['--version']);
});

test('kill switch cancels an active wrapper worker and prevents future execution', async () => {
  let child;
  const context = setup({ spawnProcess: () => {
    child = new EventEmitter();
    child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.exitCode = null; child.signalCode = null;
    child.kill = (signal) => { child.signalCode = signal; child.exitCode = 143; child.emit('close', 143, signal); return true; };
    return child;
  } });
  const execution = context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  await new Promise((resolve) => setImmediate(resolve));
  const trigger = await context.killSwitch.trigger({ triggeredBy: 'local-human', reason: 'Stop lab execution' });
  const result = await execution;
  assert.equal(trigger.triggered, true);
  assert.equal(child.signalCode, 'SIGTERM');
  assert.equal(result.reason, 'PROCESS_FAILED');
  const blocked = await context.wrapper.execute({ targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning', toolName: 'node_version', approvalId: context.approvalId, estimatedRequests: 1, scopeFingerprint: context.fingerprint });
  assert.equal(blocked.reason, 'KILL_SWITCH_ACTIVE');
});
