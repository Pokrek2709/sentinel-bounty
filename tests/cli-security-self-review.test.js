// CLI security self-review (Phase 8, round 34).
//
// Probes run against the pre-fix code (see the round-34 capability
// report) established:
//   VULNERABLE (fixed here): report --out, check-env --output and the
//     check-env storage marker all followed a planted symlink at the
//     exact output path, writing attacker-influenced content to the
//     link target; finding/target input files had no size, depth or
//     count bound (a 12 MB finding and a 31 MB / 20,000-finding file
//     were accepted in full; a 5,000-deep value made the JSON report
//     path fail with a raw stack-overflow error).
//   TESTED NEGATIVE (locked in here as regressions): prototype
//     pollution via parsed JSON (no Object.assign anywhere; all merges
//     are spreads or Maps; validator/generator/normalizer read named
//     fields only); argument injection (spawn uses shell:false with
//     fixed allowlisted args; hostile metacharacters arrive literally);
//     malicious kill-switch state (unparseable/wrong-shape state is
//     KILL_SWITCH_STATE_CORRUPT, hostile worker entries are dropped).
'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const FIXTURE = path.resolve(__dirname, 'fixtures', 'report-critical.json');
const GEN = '2026-11-26T00:00:00+07:00';

const { writeFileRefusingSymlink } = require('../src/policy/safe-write');
const { checkJsonDepth, readJsonFileBounded, MAX_JSON_DEPTH } = require('../src/policy/input-limits');
const { validateFinding, dedupeFindings } = require('../src/analysis/validator');
const { generateReport, countBySeverity } = require('../src/report/generator');
const { normalizeRawFinding } = require('../src/detection/normalized-record');
const { runStubDetector } = require('../src/detection/stub-detector');
const { ControlledExecution } = require('../src/execution/controlled-wrapper');
const { ApprovalGate } = require('../src/policy/approval-gate');
const { KillSwitch } = require('../src/policy/kill-switch');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { RequestGovernor } = require('../src/policy/request-governor');
const { TargetRegistry } = require('../src/scope/target-registry');
const { checkStorage } = require('../src/environment/checker');

async function tempDir(t, prefix) {
  return makeTempDir(t, prefix);
}

async function runCli(args) {
  try {
    const { stdout } = await execFileAsync(process.execPath, [CLI, ...args]);
    return { code: 0, stdout, stderr: '' };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function nestedJson(depth) {
  let text = '"leaf"';
  for (let i = 0; i < depth; i += 1) text = `{"a":${text}}`;
  return text;
}

// --- safe-write unit ---

test('safe-write: writes a new file with mode 0600 and overwrites a regular file', async (t) => {
  const dir = await tempDir(t, 'r34-safe-');
  const target = path.join(dir, 'out.md');
  await writeFileRefusingSymlink(target, 'one');
  assert.equal(await fs.readFile(target, 'utf8'), 'one');
  assert.equal((await fs.stat(target)).mode & 0o777, 0o600);
  await writeFileRefusingSymlink(target, 'two');
  assert.equal(await fs.readFile(target, 'utf8'), 'two');
});

test('safe-write: refuses a symlink and leaves the link target untouched', async (t) => {
  const dir = await tempDir(t, 'r34-safe-');
  const target = path.join(dir, 'target.md');
  const link = path.join(dir, 'link.md');
  await fs.writeFile(target, 'ORIGINAL');
  await fs.symlink(target, link);
  await assert.rejects(writeFileRefusingSymlink(link, 'evil'), /Refusing to write through a symbolic link/);
  assert.equal(await fs.readFile(target, 'utf8'), 'ORIGINAL');
  assert.equal((await fs.lstat(link)).isSymbolicLink(), true);
});

test('safe-write: refuses a directory target', async (t) => {
  const dir = await tempDir(t, 'r34-safe-');
  await assert.rejects(writeFileRefusingSymlink(dir, 'x'), /Refusing to write to a directory/);
});

// --- input-limits unit ---

test('input-limits: depth check accepts 100 levels and rejects 101, iteratively', () => {
  assert.doesNotThrow(() => checkJsonDepth(JSON.parse(nestedJson(99)), MAX_JSON_DEPTH));
  assert.throws(() => checkJsonDepth(JSON.parse(nestedJson(100)), MAX_JSON_DEPTH), /maximum nesting depth of 100/);
  // Wide but shallow values must not trip the depth check.
  assert.doesNotThrow(() => checkJsonDepth({ items: Array.from({ length: 20_000 }, (_, i) => i) }, MAX_JSON_DEPTH));
});

test('input-limits: bounded read rejects an oversized file and invalid JSON', async (t) => {
  const dir = await tempDir(t, 'r34-limits-');
  const big = path.join(dir, 'big.json');
  await fs.writeFile(big, 'x'.repeat(101));
  await assert.rejects(readJsonFileBounded(big, { maxBytes: 100 }), /exceeds the 100 byte limit/);
  const bad = path.join(dir, 'bad.json');
  await fs.writeFile(bad, '{not json');
  await assert.rejects(readJsonFileBounded(bad), /Invalid JSON in .*bad\.json/);
  const good = path.join(dir, 'good.json');
  await fs.writeFile(good, '{"a":1}');
  assert.deepEqual(await readJsonFileBounded(good), { a: 1 });
});

// --- countBySeverity guard ---

test('report: countBySeverity ignores an unvalidated hostile severity without polluting', () => {
  const counts = countBySeverity([{ severity: '__proto__' }, { severity: 'high' }]);
  assert.deepEqual(counts, { critical: 0, high: 1, medium: 0, low: 0, informational: 0, total: 1 });
  assert.equal(Object.prototype.hasOwnProperty.call(counts, '__proto__'), false);
  assert.equal({}.polluted, undefined);
});

// --- prototype-pollution regression (probe P2, tested negative) ---

test('security: __proto__ keys in parsed findings do not pollute Object.prototype', async (t) => {
  const finding = JSON.parse(await fs.readFile(FIXTURE, 'utf8'));
  finding['__proto__'] = { polluted: 'yes' };
  finding.evidence = [{ request: 'GET /', '__proto__': { polluted: 'yes' } }];
  finding['constructor'] = { prototype: { polluted: 'yes' } };
  validateFinding(finding);
  generateReport([finding], { format: 'json', generatedAt: GEN });
  generateReport([finding], { format: 'markdown', generatedAt: GEN });
  dedupeFindings([finding, { ...finding, finding_id: 'OTHER' }]);
  normalizeRawFinding(JSON.parse('{"__proto__":{"polluted":"yes"},"finding_id":"N-1","title":"t","vulnerability_type":"x","description":"d","impact":"i","remediation":"r","session_id":"s","target_id":"t","asset_id":"a","severity":"high","steps_to_reproduce":["s1"],"evidence":[{"__proto__":{"polluted":"yes"},"request":"GET /"}]}'), {});
  const dir = await tempDir(t, 'r34-pollution-');
  const fixturePath = path.join(dir, 'fixture.json');
  await fs.writeFile(fixturePath, JSON.stringify({ tool: 't', results: [finding] }));
  runStubDetector(fixturePath, {});
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  delete Object.prototype.polluted;
});

// --- argument-injection regression (probe P3, tested negative) ---

test('security: hostile tool args reach spawn literally, with shell:false, never a shell', async () => {
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
  const seen = [];
  const fakeProcess = () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => true;
    process.nextTick(() => { child.exitCode = 0; child.emit('close', 0, null); });
    return child;
  };
  const wrapper = new ControlledExecution({
    registry, approvalGate, governor, killSwitch: new KillSwitch({ clock: () => 0 }),
    tools: { hostile: { command: '/bin/echo', args: ['$(touch /tmp/pwned)', '; touch /tmp/pwned', '`touch /tmp/pwned`'] } },
    spawnProcess: (command, args, options) => { seen.push({ command, args, options }); return fakeProcess(); },
    killPollIntervalMs: 100, timeoutMs: 10_000, cancellationGraceMs: 0,
  });
  const result = await wrapper.execute({
    targetId: 'local-lab', requestUrl: 'https://example.test/', action: 'safe_scanning',
    toolName: 'hostile', approvalId: approved.approvalId, estimatedRequests: 1, scopeFingerprint: fingerprint,
  });
  assert.equal(result.allowed, true);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].command, '/bin/echo');
  assert.deepEqual(seen[0].args, ['$(touch /tmp/pwned)', '; touch /tmp/pwned', '`touch /tmp/pwned`']);
  assert.equal(seen[0].options.shell, false);
});

// --- malicious-state regression (probe P5, tested negative) ---

test('security: snapshot drops hostile worker entries from a hand-edited state file', async (t) => {
  const dir = await tempDir(t, 'r34-state-');
  const stateFile = path.join(dir, 'kill-switch.json');
  await fs.writeFile(stateFile, JSON.stringify({
    version: 2, active: false, trigger: null,
    workers: [null, 'x', 42, { workerId: 'w1', leaseExpiresAt: 9999999999999 },
      { '__proto__': { polluted: 'yes' }, workerId: 'w2', leaseExpiresAt: 1 },
      { workerId: 'w3' }],
  }));
  const killSwitch = new PersistentKillSwitch({ stateFile, skillDirectory: path.resolve(__dirname, '..') });
  const snapshot = await killSwitch.snapshot();
  assert.deepEqual(snapshot.workers.map((w) => w.workerId), ['w1']);
  assert.equal(snapshot.registeredWorkers, 1);
  assert.equal({}.polluted, undefined);
  delete Object.prototype.polluted;
});

// --- CLI integration: symlink refusal (probe P1, fixed) ---

test('security: CLI report --out refuses a planted symlink, target untouched', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  const target = path.join(dir, 'target.md');
  const link = path.join(dir, 'link.md');
  await fs.writeFile(target, 'ORIGINAL');
  await fs.symlink(target, link);
  const res = await runCli(['report', '--finding', FIXTURE, '--generated-at', GEN, '--out', link]);
  assert.notEqual(res.code, 0);
  assert.match(res.stderr, /Refusing to write through a symbolic link/);
  assert.equal(await fs.readFile(target, 'utf8'), 'ORIGINAL');
});

test('security: CLI check-env --output refuses a planted symlink, target untouched', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  const target = path.join(dir, 'target.json');
  const link = path.join(dir, 'link.json');
  await fs.writeFile(target, 'ORIGINAL');
  await fs.symlink(target, link);
  const res = await runCli(['check-env', '--output', link, '--probe-dir', path.join(dir, 'probe')]);
  assert.notEqual(res.code, 0);
  assert.match(res.stderr, /Refusing to write through a symbolic link/);
  assert.equal(await fs.readFile(target, 'utf8'), 'ORIGINAL');
});

test('security: checkStorage refuses a symlinked marker and leaves the target untouched', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  const target = path.join(dir, 'marker-target.json');
  await fs.writeFile(target, JSON.stringify({ createdAt: '2026-01-01T00:00:00.000Z', nonce: 'old-nonce' }));
  await fs.symlink(target, path.join(dir, '.sentinel-environment-probe.json'));
  const result = await checkStorage(dir, new Date('2026-11-26T00:00:00.000Z'));
  assert.equal(result.status, 'unavailable');
  assert.match(result.detail.reason, /Refusing to write through a symbolic link/);
  assert.equal(JSON.parse(await fs.readFile(target, 'utf8')).nonce, 'old-nonce');
});

// --- CLI integration: bounded input (probe P4, fixed) ---

test('security: CLI report refuses a finding file over the size limit', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  const finding = JSON.parse(await fs.readFile(FIXTURE, 'utf8'));
  finding.description = 'A'.repeat(11 * 1024 * 1024);
  const big = path.join(dir, 'big.json');
  await fs.writeFile(big, JSON.stringify(finding));
  const res = await runCli(['report', '--finding', big, '--generated-at', GEN]);
  assert.notEqual(res.code, 0);
  assert.match(res.stderr, /exceeds the 10485760 byte limit/);
});

test('security: CLI report refuses a findings array over the count limit', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  // A minimal valid finding (~350 bytes each) so 10,001 of them stay
  // under the 10 MiB file limit and the COUNT limit is what fires.
  const minimal = {
    finding_id: 'F-0', session_id: 'S', target_id: 'T', asset_id: 'A',
    title: 't', vulnerability_type: 'x', severity: 'low', confidence: 'potential',
    validation_status: 'detected', description: 'd', steps_to_reproduce: ['s1'],
    impact: 'i', remediation: 'r',
  };
  const many = Array.from({ length: 10_001 }, (_, i) => ({ ...minimal, finding_id: `F-${i}` }));
  const file = path.join(dir, 'many.json');
  await fs.writeFile(file, JSON.stringify(many));
  assert.ok((await fs.stat(file)).size < 10 * 1024 * 1024, 'test file must stay under the byte limit');
  const res = await runCli(['report', '--findings', file, '--generated-at', GEN, '--format', 'json']);
  assert.notEqual(res.code, 0);
  assert.match(res.stderr, /Too many findings: 10001 \(maximum 10000\)/);
});

test('security: CLI report refuses JSON nested deeper than the depth limit', async (t) => {
  const dir = await tempDir(t, 'r34-cli-');
  const baseText = (await fs.readFile(FIXTURE, 'utf8')).trim();
  const deep = path.join(dir, 'deep.json');
  await fs.writeFile(deep, `${baseText.slice(0, -1)},"extra":${nestedJson(150)}}`);
  const res = await runCli(['report', '--finding', deep, '--generated-at', GEN, '--format', 'json']);
  assert.notEqual(res.code, 0);
  assert.match(res.stderr, /maximum nesting depth of 100/);
});
