'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { AuditLog, computeAuditRecordHash, GENESIS_PREV_HASH } = require('../src/audit/audit-log');
const { runVerifyInstall } = require('../src/install/verifier');
const { runEnvironmentCheck } = require('../src/environment/checker');
const {
  collectOperatorStatus,
  renderOperatorStatusText,
  OperatorStatusError,
} = require('../src/policy/operator-status');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const SKILL_DIR = path.resolve(__dirname, '..');

// Pinned tool counts for the deterministic golden: the real prober
// depends on the machine (docker/subfinder/dnsx/httpx/katana are
// absent here), so the golden injects fixed counts. The real prober
// is covered by its own test, which compares against check-env.
const STUB_TOOLS = Object.freeze({ total: 5, available: 2, missing: 3, missingTools: ['docker', 'subfinder', 'katana'] });

function chainedRecord(event, eventId, recordedAt, details, prevHash) {
  const record = { chainVersion: 1, version: 1, event, eventId, recordedAt, details, prevHash };
  return { ...record, hash: computeAuditRecordHash(record) };
}

function legacyRecord(event, eventId, recordedAt) {
  return { version: 1, event, eventId, recordedAt, details: {} };
}

function validTarget(id, overrides = {}) {
  return {
    target_id: id,
    program_name: 'Local test fixture',
    authorization_reference: 'LOCAL-LAB-ONLY',
    allowed_domains: ['example.test', '*.example.test'],
    excluded_domains: ['admin.example.test'],
    excluded_paths: ['/account/remove'],
    ...overrides,
  };
}

// A complete fixture state: inactive switch with one live and one
// expired worker, 2 legacy + 2 chained audit records (one of them a
// round-62 AUDIT_LOG_PRUNED anchor), 2 valid + 1 invalid scope
// targets, a retention policy, all files mode 0600 in a 0700 dir so
// verify-install passes 7/7. The reset-token env var is cleared so
// resetTokenConfigured is deterministically false.
async function buildFixture(t, { killSwitch, auditLines, retention = { schema_version: 1, max_archives: 2, max_records: 100 } } = {}) {
  const directory = await makeTempDir(t, 'sentinel-status-');
  const stateDir = path.join(directory, 'state');
  await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
  await fs.chmod(stateDir, 0o700);
  const state = killSwitch || {
    version: 2,
    active: false,
    trigger: null,
    workers: [
      { workerId: 'live-worker', pid: 1234, leaseExpiresAt: Date.now() + 60_000 },
      { workerId: 'dead-worker', pid: 1235, leaseExpiresAt: Date.now() - 60_000 },
    ],
  };
  await fs.writeFile(path.join(stateDir, 'kill-switch.json'), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  const first = chainedRecord('EVENT_A', 'id-a', '2026-11-26T00:00:02.000Z', { n: 1 }, GENESIS_PREV_HASH);
  const anchor = chainedRecord('AUDIT_LOG_PRUNED', 'id-prune', '2026-11-26T00:00:03.000Z', { prunedCount: 1 }, first.hash);
  const lines = auditLines || [
    JSON.stringify(legacyRecord('EVENT_LEGACY_1', 'id-l1', '2026-11-26T00:00:00.000Z')),
    JSON.stringify(legacyRecord('EVENT_LEGACY_2', 'id-l2', '2026-11-26T00:00:01.000Z')),
    JSON.stringify(first),
    JSON.stringify(anchor),
  ];
  await fs.writeFile(path.join(stateDir, 'audit.jsonl'), `${lines.join('\n')}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(stateDir, 'scope-targets.json'), JSON.stringify({
    schema_version: 1,
    targets: [validTarget('local-lab-a'), validTarget('local-lab-b'), validTarget('local-lab-c', { allowed_domains: [] })],
  }, null, 2), { mode: 0o600 });
  if (retention !== null) {
    await fs.writeFile(path.join(stateDir, 'audit-retention.json'), `${JSON.stringify(retention, null, 2)}\n`, { mode: 0o600 });
  }
  return { directory, stateDir };
}

async function runCli(args, options = {}) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { windowsHide: true, ...options });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// The reset-token env var leaks into the status (presence only), so
// tests pin it: cleared for the golden, set for the configured test.
async function withEnv(key, value, fn) {
  const previous = process.env[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
  try {
    return await fn();
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
}

test('status: golden text + JSON on a known fixture state', async (t) => {
  await withEnv('SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE', undefined, async () => {
    const { stateDir } = await buildFixture(t);
    const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
    assert.equal(status.version, 1);
    assert.equal(status.killSwitch.state, 'inactive');
    assert.equal(status.killSwitch.workers, 1);
    assert.equal(status.killSwitch.trigger, null);
    assert.equal(status.killSwitch.resetTokenConfigured, false);
    assert.deepEqual(status.audit, {
      totalRecords: 4,
      verifiedRecords: 2,
      legacyRecords: 2,
      brokenRecords: 0,
      anchorHash: GENESIS_PREV_HASH,
      firstRecordedAt: '2026-11-26T00:00:00.000Z',
      lastRecordedAt: '2026-11-26T00:00:03.000Z',
      chainVerified: true,
      pruneAnchors: 1,
      firstBrokenReason: null,
    });
    assert.deepEqual(status.scope, { targets: 3, invalidTargets: 1 });
    assert.deepEqual(status.retention, { set: true, maxArchives: 2, maxRecords: 100, error: null });
    assert.deepEqual(status.verifyInstall, { passed: 7, failed: 0, overall: 'PASS' });
    assert.deepEqual(status.tools, STUB_TOOLS);
    assert.equal(renderOperatorStatusText(status), [
      `sentinel status — ${stateDir}`,
      'kill-switch: inactive (1 worker, reset token: not configured)',
      'audit: 4 records (2 verified, 2 legacy, 0 broken), chain verified, last: 2026-11-26T00:00:03.000Z, 1 prune anchor',
      'scope: 3 targets (1 invalid)',
      'retention: max_archives=2, max_records=100',
      'verify-install: 7 passed, 0 failed — PASS',
      'tools: 2 available, 3 missing (docker, subfinder, katana)',
    ].join('\n'));
    // --json is deterministic: two collections render byte-identically.
    const again = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
    assert.equal(JSON.stringify(status, null, 2), JSON.stringify(again, null, 2));
    assert.equal(renderOperatorStatusText(status), renderOperatorStatusText(again));
  });
});

test('status: lockless audit summary matches verifyChainPerRecord on the same fixture', async (t) => {
  const { directory, stateDir } = await buildFixture(t);
  const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
  const audit = new AuditLog({ logFile: path.join(stateDir, 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
  const chain = await audit.verifyChainPerRecord();
  assert.equal(status.audit.totalRecords, chain.summary.totalRecords);
  assert.equal(status.audit.verifiedRecords, chain.summary.verifiedRecords);
  assert.equal(status.audit.legacyRecords, chain.summary.legacyRecords);
  assert.equal(status.audit.brokenRecords, chain.summary.brokenRecords);
  assert.equal(status.audit.anchorHash, chain.summary.anchorHash);
  assert.equal(status.audit.firstRecordedAt, chain.summary.firstRecordedAt);
  assert.equal(status.audit.lastRecordedAt, chain.summary.lastRecordedAt);
  assert.equal(status.audit.chainVerified, chain.verified);
});

test('status: strictly read-only — file contents, file mtimes, and dir mtime unchanged', async (t) => {
  const { stateDir } = await buildFixture(t);
  async function snapshot() {
    const entries = {};
    for (const name of await fs.readdir(stateDir)) {
      const full = path.join(stateDir, name);
      const stat = await fs.stat(full);
      entries[name] = {
        content: await fs.readFile(full, 'utf8'),
        mtimeMs: stat.mtimeMs,
        mode: stat.mode,
      };
    }
    return { dirMtimeMs: (await fs.stat(stateDir)).mtimeMs, entries };
  }
  const before = await snapshot();
  await withEnv('SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE', undefined, async () => {
    const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
    renderOperatorStatusText(status);
  });
  const after = await snapshot();
  assert.deepEqual(after, before);
});

test('status: works while the kill-switch is armed, trigger shown', async (t) => {
  const armed = {
    version: 2,
    active: true,
    trigger: { triggerId: 'trig-1', triggeredBy: 'op-1', reason: 'test trigger', triggeredAt: 1795651200000 },
    workers: [],
  };
  const { stateDir } = await buildFixture(t, { killSwitch: armed });
  const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
  assert.equal(status.killSwitch.state, 'active');
  assert.deepEqual(status.killSwitch.trigger, armed.trigger);
  // verify-install fails while armed (its kill-switch check), but
  // status itself still exits 0 — the overview shows the failure,
  // it does not become one.
  assert.equal(status.verifyInstall.overall, 'FAIL');
  assert.equal(status.verifyInstall.failed, 1);
  assert.match(renderOperatorStatusText(status), /kill-switch: active \(triggered by op-1: test trigger\) \(0 workers, reset token: not configured\)/);
});

test('status: missing state dir is the empty view, not an error', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-status-empty-');
  const stateDir = path.join(directory, 'no-such-state');
  const status = await withEnv('SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE', undefined, () => collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS }));
  assert.equal(status.killSwitch.state, 'inactive');
  assert.equal(status.killSwitch.workers, 0);
  assert.equal(status.audit.totalRecords, 0);
  assert.equal(status.audit.chainVerified, true);
  assert.equal(status.audit.lastRecordedAt, null);
  assert.deepEqual(status.scope, { targets: 0, invalidTargets: 0 });
  assert.deepEqual(status.retention, { set: false, maxArchives: null, maxRecords: null, error: null });
  assert.match(renderOperatorStatusText(status), /audit: 0 records \(0 verified, 0 legacy, 0 broken\), chain verified\nscope: 0 targets \(0 invalid\)\nretention: unset/);
});

test('status: corrupt kill-switch state fails closed with the component named', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-status-corrupt-ks-');
  const stateDir = path.join(directory, 'state');
  await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(stateDir, 'kill-switch.json'), 'not json at all', { mode: 0o600 });
  await assert.rejects(
    collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS }),
    (error) => error instanceof OperatorStatusError && error.component === 'killSwitch' && error.reason === 'KILL_SWITCH_STATE_CORRUPT',
  );
  const cli = await runCli(['status', '--state-dir', stateDir]);
  assert.equal(cli.code, 1);
  assert.deepEqual(JSON.parse(cli.stdout), { status: false, component: 'killSwitch', reason: 'KILL_SWITCH_STATE_CORRUPT' });
});

test('status: corrupt audit content is reported in-section, exit stays 0', async (t) => {
  const { stateDir } = await buildFixture(t, {
    auditLines: [
      JSON.stringify(legacyRecord('EVENT_LEGACY_1', 'id-l1', '2026-11-26T00:00:00.000Z')),
      'this line is not json',
    ],
  });
  const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
  assert.equal(status.audit.totalRecords, 2);
  assert.equal(status.audit.brokenRecords, 1);
  assert.equal(status.audit.chainVerified, false);
  assert.equal(status.audit.firstBrokenReason, 'AUDIT_CHAIN_UNPARSEABLE');
  assert.match(renderOperatorStatusText(status), /chain NOT verified \(first break: AUDIT_CHAIN_UNPARSEABLE\)/);
  const cli = await runCli(['status', '--state-dir', stateDir]);
  assert.equal(cli.code, 0);
  assert.match(cli.stdout, /chain NOT verified \(first break: AUDIT_CHAIN_UNPARSEABLE\)/);
});

test('status: tampered chained record reports AUDIT_CHAIN_HASH_MISMATCH in-section', async (t) => {
  const first = chainedRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z', { n: 1 }, GENESIS_PREV_HASH);
  const tampered = { ...first, details: { n: 999 } };
  const { stateDir } = await buildFixture(t, { auditLines: [JSON.stringify(tampered)] });
  const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
  assert.equal(status.audit.brokenRecords, 1);
  assert.equal(status.audit.firstBrokenReason, 'AUDIT_CHAIN_HASH_MISMATCH');
});

test('status: damaged retention policy is reported in-section, exit stays 0', async (t) => {
  const { stateDir } = await buildFixture(t, { retention: { schema_version: 99, max_archives: 2 } });
  const status = await collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS });
  assert.equal(status.retention.set, false);
  assert.match(status.retention.error, /^AUDIT_RETENTION_INVALID/);
  assert.match(renderOperatorStatusText(status), /retention: error AUDIT_RETENTION_INVALID/);
});

test('status: damaged scope store fails closed with the component named', async (t) => {
  const { stateDir } = await buildFixture(t);
  await fs.writeFile(path.join(stateDir, 'scope-targets.json'), '{"schema_version": 99}', { mode: 0o600 });
  await assert.rejects(
    collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS }),
    (error) => error instanceof OperatorStatusError && error.component === 'scope' && /^SCOPE_STORE_/.test(error.reason),
  );
});

test('status: reset-token presence is reported, never the value', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-status-token-');
  const tokenFile = path.join(directory, 'hash.json');
  await fs.writeFile(tokenFile, `${crypto.createHash('sha256').update('never-shown').digest('hex')}\n`, { mode: 0o600 });
  const { stateDir } = await buildFixture(t);
  const status = await withEnv('SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE', tokenFile, () => collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR, probeTools: async () => STUB_TOOLS }));
  assert.equal(status.killSwitch.resetTokenConfigured, true);
  assert.match(renderOperatorStatusText(status), /reset token: configured/);
  assert.doesNotMatch(JSON.stringify(status), /never-shown/);
  assert.doesNotMatch(JSON.stringify(status), new RegExp(crypto.createHash('sha256').update('never-shown').digest('hex')));
});

test('status: verify-install + tool counts match the direct commands on the same state', async (t) => {
  const { directory, stateDir } = await buildFixture(t);
  const install = await runVerifyInstall({ skillDirectory: SKILL_DIR, stateDirectory: stateDir });
  const check = await runEnvironmentCheck({ probeDirectory: path.join(directory, 'probe') });
  const toolResults = Object.values(check.capabilities.tools);
  const status = await withEnv('SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE', undefined, () => collectOperatorStatus({ stateDir, skillDirectory: SKILL_DIR }));
  assert.equal(status.verifyInstall.passed, install.passed);
  assert.equal(status.verifyInstall.failed, install.failed);
  assert.equal(status.verifyInstall.overall, install.overall);
  assert.equal(status.tools.total, toolResults.length);
  assert.equal(status.tools.available, toolResults.filter((result) => result.status === 'verified').length);
  assert.equal(status.tools.missing, toolResults.filter((result) => result.status !== 'verified').length);
});

test('status CLI: text and --json, unknown option fails', async (t) => {
  const { stateDir } = await buildFixture(t);
  const text = await runCli(['status', '--state-dir', stateDir]);
  assert.equal(text.code, 0);
  assert.match(text.stdout, /^sentinel status — /);
  assert.match(text.stdout, /verify-install: 7 passed, 0 failed — PASS/);
  const json = await runCli(['status', '--state-dir', stateDir, '--json']);
  assert.equal(json.code, 0);
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.killSwitch.state, 'inactive');
  assert.equal(parsed.audit.totalRecords, 4);
  const bad = await runCli(['status', '--nope', '1', '--state-dir', stateDir]);
  assert.equal(bad.code, 1);
  assert.match(bad.stderr, /Unknown option: --nope/);
});

test('status CLI: real run leaves the state files untouched', async (t) => {
  const { stateDir } = await buildFixture(t);
  async function snapshot() {
    const entries = {};
    for (const name of await fs.readdir(stateDir)) {
      const full = path.join(stateDir, name);
      entries[name] = { content: await fs.readFile(full, 'utf8'), mtimeMs: (await fs.stat(full)).mtimeMs };
    }
    return { dirMtimeMs: (await fs.stat(stateDir)).mtimeMs, entries };
  }
  const before = await snapshot();
  const result = await runCli(['status', '--state-dir', stateDir, '--skill-dir', SKILL_DIR]);
  assert.equal(result.code, 0);
  assert.deepEqual(await snapshot(), before);
});

test('skill doc: installed-copy root SKILL.md matches the canonical copy when present', async (t) => {
  // The root copy exists only in an installed copy (a fresh clone has
  // no root SKILL.md — it is untracked on purpose). Round 62 drifted:
  // the root copy missed the retention command line and paragraph
  // because the reinstall step did not re-copy it. When the root copy
  // exists it must be byte-identical to the canonical one.
  const canonical = path.resolve(__dirname, '..', 'skills', 'sentinel-bounty', 'SKILL.md');
  const root = path.resolve(__dirname, '..', 'SKILL.md');
  let rootContent;
  try {
    rootContent = await fs.readFile(root, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      t.skip('no root SKILL.md in this checkout (fresh clone)');
      return;
    }
    throw error;
  }
  const canonicalContent = await fs.readFile(canonical, 'utf8');
  assert.equal(rootContent, canonicalContent);
  assert.match(canonicalContent, /sentinel status /);
});
