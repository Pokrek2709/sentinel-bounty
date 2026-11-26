'use strict';

// Portable state export (round 58, Phase 8): `sentinel state export`
// collects kill-switch state + scope targets + audit summary into
// one envelope with a content hash over the contents only. Tests use
// temp state dirs only — the live state directory is never touched.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateMode } = require('./helpers/private-mode');
const { computeAuditRecordHash, GENESIS_PREV_HASH } = require('../src/audit/audit-log');
const {
  collectStateExport,
  renderStateExport,
  computeStateExportHash,
  EXPORT_VERSION,
} = require('../src/policy/state-export');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const SKILL_DIR = path.resolve(__dirname, '..');
const FIXED_EXPORTED_AT = '2026-11-26T07:00:00.000Z';

async function runCli(args, stateDir) {
  try {
    const { stdout } = await execFileAsync(process.execPath, [CLI, ...args, '--state-dir', stateDir]);
    return { code: 0, stdout, stderr: '' };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// A hand-built chained record with pinned eventId/recordedAt, so the
// audit summary is fully deterministic (same helper shape as the
// round-56 audit-export tests).
function chainedRecord(event, eventId, recordedAt, details, prevHash) {
  const record = { chainVersion: 1, version: 1, event, eventId, recordedAt, details, prevHash };
  return { ...record, hash: computeAuditRecordHash(record) };
}

function legacyRecord(event, eventId, recordedAt) {
  return { version: 1, event, eventId, recordedAt, details: {} };
}

const VALID_TARGET = {
  target_id: 'lab-target-1',
  program_name: 'Lab Program',
  authorization_reference: 'auth-ref-1',
  allowed_domains: ['example.lab'],
};

const ARMED_STATE = {
  version: 2,
  active: true,
  trigger: { triggerId: 'trig-1', triggeredBy: 'op-1', reason: 'test trigger', triggeredAt: 1795648000000 },
  workers: [{ workerId: 'w-1', pid: 1234, leaseExpiresAt: 1795649000000 }],
};

async function writeStateDir(directory, { killSwitch, targets, auditRecords } = {}) {
  const stateDir = path.join(directory, 'state');
  await fs.mkdir(stateDir, { recursive: true });
  if (killSwitch !== undefined) {
    await fs.writeFile(path.join(stateDir, 'kill-switch.json'), `${JSON.stringify(killSwitch, null, 2)}\n`, { mode: 0o600 });
  }
  if (targets !== undefined) {
    await fs.writeFile(path.join(stateDir, 'scope-targets.json'), `${JSON.stringify({ schema_version: 1, targets }, null, 2)}\n`, { mode: 0o600 });
  }
  if (auditRecords !== undefined) {
    await fs.writeFile(path.join(stateDir, 'audit.jsonl'), auditRecords.map((record) => JSON.stringify(record)).join('\n') + '\n', { mode: 0o600 });
  }
  return stateDir;
}

function collectKeys(value, keys = []) {
  if (Array.isArray(value)) {
    value.forEach((entry) => collectKeys(entry, keys));
  } else if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => {
      keys.push(key);
      collectKeys(child, keys);
    });
  }
  return keys;
}

test('export: a known state exports the exact envelope, and the hash recomputes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-known-');
  const first = legacyRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z');
  const second = chainedRecord('EVENT_B', 'id-b', '2026-11-26T00:00:01.000Z', { n: 2 }, GENESIS_PREV_HASH);
  const third = chainedRecord('EVENT_C', 'id-c', '2026-11-26T00:00:02.000Z', { n: 3 }, second.hash);
  const stateDir = await writeStateDir(directory, {
    killSwitch: ARMED_STATE,
    targets: [VALID_TARGET],
    auditRecords: [first, second, third],
  });
  const contents = await collectStateExport({ stateDir, skillDirectory: SKILL_DIR });
  assert.deepEqual(contents, {
    killSwitchState: ARMED_STATE,
    scopeTargets: [VALID_TARGET],
    auditSummary: {
      totalRecords: 3,
      verifiedRecords: 2,
      legacyRecords: 1,
      brokenRecords: 0,
      chainVerified: true,
      anchorHash: GENESIS_PREV_HASH,
      firstRecordedAt: '2026-11-26T00:00:00.000Z',
      lastRecordedAt: '2026-11-26T00:00:02.000Z',
    },
  });
  const rendered = renderStateExport(contents, FIXED_EXPORTED_AT);
  const envelope = JSON.parse(rendered);
  assert.equal(envelope.exportVersion, EXPORT_VERSION);
  assert.equal(envelope.exportedAt, FIXED_EXPORTED_AT);
  assert.deepEqual(envelope.contents, contents);
  assert.equal(envelope.contentHash, computeStateExportHash(contents));
  assert.match(envelope.contentHash, /^[a-f0-9]{64}$/);
  // The hash is over the canonical contents only: recomputing from the
  // parsed envelope reproduces it exactly.
  assert.equal(computeStateExportHash(envelope.contents), envelope.contentHash);
});

test('export: the content hash is identical across timestamps and changes when state changes', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-hash-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: ARMED_STATE,
    targets: [VALID_TARGET],
    auditRecords: [],
  });
  const contents = await collectStateExport({ stateDir, skillDirectory: SKILL_DIR });
  const first = JSON.parse(renderStateExport(contents, '2026-11-26T07:00:00.000Z'));
  const second = JSON.parse(renderStateExport(contents, '2026-11-26T08:30:00.000Z'));
  assert.equal(first.contentHash, second.contentHash);
  assert.notEqual(first.exportedAt, second.exportedAt);
  const changed = {
    ...contents,
    killSwitchState: { ...contents.killSwitchState, active: false },
  };
  assert.notEqual(computeStateExportHash(changed), first.contentHash);
});

test('export: a missing state file, scope store, and audit log export as the empty state', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-empty-');
  const stateDir = path.join(directory, 'state');
  await fs.mkdir(stateDir, { recursive: true });
  const contents = await collectStateExport({ stateDir, skillDirectory: SKILL_DIR });
  assert.deepEqual(contents, {
    killSwitchState: { version: 2, active: false, trigger: null, workers: [] },
    scopeTargets: [],
    auditSummary: {
      totalRecords: 0,
      verifiedRecords: 0,
      legacyRecords: 0,
      brokenRecords: 0,
      chainVerified: true,
      anchorHash: null,
      firstRecordedAt: null,
      lastRecordedAt: null,
    },
  });
});

test('export: a corrupt kill-switch state fails with a named error and no export', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-corrupt-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: { version: 2, active: 'yes', trigger: null, workers: [] },
    targets: [],
    auditRecords: [],
  });
  await assert.rejects(
    collectStateExport({ stateDir, skillDirectory: SKILL_DIR }),
    (error) => error.message === 'STATE_EXPORT_STATE_INVALID',
  );
});

test('export: a symlinked kill-switch state file is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-symlink-');
  const stateDir = path.join(directory, 'state');
  await fs.mkdir(stateDir, { recursive: true });
  const real = path.join(directory, 'real-state.json');
  await fs.writeFile(real, `${JSON.stringify({ version: 2, active: false, trigger: null, workers: [] })}\n`);
  await fs.symlink(real, path.join(stateDir, 'kill-switch.json'));
  await assert.rejects(
    collectStateExport({ stateDir, skillDirectory: SKILL_DIR }),
    (error) => error.message === 'STATE_EXPORT_SYMLINK_REFUSED',
  );
});

test('export: a damaged scope store fails the whole export, never dropping a target', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-badstore-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
    targets: [{ target_id: 'broken-target' }],
    auditRecords: [],
  });
  await assert.rejects(
    collectStateExport({ stateDir, skillDirectory: SKILL_DIR }),
    (error) => error.code === 'SCOPE_TARGET_INVALID',
  );
});

test('export: no token, secret, password, or api-key field appears anywhere in the envelope', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-nosecret-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: ARMED_STATE,
    targets: [VALID_TARGET],
    auditRecords: [legacyRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z')],
  });
  const contents = await collectStateExport({ stateDir, skillDirectory: SKILL_DIR });
  const envelope = JSON.parse(renderStateExport(contents, FIXED_EXPORTED_AT));
  const keys = collectKeys(envelope);
  const suspicious = keys.filter((key) => /token|secret|password|api[-_]?key/i.test(key));
  assert.deepEqual(suspicious, []);
  // The exact exported shapes, by construction: nothing else may ride
  // along in the kill-switch state.
  assert.deepEqual(Object.keys(envelope.contents.killSwitchState).sort(), ['active', 'trigger', 'version', 'workers']);
  assert.deepEqual(Object.keys(envelope.contents.killSwitchState.trigger).sort(), ['reason', 'triggerId', 'triggeredAt', 'triggeredBy']);
  assert.deepEqual(Object.keys(envelope.contents.killSwitchState.workers[0]).sort(), ['leaseExpiresAt', 'pid', 'workerId']);
});

test('CLI: state export prints the envelope on stdout and --out writes the same bytes at 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-cli-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: ARMED_STATE,
    targets: [VALID_TARGET],
    auditRecords: [legacyRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z')],
  });
  const stdoutRun = await runCli(['state', 'export'], stateDir);
  assert.equal(stdoutRun.code, 0, stdoutRun.stderr);
  const envelope = JSON.parse(stdoutRun.stdout);
  assert.equal(envelope.exportVersion, EXPORT_VERSION);
  assert.equal(envelope.contents.killSwitchState.active, true);
  assert.equal(envelope.contents.scopeTargets.length, 1);
  assert.equal(envelope.contents.auditSummary.totalRecords, 1);
  assert.equal(computeStateExportHash(envelope.contents), envelope.contentHash);
  const outPath = path.join(directory, 'export.json');
  const outRun = await runCli(['state', 'export', '--out', outPath], stateDir);
  assert.equal(outRun.code, 0, outRun.stderr);
  assert.match(outRun.stdout, /State export written to /);
  const written = await fs.readFile(outPath, 'utf8');
  const writtenEnvelope = JSON.parse(written);
  // Same state, so the same content hash — only the timestamp differs.
  assert.equal(writtenEnvelope.contentHash, envelope.contentHash);
  assert.deepEqual(writtenEnvelope.contents, envelope.contents);
  await assertPrivateMode(outPath, 0o600);
});

test('CLI: a broken audit chain still exports with exit 0 and chainVerified false', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-broken-');
  const good = chainedRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z', { n: 1 }, GENESIS_PREV_HASH);
  const tampered = { ...chainedRecord('EVENT_B', 'id-b', '2026-11-26T00:00:01.000Z', { n: 2 }, good.hash), hash: '0'.repeat(64) };
  const stateDir = await writeStateDir(directory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
    targets: [],
    auditRecords: [good, tampered],
  });
  const run = await runCli(['state', 'export'], stateDir);
  assert.equal(run.code, 0, run.stderr);
  const envelope = JSON.parse(run.stdout);
  assert.equal(envelope.contents.auditSummary.chainVerified, false);
  assert.equal(envelope.contents.auditSummary.brokenRecords, 1);
  assert.equal(envelope.contents.auditSummary.verifiedRecords, 1);
});

test('CLI: an armed switch exports with exit 0 — the command is read-only', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-armed-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: ARMED_STATE,
    targets: [],
    auditRecords: [],
  });
  const run = await runCli(['state', 'export'], stateDir);
  assert.equal(run.code, 0, run.stderr);
  const envelope = JSON.parse(run.stdout);
  assert.equal(envelope.contents.killSwitchState.active, true);
});

test('CLI: a corrupt kill-switch state fails with exit 1 and a named reason, writing nothing', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-cli-bad-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: { version: 99, active: false, trigger: null, workers: [] },
    targets: [],
    auditRecords: [],
  });
  const outPath = path.join(directory, 'export.json');
  const run = await runCli(['state', 'export', '--out', outPath], stateDir);
  assert.equal(run.code, 1);
  assert.deepEqual(JSON.parse(run.stdout), { exported: false, reason: 'STATE_EXPORT_STATE_INVALID' });
  await assert.rejects(fs.stat(outPath), (error) => error.code === 'ENOENT');
});

test('CLI: a symlinked --out path is refused and the link target is untouched', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-cli-link-');
  const stateDir = await writeStateDir(directory, {
    killSwitch: { version: 2, active: false, trigger: null, workers: [] },
    targets: [],
    auditRecords: [],
  });
  const target = path.join(directory, 'target.txt');
  await fs.writeFile(target, 'untouched\n');
  const linkPath = path.join(directory, 'export.json');
  await fs.symlink(target, linkPath);
  const run = await runCli(['state', 'export', '--out', linkPath], stateDir);
  assert.equal(run.code, 1);
  assert.deepEqual(JSON.parse(run.stdout), { exported: false, reason: 'STATE_EXPORT_SYMLINK_REFUSED' });
  assert.equal(await fs.readFile(target, 'utf8'), 'untouched\n');
});

test('CLI: state without an action fails with usage guidance', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-state-export-noaction-');
  const stateDir = path.join(directory, 'state');
  const run = await runCli(['state'], stateDir);
  assert.equal(run.code, 1);
  assert.match(run.stderr, /state requires an action: export\./);
});

test('module: renderStateExport refuses malformed inputs', () => {
  assert.throws(() => renderStateExport(null), TypeError);
  assert.throws(() => renderStateExport({}), TypeError);
  assert.throws(
    () => renderStateExport({
      killSwitchState: { version: 2, active: false, trigger: null, workers: [] },
      scopeTargets: [],
      auditSummary: {},
    }, ''),
    TypeError,
  );
  // The content hash is stable: same contents, same hash, every time.
  const contents = {
    killSwitchState: { version: 2, active: false, trigger: null, workers: [] },
    scopeTargets: [],
    auditSummary: { totalRecords: 0 },
  };
  assert.equal(computeStateExportHash(contents), crypto.createHash('sha256').update(JSON.stringify(contents)).digest('hex'));
});
