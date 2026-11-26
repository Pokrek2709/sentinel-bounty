// Audit-log retention policy (round 62, Phase 8).
//
// `sentinel audit retention` sets/shows the operator's retention
// limits in `<state-dir>/audit-retention.json`; when rotation runs
// with a policy set, the oldest archives/records are pruned down to
// the limits and the prune is RECORDED by an AUDIT_LOG_PRUNED anchor
// record, chained from the old tail. Fixtures only; no scanner, no
// network, no live target. The real state directory is never touched
// — every test uses its own temp state dir.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateMode } = require('./helpers/private-mode');
const { AuditLog } = require('../src/audit/audit-log');
const { renderAuditExport } = require('../src/audit/audit-export');
const {
  AuditRetentionError,
  retentionPathFor,
  validateRetentionPolicy,
  readRetentionPolicy,
  readRetentionPolicyLenient,
  writeRetentionPolicy,
} = require('../src/audit/audit-retention');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

async function runCli(args) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { windowsHide: true });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

function parse(stdout) {
  return JSON.parse(stdout);
}

// Appends `count` events to a small-limit log (rotationBytes 700,
// retentionCount 3: a chained record is ~310 bytes, so rotation
// happens every ~2-3 appends) and returns the frozen records the
// writer returned, in chain order.
async function appendEvents(audit, count, prefix = 'EV') {
  const written = [];
  for (let index = 0; index < count; index += 1) {
    written.push(await audit.append(`${prefix}_${index}`, { n: index }));
  }
  return written;
}

function newAudit(directory, overrides = {}) {
  return new AuditLog({
    logFile: path.join(directory, 'state', 'audit.jsonl'),
    skillDirectory: path.join(directory, 'skill'),
    rotationBytes: 700,
    retentionCount: 3,
    ...overrides,
  });
}

test('retention policy validates: valid shapes normalize, invalid values fail loudly', () => {
  assert.deepEqual(validateRetentionPolicy({ schema_version: 1 }), { schema_version: 1, max_archives: null, max_records: null });
  assert.deepEqual(validateRetentionPolicy({ schema_version: 1, max_archives: 2 }), { schema_version: 1, max_archives: 2, max_records: null });
  assert.deepEqual(validateRetentionPolicy({ schema_version: 1, max_records: 10 }), { schema_version: 1, max_archives: null, max_records: 10 });
  assert.deepEqual(validateRetentionPolicy({ schema_version: 1, max_archives: 1, max_records: 1 }), { schema_version: 1, max_archives: 1, max_records: 1 });
  for (const invalid of [
    null,
    'x',
    [],
    {},
    { schema_version: 2 },
    { schema_version: 1, max_archives: 0 },
    { schema_version: 1, max_archives: -1 },
    { schema_version: 1, max_archives: 1.5 },
    { schema_version: 1, max_archives: '2' },
    { schema_version: 1, max_records: 0 },
    { schema_version: 1, max_records: 2.5 },
    { schema_version: 1, unknown_key: 1 },
  ]) {
    assert.throws(() => validateRetentionPolicy(invalid), (error) => error instanceof AuditRetentionError && error.code === 'AUDIT_RETENTION_INVALID', `must reject ${JSON.stringify(invalid)}`);
  }
});

test('retention policy file round-trips, absent reads null, symlink refused, mode 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-file-');
  const stateDirectory = path.join(directory, 'state');
  assert.equal(await readRetentionPolicy(stateDirectory), null);
  assert.equal(await readRetentionPolicyLenient(stateDirectory), null);
  const written = await writeRetentionPolicy(stateDirectory, { schema_version: 1, max_archives: 2 });
  assert.deepEqual(written, { schema_version: 1, max_archives: 2, max_records: null });
  assert.deepEqual(await readRetentionPolicy(stateDirectory), written);
  await assertPrivateMode(retentionPathFor(stateDirectory), 0o600);
  // A symlink at the policy path is refused on read and on write.
  const linkDirectory = path.join(directory, 'state-link');
  await fs.mkdir(linkDirectory, { recursive: true });
  const target = path.join(linkDirectory, 'target.json');
  await fs.writeFile(target, '{"schema_version":1,"max_archives":1}\n');
  // Round 81: symlink creation needs privileges that are not
  // guaranteed on every platform (Windows runners included) —
  // same guard as backup-restore.test.js: skip, do not fail.
  try {
    await fs.symlink(target, retentionPathFor(linkDirectory));
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code || error.message}`);
    return;
  }
  await assert.rejects(readRetentionPolicy(linkDirectory), (error) => error.code === 'AUDIT_RETENTION_SYMLINK_REFUSED');
  await assert.rejects(writeRetentionPolicy(linkDirectory, { schema_version: 1, max_archives: 1 }), (error) => error.code === 'AUDIT_RETENTION_SYMLINK_REFUSED');
  // A corrupt file fails loudly on the strict read, but the lenient
  // read (rotation path) returns null so appends are never blocked.
  await fs.writeFile(retentionPathFor(stateDirectory), 'not json\n');
  await assert.rejects(readRetentionPolicy(stateDirectory), (error) => error.code === 'AUDIT_RETENTION_INVALID');
  assert.equal(await readRetentionPolicyLenient(stateDirectory), null);
  // A non-file at the policy path is invalid, not an empty policy.
  const dirDirectory = path.join(directory, 'state-dir');
  await fs.mkdir(retentionPathFor(dirDirectory), { recursive: true });
  await assert.rejects(readRetentionPolicy(dirDirectory), (error) => error.code === 'AUDIT_RETENTION_INVALID');
});

test('audit retention CLI sets, shows, merges, and audits the change', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-cli-');
  const stateDirectory = path.join(directory, 'state');
  const store = retentionPathFor(stateDirectory);

  const shownEmpty = await runCli(['audit', 'retention', '--show', '--state-dir', stateDirectory]);
  assert.equal(shownEmpty.code, 0, shownEmpty.stderr);
  assert.deepEqual(parse(shownEmpty.stdout), { policy: null, store });

  const setArchives = await runCli(['audit', 'retention', '--max-archives', '2', '--state-dir', stateDirectory]);
  assert.equal(setArchives.code, 0, setArchives.stderr);
  const setArchivesBody = parse(setArchives.stdout);
  assert.equal(setArchivesBody.updated, true);
  assert.deepEqual(setArchivesBody.policy, { schema_version: 1, max_archives: 2, max_records: null });
  assert.equal(setArchivesBody.store, store);
  assert.equal(setArchivesBody.auditLogged, true);

  // Setting the second limit merges: the first limit is kept.
  const setRecords = await runCli(['audit', 'retention', '--max-records', '10', '--state-dir', stateDirectory]);
  assert.equal(setRecords.code, 0, setRecords.stderr);
  assert.deepEqual(parse(setRecords.stdout).policy, { schema_version: 1, max_archives: 2, max_records: 10 });

  const shown = await runCli(['audit', 'retention', '--show', '--state-dir', stateDirectory]);
  assert.deepEqual(parse(shown.stdout).policy, { schema_version: 1, max_archives: 2, max_records: 10 });

  // The change itself is audited.
  const events = (await fs.readFile(path.join(stateDirectory, 'audit.jsonl'), 'utf8'))
    .split('\n').filter(Boolean).map((line) => JSON.parse(line));
  const setEvents = events.filter((event) => event.event === 'AUDIT_RETENTION_SET');
  assert.equal(setEvents.length, 2);
  assert.deepEqual(setEvents[1].details, { maxArchives: 2, maxRecords: 10, store });

  // Invalid values fail with the named code and write nothing.
  const invalid = await runCli(['audit', 'retention', '--max-archives', '0', '--state-dir', stateDirectory]);
  assert.notEqual(invalid.code, 0);
  assert.match(invalid.stderr, /AUDIT_RETENTION_INVALID/);
  assert.deepEqual(parse((await runCli(['audit', 'retention', '--show', '--state-dir', stateDirectory])).stdout).policy, { schema_version: 1, max_archives: 2, max_records: 10 });
  for (const bad of [['--max-archives', 'x'], ['--max-archives', '1.5'], ['--max-records', '-3']]) {
    const result = await runCli(['audit', 'retention', ...bad, '--state-dir', stateDirectory]);
    assert.notEqual(result.code, 0, bad.join(' '));
    assert.match(result.stderr, /AUDIT_RETENTION_INVALID/);
  }

  // No limit and no --show is a usage error; --show cannot combine
  // with a limit.
  assert.notEqual((await runCli(['audit', 'retention', '--state-dir', stateDirectory])).code, 0);
  assert.notEqual((await runCli(['audit', 'retention', '--show', '--max-archives', '1', '--state-dir', stateDirectory])).code, 0);
  // A corrupt policy file surfaces loudly on --show.
  await fs.writeFile(store, 'garbage\n');
  const corruptShow = await runCli(['audit', 'retention', '--show', '--state-dir', stateDirectory]);
  assert.notEqual(corruptShow.code, 0);
  assert.match(corruptShow.stderr, /AUDIT_RETENTION_INVALID/);
});

test('audit retention set is refused while the kill-switch is armed, show still works', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-armed-');
  const stateDirectory = path.join(directory, 'state');
  const triggered = await runCli(['kill-switch', 'trigger', '--actor', 'lab', '--reason', 'retention guard test', '--state-dir', stateDirectory]);
  assert.equal(triggered.code, 0, triggered.stderr);
  const refused = await runCli(['audit', 'retention', '--max-archives', '1', '--state-dir', stateDirectory]);
  assert.equal(refused.code, 1, refused.stderr);
  assert.equal(parse(refused.stdout).reason, 'AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE');
  assert.equal(parse(refused.stdout).updated, false);
  assert.equal(await readRetentionPolicy(stateDirectory), null);
  const shown = await runCli(['audit', 'retention', '--show', '--state-dir', stateDirectory]);
  assert.equal(shown.code, 0, shown.stderr);
  assert.equal(parse(shown.stdout).policy, null);
});

test('rotation with max_archives=1 prunes old archives and anchors the prune exactly', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-archives-');
  const audit = newAudit(directory);
  const before = await appendEvents(audit, 6);
  const activeBefore = await audit.readEvents();
  // Six appends at a 700-byte limit: archives .1 and .2 exist, the
  // active log holds the tail.
  const entriesBefore = await fs.readdir(path.join(directory, 'state'));
  assert.ok(entriesBefore.includes('audit.jsonl.1'));
  assert.ok(entriesBefore.includes('audit.jsonl.2'));
  assert.equal(entriesBefore.includes('audit.jsonl.3'), false);
  await writeRetentionPolicy(path.join(directory, 'state'), { schema_version: 1, max_archives: 1 });
  // One more append rotates: the old archives fall out of retention.
  const incoming = await audit.append('EV_6', { n: 6 });
  const entries = await fs.readdir(path.join(directory, 'state'));
  assert.ok(entries.includes('audit.jsonl.1'));
  assert.equal(entries.includes('audit.jsonl.2'), false);
  assert.equal(entries.includes('audit.jsonl.3'), false);
  const all = await audit.readAllEvents();
  const anchors = all.filter((event) => event.event === 'AUDIT_LOG_PRUNED');
  assert.equal(anchors.length, 1);
  // The pruned set is exactly the pre-policy records that were not in
  // the active log: everything except the active tail.
  const prunedExpected = before.filter((record) => !activeBefore.some((active) => active.eventId === record.eventId));
  assert.ok(prunedExpected.length > 0);
  const anchor = anchors[0];
  assert.equal(anchor.details.prunedCount, prunedExpected.length);
  assert.equal(anchor.details.prunedFirstRecordedAt, prunedExpected[0].recordedAt);
  assert.equal(anchor.details.prunedLastRecordedAt, prunedExpected[prunedExpected.length - 1].recordedAt);
  assert.equal(anchor.details.lastPrunedHash, prunedExpected[prunedExpected.length - 1].hash);
  assert.equal(anchor.details.maxArchives, 1);
  assert.equal(anchor.details.maxRecords, null);
  // The anchor precedes the incoming record in the chain and the
  // incoming record chains from it.
  const anchorIndex = all.findIndex((event) => event.eventId === anchor.eventId);
  const incomingIndex = all.findIndex((event) => event.eventId === incoming.eventId);
  assert.equal(incomingIndex, anchorIndex + 1);
  assert.equal(incoming.prevHash, anchor.hash);
  // The chain still verifies after the prune.
  assert.equal((await audit.verifyChain()).verified, true);
  // The anchor's timestamps are monotonic with the chain: it shares
  // the incoming record's time, never a later one.
  assert.equal(anchor.recordedAt, incoming.recordedAt);
});

test('rotation with max_records prunes the oldest active lines and caps the total', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-records-');
  const audit = newAudit(directory);
  const before = await appendEvents(audit, 6);
  const activeBefore = await audit.readEvents();
  await writeRetentionPolicy(path.join(directory, 'state'), { schema_version: 1, max_archives: 1, max_records: 3 });
  const incoming = await audit.append('EV_6', { n: 6 });
  const all = await audit.readAllEvents();
  // Retained: 1 line of the old active log + anchor + incoming = 3.
  assert.equal(all.length, 3);
  assert.equal(all[all.length - 1].event, 'EV_6');
  const anchors = all.filter((event) => event.event === 'AUDIT_LOG_PRUNED');
  assert.equal(anchors.length, 1);
  const anchor = anchors[0];
  // Pruned: old archives (everything except the active tail) plus the
  // oldest active line(s) truncated for max_records.
  const archivedBefore = before.filter((record) => !activeBefore.some((active) => active.eventId === record.eventId));
  const truncatedCount = activeBefore.length - 1;
  assert.equal(anchor.details.prunedCount, archivedBefore.length + truncatedCount);
  assert.equal(anchor.details.prunedFirstRecordedAt, archivedBefore[0].recordedAt);
  assert.equal(anchor.details.prunedLastRecordedAt, activeBefore[truncatedCount - 1].recordedAt);
  assert.equal(anchor.details.lastPrunedHash, activeBefore[truncatedCount - 1].hash);
  assert.equal(anchor.details.maxArchives, 1);
  assert.equal(anchor.details.maxRecords, 3);
  assert.equal(incoming.prevHash, anchor.hash);
  assert.equal((await audit.verifyChain()).verified, true);
});

test('max_records=1 bottoms out at anchor plus incoming, never deleting the anchor', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-floor-');
  const audit = newAudit(directory);
  await appendEvents(audit, 6);
  await writeRetentionPolicy(path.join(directory, 'state'), { schema_version: 1, max_archives: 1, max_records: 1 });
  await audit.append('EV_6', { n: 6 });
  const all = await audit.readAllEvents();
  assert.equal(all.length, 2);
  assert.equal(all[0].event, 'AUDIT_LOG_PRUNED');
  assert.equal(all[1].event, 'EV_6');
  assert.equal((await audit.verifyChain()).verified, true);
});

test('a corrupt policy file never blocks appends and prunes nothing that rotation', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-corrupt-');
  const audit = newAudit(directory);
  await appendEvents(audit, 6);
  await fs.writeFile(retentionPathFor(path.join(directory, 'state')), 'garbage\n');
  // Appends keep working and rotate exactly as if no policy existed:
  // no anchor, no pruning beyond the rotation's own age-out.
  for (let index = 6; index < 12; index += 1) {
    await audit.append(`EV_${index}`, { n: index });
  }
  const all = await audit.readAllEvents();
  assert.equal(all.filter((event) => event.event === 'AUDIT_LOG_PRUNED').length, 0);
  assert.equal((await audit.verifyChain()).verified, true);
});

test('no policy means no anchor: rotation drops the oldest archive silently, as before', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-nopolicy-');
  const audit = newAudit(directory);
  await appendEvents(audit, 30);
  const all = await audit.readAllEvents();
  assert.equal(all.filter((event) => event.event === 'AUDIT_LOG_PRUNED').length, 0);
  assert.equal((await audit.verifyChain()).verified, true);
});

test('audit export on a pruned log includes the anchor as a verified record', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-retention-export-');
  const audit = newAudit(directory);
  await appendEvents(audit, 6);
  await writeRetentionPolicy(path.join(directory, 'state'), { schema_version: 1, max_archives: 1 });
  await audit.append('EV_6', { n: 6 });
  const perRecord = await audit.verifyChainPerRecord();
  assert.equal(perRecord.verified, true);
  const rendered = renderAuditExport(perRecord, 'json');
  const exported = JSON.parse(rendered);
  assert.equal(exported.verified, true);
  const anchorEntries = exported.records.filter((entry) => entry.record && entry.record.event === 'AUDIT_LOG_PRUNED');
  assert.equal(anchorEntries.length, 1);
  assert.deepEqual(anchorEntries[0].chain, { status: 'verified', reason: null });
  assert.equal(exported.summary.verifiedRecords, exported.summary.totalRecords);
});
