const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateMode } = require('./helpers/private-mode');
const { AuditLog, computeAuditRecordHash, GENESIS_PREV_HASH } = require('../src/audit/audit-log');
const { renderAuditExport } = require('../src/audit/audit-export');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

async function makeAudit(directory, options = {}) {
  return new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill'), ...options });
}

async function runCli(args, stateDir) {
  try {
    const { stdout } = await execFileAsync(process.execPath, [CLI, ...args, '--state-dir', stateDir]);
    return { code: 0, stdout };
  } catch (error) {
    return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' };
  }
}

// A hand-built chained record with pinned eventId/recordedAt, so the
// export output is fully deterministic and can be pinned exactly.
// The hash is computed with the module's own (documented) formula.
function chainedRecord(event, eventId, recordedAt, details, prevHash) {
  const record = { chainVersion: 1, version: 1, event, eventId, recordedAt, details, prevHash };
  return { ...record, hash: computeAuditRecordHash(record) };
}

function legacyRecord(event, eventId, recordedAt) {
  return { version: 1, event, eventId, recordedAt, details: {} };
}

test('export: a clean chained log exports every record as verified, with exact output', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-clean-');
  try {
    const logFile = path.join(directory, 'state', 'audit.jsonl');
    await fs.mkdir(path.join(directory, 'state'), { recursive: true });
    const first = chainedRecord('EVENT_A', 'id-a', '2026-11-26T00:00:00.000Z', { n: 1 }, GENESIS_PREV_HASH);
    const second = chainedRecord('EVENT_B', 'id-b', '2026-11-26T00:00:01.000Z', { n: 2 }, first.hash);
    const third = chainedRecord('EVENT_C', 'id-c', '2026-11-26T00:00:02.000Z', { n: 3 }, second.hash);
    await fs.writeFile(logFile, [first, second, third].map((record) => JSON.stringify(record)).join('\n') + '\n', { mode: 0o600 });
    const audit = await makeAudit(directory);
    const result = await audit.verifyChainPerRecord();
    assert.deepEqual(result, {
      verified: true,
      summary: {
        totalRecords: 3,
        verifiedRecords: 3,
        legacyRecords: 0,
        brokenRecords: 0,
        anchorHash: GENESIS_PREV_HASH,
        firstRecordedAt: '2026-11-26T00:00:00.000Z',
        lastRecordedAt: '2026-11-26T00:00:02.000Z',
      },
      records: [
        { file: 'audit.jsonl', line: 1, chain: { status: 'verified', reason: null }, record: first },
        { file: 'audit.jsonl', line: 2, chain: { status: 'verified', reason: null }, record: second },
        { file: 'audit.jsonl', line: 3, chain: { status: 'verified', reason: null }, record: third },
      ],
    });
    // The JSON render is the same object, pretty-printed: an auditor
    // comparing two exports byte-for-byte gets the same bytes.
    const rendered = renderAuditExport(result, 'json');
    assert.equal(rendered, `${JSON.stringify({ exportVersion: 1, verified: result.verified, summary: result.summary, records: result.records }, null, 2)}\n`);
    assert.equal(rendered, renderAuditExport(result, 'json'));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: statuses continue past a modified record — the successor still verifies', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-modify-');
  try {
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', { n: 1 });
    await audit.append('EVENT_B', { n: 2 });
    await audit.append('EVENT_C', { n: 3 });
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[1]);
    tampered.details = { n: 999 };
    lines[1] = JSON.stringify(tampered);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChainPerRecord();
    assert.equal(result.verified, false);
    assert.deepEqual(result.summary, {
      totalRecords: 3,
      verifiedRecords: 2,
      legacyRecords: 0,
      brokenRecords: 1,
      anchorHash: GENESIS_PREV_HASH,
      firstRecordedAt: JSON.parse(lines[0]).recordedAt,
      lastRecordedAt: JSON.parse(lines[2]).recordedAt,
    });
    assert.deepEqual(result.records.map((entry) => [entry.line, entry.chain.status, entry.chain.reason]), [
      [1, 'verified', null],
      [2, 'broken', 'AUDIT_CHAIN_HASH_MISMATCH'],
      [3, 'verified', null],
    ]);
    // The tampered record is still shown (its event and details are
    // what the auditor needs to see); only the raw line is withheld.
    assert.equal(result.records[1].record.event, 'EVENT_B');
    assert.deepEqual(result.records[1].record.details, { n: 999 });
    // verifyChain() on the same log still stops at the first break,
    // unchanged by the refactor.
    const chain = await audit.verifyChain();
    assert.equal(chain.verified, false);
    assert.equal(chain.reason, 'AUDIT_CHAIN_HASH_MISMATCH');
    assert.deepEqual(chain.brokenAt, { file: 'audit.jsonl', line: 2, reason: 'AUDIT_CHAIN_HASH_MISMATCH' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: deleting a middle record flags the successor PREV_MISMATCH and the last record still verifies', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-delete-');
  try {
    const audit = await makeAudit(directory);
    for (const event of ['EVENT_A', 'EVENT_B', 'EVENT_C']) await audit.append(event, {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    lines.splice(1, 1);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChainPerRecord();
    assert.equal(result.verified, false);
    assert.equal(result.summary.totalRecords, 2);
    assert.equal(result.summary.brokenRecords, 1);
    assert.equal(result.summary.verifiedRecords, 1);
    assert.deepEqual(result.records.map((entry) => [entry.line, entry.chain.status, entry.chain.reason]), [
      [1, 'verified', null],
      [2, 'broken', 'AUDIT_CHAIN_PREV_MISMATCH'],
    ]);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: a garbage line is an error entry with file and line, and later records still verify', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-garbage-');
  try {
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', {});
    await audit.append('EVENT_B', {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    await fs.appendFile(file, 'this is not JSONL\n');
    await audit.append('EVENT_C', {});
    const result = await audit.verifyChainPerRecord();
    assert.equal(result.verified, false);
    assert.equal(result.summary.totalRecords, 4);
    assert.equal(result.summary.brokenRecords, 1);
    assert.equal(result.summary.verifiedRecords, 3);
    assert.deepEqual(result.records.map((entry) => [entry.line, entry.chain.status, entry.chain.reason, entry.record === null]), [
      [1, 'verified', null, false],
      [2, 'verified', null, false],
      [3, 'broken', 'AUDIT_CHAIN_UNPARSEABLE', true],
      [4, 'verified', null, false],
    ]);
    assert.equal(result.records[3].record.event, 'EVENT_C');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: legacy prefix exports as legacy; a legacy record after chained records is broken', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-legacy-');
  try {
    const audit = await makeAudit(directory);
    const logFile = path.join(directory, 'state', 'audit.jsonl');
    await fs.mkdir(path.join(directory, 'state'), { recursive: true });
    await fs.writeFile(logFile, [
      JSON.stringify(legacyRecord('OLD_A', 'old-a', '2026-11-20T00:00:00.000Z')),
      JSON.stringify(legacyRecord('OLD_B', 'old-b', '2026-11-20T00:00:01.000Z')),
    ].join('\n') + '\n', { mode: 0o600 });
    await audit.append('EVENT_C', {});
    await audit.append('EVENT_D', {});
    const result = await audit.verifyChainPerRecord();
    assert.equal(result.verified, true);
    assert.deepEqual(result.summary, {
      totalRecords: 4,
      verifiedRecords: 2,
      legacyRecords: 2,
      brokenRecords: 0,
      anchorHash: GENESIS_PREV_HASH,
      firstRecordedAt: '2026-11-20T00:00:00.000Z',
      lastRecordedAt: JSON.parse((await fs.readFile(logFile, 'utf8')).trim().split('\n')[3]).recordedAt,
    });
    assert.deepEqual(result.records.map((entry) => entry.chain.status), ['legacy', 'legacy', 'verified', 'verified']);
    await fs.appendFile(logFile, `${JSON.stringify(legacyRecord('SMUGGLED', 'old-c', '2026-11-26T00:00:00.000Z'))}\n`);
    const after = await audit.verifyChainPerRecord();
    assert.equal(after.verified, false);
    assert.equal(after.summary.brokenRecords, 1);
    assert.deepEqual(after.records[4].chain, { status: 'broken', reason: 'AUDIT_CHAIN_LEGACY_AFTER_CHAINED' });
    assert.equal(after.records[4].record.event, 'SMUGGLED');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: rotation — archives export oldest first with archive file names', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-rotate-');
  try {
    const audit = await makeAudit(directory, { rotationBytes: 1000, retentionCount: 3 });
    for (let index = 0; index < 8; index += 1) await audit.append(`EVENT_${index}`, { n: index });
    const entries = await fs.readdir(path.join(directory, 'state'));
    assert.ok(entries.includes('audit.jsonl.1'), 'a rotation must have happened');
    const result = await audit.verifyChainPerRecord();
    assert.equal(result.verified, true);
    assert.equal(result.summary.totalRecords, 8);
    assert.equal(result.summary.verifiedRecords, 8);
    assert.deepEqual(result.records.map((entry) => entry.record.event), ['EVENT_0', 'EVENT_1', 'EVENT_2', 'EVENT_3', 'EVENT_4', 'EVENT_5', 'EVENT_6', 'EVENT_7']);
    // Oldest records live in the highest-numbered archive; the newest
    // record is in the active log.
    assert.match(result.records[0].file, /^audit\.jsonl\.\d+$/);
    assert.equal(result.records[7].file, 'audit.jsonl');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: empty log exports zero records with a null anchor', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-empty-');
  try {
    const audit = await makeAudit(directory);
    const result = await audit.verifyChainPerRecord();
    assert.deepEqual(result, {
      verified: true,
      summary: { totalRecords: 0, verifiedRecords: 0, legacyRecords: 0, brokenRecords: 0, anchorHash: null, firstRecordedAt: null, lastRecordedAt: null },
      records: [],
    });
    assert.equal(renderAuditExport(result, 'json'), '{\n  "exportVersion": 1,\n  "verified": true,\n  "summary": {\n    "totalRecords": 0,\n    "verifiedRecords": 0,\n    "legacyRecords": 0,\n    "brokenRecords": 0,\n    "anchorHash": null,\n    "firstRecordedAt": null,\n    "lastRecordedAt": null\n  },\n  "records": []\n}\n');
    assert.equal(renderAuditExport(result, 'jsonl'), '{"type":"audit-export-summary","exportVersion":1,"verified":true,"summary":{"totalRecords":0,"verifiedRecords":0,"legacyRecords":0,"brokenRecords":0,"anchorHash":null,"firstRecordedAt":null,"lastRecordedAt":null}}\n');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: JSON and JSONL renders are deterministic and byte-identical across runs', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-determinism-');
  try {
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', { n: 1 });
    await audit.append('EVENT_B', { n: 2 });
    const first = await audit.verifyChainPerRecord();
    const second = await audit.verifyChainPerRecord();
    assert.equal(renderAuditExport(first, 'json'), renderAuditExport(second, 'json'));
    assert.equal(renderAuditExport(first, 'jsonl'), renderAuditExport(second, 'jsonl'));
    const jsonlLines = renderAuditExport(first, 'jsonl').trim().split('\n');
    assert.equal(jsonlLines.length, 3);
    const parsed = jsonlLines.map((line) => JSON.parse(line));
    assert.equal(parsed[0].record.event, 'EVENT_A');
    assert.equal(parsed[1].record.event, 'EVENT_B');
    // Record lines carry no `type` field; only the final summary line
    // is marked, so a consumer can tell them apart.
    assert.equal(parsed[0].type, undefined);
    assert.equal(parsed[1].type, undefined);
    assert.deepEqual(parsed[2], { type: 'audit-export-summary', exportVersion: 1, verified: first.verified, summary: first.summary });
    assert.deepEqual(JSON.parse(renderAuditExport(first, 'json')), { exportVersion: 1, verified: first.verified, summary: first.summary, records: first.records });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('export: renderAuditExport refuses an unknown format and a malformed result', async () => {
  assert.throws(() => renderAuditExport({ summary: {}, records: [] }, 'yaml'), /Invalid audit export format: yaml \(expected "json" or "jsonl"\)\./);
  assert.throws(() => renderAuditExport(null, 'json'), /renderAuditExport expects a verifyChainPerRecord\(\) result\./);
  assert.throws(() => renderAuditExport({ summary: {} }, 'json'), /renderAuditExport expects a verifyChainPerRecord\(\) result\./);
});

test('cli audit export: json to stdout exits 0; --out writes mode 0600 byte-identical to stdout', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-cli-');
  try {
    const stateDir = path.join(directory, 'state');
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', { n: 1 });
    await audit.append('EVENT_B', { n: 2 });
    const stdoutRun = await runCli(['audit', 'export'], stateDir);
    assert.equal(stdoutRun.code, 0);
    const parsed = JSON.parse(stdoutRun.stdout);
    assert.equal(parsed.exportVersion, 1);
    assert.equal(parsed.verified, true);
    assert.equal(parsed.summary.totalRecords, 2);
    assert.equal(parsed.summary.verifiedRecords, 2);
    assert.deepEqual(parsed.records.map((entry) => entry.record.event), ['EVENT_A', 'EVENT_B']);
    const outPath = path.join(directory, 'export.json');
    const fileRun = await runCli(['audit', 'export', '--out', outPath], stateDir);
    assert.equal(fileRun.code, 0);
    assert.match(fileRun.stdout, /Audit export written to /);
    assert.equal(await fs.readFile(outPath, 'utf8'), stdoutRun.stdout);
    await assertPrivateMode(outPath, 0o600);
    // `audit verify` on the same log is unchanged by the refactor.
    const verify = await runCli(['audit', 'verify'], stateDir);
    assert.equal(verify.code, 0);
    assert.match(verify.stdout, /"verified": true/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cli audit export: jsonl ends with the summary marker line; a broken log still exits 0', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-cli-jsonl-');
  try {
    const stateDir = path.join(directory, 'state');
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', {});
    await audit.append('EVENT_B', {});
    const file = path.join(stateDir, 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[0]);
    tampered.event = 'FORGED';
    lines[0] = JSON.stringify(tampered);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const jsonl = await runCli(['audit', 'export', '--format', 'jsonl'], stateDir);
    assert.equal(jsonl.code, 0);
    const parsedLines = jsonl.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(parsedLines.length, 3);
    assert.equal(parsedLines[0].chain.reason, 'AUDIT_CHAIN_HASH_MISMATCH');
    assert.equal(parsedLines[1].chain.status, 'verified');
    assert.equal(parsedLines[2].type, 'audit-export-summary');
    assert.equal(parsedLines[2].verified, false);
    assert.equal(parsedLines[2].summary.brokenRecords, 1);
    // JSON on the same broken log also exits 0: the export's job is
    // to SHOW the break, not to refuse it (unlike `audit verify`,
    // which exits 4 on a broken chain).
    const json = await runCli(['audit', 'export'], stateDir);
    assert.equal(json.code, 0);
    assert.match(json.stdout, /"verified": false/);
    assert.match(json.stdout, /AUDIT_CHAIN_HASH_MISMATCH/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cli audit export: unknown format exits 1 without touching the log; symlinked --out is refused', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-cli-refuse-');
  try {
    const stateDir = path.join(directory, 'state');
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', {});
    const logFile = path.join(stateDir, 'audit.jsonl');
    const before = await fs.readFile(logFile, 'utf8');
    const badFormat = await runCli(['audit', 'export', '--format', 'yaml'], stateDir);
    assert.equal(badFormat.code, 1);
    assert.match(badFormat.stderr, /Invalid audit export format: yaml \(expected "json" or "jsonl"\)\./);
    assert.equal(await fs.readFile(logFile, 'utf8'), before);
    const target = path.join(directory, 'target.txt');
    await fs.writeFile(target, 'do not overwrite\n');
    const link = path.join(directory, 'export.json');
    // Round 81: symlink creation needs privileges that are not
    // guaranteed on every platform (Windows runners included) —
    // same guard as backup-restore.test.js: skip, do not fail.
    try {
      await fs.symlink(target, link);
    } catch (error) {
      t.skip(`symlink unavailable: ${error.code || error.message}`);
      return;
    }
    const refused = await runCli(['audit', 'export', '--out', link], stateDir);
    assert.equal(refused.code, 1);
    assert.match(refused.stderr, /Refusing to write through a symbolic link/);
    assert.equal(await fs.readFile(target, 'utf8'), 'do not overwrite\n');
    assert.ok((await fs.lstat(link)).isSymbolicLink());
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cli audit export: works while the kill-switch is armed (read-only)', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-export-cli-armed-');
  try {
    const stateDir = path.join(directory, 'state');
    const trigger = await runCli(['kill-switch', 'trigger', '--actor', 'test-operator', '--reason', 'export-armed-test'], stateDir);
    assert.equal(trigger.code, 0);
    const exported = await runCli(['audit', 'export'], stateDir);
    assert.equal(exported.code, 0);
    const parsed = JSON.parse(exported.stdout);
    assert.equal(parsed.summary.totalRecords, 1);
    assert.equal(parsed.records[0].record.event, 'KILL_SWITCH_TRIGGER');
    assert.equal(parsed.records[0].chain.status, 'verified');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
