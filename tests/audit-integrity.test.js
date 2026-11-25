const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { AuditLog, computeAuditRecordHash, GENESIS_PREV_HASH } = require('../src/audit/audit-log');

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

test('audit chain: appended records link prevHash to hash, genesis anchors a fresh chain', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-link-'));
  try {
    const audit = await makeAudit(directory);
    const first = await audit.append('EVENT_A', { n: 1 });
    const second = await audit.append('EVENT_B', { n: 2 });
    const third = await audit.append('EVENT_C', { n: 3 });
    assert.equal(first.chainVersion, 1);
    assert.equal(first.prevHash, GENESIS_PREV_HASH);
    assert.equal(second.prevHash, first.hash);
    assert.equal(third.prevHash, second.hash);
    assert.equal(computeAuditRecordHash(first), first.hash);
    assert.equal(computeAuditRecordHash(second), second.hash);
    assert.equal(computeAuditRecordHash(third), third.hash);
    // Independent recomputation from the STORED line, using only the
    // documented formula (no module helper): an external checker that
    // rebuilds the canonical object in the documented key order must
    // reproduce the stored hash.
    const stored = JSON.parse((await fs.readFile(path.join(directory, 'state', 'audit.jsonl'), 'utf8')).trim().split('\n')[1]);
    const canonical = JSON.stringify({
      chainVersion: 1,
      version: stored.version,
      event: stored.event,
      eventId: stored.eventId,
      recordedAt: stored.recordedAt,
      details: stored.details,
      prevHash: stored.prevHash,
    });
    assert.equal(crypto.createHash('sha256').update(canonical).digest('hex'), stored.hash);
    assert.deepEqual(await audit.verifyChain(), {
      verified: true,
      totalRecords: 3,
      legacyRecords: 0,
      chainedRecords: 3,
      anchorHash: GENESIS_PREV_HASH,
      brokenAt: null,
      reason: null,
    });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: a modified record is detected at its own line', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-modify-'));
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
    const result = await audit.verifyChain();
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'AUDIT_CHAIN_HASH_MISMATCH');
    assert.deepEqual(result.brokenAt, { file: 'audit.jsonl', line: 2, reason: 'AUDIT_CHAIN_HASH_MISMATCH' });
    assert.equal(result.totalRecords, 3);
    assert.equal(result.chainedRecords, 1);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: a reordered pair is detected at the first swapped line', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-reorder-'));
  try {
    const audit = await makeAudit(directory);
    for (const event of ['EVENT_A', 'EVENT_B', 'EVENT_C', 'EVENT_D']) await audit.append(event, {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    [lines[1], lines[2]] = [lines[2], lines[1]];
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChain();
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'AUDIT_CHAIN_PREV_MISMATCH');
    assert.deepEqual(result.brokenAt, { file: 'audit.jsonl', line: 2, reason: 'AUDIT_CHAIN_PREV_MISMATCH' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: deleting a middle record is detected at its successor', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-delete-'));
  try {
    const audit = await makeAudit(directory);
    for (const event of ['EVENT_A', 'EVENT_B', 'EVENT_C']) await audit.append(event, {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    lines.splice(1, 1);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChain();
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'AUDIT_CHAIN_PREV_MISMATCH');
    // The successor (old line 3, now line 2) is the first record whose
    // prevHash no longer matches its predecessor.
    assert.deepEqual(result.brokenAt, { file: 'audit.jsonl', line: 2, reason: 'AUDIT_CHAIN_PREV_MISMATCH' });
    assert.equal(result.totalRecords, 2);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: a clean log verifies across a rotation (archives are part of the chain)', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-rotate-'));
  try {
    const audit = await makeAudit(directory, { rotationBytes: 1000, retentionCount: 3 });
    for (let index = 0; index < 8; index += 1) await audit.append(`EVENT_${index}`, { n: index });
    // A chained record is ~310 bytes (prevHash + hash are 64 hex each),
    // so a 1,000-byte limit rotates every ~3 records: 8 records span
    // the active log plus archives and all stay inside retention 3.
    const entries = await fs.readdir(path.join(directory, 'state'));
    assert.ok(entries.includes('audit.jsonl.1'), 'a rotation must have happened');
    const result = await audit.verifyChain();
    assert.equal(result.verified, true);
    assert.equal(result.totalRecords, 8);
    assert.equal(result.legacyRecords, 0);
    assert.equal(result.chainedRecords, 8);
    assert.equal(result.anchorHash, GENESIS_PREV_HASH);
    // Tampering inside an archive is detected too, with the archive
    // file and line named.
    const archive = path.join(directory, 'state', 'audit.jsonl.1');
    const archiveLines = (await fs.readFile(archive, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(archiveLines[0]);
    tampered.event = 'FORGED_EVENT';
    archiveLines[0] = JSON.stringify(tampered);
    await fs.writeFile(archive, `${archiveLines.join('\n')}\n`);
    const after = await audit.verifyChain();
    assert.equal(after.verified, false);
    assert.equal(after.brokenAt.file, 'audit.jsonl.1');
    assert.equal(after.brokenAt.line, 1);
    assert.equal(after.reason, 'AUDIT_CHAIN_HASH_MISMATCH');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: pre-chain legacy records verify as a prefix; a legacy record after a chained one breaks', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-legacy-'));
  try {
    const audit = await makeAudit(directory);
    const logFile = path.join(directory, 'state', 'audit.jsonl');
    await fs.mkdir(path.join(directory, 'state'), { recursive: true });
    const legacy = (event) => JSON.stringify({ version: 1, event, eventId: crypto.randomUUID(), recordedAt: new Date().toISOString(), details: {} });
    await fs.writeFile(logFile, `${legacy('OLD_A')}\n${legacy('OLD_B')}\n`, { mode: 0o600 });
    await audit.append('EVENT_C', {});
    await audit.append('EVENT_D', {});
    const result = await audit.verifyChain();
    assert.equal(result.verified, true);
    assert.equal(result.totalRecords, 4);
    assert.equal(result.legacyRecords, 2);
    assert.equal(result.chainedRecords, 2);
    assert.equal(result.anchorHash, GENESIS_PREV_HASH);
    // A legacy record smuggled in after chained records breaks the
    // chain at its own line: the prefix rule is enforced, not assumed.
    await fs.appendFile(logFile, `${legacy('SMUGGLED')}\n`);
    const after = await audit.verifyChain();
    assert.equal(after.verified, false);
    assert.equal(after.reason, 'AUDIT_CHAIN_LEGACY_AFTER_CHAINED');
    assert.deepEqual(after.brokenAt, { file: 'audit.jsonl', line: 5, reason: 'AUDIT_CHAIN_LEGACY_AFTER_CHAINED' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: appending after a garbage line chains from the last good record; verify reports the garbage line', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-garbage-'));
  try {
    const audit = await makeAudit(directory);
    const first = await audit.append('EVENT_A', {});
    await audit.append('EVENT_B', {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    await fs.appendFile(file, 'this is not JSONL\n');
    const third = await audit.append('EVENT_C', {});
    // The new record chains from B, not from genesis and not from the
    // garbage: the writer skips unparseable lines when finding the tail.
    const second = JSON.parse((await fs.readFile(file, 'utf8')).trim().split('\n')[1]);
    assert.equal(third.prevHash, second.hash);
    assert.equal(first.hash.length, 64);
    const result = await audit.verifyChain();
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'AUDIT_CHAIN_UNPARSEABLE');
    assert.deepEqual(result.brokenAt, { file: 'audit.jsonl', line: 3, reason: 'AUDIT_CHAIN_UNPARSEABLE' });
    assert.equal(result.totalRecords, 4);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

// Documented limitations, pinned as tests so a future change cannot
// silently claim stronger guarantees: deleting a leading prefix — or
// the last record, which has no successor — is indistinguishable from
// legitimate retention / a log that simply ends there.
test('audit chain: deleting a leading prefix is undetectable (documented limitation)', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-prefix-'));
  try {
    const audit = await makeAudit(directory);
    for (const event of ['EVENT_A', 'EVENT_B', 'EVENT_C']) await audit.append(event, {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    lines.splice(0, 1);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChain();
    assert.equal(result.verified, true);
    assert.equal(result.totalRecords, 2);
    assert.equal(result.chainedRecords, 2);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit chain: deleting the last record is undetectable (documented limitation)', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-tail-'));
  try {
    const audit = await makeAudit(directory);
    for (const event of ['EVENT_A', 'EVENT_B', 'EVENT_C']) await audit.append(event, {});
    const file = path.join(directory, 'state', 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    lines.splice(2, 1);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const result = await audit.verifyChain();
    assert.equal(result.verified, true);
    assert.equal(result.totalRecords, 2);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('cli audit verify: clean log exits 0, tampered log exits 4 with brokenAt, missing log verifies empty', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-chain-cli-'));
  try {
    const stateDir = path.join(directory, 'state');
    const empty = await runCli(['audit', 'verify'], stateDir);
    assert.equal(empty.code, 0);
    assert.match(empty.stdout, /"verified": true/);
    assert.match(empty.stdout, /"totalRecords": 0/);
    const audit = await makeAudit(directory);
    await audit.append('EVENT_A', {});
    await audit.append('EVENT_B', {});
    const clean = await runCli(['audit', 'verify'], stateDir);
    assert.equal(clean.code, 0);
    assert.match(clean.stdout, /"verified": true/);
    assert.match(clean.stdout, /"chainedRecords": 2/);
    const file = path.join(stateDir, 'audit.jsonl');
    const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[0]);
    tampered.event = 'FORGED';
    lines[0] = JSON.stringify(tampered);
    await fs.writeFile(file, `${lines.join('\n')}\n`);
    const broken = await runCli(['audit', 'verify'], stateDir);
    assert.equal(broken.code, 4);
    assert.match(broken.stdout, /"verified": false/);
    assert.match(broken.stdout, /"reason": "AUDIT_CHAIN_HASH_MISMATCH"/);
    assert.match(broken.stdout, /"line": 1/);
    const unknown = await runCli(['audit', 'bogus'], stateDir);
    assert.equal(unknown.code, 1);
    assert.match(unknown.stderr, /Unknown audit action: bogus/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
