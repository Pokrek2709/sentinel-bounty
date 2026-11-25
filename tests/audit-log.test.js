const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { makeTempDir } = require('./helpers/temp-dir');
const { AuditLog } = require('../src/audit/audit-log');

const execFileAsync = promisify(execFile);

// EACCES can only be produced by an unprivileged process: root ignores
// permission bits. The nobody probe below is skipped anywhere that cannot
// run as an unprivileged user (non-root, Windows).
const canRunAsNobody = process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0;

test('audit health reports healthy for a writable log', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-healthy-');
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
    await audit.append('LAB_EVENT', { actor: 'lab' });
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: true });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health classifies ENOTDIR as AUDIT_LOG_PATH_INVALID', async (t) => {  const directory = await makeTempDir(t, 'sentinel-audit-enotdir-');
  try {
    const notADir = path.join(directory, 'notadir');
    await fs.writeFile(notADir, 'I am a regular file, not a directory');
    const audit = new AuditLog({ logFile: path.join(notADir, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: false, reason: 'AUDIT_LOG_PATH_INVALID' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health classifies EACCES as AUDIT_LOG_PERMISSION_DENIED, not AUDIT_LOG_LOCKED', { skip: !canRunAsNobody }, async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-eacces-');
  try {
    await fs.chmod(directory, 0o755);
    const stateDir = path.join(directory, 'state-ro');
    await fs.mkdir(stateDir, { mode: 0o555 });
    const logFile = path.join(stateDir, 'audit.jsonl');
    await fs.writeFile(logFile, '', { mode: 0o644 });
    const skillDirectory = path.join(directory, 'skill');
    await fs.mkdir(skillDirectory, { mode: 0o755 });
    // Same nobody-readability constraint as the kill-switch probe: copy
    // the module into the scratch directory, world-readable. The
    // module now depends on ../policy/state-permissions (round 45) and
    // ../policy/lock-file (round 47), so the scratch copy mirrors the
    // repo layout (audit/ + policy/) instead of a single flat file.
    await fs.mkdir(path.join(directory, 'audit'));
    await fs.mkdir(path.join(directory, 'policy'));
    // mkdir's mode is masked by the umask (0007 turns 0755 into
    // 0750), so set world-traversal explicitly: the probe runs as
    // nobody and must be able to enter these directories.
    await fs.chmod(path.join(directory, 'audit'), 0o755);
    await fs.chmod(path.join(directory, 'policy'), 0o755);
    const probeModule = path.join(directory, 'audit', 'audit-log.js');
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'audit', 'audit-log.js'), probeModule);
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'policy', 'state-permissions.js'), path.join(directory, 'policy', 'state-permissions.js'));
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'policy', 'lock-file.js'), path.join(directory, 'policy', 'lock-file.js'));
    await fs.chmod(probeModule, 0o644);
    await fs.chmod(path.join(directory, 'policy', 'state-permissions.js'), 0o644);
    await fs.chmod(path.join(directory, 'policy', 'lock-file.js'), 0o644);
    const probe = `
      const { AuditLog } = require(process.env.PROBE_MODULE);
      (async () => {
        const audit = new AuditLog({ logFile: process.env.PROBE_LOG_FILE, skillDirectory: process.env.PROBE_SKILL_DIR });
        console.log('OK:' + JSON.stringify(await audit.healthCheck({ additionalBytes: 0 })));
      })();
    `;
    const { stdout } = await execFileAsync(process.execPath, ['-e', probe], {
      uid: 65534,
      gid: 65534,
      // cwd must be world-readable: node resolves the -e module's
      // self-reference against cwd's package.json, and the repo checkout
      // is not readable by nobody.
      cwd: directory,
      env: {
        ...process.env,
        PROBE_MODULE: probeModule,
        PROBE_LOG_FILE: logFile,
        PROBE_SKILL_DIR: skillDirectory,
      },
    });
    assert.ok(stdout.includes('"reason":"AUDIT_LOG_PERMISSION_DENIED"'), `healthCheck as nobody must report AUDIT_LOG_PERMISSION_DENIED, got: ${stdout}`);
    assert.ok(!stdout.includes('AUDIT_LOG_LOCKED'), `healthCheck must not be mislabeled AUDIT_LOG_LOCKED, got: ${stdout}`);
    assert.equal(require('node:fs').existsSync(`${logFile}.lock`), false);
  } finally {
    await fs.chmod(directory, 0o700).catch(() => {});
    await fs.rm(directory, { recursive: true, force: true });
  }
});

// --- Rotation (round 37): the rotation itself already existed; these
// tests PROVE it. rotationBytes is injected small so the limit is hit
// with a handful of records instead of 8 MiB of lab data.

test('audit rotation triggers at the configured limit and keeps the active log small', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-rotate-');
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill'), rotationBytes: 700, retentionCount: 3 });
    // A chained record is ~310 bytes (round 43: prevHash + hash are 64
    // hex each), so three appends (~930) cross the 700-byte limit: the
    // first two rotate into .1, only the third remains active.
    await audit.append('EVENT_A', { n: 1 });
    await audit.append('EVENT_B', { n: 2 });
    await audit.append('EVENT_C', { n: 3 });
    assert.ok((await fs.stat(path.join(directory, 'state', 'audit.jsonl.1'))).isFile());
    const active = await fs.readFile(path.join(directory, 'state', 'audit.jsonl'), 'utf8');
    assert.equal(active.trim().split('\n').length, 1);
    assert.match(active, /EVENT_C/);
    const archived = await fs.readFile(path.join(directory, 'state', 'audit.jsonl.1'), 'utf8');
    assert.match(archived, /EVENT_A/);
    assert.match(archived, /EVENT_B/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit rotation loses no records: active log plus archives hold every event in order', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-noloss-');
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill'), rotationBytes: 1000, retentionCount: 3 });
    // A chained record is ~310 bytes (round 43), so a 1,000-byte limit
    // rotates every ~3 records: 12 records span the active log plus
    // three archives (capacity ~4,000 bytes) and every record survives.
    // (With a 300-byte limit the same 12 records would exceed
    // retention and the oldest would be dropped by design — that is the
    // bounded-archives test below, not a loss bug.)
    const written = [];
    for (let index = 0; index < 12; index += 1) {
      written.push((await audit.append(`EVENT_${index}`, { n: index })).eventId);
    }
    const all = await audit.readAllEvents();
    assert.deepEqual(all.map((event) => event.eventId), written);
    assert.deepEqual(all.map((event) => event.event), written.map((_, index) => `EVENT_${index}`));
    // readEvents() is active-log-only by design: it sees the tail, not
    // the history. The rotated records are only in readAllEvents().
    const activeOnly = await audit.readEvents();
    assert.ok(activeOnly.length < written.length);
    assert.deepEqual(activeOnly.map((event) => event.eventId), written.slice(written.length - activeOnly.length));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit archives stay bounded at the retention count', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-bounded-');
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill'), rotationBytes: 300, retentionCount: 2 });
    for (let index = 0; index < 30; index += 1) {
      await audit.append(`EVENT_${index}`, { n: index });
    }
    const entries = await fs.readdir(path.join(directory, 'state'));
    assert.ok(entries.includes('audit.jsonl.1'));
    assert.ok(entries.includes('audit.jsonl.2'));
    assert.equal(entries.includes('audit.jsonl.3'), false);
    assert.equal(entries.includes('audit.jsonl.4'), false);
    // Bounded does not mean lossy while within retention: the newest
    // records are all still present across active + archives.
    const all = await audit.readAllEvents();
    assert.ok(all.length >= 3);
    assert.equal(all[all.length - 1].event, 'EVENT_29');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health reports a corrupt archive instead of silently dropping it', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-audit-corrupt-archive-');
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill'), rotationBytes: 700, retentionCount: 3 });
    await audit.append('EVENT_A', { n: 1 });
    await audit.append('EVENT_B', { n: 2 });
    await audit.append('EVENT_C', { n: 3 });
    // Healthy archives keep the existing healthy result and reason codes.
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: true });
    // Corrupt the rotated archive: a garbage line, not a deleted file.
    await fs.appendFile(path.join(directory, 'state', 'audit.jsonl.1'), 'this is not JSONL\n');
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: false, reason: 'AUDIT_LOG_ARCHIVE_CORRUPT' });
    // The corrupt archive is still there to be repaired, not dropped.
    assert.match(await fs.readFile(path.join(directory, 'state', 'audit.jsonl.1'), 'utf8'), /EVENT_A/);
    // A corrupt ACTIVE log still reports the pre-existing code, not the
    // new archive code.
    const directory2 = await makeTempDir(t, 'sentinel-audit-corrupt-active-');
    try {
      const audit2 = new AuditLog({ logFile: path.join(directory2, 'state', 'audit.jsonl'), skillDirectory: path.join(directory2, 'skill'), rotationBytes: 300, retentionCount: 3 });
      await audit2.append('EVENT_A', { n: 1 });
      await fs.appendFile(path.join(directory2, 'state', 'audit.jsonl'), 'garbage\n');
      assert.deepEqual(await audit2.healthCheck({ additionalBytes: 0 }), { healthy: false, reason: 'AUDIT_LOG_CORRUPT' });
    } finally {
      await fs.rm(directory2, { recursive: true, force: true });
    }
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
