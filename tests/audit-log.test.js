const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');
const { AuditLog } = require('../src/audit/audit-log');

const execFileAsync = promisify(execFile);

// EACCES can only be produced by an unprivileged process: root ignores
// permission bits. The nobody probe below is skipped anywhere that cannot
// run as an unprivileged user (non-root, Windows).
const canRunAsNobody = process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0;

test('audit health reports healthy for a writable log', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-audit-healthy-'));
  try {
    const audit = new AuditLog({ logFile: path.join(directory, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
    await audit.append('LAB_EVENT', { actor: 'lab' });
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: true });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health classifies ENOTDIR as AUDIT_LOG_PATH_INVALID', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-audit-enotdir-'));
  try {
    const notADir = path.join(directory, 'notadir');
    await fs.writeFile(notADir, 'I am a regular file, not a directory');
    const audit = new AuditLog({ logFile: path.join(notADir, 'state', 'audit.jsonl'), skillDirectory: path.join(directory, 'skill') });
    assert.deepEqual(await audit.healthCheck({ additionalBytes: 0 }), { healthy: false, reason: 'AUDIT_LOG_PATH_INVALID' });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('audit health classifies EACCES as AUDIT_LOG_PERMISSION_DENIED, not AUDIT_LOG_LOCKED', { skip: !canRunAsNobody }, async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-audit-eacces-'));
  try {
    await fs.chmod(directory, 0o755);
    const stateDir = path.join(directory, 'state-ro');
    await fs.mkdir(stateDir, { mode: 0o555 });
    const logFile = path.join(stateDir, 'audit.jsonl');
    await fs.writeFile(logFile, '', { mode: 0o644 });
    const skillDirectory = path.join(directory, 'skill');
    await fs.mkdir(skillDirectory, { mode: 0o755 });
    // Same nobody-readability constraint as the kill-switch probe: copy the
    // single-file module into the scratch directory, world-readable.
    const probeModule = path.join(directory, 'probe-audit-log.js');
    await fs.copyFile(path.resolve(__dirname, '..', 'src', 'audit', 'audit-log.js'), probeModule);
    await fs.chmod(probeModule, 0o644);
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
