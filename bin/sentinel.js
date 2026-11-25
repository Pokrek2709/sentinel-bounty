#!/usr/bin/env node

const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry } = require('../src/scope/target-registry');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { classifyRotationLockError, classifyTokenFileError } = require('../src/policy/storage-errors');
const { AuditLog } = require('../src/audit/audit-log');
const { generateReport } = require('../src/report/generator');
const { runVerifyInstall } = require('../src/install/verifier');
const { writeFileRefusingSymlink } = require('../src/policy/safe-write');
const { backupState, restoreState, INTEGRITY_REASONS } = require('../src/policy/state-backup');
const { readJsonFileBounded, MAX_FINDINGS } = require('../src/policy/input-limits');

// Classified rotation/token-file reasons that the rotate/revoke handlers
// pass through verbatim (stable operator-facing codes, never raw paths).
// Anything else from the rotation path is a generic write/revoke failure.
const ROTATION_FAILURE_REASONS = [
  'RESET_TOKEN_FILE_CORRUPT',
  'RESET_TOKEN_FILE_UNAVAILABLE',
  'RESET_TOKEN_ROTATION_LOCKED',
  'RESET_TOKEN_ROTATION_PERMISSION_DENIED',
  'RESET_TOKEN_ROTATION_UNAVAILABLE',
  'RESET_TOKEN_ROTATION_PATH_INVALID',
  'RESET_TOKEN_FILE_PERMISSION_DENIED',
  'RESET_TOKEN_FILE_PATH_INVALID',
];

const DEFAULT_STATE_DIRECTORY = path.join(os.homedir(), 'workspace', 'sentinel-bounty', 'state');
const DEFAULT_TOKEN_VALIDITY_MS = 90 * 24 * 60 * 60 * 1000;
const STATE_WRITE_RESERVE_BYTES = 4 * 1024;

function usage() {
  return [
    'Usage:',
    '  sentinel check-env [--output <path>] [--probe-dir <path>]',
    '  sentinel check-scope --target <target.json> --url <url>',
    '  sentinel kill-switch status [--state-dir <path>]',
    '  sentinel kill-switch trigger --actor <id> --reason <reason> [--state-dir <path>]',
    '  sentinel kill-switch reset --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch audit-health [--state-dir <path>]',
    '  sentinel kill-switch rotate-token --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch revoke-token --actor <id> [--state-dir <path>]',
    '  sentinel backup --out <file> [--state-dir <path>]',
    '  sentinel restore --from <file> [--state-dir <path>]',
    '  sentinel report --finding <finding.json> [--out <report.md>] [--format markdown|json] [--template generic|immunefi|code4rena] [--generated-at <iso>] [--program <name>]',
    '  sentinel report --findings <findings-array.json> [--out <report.md>] [--format markdown|json] [--generated-at <iso>] [--program <name>]',
    '  sentinel verify-install [--state-dir <path>] [--skill-dir <path>]',
    '',
    'The checker performs no network requests and does not invoke security tools.',
  ].join('\n');
}

function parseOptions(args, permitted) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (permitted.includes(argument)) {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new Error(`${argument} requires a value.`);
      }
      options[argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
      index += 1;
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  return options;
}

function pathOutsideSkill(candidate) {
  const skillDirectory = path.resolve(__dirname, '..');
  const resolved = path.resolve(candidate);
  const relative = path.relative(skillDirectory, resolved);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) return null;
  return resolved;
}

async function readExpectedResetTokenHash() {
  const configured = process.env.SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE;
  if (!configured) return undefined;
  const hashFile = pathOutsideSkill(configured);
  if (!hashFile) return undefined;
  try {
    const stat = await fs.lstat(hashFile);
    if (stat.isSymbolicLink() || !stat.isFile()) return undefined;
    const [realHashFile, realSkillDirectory] = await Promise.all([
      fs.realpath(hashFile),
      fs.realpath(path.resolve(__dirname, '..')),
    ]);
    const realRelative = path.relative(realSkillDirectory, realHashFile);
    if (realRelative === '' || (!realRelative.startsWith('..') && !path.isAbsolute(realRelative))) return undefined;
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) return undefined;
    const value = (await fs.readFile(realHashFile, 'utf8')).trim();
    let digest = value.toLowerCase();
    let keyId = 'legacy';
    let validUntil = stat.mtimeMs + DEFAULT_TOKEN_VALIDITY_MS;
    if (value.startsWith('{')) {
      let metadata;
      try {
        metadata = JSON.parse(value);
      } catch {
        // Unparseable JSON in a file that exists and is readable: the
        // token file is damaged, not merely absent or wrong.
        throw new Error('RESET_TOKEN_FILE_CORRUPT');
      }
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new Error('RESET_TOKEN_FILE_CORRUPT');
      digest = typeof metadata.digest === 'string' ? metadata.digest.toLowerCase() : '';
      keyId = typeof metadata.keyId === 'string' && metadata.keyId.trim() ? metadata.keyId.trim() : '';
      validUntil = typeof metadata.validUntil === 'number' ? metadata.validUntil : Date.parse(metadata.validUntil);
      // Wrong-shape JSON (bad digest, missing keyId, unusable validUntil)
      // is corruption, not a wrong token. Expiry below stays
      // RESET_OPERATOR_UNAUTHORIZED: a valid digest that lapsed is not
      // a damaged file.
      if (!/^[a-f0-9]{64}$/.test(digest) || !keyId || !Number.isFinite(validUntil)) throw new Error('RESET_TOKEN_FILE_CORRUPT');
    } else if (!/^[a-f0-9]{64}$/.test(digest)) {
      // Legacy plain-text value that is not a 64-hex hash: the file
      // exists and is readable but holds no usable digest.
      throw new Error('RESET_TOKEN_FILE_CORRUPT');
    }
    if (validUntil <= Date.now()) return undefined;
    return { digest, keyId, validUntil, filePath: realHashFile };
  } catch (error) {
    // A corrupt digest file is reported distinctly (fail-closed): the
    // operator can tell a damaged token file apart from a wrong token.
    // A permission/path failure reading the digest is a storage failure,
    // not an authorization failure: surface the classified code instead
    // of swallowing it into "no usable token" (which the CLI reports
    // as RESET_OPERATOR_UNAUTHORIZED). A missing file or an expired
    // digest still returns undefined (fail-closed, unauthorized).
    if (error.message === 'RESET_TOKEN_FILE_CORRUPT') throw error;
    const classified = classifyTokenFileError(error);
    if (classified) throw new Error(classified);
    return undefined;
  }
}

async function killSwitchFor(options, resetTokenHash) {
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  return {
    killSwitch: new PersistentKillSwitch({
    stateFile: path.join(stateDirectory, 'kill-switch.json'),
    skillDirectory: path.resolve(__dirname, '..'),
    resetTokenHash: resetTokenHash?.digest,
    }),
    stateDirectory,
  };
}

async function runKillSwitch(action, args) {
  const options = parseOptions(args, ['--state-dir', '--actor', '--reason']);
  // A damaged digest file is fail-closed and reported distinctly from a
  // wrong token (RESET_TOKEN_FILE_CORRUPT, exit 3), before any state is
  // touched. The digest is read first, matching the pre-existing order,
  // so a corrupt file surfaces ahead of the audit-health gate.
  let resetTokenHash;
  let digestCorrupt = false;
  try {
    resetTokenHash = ['reset', 'rotate-token', 'revoke-token'].includes(action) ? await readExpectedResetTokenHash() : undefined;
  } catch (error) {
    if (error.message === 'RESET_TOKEN_FILE_CORRUPT') {
      digestCorrupt = true;
    } else {
      throw error;
    }
  }
  const { killSwitch, stateDirectory } = await killSwitchFor(options, resetTokenHash);
  const audit = new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  if (digestCorrupt) {
    const auditHealth = await auditHealthWithStateReserve(audit, stateDirectory);
    const reason = 'RESET_TOKEN_FILE_CORRUPT';
    if (action === 'reset') {
      process.stdout.write(`${JSON.stringify({ reset: false, reason, auditHealth, auditLogged: false }, null, 2)}\n`);
    } else if (action === 'rotate-token') {
      process.stdout.write(`${JSON.stringify({ rotated: false, reason, auditHealth, auditLogged: false }, null, 2)}\n`);
    } else if (action === 'revoke-token') {
      process.stdout.write(`${JSON.stringify({ revoked: false, reason, auditHealth, auditLogged: false }, null, 2)}\n`);
    }
    process.exitCode = 3;
    return;
  }
  if (action === 'audit-health') {
    const health = await auditHealthWithStateReserve(audit, stateDirectory);
    process.stdout.write(`${JSON.stringify(health, null, 2)}\n`);
    if (!health.healthy) process.exitCode = 4;
    return;
  }
  if (action === 'status') {
    // snapshot() already falls back internally to the canonical lockless
    // shape when storage is unavailable; it never throws
    // KILL_SWITCH_STATE_UNAVAILABLE, so there is no second CLI fallback.
    process.stdout.write(`${JSON.stringify(await killSwitch.snapshot(), null, 2)}\n`);
    return;
  }
  if (!options.actor) throw new Error(`kill-switch ${action} requires --actor.`);
  if (action === 'trigger') {
    if (!options.reason) throw new Error('kill-switch trigger requires --reason.');
    const auditHealth = await auditHealthWithStateReserve(audit, stateDirectory);
    const result = await killSwitch.trigger({ triggeredBy: options.actor, reason: options.reason });
    const auditLogged = await appendOperatorAudit(stateDirectory, 'KILL_SWITCH_TRIGGER', { actor: options.actor, reason: options.reason, result: result.reason || 'TRIGGERED' });
    process.stdout.write(`${JSON.stringify({ ...result, auditHealth, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    if (!result.triggered && result.reason !== 'KILL_SWITCH_ALREADY_ACTIVE') process.exitCode = 3;
    return;
  }
  if (action === 'reset') {
    const auditHealth = await auditHealthWithStateReserve(audit, stateDirectory);
    if (!auditHealth.healthy) {
      process.stdout.write(`${JSON.stringify({ reset: false, reason: auditHealth.reason, auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    const result = await killSwitch.reset({ resetBy: options.actor, resetToken: process.env.SENTINEL_OPERATOR_RESET_TOKEN });
    const auditLogged = await appendOperatorAudit(stateDirectory, result.reset ? 'KILL_SWITCH_RESET' : 'KILL_SWITCH_RESET_DENIED', { actor: options.actor, result: result.reason || 'RESET' });
    process.stdout.write(`${JSON.stringify({ ...result, auditHealth, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    if (!result.reset) process.exitCode = 3;
    return;
  }
  if (action === 'rotate-token') {
    const auditHealth = await auditHealthWithStateReserve(audit, stateDirectory);
    if (!auditHealth.healthy) {
      process.stdout.write(`${JSON.stringify({ rotated: false, reason: auditHealth.reason, auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    const presented = process.env.SENTINEL_OPERATOR_RESET_TOKEN;
    const nextToken = process.env.SENTINEL_OPERATOR_NEW_RESET_TOKEN;
    if (!resetTokenHash || typeof presented !== 'string') {
      process.stdout.write(`${JSON.stringify({ rotated: false, reason: 'RESET_OPERATOR_UNAUTHORIZED', auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 3;
      return;
    }
    if (typeof nextToken !== 'string' || nextToken.length < 16) {
      process.stdout.write(`${JSON.stringify({ rotated: false, reason: 'NEW_RESET_TOKEN_INVALID', auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 3;
      return;
    }
    let rotation;
    try {
      rotation = await withTokenRotationLock(resetTokenHash.filePath, async () => {
        const current = await readExpectedResetTokenHash();
        if (!current || crypto.createHash('sha256').update(presented).digest('hex') !== current.digest) return { rotated: false, reason: 'RESET_OPERATOR_UNAUTHORIZED' };
        const keyId = crypto.randomUUID();
        const validUntil = new Date(Date.now() + DEFAULT_TOKEN_VALIDITY_MS).toISOString();
        await writeTokenMetadata(current.filePath, { version: 1, keyId, digest: crypto.createHash('sha256').update(nextToken).digest('hex'), validUntil });
        return { rotated: true, keyId, validUntil };
      });
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ rotated: false, reason: ROTATION_FAILURE_REASONS.includes(error.message) ? error.message : 'RESET_TOKEN_WRITE_FAILED', auditHealth, auditLogged: false }, null, 2)}\n`);
      // A corrupt digest file discovered inside the rotation lock is a
      // fail-closed authorization outcome (exit 3), like a wrong token;
      // other rotation failures stay operational (exit 1).
      process.exitCode = error.message === 'RESET_TOKEN_FILE_CORRUPT' ? 3 : 1;
      return;
    }
    if (!rotation.rotated) {
      process.stdout.write(`${JSON.stringify({ ...rotation, auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 3;
      return;
    }
    const auditLogged = await appendOperatorAudit(stateDirectory, 'KILL_SWITCH_TOKEN_ROTATED', { actor: options.actor, keyId: rotation.keyId, validUntil: rotation.validUntil });
    process.stdout.write(`${JSON.stringify({ ...rotation, auditHealth, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    return;
  }
  if (action === 'revoke-token') {
    const auditHealth = await auditHealthWithStateReserve(audit, stateDirectory);
    if (!auditHealth.healthy) {
      process.stdout.write(`${JSON.stringify({ revoked: false, reason: auditHealth.reason, auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    const presented = process.env.SENTINEL_OPERATOR_RESET_TOKEN;
    const configuredTokenPath = resetTokenHash?.filePath || (process.env.SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE ? pathOutsideSkill(process.env.SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE) : null);
    if (!configuredTokenPath || typeof presented !== 'string') {
      process.stdout.write(`${JSON.stringify({ revoked: false, reason: 'RESET_OPERATOR_UNAUTHORIZED', auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 3;
      return;
    }
    let revocation;
    try {
      revocation = await withTokenRotationLock(configuredTokenPath, async () => {
        const events = await audit.readEvents();
        const current = await readExpectedResetTokenHash();
        const pendingEvents = events.filter((event) => event.event === 'KILL_SWITCH_TOKEN_REVOKE_PENDING' && typeof event.details?.keyId === 'string');
        const revokedKeyIds = new Set(events.filter((event) => event.event === 'KILL_SWITCH_TOKEN_REVOKED').map((event) => event.details?.keyId).filter((keyId) => typeof keyId === 'string'));
        const recoverablePending = [...pendingEvents].reverse().find((event) => !revokedKeyIds.has(event.details.keyId));
        const pending = current
          ? [...pendingEvents].reverse().find((event) => event.details.keyId === current.keyId) || recoverablePending
          : recoverablePending || [...pendingEvents].reverse()[0];
        const pendingKeyId = pending?.details?.keyId;
        const matchingRevoked = pendingKeyId && revokedKeyIds.has(pendingKeyId);
        // A completed marker for an old key must not block revocation of a newly
        // provisioned key in the same state directory. When the digest is gone,
        // the marker remains the only identity available for idempotent retry.
        const alreadyRevoked = matchingRevoked && (!current || current.keyId === pendingKeyId);
        if (alreadyRevoked) return { revoked: false, reason: 'RESET_TOKEN_ALREADY_REVOKED', auditLogged: true };
        const keyId = current?.keyId || pendingKeyId;
        if (!keyId) return { revoked: false, reason: 'RESET_OPERATOR_UNAUTHORIZED', auditLogged: false };
        if (current && crypto.createHash('sha256').update(presented).digest('hex') !== current.digest) return { revoked: false, reason: 'RESET_OPERATOR_UNAUTHORIZED', auditLogged: false };
        const pendingLogged = pending?.details?.keyId === keyId || await appendOperatorAudit(stateDirectory, 'KILL_SWITCH_TOKEN_REVOKE_PENDING', { actor: options.actor, keyId, requestedAt: new Date().toISOString() });
        if (!pendingLogged) return { revoked: false, reason: 'AUDIT_LOG_WRITE_FAILED', auditLogged: false };
        if (current) await removeTokenFile(current.filePath);
        const revokedAt = new Date().toISOString();
        const auditLogged = await appendOperatorAudit(stateDirectory, 'KILL_SWITCH_TOKEN_REVOKED', { actor: options.actor, keyId, revokedAt });
        if (!auditLogged) return { revoked: false, reason: 'AUDIT_LOG_WRITE_FAILED', auditLogged: false, keyId, revokedAt };
        return { revoked: true, keyId, revokedAt, auditLogged: true, recovered: pendingKeyId === keyId };
      });
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ revoked: false, reason: ROTATION_FAILURE_REASONS.includes(error.message) ? error.message : 'RESET_TOKEN_REVOKE_FAILED', auditHealth, auditLogged: false }, null, 2)}\n`);
      // Same fail-closed exit as the rotate path: a corrupt digest file
      // is an authorization outcome (exit 3), not an operational failure.
      process.exitCode = error.message === 'RESET_TOKEN_FILE_CORRUPT' ? 3 : 1;
      return;
    }
    process.stdout.write(`${JSON.stringify({ ...revocation, auditHealth }, null, 2)}\n`);
    if (!revocation.revoked) process.exitCode = ['RESET_OPERATOR_UNAUTHORIZED', 'RESET_TOKEN_ALREADY_REVOKED'].includes(revocation.reason) ? 3 : 4;
    return;
  }
  throw new Error(`Unknown kill-switch action: ${action}`);
}

async function auditHealthWithStateReserve(audit, stateDirectory) {
  let stateBytes = 0;
  try {
    stateBytes = (await fs.stat(path.join(stateDirectory, 'kill-switch.json'))).size;
  } catch (error) {
    // Classify the stat failure the same way the state lock does: a
    // permission or path failure is not a storage-exhaustion failure.
    if (error.code === 'ENOENT') {
      // No state file yet: fall through with the base reserve.
    } else if (['EACCES', 'EPERM'].includes(error.code)) {
      return { healthy: false, reason: 'KILL_SWITCH_STATE_PERMISSION_DENIED', reservedStateBytes: STATE_WRITE_RESERVE_BYTES };
    } else if (error.code === 'ENOTDIR') {
      return { healthy: false, reason: 'KILL_SWITCH_STATE_PATH_INVALID', reservedStateBytes: STATE_WRITE_RESERVE_BYTES };
    } else {
      return { healthy: false, reason: 'KILL_SWITCH_STATE_UNAVAILABLE', reservedStateBytes: STATE_WRITE_RESERVE_BYTES };
    }
  }
  const reservedStateBytes = stateBytes + STATE_WRITE_RESERVE_BYTES;
  return { ...(await audit.healthCheck({ additionalBytes: reservedStateBytes })), reservedStateBytes };
}

async function withTokenRotationLock(filePath, operation) {
  const lockFile = `${filePath}.rotate.lock`;
  const started = Date.now();
  let handle;
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  } catch (error) {
    const classified = classifyRotationLockError(error);
    if (classified) throw new Error(classified);
    throw error;
  }
  while (!handle) {
    try {
      handle = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      const classified = classifyRotationLockError(error);
      if (classified) throw new Error(classified);
      if (error.code !== 'EEXIST' || Date.now() - started >= 5_000) throw new Error('RESET_TOKEN_ROTATION_LOCKED');
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs >= 60_000) await fs.unlink(lockFile);
      } catch (statError) {
        const statClassified = classifyRotationLockError(statError);
        if (statClassified) throw new Error(statClassified);
        if (statError.code !== 'ENOENT') throw statError;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  try {
    return await operation();
  } finally {
    await handle.close();
    await fs.unlink(lockFile).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function writeTokenMetadata(filePath, metadata) {
  const stat = await fs.lstat(filePath).catch(() => null);
  if (!stat || stat.isSymbolicLink() || !stat.isFile() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let renamed = false;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(metadata, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await fs.chmod(temporary, 0o600);
    await renameWithRetry(temporary, filePath);
    renamed = true;
    await fs.chmod(filePath, 0o600);
  } catch (error) {
    const classified = classifyRotationLockError(error);
    if (classified) throw new Error(classified);
    throw error;
  } finally {
    if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function removeTokenFile(filePath) {
  const stat = await fs.lstat(filePath).catch(() => null);
  if (!stat || stat.isSymbolicLink() || !stat.isFile() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  try {
    await fs.unlink(filePath);
  } catch (error) {
    const classified = classifyRotationLockError(error);
    if (classified) throw new Error(classified);
    throw error;
  }
}

async function renameWithRetry(source, target) {
  const deadline = Date.now() + 1_000;
  while (true) {
    try {
      await fs.rename(source, target);
      return;
    } catch (error) {
      if (!['EPERM', 'EACCES'].includes(error.code) || Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}

async function appendOperatorAudit(stateDirectory, event, details) {
  try {
    const audit = new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
    await audit.append(event, details);
    return true;
  } catch {
    return false;
  }
}

async function runReport(args) {
  const options = parseOptions(args, ['--finding', '--findings', '--out', '--format', '--template', '--generated-at', '--program']);
  if ((options.finding && options.findings) || (!options.finding && !options.findings)) {
    throw new Error('report requires exactly one of --finding and --findings.');
  }
  // The report is generated fully in memory first; the output file is
  // only written after generation succeeds, so a validation failure can
  // never leave a half-written report behind. Input files are bounded
  // (size + nesting depth) so a hostile finding file cannot exhaust
  // memory or the call stack; the write refuses a planted symlink at
  // the output path so attacker-influenced report content can never be
  // redirected to the link target.
  let findings;
  if (options.finding) {
    findings = [await readJsonFileBounded(path.resolve(options.finding))];
  } else {
    findings = await readJsonFileBounded(path.resolve(options.findings));
    if (!Array.isArray(findings)) throw new Error('--findings must contain a JSON array.');
    if (findings.length > MAX_FINDINGS) throw new Error(`Too many findings: ${findings.length} (maximum ${MAX_FINDINGS}).`);
  }
  const report = generateReport(findings, {
    programName: options.program,
    generatedAt: options.generatedAt,
    format: options.format,
    template: options.template,
  });
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, report, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Report written to ${outputPath}\n`);
    return;
  }
  process.stdout.write(report);
}

async function runBackup(args) {
  const options = parseOptions(args, ['--out', '--state-dir']);
  if (!options.out) throw new Error('backup requires --out.');
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  try {
    const result = await backupState({ stateDir: stateDirectory, outPath: path.resolve(options.out) });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    // Named backup refusals are reported as JSON with a reason, like the
    // kill-switch refusals: integrity refusals exit 3 (fail-closed),
    // operational ones (missing state, live lock, oversized input) exit 1.
    if (INTEGRITY_REASONS.has(error.message) || ['BACKUP_STATE_MISSING', 'BACKUP_NOT_FOUND', 'BACKUP_TOO_LARGE', 'BACKUP_STATE_LOCKED'].includes(error.message)) {
      process.stdout.write(`${JSON.stringify({ backedUp: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = INTEGRITY_REASONS.has(error.message) ? 3 : 1;
      return;
    }
    throw error;
  }
}

async function runRestore(args) {
  const options = parseOptions(args, ['--from', '--state-dir']);
  if (!options.from) throw new Error('restore requires --from.');
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  try {
    const result = await restoreState({ stateDir: stateDirectory, fromPath: path.resolve(options.from) });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    if (INTEGRITY_REASONS.has(error.message) || ['BACKUP_STATE_MISSING', 'BACKUP_NOT_FOUND', 'BACKUP_TOO_LARGE', 'BACKUP_STATE_LOCKED'].includes(error.message)) {
      process.stdout.write(`${JSON.stringify({ restored: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = INTEGRITY_REASONS.has(error.message) ? 3 : 1;
      return;
    }
    throw error;
  }
}

async function runVerifyInstallCommand(args) {
  const options = parseOptions(args, ['--state-dir', '--skill-dir']);
  const skillDirectory = path.resolve(options.skillDir || path.resolve(__dirname, '..'));
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const result = await runVerifyInstall({ skillDirectory, stateDirectory });
  for (const check of result.checks) {
    process.stdout.write(`${check.status} ${check.id}: ${check.reason}\n`);
  }
  process.stdout.write(`verify-install: ${result.passed} passed, ${result.failed} failed — ${result.overall}\n`);
  if (result.failed > 0) process.exitCode = 1;
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command === 'backup') {
    await runBackup(args);
    return;
  }
  if (command === 'restore') {
    await runRestore(args);
    return;
  }
  if (command === 'verify-install') {
    await runVerifyInstallCommand(args);
    return;
  }
  if (command === 'report') {
    await runReport(args);
    return;
  }
  if (command === 'kill-switch') {
    const [action, ...actionArgs] = args;
    await runKillSwitch(action, actionArgs);
    return;
  }
  if (command === 'check-scope') {
    const options = parseOptions(args, ['--target', '--url']);
    if (!options.target || !options.url) throw new Error('check-scope requires --target and --url.');
    const target = await readJsonFileBounded(path.resolve(options.target));
    const registry = new TargetRegistry();
    const registered = registry.register(target);
    process.stdout.write(`${JSON.stringify({
      targetId: registered.targetId,
      authorizationStatus: registered.authorizationStatus,
      decision: registry.evaluate(registered.targetId, options.url),
      safety: 'No network request was made.',
    }, null, 2)}\n`);
    return;
  }

  if (command !== 'check-env') {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 1;
    return;
  }

  const options = parseOptions(args, ['--output', '--probe-dir']);
  const report = await runEnvironmentCheck({ probeDirectory: options.probeDir });
  const serialized = `${JSON.stringify(report, null, 2)}\n`;

  if (options.output) {
    const outputPath = path.resolve(options.output);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, serialized, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Environment report written to ${outputPath}\n`);
    return;
  }

  process.stdout.write(serialized);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`sentinel: ${error.message}\n`);
  process.exitCode = 1;
});
