#!/usr/bin/env node

const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry } = require('../src/scope/target-registry');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { AuditLog } = require('../src/audit/audit-log');

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
      const metadata = JSON.parse(value);
      digest = typeof metadata.digest === 'string' ? metadata.digest.toLowerCase() : '';
      keyId = typeof metadata.keyId === 'string' && metadata.keyId.trim() ? metadata.keyId.trim() : '';
      validUntil = typeof metadata.validUntil === 'number' ? metadata.validUntil : Date.parse(metadata.validUntil);
    }
    if (!/^[a-f0-9]{64}$/.test(digest) || !keyId || !Number.isFinite(validUntil) || validUntil <= Date.now()) return undefined;
    return { digest, keyId, validUntil, filePath: realHashFile };
  } catch {
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
  const resetTokenHash = ['reset', 'rotate-token', 'revoke-token'].includes(action) ? await readExpectedResetTokenHash() : undefined;
  const { killSwitch, stateDirectory } = await killSwitchFor(options, resetTokenHash);
  const audit = new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
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
      process.stdout.write(`${JSON.stringify({ rotated: false, reason: ['RESET_TOKEN_FILE_UNAVAILABLE', 'RESET_TOKEN_ROTATION_LOCKED'].includes(error.message) ? error.message : 'RESET_TOKEN_WRITE_FAILED', auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 1;
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
      process.stdout.write(`${JSON.stringify({ revoked: false, reason: ['RESET_TOKEN_FILE_UNAVAILABLE', 'RESET_TOKEN_ROTATION_LOCKED'].includes(error.message) ? error.message : 'RESET_TOKEN_REVOKE_FAILED', auditHealth, auditLogged: false }, null, 2)}\n`);
      process.exitCode = 1;
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
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  while (!handle) {
    try {
      handle = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST' || Date.now() - started >= 5_000) throw new Error('RESET_TOKEN_ROTATION_LOCKED');
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs >= 60_000) await fs.unlink(lockFile);
      } catch (statError) {
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
  } finally {
    if (!renamed) await fs.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function removeTokenFile(filePath) {
  const stat = await fs.lstat(filePath).catch(() => null);
  if (!stat || stat.isSymbolicLink() || !stat.isFile() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('RESET_TOKEN_FILE_UNAVAILABLE');
  await fs.unlink(filePath);
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

async function main(argv) {
  const [command, ...args] = argv;
  if (command === 'kill-switch') {
    const [action, ...actionArgs] = args;
    await runKillSwitch(action, actionArgs);
    return;
  }
  if (command === 'check-scope') {
    const options = parseOptions(args, ['--target', '--url']);
    if (!options.target || !options.url) throw new Error('check-scope requires --target and --url.');
    const target = JSON.parse(await fs.readFile(path.resolve(options.target), 'utf8'));
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
    await fs.writeFile(outputPath, serialized, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Environment report written to ${outputPath}\n`);
    return;
  }

  process.stdout.write(serialized);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`sentinel: ${error.message}\n`);
  process.exitCode = 1;
});
