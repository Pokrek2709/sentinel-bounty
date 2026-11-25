#!/usr/bin/env node

const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry, renderScopeExplanationText } = require('../src/scope/target-registry');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { classifyRotationLockError, classifyTokenFileError } = require('../src/policy/storage-errors');
const { AuditLog } = require('../src/audit/audit-log');
const { generateReport } = require('../src/report/generator');
const { runVerifyInstall, checkStatePermissions } = require('../src/install/verifier');
const { repairStatePermissions } = require('../src/policy/state-permissions');
const { writeFileRefusingSymlink } = require('../src/policy/safe-write');
const { backupState, restoreState, INTEGRITY_REASONS } = require('../src/policy/state-backup');
const { readJsonFileBounded, MAX_FINDINGS } = require('../src/policy/input-limits');
const { runDrill } = require('../src/policy/incident-drill');
const { closeAndRemoveLock } = require('../src/policy/lock-file');
const { getDetector, runDetector } = require('../src/detection/detector');
const { storePathFor, addScopeTarget, removeScopeTarget, findScopeTarget } = require('../src/scope/target-store');

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
    '  sentinel check-scope --target <target.json> --url <url> [--explain] [--json]',
    '  sentinel check-scope --store <scope-targets.json> --target-id <id> --url <url> [--explain] [--json]',
    '  sentinel scope add <target.json> [--state-dir <path>]',
    '  sentinel scope remove <target-id> [--state-dir <path>]',
    '  sentinel kill-switch status [--state-dir <path>]',
    '  sentinel kill-switch trigger --actor <id> --reason <reason> [--state-dir <path>]',
    '  sentinel kill-switch reset --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch audit-health [--state-dir <path>]',
    '  sentinel kill-switch rotate-token --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch revoke-token --actor <id> [--state-dir <path>]',
    '  sentinel audit verify [--state-dir <path>]',
    '  sentinel backup --out <file> [--state-dir <path>]',
    '  sentinel restore --from <file> [--state-dir <path>]',
    '  sentinel drill [--state-dir <path>] [--recover]',
    '  sentinel report --finding <finding.json> [--out <report.md>] [--format markdown|json|html] [--template generic|immunefi|code4rena] [--generated-at <iso>] [--program <name>] [--allow-mixed-targets] [--verifier stub|<path>]',
    '  sentinel report --findings <findings-array.json> [--out <report.md>] [--format markdown|json|html] [--generated-at <iso>] [--program <name>] [--allow-mixed-targets] [--verifier stub|<path>]',
    '  sentinel detect [--detector stub|<path>] --input <record.json> [--session-id <id>] [--target-id <id>] [--asset-id <id>] [--out <findings.json>]',
    '  sentinel verify-install [--state-dir <path>] [--skill-dir <path>] [--fix]',
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

// Scope target management (Phase 3, round 53). The persistent store is
// `<state-dir>/scope-targets.json`; scope changes are operator config
// writes, so they are refused while the kill-switch is ARMED — changing
// what a stopped run covers, silently, would defeat the switch. The
// guard is checked before any target is read or written. A successful
// mutation writes an audit record (SCOPE_TARGET_ADDED /
// SCOPE_TARGET_REMOVED); a mutation whose audit append fails reports
// `auditLogged: false` and exits 4, following the kill-switch trigger
// pattern. A duplicate add is an idempotent no-op (exit 0, no rewrite,
// no audit record).
async function runScopeCommand(args) {
  const [action, value, ...optionArgs] = args;
  if (action !== 'add' && action !== 'remove') {
    throw new Error('scope requires an action: add or remove.');
  }
  if (!value || value.startsWith('--')) {
    throw new Error(action === 'add' ? 'scope add requires a <target.json> file.' : 'scope remove requires a <target-id>.');
  }
  const options = parseOptions(optionArgs, ['--state-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const storePath = storePathFor(stateDirectory);
  const { killSwitch } = await killSwitchFor({ stateDir: stateDirectory });
  const guard = await killSwitch.assertNotTriggered();
  if (!guard.allowed) {
    process.stdout.write(`${JSON.stringify({ [action === 'add' ? 'added' : 'removed']: false, reason: 'SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE', trigger: guard.trigger || null }, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  if (action === 'add') {
    const targetPath = path.resolve(value);
    let targetObject;
    try {
      targetObject = await readJsonFileBounded(targetPath);
    } catch (error) {
      throw new Error(`SCOPE_TARGET_INVALID: cannot read target file: ${error.message}`);
    }
    const result = await addScopeTarget(storePath, targetObject);
    if (!result.added) {
      // Idempotent no-op: nothing was written and nothing was logged, so
      // there is no auditLogged field to report (false would imply a
      // failed append).
      process.stdout.write(`${JSON.stringify({ ...result, store: storePath }, null, 2)}\n`);
      return;
    }
    const auditLogged = await appendOperatorAudit(stateDirectory, 'SCOPE_TARGET_ADDED', { targetId: result.targetId, store: storePath });
    process.stdout.write(`${JSON.stringify({ ...result, store: storePath, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    return;
  }
  const result = await removeScopeTarget(storePath, value);
  const auditLogged = await appendOperatorAudit(stateDirectory, 'SCOPE_TARGET_REMOVED', { targetId: result.targetId, store: storePath });
  process.stdout.write(`${JSON.stringify({ ...result, store: storePath, auditLogged }, null, 2)}\n`);
  if (!auditLogged) process.exitCode = 4;
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
    // Round 47: close() throwing used to skip the lock removal and
    // leave a stale rotation lock behind for up to 60 s. See
    // src/policy/lock-file.js.
    await closeAndRemoveLock(handle, lockFile);
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

async function runAuditCommand(args) {
  const [action, ...actionArgs] = args;
  if (action !== 'verify') throw new Error(`Unknown audit action: ${action}`);
  const options = parseOptions(actionArgs, ['--state-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const audit = new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  try {
    const result = await audit.verifyChain();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    // A broken chain is an audit problem (exit 4, like audit-health),
    // not an authorization failure (exit 3) or a crash (exit 1).
    if (!result.verified) process.exitCode = 4;
  } catch (error) {
    if (['AUDIT_LOG_LOCKED', 'AUDIT_LOG_PERMISSION_DENIED', 'AUDIT_LOG_STORAGE_UNAVAILABLE', 'AUDIT_LOG_PATH_INVALID'].includes(error.message)) {
      process.stdout.write(`${JSON.stringify({ verified: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    throw error;
  }
}

async function runReport(args) {
  // --allow-mixed-targets is a boolean flag (same pattern as drill
  // --recover): strip it before parseOptions, which only accepts
  // valued options.
  const allowMixedTargets = args.includes('--allow-mixed-targets');
  const options = parseOptions(args.filter((argument) => argument !== '--allow-mixed-targets'), ['--finding', '--findings', '--out', '--format', '--template', '--generated-at', '--program', '--verifier']);
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
    allowMixedTargets,
    verifier: options.verifier,
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

async function runDetect(args) {
  // `sentinel detect` runs a conforming detector (round 51) over a
  // LOCAL input record and prints the findings as JSON. The input
  // is a raw detector-input record (the shape normalizeRawFinding
  // accepts) or a batch record `{ tool, results: [...] }`; it is
  // read bounded (size + nesting depth) like every other JSON
  // input. The detector defaults to the built-in stub; a path
  // loads a custom detector module from inside the skill
  // directory (refused with a named DETECTOR_* error when it is
  // missing, malformed, a symlink, or outside the skill root).
  // The output findings are normalized finding records, directly
  // consumable by the validator (`sentinel report` or
  // validateFinding). The optional --session-id / --target-id /
  // --asset-id options supply the `defaults` fallback for input
  // records that do not carry those ids themselves (a detector
  // never invents them); without them, a record missing an id is
  // counted in `skipped`. A bad detector path fails before any
  // output is written, so --out can never leave a half-written
  // file behind; a detector that throws or returns an invalid
  // result is recorded in the output envelope (`error` field),
  // never a crash. No network request, no scanner, no live target.
  const options = parseOptions(args, ['--detector', '--input', '--out', '--session-id', '--target-id', '--asset-id']);
  if (!options.input) throw new Error('detect requires --input.');
  const resolved = getDetector(options.detector || 'stub', path.resolve(__dirname, '..'));
  const input = await readJsonFileBounded(path.resolve(options.input));
  const defaults = {
    ...(options.sessionId ? { session_id: options.sessionId } : {}),
    ...(options.targetId ? { target_id: options.targetId } : {}),
    ...(options.assetId ? { asset_id: options.assetId } : {}),
  };
  const result = runDetector(resolved.detector, input, defaults);
  const output = {
    detector: resolved.source,
    findings: result.findings,
    skipped: result.skipped,
    errors: result.errors,
    ...(result.error ? { error: result.error } : {}),
  };
  const serialized = `${JSON.stringify(output, null, 2)}\n`;
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, serialized, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Findings written to ${outputPath}\n`);
    return;
  }
  process.stdout.write(serialized);
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

async function runDrillCommand(args) {
  // --recover is a boolean flag, not a valued option: strip it before
  // parseOptions (which requires a value for every permitted option).
  const recover = args.includes('--recover');
  const options = parseOptions(args.filter((argument) => argument !== '--recover'), ['--state-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const result = await runDrill({
    stateDir: stateDirectory,
    skillDirectory: path.resolve(__dirname, '..'),
    recover,
  });
  for (const step of result.steps) {
    process.stdout.write(`${step.status} ${step.id}: ${step.detail}${step.reason ? ` (${step.reason})` : ''}\n`);
  }
  const passed = result.steps.filter((step) => step.status === 'PASS').length;
  process.stdout.write(`drill: ${result.verdict} (${passed} passed, ${result.steps.length - passed} failed)\n`);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.verdict !== 'PASS') process.exitCode = 1;
}

async function runVerifyInstallCommand(args) {
  // --fix is a boolean flag (same pattern as drill --recover):
  // parseOptions requires a value for every permitted option, so it
  // is filtered out first. Without --fix, verify-install is strictly
  // read-only; with --fix it repairs ONLY state-permission
  // violations (chmod inside the state dir, never following a
  // symlink) and re-runs just that check.
  const fix = args.includes('--fix');
  const options = parseOptions(args.filter((argument) => argument !== '--fix'), ['--state-dir', '--skill-dir']);
  const skillDirectory = path.resolve(options.skillDir || path.resolve(__dirname, '..'));
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  let result = await runVerifyInstall({ skillDirectory, stateDirectory });
  if (fix) {
    const permissionsCheck = result.checks.find((check) => check.id === 'state-permissions');
    if (permissionsCheck && permissionsCheck.status === 'FAIL') {
      const repair = await repairStatePermissions(stateDirectory);
      for (const entry of repair.repaired) {
        process.stdout.write(`fixed ${entry.path}: ${entry.fromMode} -> ${entry.toMode}\n`);
      }
      for (const entry of repair.refused) {
        process.stdout.write(`refused ${entry.path}: ${entry.reason}\n`);
      }
      const rechecked = await checkStatePermissions(stateDirectory);
      const checks = result.checks.map((check) => (check.id === 'state-permissions' ? rechecked : check));
      const passed = checks.filter((check) => check.status === 'PASS').length;
      result = Object.freeze({
        checks: Object.freeze(checks),
        passed,
        failed: checks.length - passed,
        overall: checks.length - passed === 0 ? 'PASS' : 'FAIL',
      });
    }
  }
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
  if (command === 'drill') {
    await runDrillCommand(args);
    return;
  }
  if (command === 'verify-install') {
    await runVerifyInstallCommand(args);
    return;
  }
  if (command === 'audit') {
    await runAuditCommand(args);
    return;
  }
  if (command === 'report') {
    await runReport(args);
    return;
  }
  if (command === 'detect') {
    await runDetect(args);
    return;
  }
  if (command === 'kill-switch') {
    const [action, ...actionArgs] = args;
    await runKillSwitch(action, actionArgs);
    return;
  }
  if (command === 'scope') {
    await runScopeCommand(args);
    return;
  }
  if (command === 'check-scope') {
    // --explain and --json are boolean flags (same pattern as report
    // --allow-mixed-targets and drill --recover): strip them before
    // parseOptions, which only accepts valued options.
    const explain = args.includes('--explain');
    const json = args.includes('--json');
    const options = parseOptions(args.filter((argument) => argument !== '--explain' && argument !== '--json'), ['--target', '--url', '--store', '--target-id']);
    if (options.store && options.target) throw new Error('check-scope: --store and --target are mutually exclusive.');
    if (!options.url) throw new Error('check-scope requires --url.');
    let target;
    let targetPath;
    if (options.store) {
      // Resolve the target from the persistent scope store (round 53).
      // --store is the store FILE path (<state-dir>/scope-targets.json);
      // the decision logic below is unchanged.
      if (!options.targetId) throw new Error('check-scope --store requires --target-id.');
      const storePath = path.resolve(options.store);
      target = await findScopeTarget(storePath, options.targetId);
      if (!target) throw new Error(`SCOPE_TARGET_NOT_FOUND: no scope target with target_id "${options.targetId}" in ${storePath}`);
      targetPath = storePath;
    } else {
      if (!options.target) throw new Error('check-scope requires --target and --url.');
      targetPath = path.resolve(options.target);
      target = await readJsonFileBounded(targetPath);
    }
    const registry = new TargetRegistry();
    const registered = registry.register(target);
    const decision = registry.evaluate(registered.targetId, options.url);
    if (!explain) {
      // Plain output is unchanged: JSON with no explanation attached.
      process.stdout.write(`${JSON.stringify({
        targetId: registered.targetId,
        authorizationStatus: registered.authorizationStatus,
        decision,
        safety: 'No network request was made.',
      }, null, 2)}\n`);
      return;
    }
    const explanation = registry.explain(registered.targetId, options.url, { targetFile: targetPath });
    if (json) {
      process.stdout.write(`${JSON.stringify({
        targetId: registered.targetId,
        authorizationStatus: registered.authorizationStatus,
        decision,
        explanation,
        safety: 'No network request was made.',
      }, null, 2)}\n`);
      return;
    }
    process.stdout.write(`${renderScopeExplanationText(explanation)}\n`);
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
