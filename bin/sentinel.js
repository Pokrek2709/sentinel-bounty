#!/usr/bin/env node

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry } = require('../src/scope/target-registry');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { AuditLog } = require('../src/audit/audit-log');

const DEFAULT_STATE_DIRECTORY = path.join(os.homedir(), 'workspace', 'sentinel-bounty', 'state');

function usage() {
  return [
    'Usage:',
    '  sentinel check-env [--output <path>] [--probe-dir <path>]',
    '  sentinel check-scope --target <target.json> --url <url>',
    '  sentinel kill-switch status [--state-dir <path>]',
    '  sentinel kill-switch trigger --actor <id> --reason <reason> [--state-dir <path>]',
    '  sentinel kill-switch reset --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch audit-health [--state-dir <path>]',
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
    const value = (await fs.readFile(realHashFile, 'utf8')).trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(value) ? value : undefined;
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
    resetTokenHash,
    }),
    stateDirectory,
  };
}

async function runKillSwitch(action, args) {
  const options = parseOptions(args, ['--state-dir', '--actor', '--reason']);
  const resetTokenHash = action === 'reset' ? await readExpectedResetTokenHash() : undefined;
  const { killSwitch, stateDirectory } = await killSwitchFor(options, resetTokenHash);
  if (action === 'audit-health') {
    const health = await new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') }).healthCheck();
    process.stdout.write(`${JSON.stringify(health, null, 2)}\n`);
    if (!health.healthy) process.exitCode = 4;
    return;
  }
  if (action === 'status') {
    process.stdout.write(`${JSON.stringify(await killSwitch.snapshot(), null, 2)}\n`);
    return;
  }
  if (!options.actor) throw new Error(`kill-switch ${action} requires --actor.`);
  if (action === 'trigger') {
    if (!options.reason) throw new Error('kill-switch trigger requires --reason.');
    const result = await killSwitch.trigger({ triggeredBy: options.actor, reason: options.reason });
    const auditLogged = await appendOperatorAudit(stateDirectory, 'KILL_SWITCH_TRIGGER', { actor: options.actor, reason: options.reason, result: result.reason || 'TRIGGERED' });
    process.stdout.write(`${JSON.stringify({ ...result, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    if (!result.triggered && result.reason !== 'KILL_SWITCH_ALREADY_ACTIVE') process.exitCode = 3;
    return;
  }
  if (action === 'reset') {
    const result = await killSwitch.reset({ resetBy: options.actor, resetToken: process.env.SENTINEL_OPERATOR_RESET_TOKEN });
    const auditLogged = await appendOperatorAudit(stateDirectory, result.reset ? 'KILL_SWITCH_RESET' : 'KILL_SWITCH_RESET_DENIED', { actor: options.actor, result: result.reason || 'RESET' });
    process.stdout.write(`${JSON.stringify({ ...result, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    if (!result.reset) process.exitCode = 3;
    return;
  }
  throw new Error(`Unknown kill-switch action: ${action}`);
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
