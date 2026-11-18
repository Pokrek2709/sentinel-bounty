#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry } = require('../src/scope/target-registry');

function usage() {
  return [
    'Usage:',
    '  sentinel check-env [--output <path>] [--probe-dir <path>]',
    '  sentinel check-scope --target <target.json> --url <url>',
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
        throw new Error(`${argument} requires a path.`);
      }
      options[argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
      index += 1;
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  return options;
}

async function main(argv) {
  const [command, ...args] = argv;
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
