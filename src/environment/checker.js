const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

const TOOL_COMMANDS = Object.freeze({
  docker: ['docker', ['--version']],
  subfinder: ['subfinder', ['-version']],
  dnsx: ['dnsx', ['-version']],
  httpx: ['httpx', ['-version']],
  katana: ['katana', ['-version']],
});

function status(status, evidence, detail) {
  return { status, evidence, ...(detail ? { detail } : {}) };
}

async function defaultCommandRunner(command, args) {
  const result = await execFileAsync(command, args, {
    timeout: 3_000,
    windowsHide: true,
    maxBuffer: 8 * 1024,
  });
  return `${result.stdout || result.stderr || ''}`.trim();
}

async function checkCommand(name, command, args, commandRunner) {
  try {
    const version = await commandRunner(command, args);
    return status('verified', `${name} executed with a version command.`, {
      command,
      version: version || 'Command completed without version output.',
    });
  } catch (error) {
    const isMissing = error && ['ENOENT', 'NOT_FOUND'].includes(error.code);
    return status(isMissing ? 'unavailable' : 'not_verified', `${name} could not be verified safely.`, {
      command,
      reason: isMissing ? 'Command was not found on PATH.' : error.message,
    });
  }
}

async function checkStorage(probeDirectory, now = new Date()) {
  const probePath = path.join(probeDirectory, '.sentinel-environment-probe.json');
  const marker = { createdAt: now.toISOString(), nonce: crypto.randomUUID() };
  try {
    await fs.mkdir(probeDirectory, { recursive: true });
    let priorMarker;
    try {
      priorMarker = JSON.parse(await fs.readFile(probePath, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await fs.writeFile(probePath, JSON.stringify(marker), { encoding: 'utf8', mode: 0o600 });
    const reread = JSON.parse(await fs.readFile(probePath, 'utf8'));
    if (reread.nonce !== marker.nonce) throw new Error('Read-back marker did not match written marker.');

    return status('verified', 'A local marker was written and read back.', {
      probePath,
      persistence: priorMarker
        ? status('verified', 'A marker from a prior checker invocation was present before this run.', { previousCreatedAt: priorMarker.createdAt })
        : status('not_verified', 'Persistence requires a subsequent checker invocation to verify.'),
    });
  } catch (error) {
    return status('unavailable', 'Local storage probe failed.', { probePath, reason: error.message });
  }
}

function detectMuseEnvironment(environment) {
  const markers = Object.keys(environment).filter((key) => /^MUSE_/i.test(key));
  return markers.length > 0
    ? status('not_verified', 'Muse-like environment variables were detected; this is not proof of a Muse Secure VM.', { markers })
    : status('not_verified', 'No supported Muse runtime attestation is available to this checker.');
}

function disabledFeatures(capabilities) {
  const disabled = ['network_tools'];
  if (capabilities.python.status !== 'verified') disabled.push('python_based_tools');
  if (capabilities.binaryExecution.status !== 'verified') disabled.push('external_tool_wrappers');
  for (const [tool, result] of Object.entries(capabilities.tools)) {
    if (result.status !== 'verified') disabled.push(`tool:${tool}`);
  }
  return disabled;
}

async function runEnvironmentCheck({
  probeDirectory = path.resolve(process.cwd(), 'storage'),
  commandRunner = defaultCommandRunner,
  environment = process.env,
  now = new Date(),
} = {}) {
  const binaryExecution = await checkCommand('Node.js runtime', process.execPath, ['--version'], commandRunner);
  const python = await checkCommand('Python', 'python', ['--version'], commandRunner);
  const tools = Object.fromEntries(await Promise.all(Object.entries(TOOL_COMMANDS).map(async ([name, [command, args]]) => [
    name,
    await checkCommand(name, command, args, commandRunner),
  ])));

  const capabilities = {
    museSecureVm: detectMuseEnvironment(environment),
    runtime: status('verified', 'Node.js is executing this checker.', { version: process.version, platform: process.platform, architecture: process.arch }),
    binaryExecution,
    python,
    filesystem: await checkStorage(probeDirectory, now),
    network: status('not_tested', 'No outbound request is made by this checker; outbound network capability remains unverified.'),
    tools,
    resourceLimits: status('not_verified', 'Host-visible resources are informational and do not establish Secure VM quotas.', {
      availableParallelism: os.availableParallelism(),
      totalMemoryBytes: os.totalmem(),
      freeMemoryBytes: os.freemem(),
    }),
    skillInvocation: status('not_verified', 'Muse skill invocation cannot be verified outside a documented Muse runtime.'),
    processTermination: status('not_verified', 'Controlled cancellation has not been implemented or verified in this phase.'),
  };

  return {
    reportVersion: '1.0.0',
    generatedAt: now.toISOString(),
    safety: {
      networkRequestsMade: 0,
      securityToolsInvoked: [],
      note: 'This is a local capability check only; it is not authorization to test any target.',
    },
    executionContext: { cwd: process.cwd(), node: process.version, platform: process.platform },
    capabilities,
    disabledFeatures: disabledFeatures(capabilities),
    decision: capabilities.museSecureVm.status === 'verified'
      ? 'Muse Secure VM verification complete.'
      : 'Muse Secure VM is not verified. Do not enable scanning or claim Muse integration from this report.',
  };
}

module.exports = { checkCommand, checkStorage, runEnvironmentCheck };
