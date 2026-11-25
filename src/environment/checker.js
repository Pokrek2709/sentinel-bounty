const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { writeFileRefusingSymlink } = require('../policy/safe-write');
const { PersistentKillSwitch } = require('../policy/persistent-kill-switch');

const execFileAsync = promisify(execFile);

// Mirrors the documented requirement (README.md, package.json engines):
// Node.js 18 or later. verify-install enforces the same floor; check-env
// now enforces it too instead of reporting any executing Node as verified.
const MIN_NODE_VERSION = '18.0.0';
const MIN_NODE_MAJOR = 18;

const DEFAULT_CONFIG_PATH = path.resolve(__dirname, '..', '..', 'config', 'environment-tools.json');
const DEFAULT_SKILL_DIRECTORY = path.resolve(__dirname, '..', '..');

// The documented environment tools (config/environment-tools.json is the
// source of truth for WHICH tools are checked; this map is HOW each one is
// checked, and the fallback list when the config cannot be read). A tool
// listed in the config but missing here is reported not_verified, never
// silently skipped. Install hints are deliberately cautious: these are
// reconnaissance tools, and installing one in the lab needs a separately
// approved dependency and policy review (see docs/check-env-audit-v1.md).
const TOOL_DEFINITIONS = Object.freeze({
  docker: Object.freeze({
    command: 'docker',
    args: ['--version'],
    purpose: 'Container runtime for isolated tool execution.',
    installHint: 'Optional in the local lab. Install Docker Engine/Desktop only under a separately approved dependency and policy review (https://docs.docker.com/get-docker/), then re-run check-env.',
    caveat: 'A detected docker CLI is not evidence that a Docker daemon or container execution is usable.',
  }),
  subfinder: Object.freeze({
    command: 'subfinder',
    args: ['-version'],
    purpose: 'Passive subdomain enumeration (reconnaissance).',
    installHint: 'Optional in the local lab. Install only under a separately approved dependency and policy review: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest — then re-run check-env.',
  }),
  dnsx: Object.freeze({
    command: 'dnsx',
    args: ['-version'],
    purpose: 'DNS toolkit (reconnaissance).',
    installHint: 'Optional in the local lab. Install only under a separately approved dependency and policy review: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest — then re-run check-env.',
  }),
  httpx: Object.freeze({
    command: 'httpx',
    args: ['-version'],
    purpose: 'HTTP probing (reconnaissance).',
    installHint: 'Optional in the local lab. Install only under a separately approved dependency and policy review: go install github.com/projectdiscovery/httpx/cmd/httpx@latest — then re-run check-env.',
  }),
  katana: Object.freeze({
    command: 'katana',
    args: ['-version'],
    purpose: 'Web crawling (reconnaissance).',
    installHint: 'Optional in the local lab. Install only under a separately approved dependency and policy review: go install github.com/projectdiscovery/katana/cmd/katana@latest — then re-run check-env.',
  }),
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

function parseNodeMajor(nodeVersion) {
  const match = /^v(\d+)\./.exec(typeof nodeVersion === 'string' ? nodeVersion : '');
  return match ? Number(match[1]) : null;
}

function checkNodeVersion(nodeVersion) {
  const major = parseNodeMajor(nodeVersion);
  if (major !== null && major >= MIN_NODE_MAJOR) {
    return status('verified', `Node.js ${nodeVersion} meets the documented minimum (${MIN_NODE_VERSION} or later).`, {
      version: nodeVersion,
      minimumVersion: MIN_NODE_VERSION,
    });
  }
  return status('not_verified', 'Node.js is below the documented minimum version.', {
    version: nodeVersion,
    minimumVersion: MIN_NODE_VERSION,
    reason: `Node.js ${MIN_NODE_VERSION} or later is required (found ${nodeVersion}).`,
  });
}

async function loadToolNames(configPath = DEFAULT_CONFIG_PATH) {
  const fallback = Object.keys(TOOL_DEFINITIONS);
  let content;
  try {
    content = await fs.readFile(configPath, 'utf8');
  } catch (error) {
    const reason = error.code === 'ENOENT'
      ? 'Config file config/environment-tools.json was not found.'
      : `Config file config/environment-tools.json could not be read (${error.code || error.message}).`;
    return { names: fallback, source: 'fallback', reason };
  }
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { names: fallback, source: 'fallback', reason: 'Config file config/environment-tools.json is not valid JSON.' };
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.tools)
    || !parsed.tools.every((tool) => typeof tool === 'string' && tool.length > 0)) {
    return { names: fallback, source: 'fallback', reason: 'Config file config/environment-tools.json has an unexpected shape (expected a tools list).' };
  }
  return { names: [...new Set(parsed.tools)], source: 'config' };
}

async function checkTool(name, commandRunner) {
  const definition = TOOL_DEFINITIONS[name];
  if (!definition) {
    return status('not_verified', `${name} could not be verified safely.`, {
      tool: name,
      reason: 'No version command is defined for this tool in the checker.',
    });
  }
  const result = await checkCommand(name, definition.command, definition.args, commandRunner);
  const detail = { ...result.detail, purpose: definition.purpose };
  if (result.status === 'unavailable') {
    detail.installHint = definition.installHint;
  }
  if (definition.caveat) {
    detail.caveat = definition.caveat;
  }
  return { ...result, detail };
}

async function checkFirstAvailableCommand(name, candidates, commandRunner) {
  const attempts = [];
  for (const [command, args] of candidates) {
    const result = await checkCommand(name, command, args, commandRunner);
    attempts.push({
      command,
      status: result.status,
      ...(result.status !== 'verified' && result.detail?.reason ? { reason: result.detail.reason } : {}),
    });
    if (result.status === 'verified') {
      return status('verified', `${name} executed with a version command.`, {
        ...result.detail,
        attempts,
      });
    }
  }
  const indeterminate = attempts.find((attempt) => attempt.status === 'not_verified');
  return status(indeterminate ? 'not_verified' : 'unavailable', `${name} could not be verified from supported command names.`, {
    attempts,
  });
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
    // The marker write refuses a planted symlink at the probe path:
    // the probe directory is operator-chosen, but a predictable marker
    // filename in a shared directory must not let the write be
    // redirected to the link target. The read above still follows a
    // link (read-only); a hostile prior marker only fails validation.
    await writeFileRefusingSymlink(probePath, JSON.stringify(marker), { encoding: 'utf8', mode: 0o600 });
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

// Lightweight, read-only proof that the cancellation machinery works: run a
// PersistentKillSwitch against a fresh temporary state directory (never the
// real state dir, never armed, never triggered) and take a snapshot. The
// snapshot on a fresh directory creates only the probe directory and a
// transient lock file inside it; both are deleted afterwards. End-to-end
// cancellation of a real worker is proven by `sentinel drill`, not here.
async function checkProcessTermination({ skillDirectory = DEFAULT_SKILL_DIRECTORY } = {}) {
  let probeDirectory;
  try {
    probeDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinel-kill-switch-probe-'));
    const controller = new PersistentKillSwitch({
      stateFile: path.join(probeDirectory, 'kill-switch.json'),
      skillDirectory,
    });
    const snapshot = await controller.snapshot();
    if (snapshot.active !== false || snapshot.registeredWorkers !== 0) {
      return status('not_verified', 'The isolated kill-switch probe did not return a clean inactive state.', {
        mechanism: 'persistent-kill-switch',
        active: snapshot.active,
        registeredWorkers: snapshot.registeredWorkers,
      });
    }
    return status('verified', 'Kill-switch state machinery is present and readable in an isolated probe; end-to-end cancellation is proven by `sentinel drill`.', {
      mechanism: 'persistent-kill-switch',
      active: false,
      registeredWorkers: 0,
      endToEndProof: 'sentinel drill',
    });
  } catch (error) {
    return status('not_verified', 'The kill-switch probe could not run.', {
      mechanism: 'persistent-kill-switch',
      reason: error.message,
    });
  } finally {
    if (probeDirectory) await fs.rm(probeDirectory, { recursive: true, force: true });
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
  nodeVersion = process.version,
  configPath = DEFAULT_CONFIG_PATH,
  skillDirectory = DEFAULT_SKILL_DIRECTORY,
} = {}) {
  const binaryExecution = await checkCommand('Node.js runtime', process.execPath, ['--version'], commandRunner);
  // No Python probe (round 46): no component of this skill invokes a
  // Python interpreter — there are no .py files, no spawn of `python`,
  // and README.md lists only Node.js 18+ as a requirement. The earlier
  // probe reported a capability nothing used and listed a
  // `python_based_tools` feature that does not exist. See
  // docs/check-env-audit-v1.md. checkFirstAvailableCommand is retained
  // as a tested utility for future first-available probes.
  const toolList = await loadToolNames(configPath);
  const tools = Object.fromEntries(await Promise.all(toolList.names.map(async (name) => [
    name,
    await checkTool(name, commandRunner),
  ])));
  const nodeVersionCheck = checkNodeVersion(nodeVersion);

  const capabilities = {
    museSecureVm: detectMuseEnvironment(environment),
    runtime: {
      ...nodeVersionCheck,
      detail: {
        ...nodeVersionCheck.detail,
        platform: process.platform,
        architecture: process.arch,
      },
    },
    binaryExecution,
    filesystem: await checkStorage(probeDirectory, now),
    network: status('not_tested', 'No outbound request is made by this checker; outbound network capability remains unverified.'),
    tools,
    toolConfiguration: toolList.source === 'config'
      ? status('verified', 'Tool list loaded from config/environment-tools.json.', {
        source: 'config',
        configPath,
        tools: toolList.names,
      })
      : status('not_verified', 'Tool list fell back to the checker\'s built-in definitions; config/environment-tools.json could not be used.', {
        source: 'fallback',
        configPath,
        reason: toolList.reason,
        tools: toolList.names,
      }),
    resourceLimits: status('not_verified', 'Host-visible resources are informational and do not establish Secure VM quotas.', {
      availableParallelism: os.availableParallelism(),
      totalMemoryBytes: os.totalmem(),
      freeMemoryBytes: os.freemem(),
    }),
    skillInvocation: status('not_verified', 'Muse skill invocation cannot be verified outside a documented Muse runtime.'),
    processTermination: await checkProcessTermination({ skillDirectory }),
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

module.exports = {
  checkCommand,
  checkFirstAvailableCommand,
  checkStorage,
  checkNodeVersion,
  checkTool,
  checkProcessTermination,
  loadToolNames,
  runEnvironmentCheck,
  MIN_NODE_VERSION,
  TOOL_DEFINITIONS,
};
