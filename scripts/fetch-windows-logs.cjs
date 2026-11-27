// Windows CI log archiver (round 99).
//
// Rounds 91-92 archived the four red-run logs by hand: the operator
// downloaded each zip from GitHub Actions and unzipped it into
// ~/workspace/sentinel-bounty/windows-ci-logs/ as
// logs_<check_suite_id>-<shortsha>/. This script does the same steps
// for one run, so the archive procedure is a command, not a memory:
//
//   node scripts/fetch-windows-logs.cjs --run-id 46052614644 \
//     --out-dir ~/workspace/sentinel-bounty/windows-ci-logs
//
// It resolves the run (head SHA, check_suite_id, conclusion) from the
// GitHub API, downloads the logs zip (the API answers 302 to a signed
// URL), and extracts it into logs_<check_suite_id>-<shortsha>/ under
// --out-dir (default ./windows-ci-logs). An existing folder is refused
// unless --force is given. Rate limits are reported, not retried:
// unauthenticated calls get 60/hour per egress IP (rounds 88 and 92
// both hit it); set GITHUB_TOKEN (or --token-env <name>) for the
// 5,000/hour authenticated quota. The script never pushes, never
// commits, and never touches the repo — it only writes the archive
// folder. Extraction shells out to `unzip`, which must be installed.
//
// Flags:
//   --run-id <n>       workflow run id (required)
//   --out-dir <path>   archive root (default ./windows-ci-logs)
//   --repo <owner/repo> (default Pokrek2709/sentinel-bounty)
//   --api-base <url>   (default https://api.github.com; tests point
//                      this at a local stub server)
//   --token-env <name> env var holding a GitHub token (default
//                      GITHUB_TOKEN; unset means unauthenticated)
//   --force            overwrite an existing archive folder
//   --help             print usage
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

const DEFAULT_API_BASE = 'https://api.github.com';
const DEFAULT_REPO = 'Pokrek2709/sentinel-bounty';

// Structured errors are real Errors (with .code and .detail), not
// plain objects, so callers can assert on the code and still get a
// stack trace.
function fail(code, detail) {
  const error = new Error(detail);
  error.code = code;
  error.detail = detail;
  return error;
}

function buildRunUrl(apiBase, repo, runId) {
  return `${apiBase.replace(/\/+$/, '')}/repos/${repo}/actions/runs/${runId}`;
}

function buildLogsUrl(apiBase, repo, runId) {
  return `${buildRunUrl(apiBase, repo, runId)}/logs`;
}

function archiveFolderName(checkSuiteId, headSha) {
  return `logs_${checkSuiteId}-${String(headSha).slice(0, 7)}`;
}

// Classifies a GitHub API failure from its status and headers. A 403
// with a zero remaining quota is the rate limit (rounds 88/92); a 404
// is an unknown run id; anything else is reported by status.
function classifyApiError(status, headers) {
  const remaining = headers.get('x-ratelimit-remaining');
  const reset = headers.get('x-ratelimit-reset');
  if (status === 403 && remaining === '0') {
    const resetAt = reset ? new Date(Number(reset) * 1000).toISOString() : 'unknown';
    return fail('RATE_LIMITED', `GitHub API rate limit exceeded (reset ${resetAt}); retry later or set GITHUB_TOKEN for the authenticated quota`);
  }
  if (status === 404) return fail('RUN_NOT_FOUND', 'no workflow run with that id (or it is not visible to this token)');
  return fail(`HTTP_${status}`, `GitHub API answered HTTP ${status}`);
}

async function apiGetJson(url, token) {
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) headers.Authorization = `Bearer ${token}`;
  let response;
  try {
    response = await fetch(url, { headers });
  } catch (error) {
    throw fail('NETWORK_ERROR', `could not reach ${url}: ${error.message}`);
  }
  if (!response.ok) throw classifyApiError(response.status, response.headers);
  return response.json();
}

async function downloadLogsZip(url, token) {
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) headers.Authorization = `Bearer ${token}`;
  let response;
  try {
    // fetch follows the 302 to the signed zip URL by default.
    response = await fetch(url, { headers, redirect: 'follow' });
  } catch (error) {
    throw fail('NETWORK_ERROR', `could not reach ${url}: ${error.message}`);
  }
  if (!response.ok) throw classifyApiError(response.status, response.headers);
  return Buffer.from(await response.arrayBuffer());
}

async function assertUnzipAvailable() {
  try {
    await execFileAsync('unzip', ['-v'], { timeout: 10_000 });
  } catch (error) {
    if (error.code === 'ENOENT') throw fail('UNZIP_MISSING', 'the `unzip` command is not installed; install it to extract CI logs');
    throw fail('UNZIP_FAILED', `could not run \`unzip\`: ${error.message}`);
  }
}

// Downloads one run's logs and extracts them. Returns the archive
// record. Throws a structured Error (.code, .detail) on every
// failure mode above; nothing is partially archived.
async function downloadAndExtract({ runId, outDir, apiBase = DEFAULT_API_BASE, repo = DEFAULT_REPO, token = null, force = false } = {}) {
  if (!runId) throw fail('ARG_ERROR', '--run-id is required');
  await assertUnzipAvailable();
  const meta = await apiGetJson(buildRunUrl(apiBase, repo, runId), token);
  const folder = archiveFolderName(meta.check_suite_id, meta.head_sha);
  const dest = path.join(outDir, folder);
  if (!force && fs.existsSync(dest)) {
    throw fail('ARCHIVE_EXISTS', `archive folder ${dest} already exists (re-run with --force to overwrite)`);
  }
  const zip = await downloadLogsZip(buildLogsUrl(apiBase, repo, runId), token);
  await fs.promises.mkdir(outDir, { recursive: true });
  const tmpZip = path.join(outDir, `.fetch-logs-${runId}-${process.pid}.zip`);
  try {
    await fs.promises.writeFile(tmpZip, zip, { mode: 0o600 });
    await execFileAsync('unzip', ['-o', '-q', tmpZip, '-d', dest], { timeout: 60_000 });
  } finally {
    await fs.promises.unlink(tmpZip).catch(() => {});
  }
  return {
    folder,
    dest,
    runId: String(runId),
    checkSuiteId: meta.check_suite_id,
    headSha: meta.head_sha,
    status: meta.status,
    conclusion: meta.conclusion,
  };
}

function printUsage(out) {
  out.write(
    'Usage: node scripts/fetch-windows-logs.cjs --run-id <n> [--out-dir <path>] [--repo <owner/repo>] [--api-base <url>] [--token-env <name>] [--force] [--help]\n'
    + '  Downloads one Windows CI run\'s logs and extracts them into logs_<check_suite_id>-<shortsha>/ under --out-dir (default ./windows-ci-logs).\n',
  );
}

function parseArgs(argv) {
  const opts = { runId: undefined, outDir: './windows-ci-logs', repo: DEFAULT_REPO, apiBase: DEFAULT_API_BASE, tokenEnv: 'GITHUB_TOKEN', force: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--force') opts.force = true;
    else if (arg === '--help') opts.help = true;
    else if (arg === '--run-id' || arg === '--out-dir' || arg === '--repo' || arg === '--api-base' || arg === '--token-env') {
      i += 1;
      if (i >= argv.length) throw fail('ARG_ERROR', `${arg} needs a value`);
      const key = { '--run-id': 'runId', '--out-dir': 'outDir', '--repo': 'repo', '--api-base': 'apiBase', '--token-env': 'tokenEnv' }[arg];
      opts[key] = argv[i];
    } else throw fail('ARG_ERROR', `unknown argument: ${arg}`);
  }
  return opts;
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`fetch-windows-logs: ${error.detail}\n`);
    printUsage(process.stderr);
    return 2;
  }
  if (opts.help) {
    printUsage(process.stdout);
    return 0;
  }
  if (!opts.runId) {
    process.stderr.write('fetch-windows-logs: --run-id is required\n');
    printUsage(process.stderr);
    return 2;
  }
  const token = process.env[opts.tokenEnv] || null;
  try {
    const record = await downloadAndExtract({
      runId: opts.runId,
      outDir: path.resolve(opts.outDir),
      apiBase: opts.apiBase,
      repo: opts.repo,
      token,
      force: opts.force,
    });
    process.stdout.write(
      `archived run ${record.runId} (head ${String(record.headSha).slice(0, 7)}, conclusion ${record.conclusion || record.status}) to ${record.dest}\n`,
    );
    return 0;
  } catch (error) {
    process.stderr.write(`fetch-windows-logs: ${error.detail || error.code}\n`);
    return 1;
  }
}

module.exports = { buildRunUrl, buildLogsUrl, archiveFolderName, classifyApiError, apiGetJson, downloadLogsZip, downloadAndExtract, DEFAULT_API_BASE, DEFAULT_REPO };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
