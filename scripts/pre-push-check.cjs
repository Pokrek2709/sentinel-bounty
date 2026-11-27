// Pre-push gate (round 99).
//
// The four-red-run saga (rounds 91-92) was fixed by a test change, but
// two procedural lessons had no guard at all:
//
//   1. Round 94's CHANGELOG entry missed the main commit and landed as
//      a follow-up commit (683169c). A code change without its
//      CHANGELOG entry in the SAME commit is now refused by the
//      changelog rule below.
//   2. Rounds 91-98 ran the Windows simulation from a /tmp preload
//      that the VM wipes on every restart. The simulation is now the
//      committed scripts/fake-win32.cjs, and this gate runs it.
//
// Run before pushing: `node scripts/pre-push-check.cjs` (or
// `npm run pre-push`). It fails fast on the first failing step and
// prints what failed; nothing here writes to the repo except the
// suite's own temp fixtures. It is deliberately NOT installed as a
// git hook by this round: a hook the operator cannot see or disable
// would be a silent gate. To wire it as a hook yourself, write
// .git/hooks/pre-push as:
//   #!/bin/sh
//   exec node scripts/pre-push-check.cjs
// and chmod +x it. That is opt-in; the script never installs itself.
// Tests point the git operations at a scratch repo with the
// SENTINEL_PRE_PUSH_REPO_ROOT environment variable (test seam only;
// never set it in normal use).
//
// Flags:
//   --changelog-only   only the changelog rule, no suite/sim/verify
//   --skip-tests       skip `npm test`
//   --skip-win32       skip the Windows simulation
//   --skip-verify      skip `sentinel verify-install`
//   --range <a>..<b>   commit range for the changelog rule
//                      (default HEAD~1..HEAD; an all-zero start,
//                      as GitHub sends for a first push, falls back
//                      to HEAD~1..HEAD)
//   --ci               CI mode: implies --changelog-only, and a git
//                      range that cannot be resolved is fatal
//                      instead of a warning (CI checks out with
//                      fetch-depth: 0, so history is present)
//   --help             print usage
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');

// Structured errors are real Errors (with .code and .detail), not
// plain objects, so callers can assert on the code and still get a
// stack trace.
function fail(code, detail) {
  const error = new Error(detail);
  error.code = code;
  error.detail = detail;
  return error;
}

// Paths that count as "code" for the changelog rule. A commit touching
// any of these must carry a CHANGELOG.md entry in the same commit.
// Docs-only commits are exempt: prose drift is covered by the
// docs-crossref guard (tests/docs-crossref.test.js), not by this rule.
const CODE_PREFIXES = ['src/', 'bin/', 'tests/', 'scripts/', '.github/workflows/'];
const CODE_FILES = ['package.json'];

function touchesCode(files) {
  return files.some((file) => CODE_FILES.includes(file)
    || CODE_PREFIXES.some((prefix) => file.startsWith(prefix)));
}

function commitNeedsChangelog(files) {
  return touchesCode(files) && !files.includes('CHANGELOG.md');
}

function checkCommits(commits) {
  const failures = [];
  for (const commit of commits) {
    if (commitNeedsChangelog(commit.files)) failures.push({ sha: commit.sha, files: commit.files });
  }
  return { failures };
}

function resolveRange(range) {
  if (typeof range !== 'string' || range.trim() === '') return 'HEAD~1..HEAD';
  const start = range.split('..')[0];
  if (/^0+$/.test(start)) return 'HEAD~1..HEAD';
  return range;
}

// Returns [{ sha, files }] for the range, or throws
// { code: 'GIT_RANGE_FAILED', detail } when git cannot resolve it.
// Merge commits list no files (their diff is empty by default) and
// pass: a merge carries no own change to document.
function commitsInRange(range, repoRoot = REPO_ROOT) {
  const resolved = resolveRange(range);
  const result = spawnSync('git', ['log', '--format=COMMIT:%H', '--name-only', resolved], {
    cwd: repoRoot, encoding: 'utf8',
  });
  if (result.error) throw fail('GIT_RANGE_FAILED', result.error.message);
  if (result.status !== 0) throw fail('GIT_RANGE_FAILED', (result.stderr || '').trim());
  const commits = [];
  let current = null;
  for (const line of (result.stdout || '').split('\n')) {
    if (line.startsWith('COMMIT:')) {
      current = { sha: line.slice('COMMIT:'.length), files: [] };
      commits.push(current);
    } else if (line.trim() !== '' && current) {
      current.files.push(line.trim());
    }
  }
  return commits;
}

// Runs the changelog rule. Returns { ok, failures, skipped, reason }.
// In CI mode a git failure is fatal (thrown); locally it warns and
// skips, because a gate that cannot see history must not block a push
// on infrastructure it cannot verify — CI (fetch-depth: 0) is where
// the rule is enforced.
function runChangelogCheck(range, { strict = false, repoRoot = REPO_ROOT } = {}) {
  let commits;
  try {
    commits = commitsInRange(range, repoRoot);
  } catch (error) {
    if (strict) throw error;
    return { ok: true, failures: [], skipped: true, reason: `changelog check skipped: git range ${resolveRange(range)} could not be resolved (${error.detail || error.code})` };
  }
  const { failures } = checkCommits(commits);
  return { ok: failures.length === 0, failures, skipped: false, reason: null };
}

function runStep(label, command, args, env = {}, repoRoot = REPO_ROOT) {
  process.stderr.write(`[pre-push] ${label}: ${command} ${args.join(' ')}\n`);
  const result = spawnSync(command, args, {
    cwd: repoRoot, stdio: 'inherit', env: { ...process.env, ...env },
  });
  if (result.error) return { ok: false, reason: `${label} could not start (${result.error.message})` };
  if (result.status !== 0) return { ok: false, reason: `${label} exited ${result.status}` };
  return { ok: true };
}

function printUsage(out) {
  out.write(
    'Usage: node scripts/pre-push-check.cjs [--changelog-only] [--skip-tests] [--skip-win32] [--skip-verify] [--range <a>..<b>] [--ci] [--help]\n'
    + '  Full gate (default): changelog rule, npm test, Windows simulation, verify-install.\n'
    + '  --ci implies --changelog-only; a git range that cannot be resolved is fatal in --ci.\n',
  );
}

function parseArgs(argv) {
  const opts = { changelogOnly: false, skipTests: false, skipWin32: false, skipVerify: false, range: undefined, ci: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--changelog-only') opts.changelogOnly = true;
    else if (arg === '--skip-tests') opts.skipTests = true;
    else if (arg === '--skip-win32') opts.skipWin32 = true;
    else if (arg === '--skip-verify') opts.skipVerify = true;
    else if (arg === '--ci') opts.ci = true;
    else if (arg === '--help') opts.help = true;
    else if (arg === '--range') {
      i += 1;
      if (i >= argv.length) throw fail('ARG_ERROR', '--range needs a value');
      opts.range = argv[i];
    } else throw fail('ARG_ERROR', `unknown argument: ${arg}`);
  }
  if (opts.ci) opts.changelogOnly = true;
  return opts;
}

function main(argv, { repoRoot = process.env.SENTINEL_PRE_PUSH_REPO_ROOT || REPO_ROOT } = {}) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`pre-push-check: ${error.detail}\n`);
    printUsage(process.stderr);
    return 2;
  }
  if (opts.help) {
    printUsage(process.stdout);
    return 0;
  }

  const range = resolveRange(opts.range);
  let changelog;
  try {
    changelog = runChangelogCheck(range, { strict: opts.ci, repoRoot });
  } catch (error) {
    process.stderr.write(`pre-push-check: changelog check failed: ${error.detail || error.code}\n`);
    return 2;
  }
  if (changelog.skipped) {
    process.stderr.write(`[pre-push] ${changelog.reason}\n`);
  } else if (!changelog.ok) {
    for (const failure of changelog.failures) {
      process.stderr.write(`pre-push-check: commit ${failure.sha} touches code but carries no CHANGELOG.md entry in the same commit (files: ${failure.files.join(', ')})\n`);
    }
    return 1;
  } else {
    process.stderr.write(`[pre-push] changelog rule: ok (${range})\n`);
  }
  if (opts.changelogOnly) return 0;

  if (!opts.skipTests) {
    const step = runStep('suite', 'npm', ['test'], {}, repoRoot);
    if (!step.ok) { process.stderr.write(`pre-push-check: ${step.reason}\n`); return 1; }
  }
  if (!opts.skipWin32) {
    const step = runStep('win32 simulation', process.execPath, ['--test', '--require', './scripts/fake-win32.cjs'], { TEMP: '/tmp', TMP: '/tmp', USERPROFILE: '/tmp' }, repoRoot);
    if (!step.ok) { process.stderr.write(`pre-push-check: ${step.reason}\n`); return 1; }
  }
  if (!opts.skipVerify) {
    const step = runStep('verify-install', process.execPath, ['bin/sentinel.js', 'verify-install'], {}, repoRoot);
    if (!step.ok) { process.stderr.write(`pre-push-check: ${step.reason}\n`); return 1; }
  }
  process.stderr.write('[pre-push] all checks passed\n');
  return 0;
}

module.exports = { touchesCode, commitNeedsChangelog, checkCommits, resolveRange, commitsInRange, runChangelogCheck, main };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
