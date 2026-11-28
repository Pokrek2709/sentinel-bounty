#!/usr/bin/env node

const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { runEnvironmentCheck } = require('../src/environment/checker');
const { TargetRegistry, renderScopeExplanationText } = require('../src/scope/target-registry');
const { PersistentKillSwitch } = require('../src/policy/persistent-kill-switch');
const { classifyRotationLockError, classifyTokenFileError, hasNonDirectoryAncestor, classifyEnoentPathError } = require('../src/policy/storage-errors');
const { AuditLog } = require('../src/audit/audit-log');
const { renderAuditExport, AUDIT_EXPORT_FORMATS } = require('../src/audit/audit-export');
const { retentionPathFor, readRetentionPolicy, writeRetentionPolicy } = require('../src/audit/audit-retention');
const { generateReport } = require('../src/report/generator');
const {
  diffReports,
  renderReportDiffMarkdown,
  renderReportDiffJson,
  readReportFile,
} = require('../src/report/report-diff');
const {
  readReportFileForValidation,
  validateReport,
  renderReportValidationText,
  renderReportValidationJson,
} = require('../src/report/validate');
const { mergeReports } = require('../src/report/merge');
const { anonymizeReport } = require('../src/report/anonymize');
const { splitReport } = require('../src/report/split');
const { filterReport } = require('../src/report/filter');
const { computeReportStats, renderReportStatsText, renderReportStatsJson } = require('../src/report/stats');
const { renderReport } = require('../src/report/render');
const { runVerifyInstall, checkStatePermissions } = require('../src/install/verifier');
const { repairStatePermissions } = require('../src/policy/state-permissions');
const { writeFileRefusingSymlink } = require('../src/policy/safe-write');
const { backupState, restoreState, INTEGRITY_REASONS } = require('../src/policy/state-backup');
const { collectStateExport, renderStateExport } = require('../src/policy/state-export');
const { collectOperatorStatus, renderOperatorStatusText, OperatorStatusError } = require('../src/policy/operator-status');
const { readJsonFileBounded, MAX_FINDINGS } = require('../src/policy/input-limits');
const { runDrill } = require('../src/policy/incident-drill');
const { closeAndRemoveLock } = require('../src/policy/lock-file');
const { getDetector, runDetector } = require('../src/detection/detector');
const { POLICY_VERSION, enforceReportPolicies, getPolicySummary } = require('../src/analysis/policies');
const { storePathFor, addScopeTarget, removeScopeTarget, findScopeTarget, listScopeTargets } = require('../src/scope/target-store');
const {
  storePathFor: publicTargetStorePathFor,
  addPublicTarget,
  removePublicTarget,
  listPublicTargets,
} = require('../src/scope/public-target-store');
const {
  previewPublicFetch,
  mintPublicFetchApprovalFor,
  runPublicFetch,
  renderPreviewText,
} = require('../src/http/public-fetch');
const {
  storePathFor: sessionStorePathFor,
  startOperatorSession,
  heartbeatOperatorSession,
  revokeOperatorSession,
  rotateOperatorSession,
  listOperatorSessions,
  getOperatorSession,
} = require('../src/policy/operator-sessions');

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
    '  sentinel scope list [--state-dir <path>] [--store <file>] [--url <url>] [--json]',
    '  sentinel target add <host> --scope <path> --purpose <purpose> --auth-ref <reference> [--program <name>] [--state-dir <path>]',
    '  sentinel target list [--state-dir <path>] [--json]',
    '  sentinel target remove <host> [--state-dir <path>]',
    '  sentinel fetch --url <url> [--state-dir <path>] [--timeout-ms <n>] [--max-body-bytes <n>] [--mint-approval] [--approve-token <token>] [--session-token <token>]',
    '  sentinel session start [--label <label>] [--ttl-seconds <n>] [--lease-seconds <n>] [--state-dir <path>]',
    '  sentinel session heartbeat --token <token> [--state-dir <path>]',
    '  sentinel session list [--state-dir <path>] [--json]',
    '  sentinel session status <session-id> [--state-dir <path>] [--json]',
    '  sentinel session revoke <session-id> [--state-dir <path>]',
    '  sentinel session rotate <session-id> [--state-dir <path>]',
    '  sentinel kill-switch status [--state-dir <path>]',
    '  sentinel kill-switch trigger --actor <id> --reason <reason> [--state-dir <path>]',
    '  sentinel kill-switch reset --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch audit-health [--state-dir <path>]',
    '  sentinel kill-switch rotate-token --actor <id> [--state-dir <path>]',
    '  sentinel kill-switch revoke-token --actor <id> [--state-dir <path>]',
    '  sentinel audit verify [--state-dir <path>]',
    '  sentinel audit export [--state-dir <path>] [--out <file>] [--format json|jsonl]',
    '  sentinel audit retention [--state-dir <path>] [--max-archives <n>] [--max-records <n>] [--show]',
    '  sentinel status [--state-dir <path>] [--skill-dir <path>] [--json]',
    '  sentinel policy [--json]',
    '  sentinel backup --out <file> [--state-dir <path>]',
    '  sentinel restore --from <file> [--state-dir <path>]',
    '  sentinel state export [--state-dir <path>] [--out <file>]',
    '  sentinel drill [--state-dir <path>] [--recover]',
    '  sentinel report --finding <finding.json> [--out <report.md>] [--format markdown|json|html|csv|summary|jsonl] [--template generic|immunefi|code4rena|hackerone|bugcrowd] [--generated-at <iso>] [--program <name>] [--allow-mixed-targets] [--verifier stub|<path>]',
    '  sentinel report --findings <findings-array.json> [--out <report.md>] [--format markdown|json|html|csv|summary|jsonl] [--generated-at <iso>] [--program <name>] [--allow-mixed-targets] [--verifier stub|<path>] [--include-false-positives]',
    '  sentinel report validate <report.json> [--json]',
    '  sentinel report merge <a-report.json> <b-report.json> [--out <merged.json>]',
    '  sentinel report anonymize <report.json> [--out <anon.json>] [--salt <hex>]',
    '  sentinel report split <report.json> --by severity|verdict --out-dir <dir> [--force]',
    '  sentinel report filter <report.json> [--severity <level>] [--verdict <rule-verdict>] [--out <filtered.json>]',
    '  sentinel report stats <report.json> [--json]',
    '  sentinel report render <report.json> --format markdown|json|html|csv|summary|jsonl [--out <file>]',
    '  sentinel report-diff <old-report.json> <new-report.json> [--format markdown|json] [--out <diff.md>]',
    '  sentinel detect [--detector stub|secret-scan|dangerous-call|insecure-crypto|hardcoded-credential|insecure-transport|tainted-deserialize|tainted-command-execution|tainted-sql|tainted-xss|tainted-ssti|tainted-path-traversal|tainted-ssrf|tainted-ldap|tainted-xpath|tainted-open-redirect|solidity-reentrancy|solidity-access-control|solidity-unprotected-initializer|solidity-rounding|solidity-tx-origin|solidity-weak-randomness|<path>] --input <record.json> [--session-id <id>] [--target-id <id>] [--asset-id <id>] [--out <findings.json>]',
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

// Refuse a candidate path inside the skill directory or the state
// directory (round 70, `report split --out-dir`): the same
// path.relative inside-check as pathOutsideSkill above, applied
// to both roots (the skill dir, where a stray write could
// corrupt the installed skill, and the state dir, where it could
// corrupt kill-switch/audit state). Returns the resolved path
// when it is outside both, else null. Like pathOutsideSkill
// this is a lexical check on the resolved path: a symlinked
// parent directory is the operator's own path (the safe-write
// philosophy — see src/policy/safe-write.js), so it is not
// chased here.
function pathOutsideSkillAndState(candidate) {
  const roots = [path.resolve(__dirname, '..'), path.resolve(DEFAULT_STATE_DIRECTORY)];
  const resolved = path.resolve(candidate);
  for (const root of roots) {
    const relative = path.relative(root, resolved);
    if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) return null;
  }
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
    // Windows reports a path through a file as ENOENT, not ENOTDIR, so
    // an unclassified ENOENT here is ambiguous: genuinely missing, or
    // a parent that is a file. Only the latter is a path failure
    // (RESET_TOKEN_FILE_PATH_INVALID); a genuinely missing digest stays
    // "no usable token" (fail-closed, unauthorized).
    if (error.code === 'ENOENT' && await hasNonDirectoryAncestor(hashFile)) {
      throw new Error('RESET_TOKEN_FILE_PATH_INVALID');
    }
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
// Scope list (Phase 3, round 54). Read-only: it changes nothing, so it
// needs no kill-switch guard and works while the switch is armed.
// Renders the list as text, or as deterministic JSON with --json.
function renderScopeListText(result) {
  if (result.count === 0) return `No scope targets in ${result.store}.`;
  const lines = [`Scope targets in ${result.store} (${result.count}):`];
  for (const entry of result.targets) {
    if (!entry.valid) {
      lines.push(`  ${entry.targetId || '(no target_id)'} | INVALID: ${entry.error}`);
      continue;
    }
    const decision = entry.decision ? entry.decision.reason : '—';
    const defaults = entry.defaultExcludedPathsOverridden ? ' | defaults: overridden' : '';
    lines.push(`  ${entry.targetId} | valid | decision: ${decision} | allowed_domains: ${entry.allowedDomains.join(', ')} | excluded_paths: ${entry.excludedPaths.join(', ')}${defaults}`);
  }
  return lines.join('\n');
}

async function runScopeCommand(args) {
  const [action, value, ...optionArgs] = args;
  if (action === 'list') {
    // `scope list` takes no positional value: every argument after the
    // action is an option, so parse from args.slice(1) — not from
    // optionArgs, which would swallow the first option as the value.
    const listArgs = args.slice(1);
    const json = listArgs.includes('--json');
    const options = parseOptions(listArgs.filter((argument) => argument !== '--json'), ['--state-dir', '--store', '--url']);
    if (options.stateDir && options.store) throw new Error('scope list: --state-dir and --store are mutually exclusive.');
    const storePath = options.store
      ? path.resolve(options.store)
      : storePathFor(path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY));
    const result = await listScopeTargets(storePath, { url: options.url });
    if (json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return;
    }
    process.stdout.write(`${renderScopeListText(result)}\n`);
    return;
  }
  if (action !== 'add' && action !== 'remove') {
    throw new Error('scope requires an action: add, remove, or list.');
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

// Public-target management (Phase 4, round 93). The persistent
// store is `<state-dir>/public-targets.json` — one host, one
// path-prefix scope, one purpose, one authorization reference per
// entry. Like scope changes, add/remove are operator config writes,
// so they are refused while the kill-switch is ARMED; a successful
// mutation writes an audit record (PUBLIC_TARGET_ADDED /
// PUBLIC_TARGET_REMOVED); a mutation whose audit append fails
// reports `auditLogged: false` and exits 4. A duplicate add with
// identical fields is an idempotent no-op (exit 0, no rewrite, no
// audit record); a duplicate with different fields is refused by
// the store (PUBLIC_TARGET_ALREADY_REGISTERED — remove first, then
// re-add). `target list` is read-only: it changes nothing, so it
// needs no kill-switch guard and works while the switch is armed.
// The authorization reference is never printed by list (neither
// text nor JSON): the fetch command reads it from the store
// directly.
function renderPublicTargetListText(result) {
  if (result.count === 0) return `No public targets in ${result.store}.`;
  const lines = [`Public targets in ${result.store} (${result.count}):`];
  for (const entry of result.targets) {
    lines.push(`  ${entry.targetId} | scope: ${entry.scope} | purpose: ${entry.purpose} | program: ${entry.programName} | budget: ${entry.requestBudget}`);
  }
  return lines.join('\n');
}

async function runTargetCommand(args) {
  const [action, value, ...optionArgs] = args;
  if (action === 'list') {
    const listArgs = args.slice(1);
    const json = listArgs.includes('--json');
    const options = parseOptions(listArgs.filter((argument) => argument !== '--json'), ['--state-dir']);
    const storePath = publicTargetStorePathFor(path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY));
    const result = await listPublicTargets(storePath);
    if (json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return;
    }
    process.stdout.write(`${renderPublicTargetListText(result)}\n`);
    return;
  }
  if (action !== 'add' && action !== 'remove') {
    throw new Error('target requires an action: add, remove, or list.');
  }
  if (!value || value.startsWith('--')) {
    throw new Error(action === 'add' ? 'target add requires a <host>.' : 'target remove requires a <host>.');
  }
  const options = parseOptions(optionArgs, action === 'add' ? ['--scope', '--purpose', '--auth-ref', '--program', '--state-dir'] : ['--state-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const storePath = publicTargetStorePathFor(stateDirectory);
  const { killSwitch } = await killSwitchFor({ stateDir: stateDirectory });
  const guard = await killSwitch.assertNotTriggered();
  if (!guard.allowed) {
    process.stdout.write(`${JSON.stringify({ [action === 'add' ? 'added' : 'removed']: false, reason: 'PUBLIC_TARGET_CHANGE_REFUSED_KILL_SWITCH_ACTIVE', trigger: guard.trigger || null }, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  if (action === 'add') {
    if (!options.scope || !options.purpose || !options.authRef) {
      throw new Error('target add requires --scope, --purpose, and --auth-ref.');
    }
    const result = await addPublicTarget(storePath, {
      host: value,
      scope: options.scope,
      purpose: options.purpose,
      authorization_reference: options.authRef,
      ...(options.program ? { program_name: options.program } : {}),
    });
    if (!result.added) {
      // Idempotent no-op: nothing was written and nothing was logged.
      process.stdout.write(`${JSON.stringify({ ...result, store: storePath }, null, 2)}\n`);
      return;
    }
    const auditLogged = await appendOperatorAudit(stateDirectory, 'PUBLIC_TARGET_ADDED', { targetId: result.targetId, host: value, scope: options.scope, store: storePath });
    process.stdout.write(`${JSON.stringify({ ...result, store: storePath, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
    return;
  }
  const result = await removePublicTarget(storePath, value);
  const auditLogged = await appendOperatorAudit(stateDirectory, 'PUBLIC_TARGET_REMOVED', { targetId: result.targetId, store: storePath });
  process.stdout.write(`${JSON.stringify({ ...result, store: storePath, auditLogged }, null, 2)}\n`);
  if (!auditLogged) process.exitCode = 4;
}

// Public fetch (Phase 4, round 93): the ONLY command that invokes
// the public HTTP adapter. The preview is printed to stderr so
// stdout stays clean JSON. The flow, in order:
//   --mint-approval: resolve the context, print the preview, mint
//     a one-time token (5-minute TTL, bound to this exact URL /
//     target / scope fingerprint) and print it ONCE on stdout.
//     Nothing is executed.
//   --approve-token <token>: consume the token (single-use — a fetch
//     that then fails still burns it), then run the adapter.
//   default (no token): the operator must be at a terminal — a
//     piped stdin cannot type YA — then the prompt asks for an
//     explicit YA; anything else denies and nothing is executed.
// There is deliberately no --yes flag. Exit 0 when fetched, 1 on a
// gate refusal or usage error, 4 when an audit append failed
// (auditLogged: false). The response body goes to stdout only,
// never to the audit log.
async function runFetchCommand(args) {
  const mintApproval = args.includes('--mint-approval');
  const options = parseOptions(args.filter((argument) => argument !== '--mint-approval'), ['--url', '--state-dir', '--timeout-ms', '--max-body-bytes', '--approve-token', '--session-token']);
  if (!options.url) throw new Error('fetch requires --url.');
  if (mintApproval && options.approveToken) throw new Error('fetch: --mint-approval and --approve-token are mutually exclusive.');
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const timeoutMs = options.timeoutMs === undefined ? undefined : Number(options.timeoutMs);
  const maxBodyBytes = options.maxBodyBytes === undefined ? undefined : Number(options.maxBodyBytes);
  if (mintApproval) {
    const minted = await mintPublicFetchApprovalFor({ stateDir: stateDirectory, url: options.url, timeoutMs, maxBodyBytes, sessionToken: options.sessionToken });
    if (!minted.minted) {
      process.stdout.write(`${JSON.stringify({ minted: false, reason: minted.reason, targetId: minted.targetId || null, auditLogged: minted.auditLogged }, null, 2)}\n`);
      process.exitCode = minted.auditLogged === false ? 4 : 1;
      return;
    }
    process.stderr.write(`${renderPreviewText(minted.preview)}\n`);
    process.stdout.write(`${JSON.stringify({ minted: true, token: minted.token, expiresAt: new Date(minted.expiresAt).toISOString(), targetId: minted.preview.targetId, url: minted.preview.url, auditLogged: minted.auditLogged }, null, 2)}\n`);
    if (minted.auditLogged === false) process.exitCode = 4;
    return;
  }
  const previewed = await previewPublicFetch({ stateDir: stateDirectory, url: options.url, timeoutMs, maxBodyBytes });
  if (!previewed.allowed) {
    process.stdout.write(`${JSON.stringify({ fetched: false, reason: previewed.reason, targetId: previewed.targetId || null }, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  process.stderr.write(`${renderPreviewText(previewed.preview)}\n`);
  let approval;
  if (options.approveToken) {
    approval = { kind: 'token', token: options.approveToken };
  } else {
    if (!process.stdin.isTTY) {
      process.stdout.write(`${JSON.stringify({ fetched: false, reason: 'PUBLIC_HTTP_APPROVAL_REQUIRES_TTY', targetId: previewed.preview.targetId }, null, 2)}\n`);
      process.exitCode = 1;
      return;
    }
    approval = {
      kind: 'interactive',
      confirm: async () => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const answer = await new Promise((resolve) => {
          rl.question('Type YA to approve this fetch (anything else cancels): ', (line) => {
            rl.close();
            resolve(line);
          });
        });
        return answer.trim().toLowerCase() === 'ya';
      },
    };
  }
  const fetched = await runPublicFetch({ stateDir: stateDirectory, url: options.url, approval, timeoutMs, maxBodyBytes, sessionToken: options.sessionToken });
  process.stdout.write(`${JSON.stringify(fetched, null, 2)}\n`);
  if (!fetched.fetched) process.exitCode = fetched.auditLogged === false ? 4 : 1;
}

// Local operator sessions (Phase 1, round 98). The session token
// is a bearer credential for the local lab: `session start` and
// `session rotate` print it ONCE on stdout (JSON) and never again;
// `list` and `status` never print it. Start and rotate create or
// refresh access, so they are refused while the kill switch is
// armed (same guard pattern as target add/remove); revoke removes
// access and stays available while armed; heartbeat, list, and
// status are liveness and inspection and work while armed. A
// successful mutation writes an audit record
// (OPERATOR_SESSION_STARTED / HEARTBEAT / REVOKED / ROTATED); a
// mutation whose audit append fails reports `auditLogged: false`
// and exits 4. A duplicate revoke is an idempotent no-op (exit 0,
// no rewrite, no audit record). Module refusals print as JSON
// `{ <verb>: false, reason }` with exit 1, never as a bare stderr
// line, so operators can grep the reason code.
function renderOperatorSessionListText(result) {
  if (result.count === 0) return `No operator sessions in ${result.store}.`;
  const lines = [`Operator sessions in ${result.store} (${result.count}):`];
  for (const session of result.sessions) {
    lines.push(`  ${session.sessionId} | ${session.label || '(no label)'} | ${session.status} | expires ${new Date(session.expiresAt).toISOString()} | lease ${session.leaseSeconds}s | heartbeats ${session.heartbeatCount} | rotations ${session.rotationCount}`);
  }
  return lines.join('\n');
}

function renderOperatorSessionStatusText(session) {
  return [
    `Operator session ${session.sessionId}:`,
    `  Label: ${session.label || '(no label)'}`,
    `  Status: ${session.status}`,
    `  Created: ${new Date(session.createdAt).toISOString()}`,
    `  Expires: ${new Date(session.expiresAt).toISOString()} (TTL remaining ${Math.floor(session.ttlRemainingMs / 1_000)}s)`,
    `  Lease: ${session.leaseSeconds}s (remaining ${Math.floor(session.leaseRemainingMs / 1_000)}s)`,
    `  Heartbeats: ${session.heartbeatCount}`,
    `  Rotations: ${session.rotationCount}`,
  ].join('\n');
}

function sessionRefusalReason(error) {
  return typeof error.code === 'string' && error.code.startsWith('OPERATOR_SESSION_') ? error.code : null;
}

async function runSessionCommand(args) {
  const [action, ...rest] = args;
  if (action === 'list') {
    const json = rest.includes('--json');
    const options = parseOptions(rest.filter((argument) => argument !== '--json'), ['--state-dir']);
    const storePath = sessionStorePathFor(path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY));
    const result = await listOperatorSessions({ storePath });
    if (json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return;
    }
    process.stdout.write(`${renderOperatorSessionListText(result)}\n`);
    return;
  }
  if (action === 'status') {
    const [value, ...optionArgs] = rest;
    if (!value || value.startsWith('--')) throw new Error('session status requires a <session-id>.');
    const json = optionArgs.includes('--json');
    const options = parseOptions(optionArgs.filter((argument) => argument !== '--json'), ['--state-dir']);
    const storePath = sessionStorePathFor(path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY));
    try {
      const session = await getOperatorSession({ storePath, sessionId: value });
      if (json) {
        process.stdout.write(`${JSON.stringify(session, null, 2)}\n`);
        return;
      }
      process.stdout.write(`${renderOperatorSessionStatusText(session)}\n`);
    } catch (error) {
      const reason = sessionRefusalReason(error);
      if (!reason) throw error;
      process.stdout.write(`${JSON.stringify({ status: false, reason, sessionId: value }, null, 2)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (action === 'heartbeat') {
    const options = parseOptions(rest, ['--token', '--state-dir']);
    if (!options.token) throw new Error('session heartbeat requires --token.');
    const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
    const storePath = sessionStorePathFor(stateDirectory);
    try {
      const beat = await heartbeatOperatorSession({ storePath, token: options.token });
      const auditLogged = await appendOperatorAudit(stateDirectory, 'OPERATOR_SESSION_HEARTBEAT', { sessionId: beat.sessionId, heartbeatCount: beat.heartbeatCount });
      process.stdout.write(`${JSON.stringify({ heartbeat: true, sessionId: beat.sessionId, expiresAt: new Date(beat.expiresAt).toISOString(), leaseExpiresAt: new Date(beat.leaseExpiresAt).toISOString(), heartbeatCount: beat.heartbeatCount, auditLogged }, null, 2)}\n`);
      if (!auditLogged) process.exitCode = 4;
    } catch (error) {
      const reason = sessionRefusalReason(error);
      if (!reason) throw error;
      process.stdout.write(`${JSON.stringify({ heartbeat: false, reason }, null, 2)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (action === 'revoke') {
    const [value, ...optionArgs] = rest;
    if (!value || value.startsWith('--')) throw new Error('session revoke requires a <session-id>.');
    const options = parseOptions(optionArgs, ['--state-dir']);
    const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
    const storePath = sessionStorePathFor(stateDirectory);
    try {
      const result = await revokeOperatorSession({ storePath, sessionId: value });
      if (!result.revoked) {
        // Idempotent no-op: nothing was written and nothing was logged.
        process.stdout.write(`${JSON.stringify({ ...result, store: storePath }, null, 2)}\n`);
        return;
      }
      const auditLogged = await appendOperatorAudit(stateDirectory, 'OPERATOR_SESSION_REVOKED', { sessionId: result.sessionId });
      process.stdout.write(`${JSON.stringify({ ...result, store: storePath, auditLogged }, null, 2)}\n`);
      if (!auditLogged) process.exitCode = 4;
    } catch (error) {
      const reason = sessionRefusalReason(error);
      if (!reason) throw error;
      process.stdout.write(`${JSON.stringify({ revoked: false, reason, sessionId: value }, null, 2)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (action !== 'start' && action !== 'rotate') {
    throw new Error('session requires an action: start, heartbeat, list, status, revoke, or rotate.');
  }
  const options = action === 'start'
    ? parseOptions(rest, ['--label', '--ttl-seconds', '--lease-seconds', '--state-dir'])
    : parseOptions(rest.slice(1), ['--state-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const { killSwitch } = await killSwitchFor({ stateDir: stateDirectory });
  const guard = await killSwitch.assertNotTriggered();
  if (!guard.allowed) {
    const key = action === 'start' ? 'started' : 'rotated';
    process.stdout.write(`${JSON.stringify({ [key]: false, reason: 'OPERATOR_SESSION_REFUSED_KILL_SWITCH_ACTIVE', trigger: guard.trigger || null }, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  if (action === 'start') {
    const storePath = sessionStorePathFor(stateDirectory);
    try {
      const started = await startOperatorSession({
        storePath,
        ...(options.label !== undefined ? { label: options.label } : {}),
        ...(options.ttlSeconds !== undefined ? { ttlMs: Number(options.ttlSeconds) * 1_000 } : {}),
        ...(options.leaseSeconds !== undefined ? { leaseMs: Number(options.leaseSeconds) * 1_000 } : {}),
      });
      const auditLogged = await appendOperatorAudit(stateDirectory, 'OPERATOR_SESSION_STARTED', { sessionId: started.sessionId, label: options.label || '', expiresAt: new Date(started.expiresAt).toISOString() });
      process.stdout.write(`${JSON.stringify({ started: true, sessionId: started.sessionId, token: started.token, expiresAt: new Date(started.expiresAt).toISOString(), leaseSeconds: started.leaseSeconds, auditLogged }, null, 2)}\n`);
      if (!auditLogged) process.exitCode = 4;
    } catch (error) {
      const reason = sessionRefusalReason(error);
      if (!reason) throw error;
      process.stdout.write(`${JSON.stringify({ started: false, reason }, null, 2)}\n`);
      process.exitCode = 1;
    }
    return;
  }
  const [value] = rest;
  if (!value || value.startsWith('--')) throw new Error('session rotate requires a <session-id>.');
  const storePath = sessionStorePathFor(stateDirectory);
  try {
    const rotated = await rotateOperatorSession({ storePath, sessionId: value });
    const auditLogged = await appendOperatorAudit(stateDirectory, 'OPERATOR_SESSION_ROTATED', { sessionId: rotated.sessionId, rotationCount: rotated.rotationCount });
    process.stdout.write(`${JSON.stringify({ rotated: true, sessionId: rotated.sessionId, token: rotated.token, expiresAt: new Date(rotated.expiresAt).toISOString(), rotationCount: rotated.rotationCount, auditLogged }, null, 2)}\n`);
    if (!auditLogged) process.exitCode = 4;
  } catch (error) {
    const reason = sessionRefusalReason(error);
    if (!reason) throw error;
    process.stdout.write(`${JSON.stringify({ rotated: false, reason, sessionId: value }, null, 2)}\n`);
    process.exitCode = 1;
  }
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
      // No state file yet: fall through with the base reserve — unless
      // a parent is a file (Windows reports that as ENOENT, not
      // ENOTDIR), which is a path failure, not a missing file.
      if (await hasNonDirectoryAncestor(path.join(stateDirectory, 'kill-switch.json'))) {
        return { healthy: false, reason: 'KILL_SWITCH_STATE_PATH_INVALID', reservedStateBytes: STATE_WRITE_RESERVE_BYTES };
      }
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
    const classified = classifyRotationLockError(error)
      || await classifyEnoentPathError(error, path.dirname(filePath), 'RESET_TOKEN_ROTATION_PATH_INVALID');
    if (classified) throw new Error(classified);
    throw error;
  }
  while (!handle) {
    try {
      handle = await fs.open(lockFile, 'wx', 0o600);
    } catch (error) {
      const classified = classifyRotationLockError(error)
        || await classifyEnoentPathError(error, lockFile, 'RESET_TOKEN_ROTATION_PATH_INVALID');
      if (classified) throw new Error(classified);
      if (error.code !== 'EEXIST' || Date.now() - started >= 5_000) throw new Error('RESET_TOKEN_ROTATION_LOCKED');
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs >= 60_000) await fs.unlink(lockFile);
      } catch (statError) {
        const statClassified = classifyRotationLockError(statError)
          || await classifyEnoentPathError(statError, lockFile, 'RESET_TOKEN_ROTATION_PATH_INVALID');
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
    const classified = classifyRotationLockError(error)
      || await classifyEnoentPathError(error, temporary, 'RESET_TOKEN_ROTATION_PATH_INVALID');
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
    const classified = classifyRotationLockError(error)
      || await classifyEnoentPathError(error, filePath, 'RESET_TOKEN_ROTATION_PATH_INVALID');
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

async function runAuditRetentionCommand(args) {
  // `sentinel audit retention` (round 62): set or show the audit-log
  // retention policy `<state-dir>/audit-retention.json`. Setting it is
  // an operator config write, so it is refused while the kill-switch
  // is armed (same guard pattern as round 53's scope changes, checked
  // before any policy read or write). `--show` is read-only and works
  // while armed. A successful set writes an AUDIT_RETENTION_SET audit
  // record; a set whose audit append fails reports `auditLogged: false`
  // and exits 4, following the scope pattern.
  const show = args.includes('--show');
  const options = parseOptions(args.filter((argument) => argument !== '--show'), ['--state-dir', '--max-archives', '--max-records']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const retentionPath = retentionPathFor(stateDirectory);
  if (show) {
    if (options.maxArchives !== undefined || options.maxRecords !== undefined) {
      throw new Error('audit retention: --show cannot be combined with --max-archives or --max-records.');
    }
    const policy = await readRetentionPolicy(stateDirectory);
    process.stdout.write(`${JSON.stringify({ policy, store: retentionPath }, null, 2)}\n`);
    return;
  }
  if (options.maxArchives === undefined && options.maxRecords === undefined) {
    throw new Error('audit retention requires --max-archives <n> and/or --max-records <n>, or --show.');
  }
  const parseLimit = (raw, name) => {
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1) {
      throw new Error(`AUDIT_RETENTION_INVALID: ${name} must be an integer >= 1, got ${JSON.stringify(raw)}.`);
    }
    return value;
  };
  const { killSwitch } = await killSwitchFor({ stateDir: stateDirectory });
  const guard = await killSwitch.assertNotTriggered();
  if (!guard.allowed) {
    process.stdout.write(`${JSON.stringify({ updated: false, reason: 'AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE', trigger: guard.trigger || null }, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  const current = await readRetentionPolicy(stateDirectory);
  const merged = {
    schema_version: 1,
    ...(current || {}),
    ...(options.maxArchives !== undefined ? { max_archives: parseLimit(options.maxArchives, '--max-archives') } : {}),
    ...(options.maxRecords !== undefined ? { max_records: parseLimit(options.maxRecords, '--max-records') } : {}),
  };
  const policy = await writeRetentionPolicy(stateDirectory, merged);
  const auditLogged = await appendOperatorAudit(stateDirectory, 'AUDIT_RETENTION_SET', { maxArchives: policy.max_archives, maxRecords: policy.max_records, store: retentionPath });
  process.stdout.write(`${JSON.stringify({ updated: true, policy, store: retentionPath, auditLogged }, null, 2)}\n`);
  if (!auditLogged) process.exitCode = 4;
}

async function runAuditCommand(args) {
  const [action, ...actionArgs] = args;
  if (action !== 'verify' && action !== 'export' && action !== 'retention') throw new Error(`Unknown audit action: ${action}`);
  if (action === 'retention') {
    await runAuditRetentionCommand(actionArgs);
    return;
  }
  if (action === 'verify') {
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
    return;
  }
  // `audit export` (round 56): dump the whole retained trail — active
  // log plus archives, oldest first — with each record's hash-chain
  // status attached. A broken chain is NOT a refusal: the export's
  // whole point is to show exactly which records verify and which do
  // not, so the command exits 0 even when records are broken. The
  // format is validated BEFORE the log is touched, so a bad --format
  // never takes the audit lock. The output carries no timestamp, so
  // the same log always renders byte-identically.
  const options = parseOptions(actionArgs, ['--state-dir', '--out', '--format']);
  const format = options.format || 'json';
  if (!AUDIT_EXPORT_FORMATS.includes(format)) {
    throw new Error(`Invalid audit export format: ${format} (expected "json" or "jsonl").`);
  }
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const audit = new AuditLog({ logFile: path.join(stateDirectory, 'audit.jsonl'), skillDirectory: path.resolve(__dirname, '..') });
  try {
    const result = await audit.verifyChainPerRecord();
    const rendered = renderAuditExport(result, format);
    if (options.out) {
      const outputPath = path.resolve(options.out);
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await writeFileRefusingSymlink(outputPath, rendered, { encoding: 'utf8', mode: 0o600 });
      process.stdout.write(`Audit export written to ${outputPath}\n`);
      return;
    }
    process.stdout.write(rendered);
  } catch (error) {
    if (['AUDIT_LOG_LOCKED', 'AUDIT_LOG_PERMISSION_DENIED', 'AUDIT_LOG_STORAGE_UNAVAILABLE', 'AUDIT_LOG_PATH_INVALID'].includes(error.message)) {
      process.stdout.write(`${JSON.stringify({ exported: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    throw error;
  }
}

async function runReportValidate(args) {
  // `sentinel report validate` checks a JSON report file before the
  // operator trusts it (round 67, Phase 7): shape, per-finding
  // strict check + rule verdict, and the report-id recomputation.
  // --json is a boolean flag (same strip pattern as check-scope
  // --explain/--json): strip it before parseOptions, which only
  // accepts valued options. Read-only: nothing is written. Exit 0
  // when the file parses and every finding validates
  // (false_positive / needs_evidence are findings, not defects);
  // exit 1 when any finding is an error. Shape failures throw
  // named errors, like every other command.
  const [filePath, ...rest] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report validate requires a report file: sentinel report validate <report.json> [--json]');
  }
  const json = rest.includes('--json');
  parseOptions(rest.filter((argument) => argument !== '--json'), []);
  const report = await readReportFileForValidation(path.resolve(filePath));
  const result = validateReport(report);
  const rendered = json ? renderReportValidationJson(result) : renderReportValidationText(result);
  process.stdout.write(rendered);
  process.exitCode = result.status === 'VALID' ? 0 : 1;
}

async function runReportMerge(args) {
  // `sentinel report merge` combines two JSON reports into one
  // valid round-31 JSON report (round 68, Phase 7): identical
  // findings kept once, disjoint findings unioned, a same-id
  // finding with different content fails the merge instead of
  // silently picking one version. The two report files are
  // positionals (the runReportDiff pattern). The merged JSON goes
  // to stdout (pipeable) or --out (safe-write, mode 0600); the
  // one-line merge summary always goes to stderr, so stdout
  // stays a clean report. The merge is computed fully in memory
  // first, so a bad input can never leave a half-written file
  // behind.
  const [aPath, bPath, ...optionArgs] = args;
  if (!aPath || !bPath || aPath.startsWith('--') || bPath.startsWith('--')) {
    throw new Error('report merge requires two report files: sentinel report merge <a-report.json> <b-report.json> [--out <merged.json>]');
  }
  const options = parseOptions(optionArgs, ['--out']);
  const a = await readReportFile(path.resolve(aPath));
  const b = await readReportFile(path.resolve(bPath));
  const merged = mergeReports(a, b);
  const summary = merged.summary;
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, merged.report, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Merged report written to ${outputPath}\n`);
  } else {
    process.stdout.write(merged.report);
  }
  process.stderr.write(`merged ${summary.total} findings from ${summary.fromA} + ${summary.fromB} (${summary.shared} shared, 0 conflicts)\n`);
}

async function runReportAnonymize(args) {
  // `sentinel report anonymize` strips internal identifiers
  // from a JSON report so it can be shared (round 69, Phase
  // 7): target_id, session_id, and asset_id map to
  // deterministic `anon-<sha256>` values, and internal
  // hostnames/IPs in `description` and evidence `notes` are
  // scrubbed. The input file is never modified. The
  // anonymized JSON goes to stdout (pipeable) or --out
  // (safe-write, mode 0600); the one-line summary always
  // goes to stderr, so stdout stays a clean report. The salt
  // is never printed anywhere: not in the output, not in
  // the summary, and not in an error message. The command is
  // computed fully in memory first, so a bad input can never
  // leave a half-written file behind.
  const [filePath, ...optionArgs] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report anonymize requires a report file: sentinel report anonymize <report.json> [--out <anon.json>] [--salt <hex>]');
  }
  const options = parseOptions(optionArgs, ['--out', '--salt']);
  const report = await readReportFile(path.resolve(filePath));
  const anonymized = anonymizeReport(report, { salt: options.salt });
  const summary = anonymized.summary;
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, anonymized.report, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Anonymized report written to ${outputPath}\n`);
  } else {
    process.stdout.write(anonymized.report);
  }
  process.stderr.write(`anonymized ${summary.total} findings (${summary.identifiers_replaced} identifiers replaced, ${summary.text_substitutions} text substitutions)\n`);
}

async function prepareSplitOutDir(outDir, force) {
  // Prepare the --out-dir for `report split`: create it (mode
  // 0700, parents included) when missing; refuse to write into
  // an existing non-empty directory unless --force is passed.
  // An existing path that is not a directory is refused outright.
  // --force only overwrites the files this split writes — other
  // files already in the directory are left alone (documented
  // in docs/report-split-v1.md).
  let stat = null;
  try {
    stat = await fs.lstat(outDir);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (stat && !stat.isDirectory()) {
    throw new Error(`REPORT_SPLIT_OUT_DIR_NOT_A_DIRECTORY: --out-dir ${outDir} exists and is not a directory.`);
  }
  if (!stat) {
    await fs.mkdir(outDir, { recursive: true, mode: 0o700 });
  }
  const entries = await fs.readdir(outDir);
  if (entries.length > 0 && !force) {
    throw new Error(
      `REPORT_SPLIT_OUT_DIR_NOT_EMPTY: --out-dir ${outDir} is not empty (${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}); `
      + 'pass --force to write into it.',
    );
  }
}

async function runReportSplit(args) {
  // `sentinel report split` splits one JSON report into one JSON
  // report per severity or per rule verdict (round 70, Phase 7):
  // one file per non-empty group in --out-dir, each a valid
  // round-31 JSON report with its own recomputed report id.
  // --by and --out-dir are both required; --force is a boolean
  // flag (same strip pattern as check-scope --explain/--json).
  // The split is computed fully in memory first, so a bad input
  // can never create the directory or leave a half-written file
  // behind. stdout carries only the written file paths, one per
  // line (pipeable); the per-group summary lines go to stderr.
  const [filePath, ...optionArgs] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report split requires a report file: sentinel report split <report.json> --by severity|verdict --out-dir <dir> [--force]');
  }
  const force = optionArgs.includes('--force');
  const options = parseOptions(optionArgs.filter((argument) => argument !== '--force'), ['--by', '--out-dir']);
  if (!options.by) {
    throw new Error('report split requires --by severity|verdict: sentinel report split <report.json> --by severity|verdict --out-dir <dir> [--force]');
  }
  if (!options.outDir) {
    throw new Error('report split requires --out-dir <dir>: sentinel report split <report.json> --by severity|verdict --out-dir <dir> [--force]');
  }
  const report = await readReportFile(path.resolve(filePath));
  const split = splitReport(report, { groupBy: options.by });
  const outDir = path.resolve(options.outDir);
  if (pathOutsideSkillAndState(outDir) === null) {
    throw new Error('REPORT_SPLIT_OUT_DIR_FORBIDDEN: --out-dir must be outside the skill directory and the state directory.');
  }
  await prepareSplitOutDir(outDir, force);
  const written = [];
  for (const file of split.files) {
    const outputPath = path.join(outDir, file.fileName);
    await writeFileRefusingSymlink(outputPath, file.report, { encoding: 'utf8', mode: 0o600 });
    written.push(outputPath);
    process.stderr.write(`${file.group}: ${file.count} finding${file.count === 1 ? '' : 's'} -> ${outputPath}\n`);
  }
  process.stdout.write(`${written.join('\n')}\n`);
}

async function runReportFilter(args) {
  // `sentinel report filter` keeps a threshold subset of one JSON
  // report (round 71, Phase 7): --severity keeps findings at or
  // above that severity, --verdict keeps findings whose RULE
  // verdict (round 67's validateOneFinding — valid /
  // false_positive / needs_evidence, NOT the stored
  // validation_status workflow state) equals the given value.
  // At least one predicate is required; both AND together. The
  // filtered JSON goes to stdout (pipeable) or --out (safe-write,
  // mode 0600); the one-line summary always goes to stderr, so
  // stdout stays a clean report. The filter is computed fully in
  // memory first, so a bad input can never leave a half-written
  // file behind. An empty result is a valid empty report, not an
  // error.
  const [filePath, ...optionArgs] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report filter requires a report file: sentinel report filter <report.json> [--severity <level>] [--verdict <rule-verdict>] [--out <filtered.json>]');
  }
  const options = parseOptions(optionArgs, ['--severity', '--verdict', '--out']);
  const report = await readReportFile(path.resolve(filePath));
  const filtered = filterReport(report, { severity: options.severity, verdict: options.verdict });
  const summary = filtered.summary;
  const predicates = [];
  if (summary.severity !== null) predicates.push(`severity >= ${summary.severity}`);
  if (summary.verdict !== null) predicates.push(`verdict ${summary.verdict}`);
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, filtered.report, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Filtered report written to ${outputPath}\n`);
  } else {
    process.stdout.write(filtered.report);
  }
  process.stderr.write(`filtered ${summary.kept} of ${summary.total} findings (${predicates.join(', ')})\n`);
}

async function runReportStats(args) {
  // `sentinel report stats` prints a compact triage summary of one
  // JSON report file (round 74, Phase 7): total, counts by
  // severity / rule verdict / class, the CVSS distribution, and
  // the top 5 assets — plus the generator's executive summary
  // line. --json is a boolean flag (same strip pattern as
  // check-scope --explain/--json): strip it before parseOptions,
  // which only accepts valued options. Read-only: nothing is
  // written. Exit 0 whenever the file parses — stats is a summary
  // view, not a verdict, so even an all-false-positive report or
  // a report full of `error` findings exits 0. Shape failures
  // throw named errors, like every other command.
  const [filePath, ...rest] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report stats requires a report file: sentinel report stats <report.json> [--json]');
  }
  const json = rest.includes('--json');
  parseOptions(rest.filter((argument) => argument !== '--json'), []);
  const report = await readReportFile(path.resolve(filePath));
  const stats = computeReportStats(report);
  const rendered = json ? renderReportStatsJson(stats) : renderReportStatsText(stats);
  process.stdout.write(rendered);
  process.exitCode = 0;
}

async function runReportRender(args) {
  // `sentinel report render` re-renders an existing JSON report
  // file into another format (round 75, Phase 7): Markdown,
  // JSON, HTML, CSV, summary, or JSONL, through the generator's
  // own render path, so the output is byte-identical to what the
  // generator would have produced for the same finding set. The
  // source report's generated_at is carried through (never
  // re-stamped); a platform-template source is refused; a
  // mixed-target source renders only when it declares
  // mixed_targets. --format is required. The rendered report
  // goes to stdout (pipeable) or --out (safe-write, mode 0600);
  // the one-line summary always goes to stderr, so stdout stays
  // a clean report. The render is computed fully in memory
  // first, so a bad input can never leave a half-written file
  // behind.
  const [filePath, ...optionArgs] = args;
  if (!filePath || filePath.startsWith('--')) {
    throw new Error('report render requires a report file: sentinel report render <report.json> --format markdown|json|html|csv|summary|jsonl [--out <file>]');
  }
  const options = parseOptions(optionArgs, ['--format', '--out']);
  if (!options.format) {
    throw new Error('report render requires --format markdown|json|html|csv|summary|jsonl: sentinel report render <report.json> --format <format> [--out <file>]');
  }
  const report = await readReportFile(path.resolve(filePath));
  const rendered = renderReport(report, { format: options.format });
  const summary = rendered.summary;
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, rendered.report, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Rendered report written to ${outputPath}\n`);
  } else {
    process.stdout.write(rendered.report);
  }
  process.stderr.write(`rendered ${summary.total} findings as ${summary.format} from ${summary.report_id}\n`);
}

async function runReport(args) {
  // `sentinel report validate` is a subcommand of `report`
  // (round 67): intercept before parseOptions, which would reject
  // 'validate' as an unknown option.
  if (args[0] === 'validate') {
    await runReportValidate(args.slice(1));
    return;
  }
  // `sentinel report merge` is a subcommand of `report` too
  // (round 68): same intercept, same reason.
  if (args[0] === 'merge') {
    await runReportMerge(args.slice(1));
    return;
  }
  // `sentinel report anonymize` is a subcommand of `report`
  // too (round 69): same intercept, same reason.
  if (args[0] === 'anonymize') {
    await runReportAnonymize(args.slice(1));
    return;
  }
  // `sentinel report split` is a subcommand of `report` too
  // (round 70): same intercept, same reason.
  if (args[0] === 'split') {
    await runReportSplit(args.slice(1));
    return;
  }
  // `sentinel report filter` is a subcommand of `report` too
  // (round 71): same intercept, same reason.
  if (args[0] === 'filter') {
    await runReportFilter(args.slice(1));
    return;
  }
  // `sentinel report stats` is a subcommand of `report` too
  // (round 74): same intercept, same reason.
  if (args[0] === 'stats') {
    await runReportStats(args.slice(1));
    return;
  }
  // `sentinel report render` is a subcommand of `report` too
  // (round 75): same intercept, same reason.
  if (args[0] === 'render') {
    await runReportRender(args.slice(1));
    return;
  }
  // --allow-mixed-targets is a boolean flag (same pattern as drill
  // --recover): strip it before parseOptions, which only accepts
  // valued options.
  const allowMixedTargets = args.includes('--allow-mixed-targets');
  // --include-false-positives is a boolean flag too (policy F6,
  // round 90): by default, findings whose RULE verdict is
  // false_positive are excluded from a report generated from raw
  // findings; the flag keeps them. Strip it before parseOptions.
  const includeFalsePositives = args.includes('--include-false-positives');
  const options = parseOptions(args.filter((argument) => argument !== '--allow-mixed-targets' && argument !== '--include-false-positives'), ['--finding', '--findings', '--out', '--format', '--template', '--generated-at', '--program', '--verifier']);
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
  // Policy F6 (round 90, user-approved 2026-11-28; enforced by
  // enforceReportPolicies, round 96): rule-verdict
  // false_positive findings are excluded from a report generated
  // from raw findings, unless --include-false-positives is given,
  // and the kept findings are then merged by the conservative
  // semantic dedup pass. Exclusion runs FIRST, so a valid finding
  // can never absorb a false_positive's evidence by merging, and
  // a false_positive can never survive inside a merged valid
  // finding. Both steps run before generateReport (which is
  // untouched, so report transformations keep whatever a stored
  // report already carries). If every finding is excluded, fail
  // closed with a named error instead of rendering an empty
  // report — the operator asked for a report, not a blank page.
  // The stderr notes carry the policy version, so a run's
  // enforcement is auditable from its own output (see
  // docs/policy-versioning-v1.md).
  const { kept, excluded, duplicates } = enforceReportPolicies(findings, { includeFalsePositives });
  if (!includeFalsePositives && findings.length > 0 && kept.length === 0) {
    throw new Error('REPORT_ALL_FINDINGS_FALSE_POSITIVE: every finding in the input has rule verdict false_positive; nothing to report (use --include-false-positives to keep them).');
  }
  if (excluded.length > 0) {
    process.stderr.write(`Excluded ${excluded.length} false_positive finding${excluded.length === 1 ? '' : 's'} from the report (policy F6 v${POLICY_VERSION}; use --include-false-positives to keep them).\n`);
  }
  if (duplicates > 0) {
    process.stderr.write(`Merged ${duplicates} duplicate finding${duplicates === 1 ? '' : 's'} (policy F6 v${POLICY_VERSION}, conservative semantic dedup).\n`);
  }
  findings = kept;
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

async function runReportDiff(args) {
  // `sentinel report-diff` compares two JSON reports from two runs
  // (round 64, Phase 7): added / removed / changed findings, matched
  // by finding_id. The two report files are positionals (the
  // runScopeCommand pattern: destructure them first, then parse the
  // options from the rest). A diff compares reports; it does not
  // render one, so --template is refused explicitly instead of
  // surfacing as a generic unknown option. Both inputs are read
  // bounded with a symlink refusal (readReportFile); the diff is
  // computed fully in memory first, so a bad input can never leave
  // a half-written output file behind.
  const [oldPath, newPath, ...optionArgs] = args;
  if (!oldPath || !newPath || oldPath.startsWith('--') || newPath.startsWith('--')) {
    throw new Error('report-diff requires two report files: sentinel report-diff <old-report.json> <new-report.json> [--format markdown|json] [--out <diff.md>]');
  }
  if (optionArgs.includes('--template')) {
    throw new Error('report-diff does not take --template: a diff compares two reports, it does not render one.');
  }
  const options = parseOptions(optionArgs, ['--format', '--out']);
  const format = options.format || 'markdown';
  if (format !== 'markdown' && format !== 'json') {
    throw new Error(`Invalid report-diff format: ${format} (expected "markdown" or "json").`);
  }
  const oldReport = await readReportFile(path.resolve(oldPath));
  const newReport = await readReportFile(path.resolve(newPath));
  const diff = diffReports(oldReport, newReport);
  const rendered = format === 'json' ? renderReportDiffJson(diff) : renderReportDiffMarkdown(diff);
  if (options.out) {
    const outputPath = path.resolve(options.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await writeFileRefusingSymlink(outputPath, rendered, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`Report diff written to ${outputPath}\n`);
    return;
  }
  process.stdout.write(rendered);
}

async function runDetect(args) {
  // `sentinel detect` runs a conforming detector (round 51) over a
  // LOCAL input record and prints the findings as JSON. The input
  // is a raw detector-input record (the shape normalizeRawFinding
  // accepts) or a batch record `{ tool, results: [...] }`; it is
  // read bounded (size + nesting depth) like every other JSON
  // input. The detector defaults to the built-in stub; `secret-scan`
  // (round 86) is the first real detector — it scans the `content`
  // string of a local record for well-known credential formats
  // and reports one finding per distinct secret, never the full
  // secret itself; `dangerous-call` (round 87) is the second real
  // detector — it scans the `content` string for risky code-sink
  // calls (eval, Function, command execution, innerHTML,
  // document.write, unsafe deserialization) and reports one
  // finding per distinct call site, never executing the code;
  // `insecure-crypto` (round 88) is the third real detector — it
  // scans the `content` string for weak-cryptography call sites
  // (MD5/SHA-1 hashes, ECB mode, DES/RC4 ciphers, Node's
  // deprecated createCipher()/createDecipher(), Math.random() /
  // random.random()) and reports one finding per distinct call
  // site, never executing the code; `hardcoded-credential`
  // (round 89) is the fourth real detector — it scans the
  // `content` string for credential-named variables assigned a
  // quoted string literal (password, API key, secret/token) and
  // reports one finding per distinct assignment site, carrying
  // only the masked assignment (`<name><operator> "****"`) —
  // never the literal value itself; `insecure-transport`
  // (round 90) is the fifth real detector — it scans the
  // `content` string for cleartext HTTP URLs and disabled TLS
  // verification and reports one finding per distinct call
  // site, never executing the code; `tainted-deserialize`
  // (round 95) is the sixth real detector and the first
  // parser-based one — it parses the `content` string as
  // JavaScript (hand-written stdlib-only subset parser) and
  // tracks taint from function parameters and `process.argv`
  // to unsafe deserialization sinks (yaml.load, YAML.load,
  // yaml.loadAll, unserialize), reporting a sink call only
  // when its first argument is tainted or the call is reached
  // through an alias, never carrying a literal value;
  // `tainted-command-execution` (round 100) is the seventh
  // real detector and the second parser-based one — it reuses
  // the same taint engine on command-execution sinks
  // (child_process.exec, execSync, spawn, spawnSync,
  // execFile, execFileSync), reporting a sink call only when
  // its first argument is tainted or the call is reached
  // through an alias, never carrying a literal value;
  // `tainted-sql` (round 103) is the eighth real detector
  // and the third parser-based one — it reuses the same
  // taint engine on SQL query sinks (db, pool, connection,
  // client, conn — `query` and `execute` each), reporting a
  // sink call only when its first argument is tainted or
  // the call is reached through an alias, never carrying a
  // literal value; `tainted-xss` (round 104) is the ninth
  // real detector and the fourth parser-based one — it
  // reuses the same taint engine on HTML sinks (innerHTML /
  // outerHTML assignment, document.write / writeln, and
  // insertAdjacentHTML, which judges its second argument,
  // the HTML), reporting a sink only when the judged value
  // is tainted or the call is reached through an alias,
  // never carrying a literal value; `tainted-ssti` (round
  // 105) is the tenth real detector and the fifth
  // parser-based one — it reuses the same taint engine on
  // template-engine sinks (ejs.render / compile,
  // pug.compile / render, nunjucks.renderString,
  // handlebars.compile), reporting a sink call only when
  // its first argument (the template string) is tainted or
  // the call is reached through an alias, never carrying a
  // literal value; `tainted-path-traversal` (round 105) is
  // the eleventh real detector and the sixth parser-based
  // one — it reuses the same taint engine on filesystem
  // path sinks (fs.readFile / readFileSync / writeFile /
  // writeFileSync / createReadStream / createWriteStream /
  // readdir / readdirSync / unlink / unlinkSync), reporting
  // a sink call only when its first argument (the path) is
  // tainted or the call is reached through an alias, never
  // carrying a literal value; `tainted-ssrf` (round 105)
  // is the twelfth real detector and the seventh
  // parser-based one — it reuses the same taint engine on
  // outbound-request sinks (fetch, request, http.get /
  // request, https.get / request, axios.get / post / put /
  // delete / request), reporting a sink call only when its
  // first argument (the URL) is tainted or the call is
  // reached through an alias, never carrying a literal
  // value; `tainted-ldap` (round 107) is the thirteenth
  // real detector and the eighth parser-based one — it
  // reuses the same taint engine on LDAP search sinks
  // (client.search, judging its second argument, the
  // filter / options), reporting a sink call only when the
  // judged argument is tainted or the call is reached
  // through an alias, never carrying a literal value;
  // `tainted-xpath` (round 107) is the fourteenth real
  // detector and the ninth parser-based one — it reuses
  // the same taint engine on XPath evaluation sinks
  // (xpath.select / select1 / evaluate,
  // document.evaluate), reporting a sink call only when
  // its first argument (the expression) is tainted or the
  // call is reached through an alias, never carrying a
  // literal value; `tainted-open-redirect` (round 107) is
  // the fifteenth real detector and the tenth parser-based
  // one — it reuses the same taint engine on HTTP redirect
  // sinks (res / response / reply / ctx — `redirect`),
  // reporting a sink call only when its first argument
  // (the URL) is tainted or the call is reached through
  // an alias, never carrying a literal value;
  // `solidity-reentrancy` (round 108) is the sixteenth real
  // detector and the FIRST Solidity detector — it does NOT
  // reuse the JavaScript taint engine (which is
  // JavaScript-specific); it runs a separate segment-based
  // analysis over the Solidity subset AST (sol-parser.js),
  // flagging a function that performs an external call
  // (.call / .transfer / .send) and then writes state
  // (CWE-841, SWC-107), one finding per call site;
  // `solidity-access-control` (round 109) is the seventeenth
  // real detector and the second Solidity detector — it runs
  // a separate analysis over the same subset AST, flagging
  // an external/public function that performs a sensitive
  // operation (state write, fund-moving call, selfdestruct,
  // delegatecall) with no access control (CWE-862), one
  // finding per function; `solidity-unprotected-initializer`
  // (round 109) is the eighteenth real detector and the third
  // Solidity detector — it runs a separate analysis over the
  // same subset AST, flagging an external/public initialize()
  // with neither the `initializer` / `reinitializer`
  // modifier nor any access control (CWE-862), one finding
  // per initialize function; `solidity-rounding`
  // (round 110) is the nineteenth real detector and the fourth
  // Solidity detector — it runs a separate analysis over the
  // same subset AST, flagging a `*` whose operand is directly
  // a `/` (division before multiplication, CWE-682), one
  // finding per multiplication site; `solidity-tx-origin`
  // (round 110) is the twentieth real detector and the fifth
  // Solidity detector — it runs a separate analysis over the
  // same subset AST, flagging a `==` / `!=` comparison
  // containing `tx.origin` in a function or modifier body
  // (CWE-862), one finding per comparison site;
  // `solidity-weak-randomness` (round 110) is the
  // twenty-first real detector and the sixth Solidity
  // detector — it runs a separate analysis over the same
  // subset AST, flagging block entropy (block.timestamp /
  // block.number / blockhash / block.difficulty /
  // block.prevrandao / block.coinbase) inside a hash call,
  // a modulo, or a seed initializer (CWE-338), one finding
  // per entropy-source site; a path loads
  // a custom detector module
  // from inside the skill directory (refused with a named
  // DETECTOR_* error when it is missing, malformed, a
  // symlink, or outside the skill root).
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

async function runStateCommand(args) {
  // `state export` (round 58): one portable document of the whole
  // operator state — kill-switch state + scope targets + audit
  // summary — for migration or off-machine inspection. EXPORT ONLY:
  // there is no `state import`; importing foreign state would need a
  // trust decision that stays with the user. The envelope is rendered
  // fully in memory first, so a collection failure can never leave a
  // half-written export behind. A broken audit chain is NOT a
  // refusal: the summary reports it (chainVerified: false with the
  // per-status counts), exactly as `audit export` shows broken
  // records instead of refusing. The command is read-only and works
  // while the kill-switch is armed.
  const [action, ...actionArgs] = args;
  if (action !== 'export') throw new Error('state requires an action: export.');
  const options = parseOptions(actionArgs, ['--state-dir', '--out']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  try {
    const contents = await collectStateExport({ stateDir: stateDirectory, skillDirectory: path.resolve(__dirname, '..') });
    const rendered = renderStateExport(contents);
    if (options.out) {
      const outputPath = path.resolve(options.out);
      try {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await writeFileRefusingSymlink(outputPath, rendered, { encoding: 'utf8', mode: 0o600 });
      } catch (error) {
        if (/symbolic link/i.test(error.message)) throw new Error('STATE_EXPORT_SYMLINK_REFUSED');
        throw error;
      }
      process.stdout.write(`State export written to ${outputPath}\n`);
      return;
    }
    process.stdout.write(rendered);
  } catch (error) {
    if (typeof error.message === 'string'
      && (error.message.startsWith('STATE_EXPORT_')
        || error.message.startsWith('SCOPE_STORE_')
        || error.message.startsWith('SCOPE_TARGET_'))) {
      process.stdout.write(`${JSON.stringify({ exported: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = 1;
      return;
    }
    if (['AUDIT_LOG_LOCKED', 'AUDIT_LOG_PERMISSION_DENIED', 'AUDIT_LOG_STORAGE_UNAVAILABLE', 'AUDIT_LOG_PATH_INVALID'].includes(error.message)) {
      process.stdout.write(`${JSON.stringify({ exported: false, reason: error.message }, null, 2)}\n`);
      process.exitCode = 4;
      return;
    }
    throw error;
  }
}

async function runPolicyCommand(args) {
  // `sentinel policy` prints the active F6 policy version and
  // decisions (round 96): the version tracks the decision set
  // (docs/policy-versioning-v1.md), and the decisions are the
  // user-approved constants in src/analysis/policies.js.
  // Read-only: it changes nothing, and there is no flag or
  // variable that can change a decision — a decision changes
  // only by editing the policy module alongside its doc, which
  // is what the versioning doc requires a future user decision
  // for. --json prints the same summary as JSON.
  const json = args.includes('--json');
  const rest = args.filter((argument) => argument !== '--json');
  if (rest.length > 0) throw new Error(`Unknown option: ${rest[0]}`);
  const summary = getPolicySummary();
  if (json) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return;
  }
  const decisions = summary.decisions;
  process.stdout.write([
    `Sentinel policy F6 v${summary.version}`,
    `  semantic dedup: ${decisions.semanticDedupMode} — enforced at report generation from raw findings (sentinel report)`,
    `  false positives: ${decisions.falsePositiveReporting} — excluded from generated reports unless --include-false-positives`,
    `  AI verdict: advisory only, never overrides the rule verdict (AI_VERDICT_OVERRIDE=${decisions.aiVerdictOverride})`,
    `  detection auto-run: ${decisions.detectionAutoRun ? 'yes' : 'no'} — detectors run only via explicit \`sentinel detect\``,
    `  detectors: ${decisions.detectorAsync ? 'async allowed' : 'synchronous only'} — an async detector is refused`,
    'See docs/policies-f6-v1.md and docs/policy-versioning-v1.md.',
    '',
  ].join('\n'));
}

async function runStatusCommand(args) {
  // `sentinel status` (round 63): one strictly read-only overview of
  // the whole operator state. Fail-closed component failures
  // (kill-switch state, audit-log storage, scope-store shape) are
  // reported as JSON with the component named and exit 1; audit
  // content breaks and a damaged retention policy are reported
  // inside their sections and the command still exits 0 (see
  // src/policy/operator-status.js for the full semantics).
  const json = args.includes('--json');
  const options = parseOptions(args.filter((argument) => argument !== '--json'), ['--state-dir', '--skill-dir']);
  const stateDirectory = path.resolve(options.stateDir || DEFAULT_STATE_DIRECTORY);
  const skillDirectory = path.resolve(options.skillDir || path.resolve(__dirname, '..'));
  try {
    const status = await collectOperatorStatus({ stateDir: stateDirectory, skillDirectory });
    process.stdout.write(json ? `${JSON.stringify(status, null, 2)}\n` : `${renderOperatorStatusText(status)}\n`);
  } catch (error) {
    if (error instanceof OperatorStatusError) {
      process.stdout.write(`${JSON.stringify({ status: false, component: error.component, reason: error.reason }, null, 2)}\n`);
      process.exitCode = 1;
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
  if (command === 'state') {
    await runStateCommand(args);
    return;
  }
  if (command === 'status') {
    await runStatusCommand(args);
    return;
  }
  if (command === 'policy') {
    await runPolicyCommand(args);
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
  if (command === 'report-diff') {
    await runReportDiff(args);
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
  if (command === 'target') {
    await runTargetCommand(args);
    return;
  }
  if (command === 'fetch') {
    await runFetchCommand(args);
    return;
  }
  if (command === 'session') {
    await runSessionCommand(args);
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
