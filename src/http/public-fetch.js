// Public-fetch invocation path (Phase 4, round 93): the CLI-facing
// orchestration for `sentinel fetch`.
//
// The adapter (`src/http/public-http-adapter.js`, round 90) is the
// gate and the transport. This module is the human-facing half: it
// resolves a URL against the public-target store, shows the preview,
// obtains the explicit human approval, and only then hands the
// request to the adapter. The order is the approved design, and the
// first failing step decides:
//
//   1. The URL parses as http(s) without credentials or an IP host
//      (INVALID_URL) — the same normalization the scope rule uses,
//      so `//` and `/../` tricks cannot escape the scope prefix.
//   2. The hostname is a registered public target
//      (PUBLIC_TARGET_NOT_REGISTERED) — unregistered, refused
//      outright, before any approval is spent or any DNS happens.
//   3. The kill switch is not triggered (KILL_SWITCH_ACTIVE).
//   4. The request path falls inside the target's registered scope
//      prefix (PUBLIC_HTTP_OUT_OF_SCOPE).
//   5. The preview is shown: GET only, no headers/body/credentials,
//      timeout and body cap. Nothing is executed yet.
//   6. Explicit human approval — exactly one of:
//      (a) interactive confirmation: the CLI's `confirm` callback
//          asks the operator (type YA); anything else denies, and
//          nothing is executed;
//      (b) a one-time token minted earlier by `fetch --mint-approval`,
//          bound to this exact URL/target/fingerprint, 5-minute
//          TTL, consumed BEFORE the adapter runs — so a fetch that
//          then fails (DNS included) still burns the approval.
//      There is deliberately no `--yes` flag: a standing approval
//      would defeat the gate this module exists to enforce.
//   7. The adapter runs (its own gate re-validates everything:
//      kill switch, hostname, authorization reference, scope,
//      method, fingerprint, governor, the single-use in-process
//      approval, then DNS resolution AFTER the approval, refusing
//      non-public resolved addresses). A redirect is never followed:
//      a 3xx is returned as-is with `redirected: true`.
//
// Audit: this module appends metadata-only events for the steps the
// adapter does not cover — PUBLIC_FETCH_APPROVAL_MINTED (targetId,
// url, expiresAt; never the token), PUBLIC_FETCH_APPROVAL_DENIED,
// PUBLIC_FETCH_TOKEN_INVALID (never the presented token), and
// PUBLIC_FETCH_BLOCKED (pre-adapter refusals). The adapter's own
// PUBLIC_HTTP_REQUEST_ALLOWED / PUBLIC_HTTP_RESPONSE events are the
// record of the request itself. No event carries the response body,
// response headers, or the authorization reference. An audit-append
// failure never blocks the refusal it reports, but the result
// carries `auditLogged: false` so the CLI can exit 4 (audit
// integrity incident, the kill-switch/scope pattern).
//
// No function here touches a real socket or real DNS by itself:
// the transport and resolver are the adapter's injectable defaults
// (real `https.get` / `dns.promises.lookup`), and tests inject
// stubs. Nothing in this module is invoked against a real target in
// round 93 — the CLI is built and tested with stubs and fixtures
// only.
'use strict';

const path = require('node:path');
const { AuditLog } = require('../audit/audit-log');
const { ApprovalGate } = require('../policy/approval-gate');
const { PersistentKillSwitch } = require('../policy/persistent-kill-switch');
const { RequestGovernor } = require('../policy/request-governor');
const { TargetRegistry, normalizeUrl } = require('../scope/target-registry');
const { PublicHttpAdapter } = require('./public-http-adapter');
const {
  storePathFor: publicTargetStorePathFor,
  findPublicTarget,
  buildTargetForAdapter,
  scopePrefixMatches,
} = require('../scope/public-target-store');
const {
  storePathFor: approvalStorePathFor,
  mintPublicFetchApproval,
  consumePublicFetchApproval,
  TOKEN_TTL_MS,
} = require('./public-fetch-approvals');

const SKILL_DIRECTORY = path.resolve(__dirname, '..', '..');
const PUBLIC_FETCH_TIMEOUT_MS = 5_000;
const PUBLIC_FETCH_MAX_BODY_BYTES = 1_048_576;
const MAX_TIMEOUT_MS = 60_000;
const MAX_BODY_BYTES = 10_485_760;
const FETCH_ACTION = 'http_probing';

function result(fetched, reason, detail = {}) {
  return { fetched, reason, ...detail };
}

function normalizeFetchLimits({ timeoutMs = PUBLIC_FETCH_TIMEOUT_MS, maxBodyBytes = PUBLIC_FETCH_MAX_BODY_BYTES } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(`timeoutMs must be an integer from 1 to ${MAX_TIMEOUT_MS}.`);
  }
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES) {
    throw new RangeError(`maxBodyBytes must be an integer from 1 to ${MAX_BODY_BYTES}.`);
  }
  return { timeoutMs, maxBodyBytes };
}

async function appendFetchAudit(auditLog, event, details) {
  try {
    await auditLog.append(event, details);
    return true;
  } catch {
    return false;
  }
}

function defaultDeps(stateDir, deps = {}) {
  return {
    killSwitch: deps.killSwitch || new PersistentKillSwitch({
      stateFile: path.join(stateDir, 'kill-switch.json'),
      skillDirectory: SKILL_DIRECTORY,
    }),
    auditLog: deps.auditLog || new AuditLog({
      logFile: path.join(stateDir, 'audit.jsonl'),
      skillDirectory: SKILL_DIRECTORY,
    }),
    requestGet: deps.requestGet,
    resolveHost: deps.resolveHost,
    clock: deps.clock || (() => Date.now()),
  };
}

function renderPreviewText(preview) {
  return [
    'Public fetch preview — nothing has been sent yet.',
    `  Method: GET (only)`,
    `  URL: ${preview.url}`,
    `  Target: ${preview.targetId} (host ${preview.host}, scope ${preview.scope})`,
    `  Purpose: ${preview.purpose}`,
    `  Timeout: ${preview.timeoutMs} ms — body cap: ${preview.maxBodyBytes} bytes`,
    `  Estimated requests: ${preview.estimatedRequests} — headers: none — credentials: none`,
  ].join('\n');
}

// Resolves a URL to its fetch context: registered target, kill
// switch, scope prefix. Returns `{ allowed: true, context }` or
// `{ allowed: false, reason, targetId }`. The adapter re-validates
// every one of these rules itself; these pre-checks exist so the
// preview and the approval step never run for a request the gate
// would refuse anyway.
async function resolveFetchContext({ stateDir, url, timeoutMs, maxBodyBytes, deps }) {
  const limits = normalizeFetchLimits({ timeoutMs, maxBodyBytes });
  let normalized;
  try {
    normalized = normalizeUrl(url, 'request URL');
  } catch {
    return { allowed: false, reason: 'INVALID_URL', targetId: null };
  }
  const entry = await findPublicTarget(publicTargetStorePathFor(stateDir), normalized.hostname);
  if (!entry) {
    return { allowed: false, reason: 'PUBLIC_TARGET_NOT_REGISTERED', targetId: null };
  }
  const { killSwitch } = deps;
  const guard = await killSwitch.assertNotTriggered();
  if (!guard.allowed) {
    return { allowed: false, reason: guard.reason, targetId: entry.target_id };
  }
  if (!scopePrefixMatches(entry.scope, normalized.path)) {
    return { allowed: false, reason: 'PUBLIC_HTTP_OUT_OF_SCOPE', targetId: entry.target_id };
  }
  const registry = new TargetRegistry();
  const target = registry.register(buildTargetForAdapter(entry));
  const fingerprint = registry.getScopeFingerprint(target.targetId);
  const preview = {
    method: 'GET',
    url: normalized.normalized,
    targetId: target.targetId,
    host: entry.host,
    scope: entry.scope,
    purpose: entry.purpose,
    timeoutMs: limits.timeoutMs,
    maxBodyBytes: limits.maxBodyBytes,
    estimatedRequests: 1,
    scopeFingerprint: fingerprint,
  };
  return {
    allowed: true,
    context: {
      entry, registry, target, fingerprint, preview,
      killSwitch, normalizedUrl: normalized.normalized,
    },
  };
}

async function previewPublicFetch({ stateDir, url, timeoutMs, maxBodyBytes, ...deps }) {
  const resolved = await resolveFetchContext({ stateDir, url, timeoutMs, maxBodyBytes, deps: defaultDeps(stateDir, deps) });
  if (!resolved.allowed) return { allowed: false, reason: resolved.reason, targetId: resolved.targetId };
  return { allowed: true, preview: resolved.context.preview };
}

// Mints a one-time approval token for one exact URL, after the
// preview checks pass. The token is returned ONCE (the caller
// prints it to the operator); the store holds only its hash.
async function mintPublicFetchApprovalFor({ stateDir, url, timeoutMs, maxBodyBytes, ...deps }) {
  const resolvedDeps = defaultDeps(stateDir, deps);
  const resolved = await resolveFetchContext({ stateDir, url, timeoutMs, maxBodyBytes, deps: resolvedDeps });
  if (!resolved.allowed) {
    const auditLogged = await appendFetchAudit(resolvedDeps.auditLog, 'PUBLIC_FETCH_BLOCKED', { targetId: resolved.targetId, url, reason: resolved.reason });
    return { minted: false, reason: resolved.reason, targetId: resolved.targetId, auditLogged };
  }
  const { preview, fingerprint, target } = resolved.context;
  const now = resolvedDeps.clock();
  const minted = await mintPublicFetchApproval({
    storePath: approvalStorePathFor(stateDir),
    targetId: target.targetId,
    url: preview.url,
    scopeFingerprint: fingerprint,
    now,
  });
  const auditLogged = await appendFetchAudit(resolvedDeps.auditLog, 'PUBLIC_FETCH_APPROVAL_MINTED', { targetId: target.targetId, url: preview.url, expiresAt: new Date(minted.expiresAt).toISOString() });
  return { minted: true, token: minted.token, expiresAt: minted.expiresAt, preview, auditLogged };
}

// Runs a public fetch end to end. `approval` is exactly one of:
//   { kind: 'interactive', confirm } — confirm(preview) asks the
//     operator and resolves to true only on an explicit yes.
//   { kind: 'token', token } — a one-time token minted earlier.
// The token is consumed before the adapter runs; a fetch that then
// fails still burns it. The in-process ApprovalGate approval the
// adapter requires is created and approved here, bound to the same
// target/action/fingerprint — it is the mechanical half of the
// human approval above, not a second approval.
async function runPublicFetch({ stateDir, url, approval, timeoutMs, maxBodyBytes, ...deps }) {
  const resolvedDeps = defaultDeps(stateDir, deps);
  const limits = normalizeFetchLimits({ timeoutMs, maxBodyBytes });
  const resolved = await resolveFetchContext({ stateDir, url, timeoutMs: limits.timeoutMs, maxBodyBytes: limits.maxBodyBytes, deps: resolvedDeps });
  if (!resolved.allowed) {
    const auditLogged = await appendFetchAudit(resolvedDeps.auditLog, 'PUBLIC_FETCH_BLOCKED', { targetId: resolved.targetId, url, reason: resolved.reason });
    return result(false, resolved.reason, { targetId: resolved.targetId, auditLogged });
  }
  const { preview, fingerprint, target, registry, entry } = resolved.context;
  if (!approval || (approval.kind !== 'interactive' && approval.kind !== 'token')) {
    return result(false, 'PUBLIC_HTTP_APPROVAL_REQUIRED', { targetId: target.targetId });
  }
  if (approval.kind === 'interactive') {
    if (typeof approval.confirm !== 'function') {
      return result(false, 'PUBLIC_HTTP_APPROVAL_REQUIRED', { targetId: target.targetId });
    }
    let confirmed = false;
    try {
      confirmed = await approval.confirm(preview);
    } catch {
      confirmed = false;
    }
    if (!confirmed) {
      const auditLogged = await appendFetchAudit(resolvedDeps.auditLog, 'PUBLIC_FETCH_APPROVAL_DENIED', { targetId: target.targetId, url: preview.url });
      return result(false, 'PUBLIC_HTTP_APPROVAL_DENIED', { targetId: target.targetId, auditLogged });
    }
  } else {
    try {
      await consumePublicFetchApproval({
        storePath: approvalStorePathFor(stateDir),
        token: approval.token,
        targetId: target.targetId,
        url: preview.url,
        scopeFingerprint: fingerprint,
        now: resolvedDeps.clock(),
      });
    } catch (error) {
      const reason = typeof error.code === 'string' ? error.code : 'PUBLIC_FETCH_TOKEN_NOT_FOUND';
      const auditLogged = await appendFetchAudit(resolvedDeps.auditLog, 'PUBLIC_FETCH_TOKEN_INVALID', { targetId: target.targetId, url: preview.url, reason });
      return result(false, reason, { targetId: target.targetId, auditLogged });
    }
  }
  const gate = new ApprovalGate({ clock: resolvedDeps.clock });
  const pending = gate.request({
    targetId: target.targetId,
    action: FETCH_ACTION,
    estimatedRequests: 1,
    scopeFingerprint: fingerprint,
    reason: 'public-fetch',
  });
  const approved = gate.approve(pending.requestId, { approver: approval.kind === 'token' ? 'operator-token' : 'operator' });
  if (!approved.allowed) {
    return result(false, approved.reason, { targetId: target.targetId });
  }
  const governor = RequestGovernor.fromTarget(target);
  const adapter = new PublicHttpAdapter({
    registry,
    approvalGate: gate,
    governor,
    killSwitch: resolvedDeps.killSwitch,
    auditLog: resolvedDeps.auditLog,
    timeoutMs: limits.timeoutMs,
    maxBodyBytes: limits.maxBodyBytes,
    ...(resolvedDeps.requestGet ? { requestGet: resolvedDeps.requestGet } : {}),
    ...(resolvedDeps.resolveHost ? { resolveHost: resolvedDeps.resolveHost } : {}),
  });
  const response = await adapter.get({
    targetId: target.targetId,
    url: preview.url,
    authorizationRef: entry.authorization_reference,
    approvalId: approved.approvalId,
    estimatedRequests: 1,
    scopeFingerprint: fingerprint,
  });
  if (!response.allowed) {
    // The adapter's refusal carries a `cancellation` detail when the
    // kill switch aborted a request in flight (round 94 drill
    // finding: the orchestration dropped it, so the operator saw a
    // bare PROCESS_FAILED and could not tell a kill-switch abort
    // from any other process failure). Propagate it so the CLI
    // result — and the audit trail the operator reads — names the
    // cause. No other adapter detail is forwarded: the refusal
    // reason stays the contract.
    return result(false, response.reason, {
      targetId: target.targetId,
      ...(response.cancellation ? { cancellation: response.cancellation } : {}),
    });
  }
  return result(true, 'HTTP_COMPLETED', {
    targetId: target.targetId,
    url: preview.url,
    statusCode: response.statusCode,
    contentLength: response.contentLength,
    truncated: response.truncated,
    redirected: response.redirected,
    headers: response.headers,
    body: response.body,
  });
}

module.exports = {
  PUBLIC_FETCH_TIMEOUT_MS,
  PUBLIC_FETCH_MAX_BODY_BYTES,
  MAX_TIMEOUT_MS,
  MAX_BODY_BYTES,
  TOKEN_TTL_MS,
  normalizeFetchLimits,
  renderPreviewText,
  previewPublicFetch,
  mintPublicFetchApprovalFor,
  runPublicFetch,
};
