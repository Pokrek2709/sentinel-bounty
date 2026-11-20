const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_EXCLUDED_PATHS = Object.freeze([
  '/logout',
  '/signout',
  '/delete',
  '/reset-password',
  '/unsubscribe',
]);

const ALLOWED_METHODS = new Set([
  'passive_recon',
  'dns_resolution',
  'http_probing',
  'crawling',
  'safe_scanning',
  'active_scanning',
]);
const MAX_REQUEST_BUDGET = 10_000;
const MAX_CONCURRENCY = 2;

function fail(message) {
  throw new TypeError(`Invalid target registration: ${message}`);
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${field} must be a non-empty string.`);
  return value.trim();
}

function normalizeDomain(value, field) {
  const raw = requireNonEmptyString(value, field).toLowerCase().replace(/\.$/, '');
  const wildcard = raw.startsWith('*.');
  const hostname = wildcard ? raw.slice(2) : raw;
  if (!hostname || raw.includes('*', wildcard ? 1 : 0) || net.isIP(hostname)) {
    fail(`${field} must be a DNS hostname or a leading wildcard DNS hostname.`);
  }
  try {
    const parsed = new URL(`http://${hostname}`);
    if (parsed.hostname !== hostname || parsed.port || parsed.username || parsed.password) throw new Error('not canonical');
  } catch {
    fail(`${field} is not a canonical DNS hostname.`);
  }
  return { raw: wildcard ? `*.${hostname}` : hostname, hostname, wildcard };
}

function normalizePath(value, field) {
  const raw = requireNonEmptyString(value, field);
  if (!raw.startsWith('/') || raw.includes('?') || raw.includes('#')) fail(`${field} must be an absolute path without query or fragment.`);
  return raw.length > 1 ? raw.replace(/\/+$/, '') : raw;
}

function normalizeRateLimit(value) {
  if (value !== undefined && (!value || typeof value !== 'object' || Array.isArray(value))) fail('rate_limit must be an object.');
  const requestsPerSecond = value?.requests_per_second ?? 2;
  const concurrency = value?.concurrency ?? 2;
  if (typeof requestsPerSecond !== 'number' || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0) {
    fail('rate_limit.requests_per_second must be a positive number.');
  }
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
    fail(`rate_limit.concurrency must be an integer from 1 to ${MAX_CONCURRENCY}.`);
  }
  return Object.freeze({ requests_per_second: requestsPerSecond, concurrency });
}

function normalizeRequestBudget(value) {
  const budget = value ?? 1_000;
  if (!Number.isInteger(budget) || budget < 1 || budget > MAX_REQUEST_BUDGET) {
    fail(`request_budget must be an integer from 1 to ${MAX_REQUEST_BUDGET}.`);
  }
  return budget;
}

function normalizeUrl(value, field) {
  const raw = requireNonEmptyString(value, field);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    fail(`${field} must be an absolute URL.`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) fail(`${field} must use http or https.`);
  if (parsed.username || parsed.password || net.isIP(parsed.hostname)) fail(`${field} must not contain credentials or an IP address.`);
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port,
    path: normalizeRequestPath(parsed.pathname),
    normalized: parsed.toString(),
  };
}

function normalizeRequestPath(value) {
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new TypeError('Invalid request URL: path contains malformed percent encoding.');
  }
  const normalized = path.posix.normalize(decoded);
  return normalized.startsWith('/') ? normalized : `/${normalized}`;
}

function domainMatches(hostname, pattern) {
  if (pattern.wildcard) return hostname.endsWith(`.${pattern.hostname}`) && hostname !== pattern.hostname;
  return hostname === pattern.hostname;
}

function excludedDomainMatches(hostname, pattern) {
  if (pattern.wildcard) return domainMatches(hostname, pattern);
  return hostname === pattern.hostname || hostname.endsWith(`.${pattern.hostname}`);
}

function pathMatches(requestPath, excludedPath) {
  return excludedPath === '/' || requestPath === excludedPath || requestPath.startsWith(`${excludedPath}/`);
}

function freezeTarget(target) {
  Object.freeze(target.allowedDomains);
  Object.freeze(target.excludedDomains);
  Object.freeze(target.excludedPaths);
  Object.freeze(target.allowedUrls);
  Object.freeze(target.allowedMethods);
  return Object.freeze(target);
}

function scopeFingerprint(target) {
  const canonical = JSON.stringify({
    targetId: target.targetId,
    allowedDomains: target.allowedDomains,
    excludedDomains: target.excludedDomains,
    excludedPaths: target.excludedPaths,
    allowedUrls: target.allowedUrls,
    allowedMethods: target.allowedMethods,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function normalizeTarget(target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) fail('target must be an object.');
  const targetId = requireNonEmptyString(target.target_id, 'target_id');
  const programName = requireNonEmptyString(target.program_name, 'program_name');
  const authorizationReference = requireNonEmptyString(target.authorization_reference, 'authorization_reference');
  if (!Array.isArray(target.allowed_domains) || target.allowed_domains.length === 0) fail('allowed_domains must contain at least one domain.');

  const allowedDomains = target.allowed_domains.map((entry, index) => normalizeDomain(entry, `allowed_domains[${index}]`));
  const excludedDomains = (target.excluded_domains || []).map((entry, index) => normalizeDomain(entry, `excluded_domains[${index}]`));
  const excludedPaths = [...new Set([
    ...DEFAULT_EXCLUDED_PATHS,
    ...(target.excluded_paths || []),
  ].map((entry, index) => normalizePath(entry, `excluded_paths[${index}]`)))];
  const allowedUrls = (target.allowed_urls || []).map((entry, index) => normalizeUrl(entry, `allowed_urls[${index}]`));

  for (const allowedUrl of allowedUrls) {
    if (!allowedDomains.some((pattern) => domainMatches(allowedUrl.hostname, pattern))) {
      fail('allowed_urls may not extend the allowed_domains boundary in this version.');
    }
  }

  const allowedMethods = target.allowed_methods || ['passive_recon', 'dns_resolution', 'http_probing', 'crawling', 'safe_scanning'];
  if (!Array.isArray(allowedMethods) || allowedMethods.some((method) => !ALLOWED_METHODS.has(method))) {
    fail('allowed_methods contains an unsupported method.');
  }
  if (target.requires_approval !== undefined && typeof target.requires_approval !== 'boolean') fail('requires_approval must be boolean.');

  return freezeTarget({
    targetId,
    programName,
    authorizationReference,
    authorizationStatus: 'declared_not_verified',
    allowedDomains,
    excludedDomains,
    excludedPaths,
    allowedUrls,
    allowedMethods: [...new Set(allowedMethods)],
    rateLimit: normalizeRateLimit(target.rate_limit),
    requestBudget: normalizeRequestBudget(target.request_budget),
    requiresApproval: target.requires_approval ?? true,
  });
}

function decision(allowed, reason, detail = {}) {
  return Object.freeze({ allowed, reason, ...detail });
}

function evaluateTargetRequest(target, requestUrl) {
  let request;
  try {
    request = normalizeUrl(requestUrl, 'request URL');
  } catch (error) {
    return decision(false, 'INVALID_URL', { detail: error.message });
  }
  const excludedDomain = target.excludedDomains.find((pattern) => excludedDomainMatches(request.hostname, pattern));
  if (excludedDomain) return decision(false, 'EXCLUDED_DOMAIN', { hostname: request.hostname, pattern: excludedDomain.raw });
  const allowedDomain = target.allowedDomains.find((pattern) => domainMatches(request.hostname, pattern));
  if (!allowedDomain) return decision(false, 'HOST_OUT_OF_SCOPE', { hostname: request.hostname });
  const excludedPath = target.excludedPaths.find((entry) => pathMatches(request.path, entry));
  if (excludedPath) return decision(false, 'EXCLUDED_PATH', { hostname: request.hostname, path: request.path, pattern: excludedPath });
  return decision(true, 'IN_SCOPE', { hostname: request.hostname, path: request.path, pattern: allowedDomain.raw });
}

class TargetRegistry {
  #targets = new Map();

  register(target) {
    const normalized = normalizeTarget(target);
    if (this.#targets.has(normalized.targetId)) throw new Error(`Target is already registered: ${normalized.targetId}`);
    this.#targets.set(normalized.targetId, normalized);
    return normalized;
  }

  evaluate(targetId, requestUrl) {
    const target = this.#targets.get(targetId);
    if (!target) return decision(false, 'TARGET_NOT_REGISTERED', { targetId });
    return evaluateTargetRequest(target, requestUrl);
  }

  getScopeFingerprint(targetId) {
    const target = this.#targets.get(targetId);
    return target ? scopeFingerprint(target) : null;
  }

  isMethodAllowed(targetId, method) {
    const target = this.#targets.get(targetId);
    return Boolean(target && typeof method === 'string' && target.allowedMethods.includes(method));
  }
}

module.exports = { DEFAULT_EXCLUDED_PATHS, TargetRegistry, evaluateTargetRequest, normalizeTarget };
