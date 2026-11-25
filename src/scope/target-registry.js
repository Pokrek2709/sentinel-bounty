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

function normalizeDefaultExcludedPaths(value) {
  // `default_excluded_paths` is the target file's override for the
  // built-in default excluded paths (round 54, Phase 3). An absent field
  // keeps the built-in defaults; a present field REPLACES them for this
  // target only — an empty array means "no default exclusions". A
  // non-array value, or an entry that is not an absolute path, fails
  // loudly; there is no silent fallback to the built-in list.
  if (!Array.isArray(value)) fail('default_excluded_paths must be an array of absolute paths.');
  return value.map((entry, index) => normalizePath(entry, `default_excluded_paths[${index}]`));
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
  Object.freeze(target.defaultExcludedPaths);
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
  const defaultExcludedPathsOverridden = target.default_excluded_paths !== undefined;
  const defaultExcludedPaths = defaultExcludedPathsOverridden
    ? normalizeDefaultExcludedPaths(target.default_excluded_paths)
    : [...DEFAULT_EXCLUDED_PATHS];
  const excludedPaths = [...new Set([
    ...defaultExcludedPaths,
    ...(target.excluded_paths || []).map((entry, index) => normalizePath(entry, `excluded_paths[${index}]`)),
  ])];
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
    // The effective default excluded-path list for this target, and
    // whether it came from the target file's `default_excluded_paths`
    // override (round 54) rather than the built-in defaults. The trail
    // and the suggestion use these to cite the right source.
    defaultExcludedPaths,
    defaultExcludedPathsOverridden,
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

// --- Scope-decision explainability (round 52, Phase 3) ---------------------
// The scope rules are evaluated in a fixed order; the first rule whose
// condition holds decides the outcome and the rest are never evaluated.
// A trail records every rule in that order, honestly marking the ones
// that were short-circuited as not evaluated. The decision logic itself
// is unchanged: explainability only observes it.

const TRAIL_RULES = Object.freeze([
  { rule: 'TARGET_REGISTERED', description: 'The target_id is registered in this registry.' },
  { rule: 'URL_VALID', description: 'The request URL is an absolute http(s) URL without credentials or an IP host.' },
  { rule: 'EXCLUDED_DOMAIN', description: 'The request hostname matches an excluded domain (exact or subdomain).' },
  { rule: 'ALLOWED_DOMAIN', description: 'The request hostname matches no allowed domain.' },
  { rule: 'EXCLUDED_PATH', description: 'The request path matches an excluded path.' },
  { rule: 'IN_SCOPE', description: 'All scope rules passed; the request is in scope.' },
]);

const BUILTIN_SOURCE = 'built-in: src/scope/target-registry.js';
const BUILTIN_PATH_SOURCE = 'built-in default: src/scope/target-registry.js (DEFAULT_EXCLUDED_PATHS); policies/scope-policy.md section 4';

function trailEntry(rule, evaluated, matched, outcome, source, detail, note) {
  const meta = TRAIL_RULES.find((entry) => entry.rule === rule);
  return Object.freeze({
    rule,
    description: meta ? meta.description : '',
    evaluated,
    matched,
    outcome,
    source,
    detail: Object.freeze(detail),
    note,
  });
}

function notEvaluatedEntries(ruleNames, sourceFor) {
  return ruleNames.map((rule) => trailEntry(
    rule, false, false, 'not-evaluated', sourceFor(rule), {},
    'An earlier rule already decided the outcome.',
  ));
}

function targetFileSource(targetFile, field) {
  return targetFile ? `target file: ${targetFile} (${field})` : `target file (${field})`;
}

function suggestionFor(reason, detail, targetFile, context = {}) {
  switch (reason) {
    case 'TARGET_NOT_REGISTERED':
      return `Register the target first: sentinel check-scope --target <target.json> --url <url> with target_id "${detail.targetId}".`;
    case 'INVALID_URL':
      return 'Fix the request URL: use an absolute http(s) URL without credentials or an IP host.';
    case 'EXCLUDED_DOMAIN':
      return `Remove "${detail.pattern}" from excluded_domains in ${targetFile || 'the target file'}, or use a different host.`;
    case 'HOST_OUT_OF_SCOPE':
      return `Add "${detail.hostname}" (or a matching wildcard) to allowed_domains in ${targetFile || 'the target file'}.`;
    case 'EXCLUDED_PATH':
      // Round 54 changed the policy: a built-in default path CAN now be
      // overridden for a target by declaring `default_excluded_paths` in
      // the target file. The suggestion therefore names the override
      // instead of saying "cannot be un-excluded" (the round-52 wording).
      if (context.fromDefaultList) {
        if (context.defaultExcludedPathsOverridden) {
          return `Remove "${detail.pattern}" from default_excluded_paths in ${targetFile || 'the target file'}, or use a different path.`;
        }
        return `"${detail.pattern}" is a built-in policy default (policies/scope-policy.md section 4). To allow it for this target, declare "default_excluded_paths" in the target file — a list that replaces the built-in defaults — or use a different path.`;
      }
      return `Remove "${detail.pattern}" from excluded_paths in ${targetFile || 'the target file'}, or use a different path.`;
    case 'IN_SCOPE':
      return 'No change needed — the request is in scope.';
    default:
      return 'No suggestion recorded for this decision.';
  }
}

// Evaluates a request against a normalized target and returns the decision
// together with the full rule trail. The decision object is identical to
// what evaluateTargetRequest returns; only the observation is new.
function evaluateTargetRequestWithTrail(target, requestUrl, source = {}) {
  const targetFile = source.targetFile || null;
  const trail = [];
  const rest = (fromIndex) => notEvaluatedEntries(
    TRAIL_RULES.slice(fromIndex).map((entry) => entry.rule),
    (rule) => (rule === 'EXCLUDED_PATH' ? targetFileSource(targetFile, 'excluded_paths') : targetFileSource(targetFile, 'allowed_domains')),
  );

  let request;
  try {
    request = normalizeUrl(requestUrl, 'request URL');
  } catch (error) {
    const detail = { detail: error.message };
    trail.push(trailEntry('URL_VALID', true, true, 'deny', BUILTIN_SOURCE, { url: requestUrl, error: error.message }, `Request URL is not valid: ${error.message}`));
    trail.push(...rest(2));
    return {
      decision: decision(false, 'INVALID_URL', detail),
      trail,
      decidingRule: 'URL_VALID',
      suggestion: suggestionFor('INVALID_URL', detail, targetFile),
    };
  }
  trail.push(trailEntry('URL_VALID', true, false, 'pass', BUILTIN_SOURCE, { url: requestUrl }, 'Request URL parses as an absolute http(s) URL.'));

  const excludedDomain = target.excludedDomains.find((pattern) => excludedDomainMatches(request.hostname, pattern));
  if (excludedDomain) {
    const detail = { hostname: request.hostname, pattern: excludedDomain.raw };
    trail.push(trailEntry('EXCLUDED_DOMAIN', true, true, 'deny', targetFileSource(targetFile, 'excluded_domains'), detail, `Hostname "${request.hostname}" matches excluded domain "${excludedDomain.raw}".`));
    trail.push(...rest(3));
    return {
      decision: decision(false, 'EXCLUDED_DOMAIN', detail),
      trail,
      decidingRule: 'EXCLUDED_DOMAIN',
      suggestion: suggestionFor('EXCLUDED_DOMAIN', detail, targetFile),
    };
  }
  trail.push(trailEntry('EXCLUDED_DOMAIN', true, false, 'pass', targetFileSource(targetFile, 'excluded_domains'), { hostname: request.hostname }, `Hostname "${request.hostname}" matches no excluded domain.`));

  const allowedDomain = target.allowedDomains.find((pattern) => domainMatches(request.hostname, pattern));
  if (!allowedDomain) {
    const detail = { hostname: request.hostname };
    trail.push(trailEntry('ALLOWED_DOMAIN', true, true, 'deny', targetFileSource(targetFile, 'allowed_domains'), detail, `Hostname "${request.hostname}" matches no allowed domain.`));
    trail.push(...rest(4));
    return {
      decision: decision(false, 'HOST_OUT_OF_SCOPE', detail),
      trail,
      decidingRule: 'ALLOWED_DOMAIN',
      suggestion: suggestionFor('HOST_OUT_OF_SCOPE', detail, targetFile),
    };
  }
  trail.push(trailEntry('ALLOWED_DOMAIN', true, false, 'pass', targetFileSource(targetFile, 'allowed_domains'), { hostname: request.hostname, pattern: allowedDomain.raw }, `Hostname "${request.hostname}" matches allowed domain "${allowedDomain.raw}".`));

  const excludedPath = target.excludedPaths.find((entry) => pathMatches(request.path, entry));
  if (excludedPath) {
    const detail = { hostname: request.hostname, path: request.path, pattern: excludedPath };
    // The decision detail stays exactly {hostname, path, pattern} (the
    // pre-existing shape); the default-list provenance is passed to the
    // suggestion separately, so the decision object never changes shape.
    const fromDefaultList = target.defaultExcludedPaths.includes(excludedPath);
    const pathSource = fromDefaultList
      ? (target.defaultExcludedPathsOverridden ? targetFileSource(targetFile, 'default_excluded_paths') : BUILTIN_PATH_SOURCE)
      : targetFileSource(targetFile, 'excluded_paths');
    trail.push(trailEntry('EXCLUDED_PATH', true, true, 'deny', pathSource, detail, `Path "${request.path}" matches excluded path "${excludedPath}".`));
    trail.push(...rest(5));
    return {
      decision: decision(false, 'EXCLUDED_PATH', detail),
      trail,
      decidingRule: 'EXCLUDED_PATH',
      suggestion: suggestionFor('EXCLUDED_PATH', detail, targetFile, { fromDefaultList, defaultExcludedPathsOverridden: target.defaultExcludedPathsOverridden }),
    };
  }
  trail.push(trailEntry('EXCLUDED_PATH', true, false, 'pass', targetFileSource(targetFile, 'excluded_paths'), { hostname: request.hostname, path: request.path }, `Path "${request.path}" matches no excluded path.`));

  const detail = { hostname: request.hostname, path: request.path, pattern: allowedDomain.raw };
  trail.push(trailEntry('IN_SCOPE', true, true, 'allow', targetFileSource(targetFile, 'allowed_domains'), detail, 'All scope rules passed.'));
  return {
    decision: decision(true, 'IN_SCOPE', detail),
    trail,
    decidingRule: 'IN_SCOPE',
    suggestion: suggestionFor('IN_SCOPE', detail, targetFile),
  };
}

function renderScopeExplanationText(explanation) {
  const lines = [
    'Scope decision',
    `  Target: ${explanation.targetId}`,
    `  Request URL: ${explanation.requestUrl}`,
    `  Decision: ${explanation.decision.reason} (${explanation.decision.allowed ? 'allowed' : 'denied'})`,
    `  Policy source: ${explanation.source.targetFile || '(target file path not provided)'}`,
    '',
    '  Rules evaluated in order:',
  ];
  explanation.rules.forEach((entry, index) => {
    const verdict = entry.outcome === 'allow' ? 'DECIDED (allow)'
      : entry.outcome === 'deny' ? 'DECIDED (deny)'
        : entry.outcome === 'pass' ? 'passed'
          : 'not evaluated';
    lines.push(`  ${index + 1}. ${entry.rule}: ${verdict} — ${entry.note} (source: ${entry.source})`);
  });
  lines.push(
    '',
    `  Deciding rule: ${explanation.decidingRule}`,
    `  Suggestion: ${explanation.suggestion}`,
  );
  return lines.join('\n');
}

function evaluateTargetRequest(target, requestUrl) {
  return evaluateTargetRequestWithTrail(target, requestUrl).decision;
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

  // Explains a scope decision: the decision itself plus the ordered rule
  // trail, the deciding rule, and a suggestion. The decision is identical
  // to evaluate(); only the observation is new. `source.targetFile` is the
  // --target file path, used to cite the policy source in the trail.
  explain(targetId, requestUrl, source = {}) {
    const targetFile = source.targetFile || null;
    const target = this.#targets.get(targetId);
    if (!target) {
      const detail = { targetId };
      const trail = [
        trailEntry('TARGET_REGISTERED', true, true, 'deny', 'registry: TargetRegistry', detail, `Target "${targetId}" is not registered in this registry.`),
        ...notEvaluatedEntries(
          ['URL_VALID', 'EXCLUDED_DOMAIN', 'ALLOWED_DOMAIN', 'EXCLUDED_PATH', 'IN_SCOPE'],
          (rule) => (rule === 'EXCLUDED_PATH' ? targetFileSource(targetFile, 'excluded_paths') : targetFileSource(targetFile, 'allowed_domains')),
        ),
      ];
      return Object.freeze({
        targetId,
        requestUrl,
        decision: decision(false, 'TARGET_NOT_REGISTERED', detail),
        rules: trail,
        decidingRule: 'TARGET_REGISTERED',
        suggestion: suggestionFor('TARGET_NOT_REGISTERED', detail, targetFile),
        source: Object.freeze({ targetFile }),
      });
    }
    const evaluated = evaluateTargetRequestWithTrail(target, requestUrl, source);
    const registered = trailEntry(
      'TARGET_REGISTERED', true, false, 'pass',
      targetFile ? `registry: TargetRegistry (registered from ${targetFile})` : 'registry: TargetRegistry',
      { targetId },
      `Target "${targetId}" is registered.`,
    );
    return Object.freeze({
      targetId,
      requestUrl,
      decision: evaluated.decision,
      rules: Object.freeze([registered, ...evaluated.trail]),
      decidingRule: evaluated.decidingRule,
      suggestion: evaluated.suggestion,
      source: Object.freeze({ targetFile }),
    });
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

module.exports = { DEFAULT_EXCLUDED_PATHS, TargetRegistry, evaluateTargetRequest, evaluateTargetRequestWithTrail, renderScopeExplanationText, normalizeTarget, normalizeUrl };
