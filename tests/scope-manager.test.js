const assert = require('node:assert/strict');
const test = require('node:test');
const { TargetRegistry, normalizeTarget } = require('../src/scope/target-registry');

function target(overrides = {}) {
  return {
    target_id: 'local-lab',
    program_name: 'Local test fixture',
    authorization_reference: 'LOCAL-LAB-ONLY',
    allowed_domains: ['example.test', '*.example.test'],
    excluded_domains: ['admin.example.test'],
    excluded_paths: ['/account/remove'],
    ...overrides,
  };
}

test('uses default deny for an unregistered target and an outside host', () => {
  const registry = new TargetRegistry();
  assert.equal(registry.evaluate('missing', 'https://example.test/').reason, 'TARGET_NOT_REGISTERED');
  registry.register(target());
  const result = registry.evaluate('local-lab', 'https://outside.test/');
  assert.deepEqual(result, { allowed: false, reason: 'HOST_OUT_OF_SCOPE', hostname: 'outside.test' });
});

test('accepts an exact allowlist entry and a permitted wildcard subdomain', () => {
  const registry = new TargetRegistry();
  registry.register(target());
  assert.equal(registry.evaluate('local-lab', 'https://example.test/docs').allowed, true);
  assert.equal(registry.evaluate('local-lab', 'https://app.example.test/docs').allowed, true);
});

test('gives excluded domains precedence over allowlist wildcards, including children', () => {
  const registry = new TargetRegistry();
  registry.register(target());
  assert.equal(registry.evaluate('local-lab', 'https://admin.example.test/').reason, 'EXCLUDED_DOMAIN');
  assert.equal(registry.evaluate('local-lab', 'https://v2.admin.example.test/').reason, 'EXCLUDED_DOMAIN');
});

test('blocks policy-default and configured excluded paths after percent decoding', () => {
  const registry = new TargetRegistry();
  registry.register(target());
  assert.equal(registry.evaluate('local-lab', 'https://app.example.test/logout%2Fsession').reason, 'EXCLUDED_PATH');
  assert.equal(registry.evaluate('local-lab', 'https://app.example.test/account/remove/history').reason, 'EXCLUDED_PATH');
});

test('rejects malformed, credentialed, IP-address, and boundary-extending registrations', () => {
  const registry = new TargetRegistry();
  registry.register(target());
  assert.equal(registry.evaluate('local-lab', 'https://user:pass@example.test/').reason, 'INVALID_URL');
  assert.equal(registry.evaluate('local-lab', 'https://127.0.0.1/').reason, 'INVALID_URL');
  assert.throws(() => normalizeTarget(target({ allowed_urls: ['https://third-party.test/'] })), /may not extend/);
  assert.throws(() => normalizeTarget(target({ request_budget: 10_001 })), /request_budget/);
  assert.throws(() => normalizeTarget(target({ rate_limit: { concurrency: 3 } })), /rate_limit.concurrency/);
});
