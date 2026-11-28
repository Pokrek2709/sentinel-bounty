// Fifteenth REAL detector (Phase 5, round 107): tainted-open-redirect.
//
// The tenth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to HTTP
// redirect sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §11 for the
// scoping (open redirect was one of the three named AST
// classes after tainted SSRF) and
// docs/detection-tainted-open-redirect-v1.md for the
// detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the redirect
//     URL) is tainted (kind 'tainted-arg', evidence carries
//     the taint chain — since round 101 the chain may cross
//     function boundaries: call-site values -> callee
//     parameter -> sink);
//   - an ALIASED sink call (`const r = res.redirect`,
//     `const { redirect } = res`) with any argument (kind
//     'aliased-call', evidence carries the alias binding
//     — the regex detector cannot see these calls at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — HTTP redirects: Express `res`,
// Fastify `reply`, Koa `ctx`, and the `response` alias).
// Only the listed two-part member calls are sinks: a bare
// `redirect(...)` is deliberately NOT a sink (the name is
// too generic), and a three-part call
// (`app.res.redirect(...)`) is not resolved either.
// `res.render` is NOT a sink (a view name, not a redirect
// URL). A `window.location` assignment is NOT a sink in
// this round (an assignment shape, not a redirect call —
// future work). Other redirect shapes stay regex-covered
// by dangerous-call — this parser is JavaScript-only by
// design. Only the FIRST argument is judged (the URL):
// the two-argument form `res.redirect(status, url)`
// judges only its first argument (the status, normally a
// constant) — a tainted URL in second position is NOT
// covered in this round, documented limitation.
//
// Sources: every function parameter (untrusted input by
// definition) and member access rooted at `process.argv`.
// Since round 101 taint also flows across function
// boundaries (call graph) and through return values; a
// helper never called, or called only with clean arguments,
// is still analyzed with parameters-as-sources (the
// round-95 fallback), so its sink is flagged with
// confidence `potential` and no claim of reachability.
//
// Safety properties (tested, not assumed): see
// src/detection/taint-engine.js — a finding carries only
// the sink name, position, and a taint chain of IDENTIFIER
// NAMES, never a literal value or a source line; one
// finding per distinct sink call site per record; caps,
// determinism, and the no-regex-fallback rule are enforced
// by the shared engine.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
  memberName,
  createTaintDetector,
} = require('./taint-engine');

// Canonical sink name -> { label }. The first argument
// (the redirect URL) is judged.
const SINKS = {
  'res.redirect': { label: 'res.redirect() call' },
  'response.redirect': { label: 'response.redirect() call' },
  'reply.redirect': { label: 'reply.redirect() call' },
  'ctx.redirect': { label: 'ctx.redirect() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { redirect } = res` binds `redirect` to
// `res.redirect`.
const SINK_ROOTS = {
  res: ['redirect'],
  response: ['redirect'],
  reply: ['redirect'],
  ctx: ['redirect'],
};

// No import resolution table: res / response / reply / ctx
// are request-handler parameters, not modules.

const CONFIG = {
  detectorName: 'tainted-open-redirect',
  vulnerabilityType: 'open redirect',
  severity: 'high',
  cweId: 'CWE-601',
  impact: 'These calls hand a URL to an HTTP redirect, so attacker-controlled input reaching them is open redirect: victims sent to attacker-controlled pages, phishing under the application\'s own domain, and OAuth/token theft through redirect-based flows.',
  remediation: 'Never pass untrusted input as a redirect URL: validate the URL against an allow-list of hosts and relative paths, reject absolute URLs to other origins, or redirect only to a fixed set of known routes.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
};

const taintedOpenRedirectDetector = createTaintDetector(CONFIG);

module.exports = taintedOpenRedirectDetector;
module.exports.taintedOpenRedirectDetector = taintedOpenRedirectDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-open-redirect', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
