// Twelfth REAL detector (Phase 5, round 105): tainted-ssrf.
//
// The seventh PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to
// outbound-request sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §9 for the
// scoping (SSRF was one of the three named AST classes
// after tainted XSS) and docs/detection-tainted-ssrf-v1.md
// for the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the URL)
//     is tainted (kind 'tainted-arg', evidence carries the
//     taint chain — since round 101 the chain may cross
//     function boundaries: call-site values -> callee
//     parameter -> sink);
//   - an ALIASED sink call (`const g = http.get`,
//     `const { request } = http`, `const f = fetch`) with any
//     first argument (kind 'aliased-call', evidence
//     carries the alias binding — the regex detector
//     cannot see these calls at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — the outbound-request call-site
// shapes). The bare names `fetch` and `request` ARE sinks
// in this round: unlike `query` (round 103) or `render`
// (this round's SSTI detector), both names are distinctive
// globals in JavaScript — `fetch` is the platform fetch
// API and `request` is the request library's main export —
// so a bare call is a request by construction. A
// user-defined function of the same name is flagged too
// (documented over-approximation, confidence `potential`
// for exactly this reason). Only the listed two-part
// member calls are sinks otherwise: a three-part call
// (`app.http.get(...)`) is not resolved, and
// `require('http').get(...)` is not resolved (no import
// resolution in this round). `window.fetch` is NOT a sink
// in this round (the `window` receiver is not in the sink
// list — future work). `XMLHttpRequest.open` is NOT a sink
// (client-side XHR, not a server-side request) and
// `WebSocket` is NOT a sink (a different protocol).
// Other shapes stay regex-covered by dangerous-call —
// this parser is JavaScript-only by design. Only the
// FIRST argument is judged (the URL): a tainted second
// argument (options, body, config) is NOT covered in this
// round, documented limitation.
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

// Canonical sink name -> { label }. The bare names `fetch`
// and `request` are sinks by name alone (see header).
const SINKS = {
  fetch: { label: 'fetch() call' },
  request: { label: 'request() call' },
  'http.get': { label: 'http.get() call' },
  'http.request': { label: 'http.request() call' },
  'https.get': { label: 'https.get() call' },
  'https.request': { label: 'https.request() call' },
  'axios.get': { label: 'axios.get() call' },
  'axios.post': { label: 'axios.post() call' },
  'axios.put': { label: 'axios.put() call' },
  'axios.delete': { label: 'axios.delete() call' },
  'axios.request': { label: 'axios.request() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { get } = http` binds `get` to `http.get`.
const SINK_ROOTS = {
  http: ['get', 'request'],
  https: ['get', 'request'],
  axios: ['get', 'post', 'put', 'delete', 'request'],
};

const CONFIG = {
  detectorName: 'tainted-ssrf',
  vulnerabilityType: 'server-side request forgery',
  severity: 'high',
  cweId: 'CWE-918',
  impact: 'These calls hand a URL to an outbound request, so attacker-controlled input reaching them is server-side request forgery: requests to internal services, cloud metadata endpoints, and other addresses the server can reach but the attacker cannot.',
  remediation: 'Never pass untrusted input as a request URL: validate the URL against an allow-list of hosts and schemes, resolve and re-check the host after DNS (or use a fixed egress proxy with an allow-list), and block private/link-local/metadata address ranges.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
};

const taintedSsrfDetector = createTaintDetector(CONFIG);

module.exports = taintedSsrfDetector;
module.exports.taintedSsrfDetector = taintedSsrfDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-ssrf', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
