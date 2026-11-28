// Thirteenth REAL detector (Phase 5, round 107): tainted-ldap.
//
// The eighth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to LDAP
// search sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §11 for the
// scoping (LDAP was one of the three named AST classes
// after tainted SSRF) and docs/detection-tainted-ldap-v1.md
// for the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose judged argument (the
//     filter / options, argument 2) is tainted (kind
//     'tainted-arg', evidence carries the taint chain —
//     since round 101 the chain may cross function
//     boundaries: call-site values -> callee parameter
//     -> sink);
//   - an ALIASED sink call (`const s = client.search`,
//     `const { search } = client`) with any argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these
//     calls at all).
// A direct sink call with a clean judged argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — the ldapjs search call). The judged
// argument is the SECOND one (argIndex 1): `client.search`
// takes `(base, options, callback)` in ldapjs, and the
// LDAP filter lives in `options` — either as a string
// filter or as an object (`{ filter: '...' }`, judged as
// a whole because an object's properties' taint joins).
// The first argument (the search base DN) is NOT judged
// in this round: a tainted base is DN injection, a
// different shape from the classic filter injection this
// detector covers — documented limitation, pinned by a
// test. Only the listed two-part member call is a sink:
// a bare `search(...)` is deliberately NOT a sink (the
// name is too generic), and a three-part call
// (`app.client.search(...)`) is not resolved either.
// `client.bind` / `client.add` / `client.modify` /
// `client.del` are NOT sinks (they are not search
// queries). Other LDAP shapes stay regex-covered by
// dangerous-call — this parser is JavaScript-only by
// design.
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

// Canonical sink name -> { label, argIndex }. The judged
// argument is the SECOND one (argIndex 1): the filter /
// options of `client.search(base, options, callback)`.
// The first argument (the search base DN) is NOT judged.
const SINKS = {
  'client.search': { label: 'client.search() call', argIndex: 1 },
};

// Object roots whose destructured members resolve to sinks:
// `const { search } = client` binds `search` to
// `client.search`.
const SINK_ROOTS = {
  client: ['search'],
};

// Import resolution (round 106): module name -> sink root.
const MODULE_ROOTS = {
  'ldapjs': 'client',
  'ldapts': 'client',
};

const CONFIG = {
  detectorName: 'tainted-ldap',
  vulnerabilityType: 'ldap injection',
  severity: 'high',
  cweId: 'CWE-90',
  impact: 'These calls hand a search filter to an LDAP directory, so attacker-controlled input reaching them is LDAP injection: directory queries the attacker controls, authentication bypass through crafted filters, and disclosure of directory entries the application did not intend to expose.',
  remediation: 'Never pass untrusted input as an LDAP filter: build filters from a fixed template with escaped values (escape *, (, ), \\, and NUL per RFC 4515), or use a parameterized LDAP API; validate the filter against an allow-list of expected shapes before searching.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
};

const taintedLdapDetector = createTaintDetector(CONFIG);

module.exports = taintedLdapDetector;
module.exports.taintedLdapDetector = taintedLdapDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-ldap', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
