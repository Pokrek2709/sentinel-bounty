// Twenty-seventh REAL detector (Phase 5, round 113): tainted-redos.
//
// The twelfth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to
// regular-expression construction and use. It reuses the
// shared taint engine (`src/detection/taint-engine.js`,
// extracted in round 101); this module only supplies the
// detector's config (sink tables, finding metadata) and
// re-exports the shared constants. See
// docs/parser-taint-scope-v1.md §17 for the scoping (ReDoS
// was the second of the two JavaScript classes of round
// 113, the return to JavaScript after the Solidity set
// closed in round 112) and
// docs/detection-tainted-redos-v1.md for the detector doc.
//
// Round 113 is the second round to EXTEND the shared engine
// for a new sink shape (round 104 was the first): `new`
// expressions are now sink-checked like calls, so `new
// RegExp(tainted)` flags exactly like `RegExp(tainted)`.
// The extension is config-driven and additive; no earlier
// detector declares a sink named like a constructor, so
// earlier detectors behave exactly as before.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the regex
//     pattern) is tainted (kind 'tainted-arg', evidence
//     carries the taint chain — since round 101 the chain
//     may cross function boundaries: call-site values ->
//     callee parameter -> sink);
//   - an ALIASED sink call (`const R = RegExp`, `const m
//     = str.match` is not a call — aliases are identifier
//     bindings, e.g. `const re = RegExp; re(tainted)`)
//     with any argument (kind 'aliased-call', evidence
//     carries the alias binding — the regex detector
//     cannot see these calls at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — regular-expression use, CWE-1333).
// The first argument (the pattern) is judged. Only the
// listed shapes are sinks:
//   - `RegExp(tainted)` and `new RegExp(tainted)` (a bare
//     sink): the pattern is compiled as a regular
//     expression, so attacker control of the pattern is a
//     denial-of-service vector.
//   - `str.match` / `str.search` (method sinks, matched by
//     method name alone, whatever the receiver): a string
//     argument is coerced to a regular expression, so a
//     tainted pattern is a vector exactly like `RegExp`.
//   - `str.replace` / `str.split` (method sinks): a string
//     argument is matched LITERALLY (no regex compilation),
//     so only a tainted RegExp OBJECT passed as the
//     pattern is a vector — the engine cannot tell a
//     tainted string from a tainted RegExp object, so a
//     finding here is `potential` and the operator must
//     check the pattern's type. Pinned by tests and stated
//     in the detector doc, not hidden.
// `regex.test` / `regex.exec` are NOT sinks: the danger
// lives in the receiver pattern, which the engine cannot
// analyze for catastrophic backtracking (there is no
// regex-complexity analysis — see below). `matchAll` is
// NOT a sink (outside the brief's named scope; a string
// argument to `matchAll` throws). A bare `match(...)` /
// `search(...)` / `replace(...)` / `split(...)` call
// matches the method sink by name alone (the engine's
// method-sink rule, same as `insertAdjacentHTML` in the
// XSS detector) and is flagged.
//
// NO REGEX-COMPLEXITY ANALYSIS — the honest limit of this
// detector, stated here and in the doc, not hidden: the
// engine never inspects pattern text. A tainted pattern
// reaching a sink is flagged because the attacker fully or
// partly controls the pattern, so any catastrophic
// construct (nested quantifiers such as `(a+)+`,
// `(a|a)*`, `(a*)*`) can be supplied — but the detector
// does NOT prove the pattern contains one. A tainted
// pattern that is in fact harmless (for example a plain
// literal string used with `match`/`search`, or a pattern
// validated elsewhere) is a false positive the operator
// must dismiss. Conversely a clean pattern is never
// flagged, however catastrophic it looks: the pattern is
// developer-controlled, so there is no attacker vector.
// Severity is `medium`: the impact is availability only
// (CPU exhaustion), never data disclosure or code
// execution.
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
// (the regex pattern) is judged. `RegExp` is a bare sink:
// it fires for `RegExp(tainted)` and, via the round-113
// engine extension, for `new RegExp(tainted)`.
const SINKS = {
  'RegExp': { label: 'RegExp() call' },
};

// Method sinks: matched by method name alone, whatever the
// receiver. `match` / `search` coerce a string argument to
// a RegExp (a tainted pattern is a vector); `replace` /
// `split` match a string argument literally (only a tainted
// RegExp object is a vector — see the module header).
const METHOD_SINKS = {
  match: { label: 'String.match() call' },
  search: { label: 'String.search() call' },
  replace: { label: 'String.replace() call' },
  split: { label: 'String.split() call' },
};

// No import tables: `RegExp` and the string methods are
// built-ins, not module members — there is nothing to
// resolve through imports.

const CONFIG = {
  detectorName: 'tainted-redos',
  vulnerabilityType: 'regular expression denial of service',
  severity: 'medium',
  cweId: 'CWE-1333',
  impact: 'These calls compile attacker-controlled input as a regular expression (or receive it as a regex pattern), so a crafted pattern with catastrophic backtracking can exhaust the CPU and deny service.',
  remediation: 'Never compile untrusted input as a regular expression: validate or allow-list the pattern first, use a literal string search or a timeout-bounded / linear-time regex engine where one is available, and prefer exact-match or parsed input over free-form patterns.',
  sinks: SINKS,
  methodSinks: METHOD_SINKS,
};

const taintedRedosDetector = createTaintDetector(CONFIG);

module.exports = taintedRedosDetector;
module.exports.taintedRedosDetector = taintedRedosDetector;
module.exports.SINKS = SINKS;
module.exports.METHOD_SINKS = METHOD_SINKS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-redos', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
