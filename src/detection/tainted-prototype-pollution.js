// Twenty-eighth REAL detector (Phase 5, round 114): tainted-prototype-pollution.
//
// The thirteenth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to
// prototype-pollution sinks. It reuses the shared taint
// engine (`src/detection/taint-engine.js`, extracted in
// round 101); this module only supplies the detector's
// config (sink tables, finding metadata) and re-exports the
// shared constants. See docs/parser-taint-scope-v1.md §18
// for the scoping (prototype pollution was the last
// JavaScript class on the approved map, after XXE + ReDoS
// in round 113, before the language rounds) and
// docs/detection-tainted-prototype-pollution-v1.md for the
// detector doc.
//
// Round 114 is the third round to EXTEND the shared engine
// for a new sink shape (round 104 was the first, round 113
// the second): a sink entry may name `argIndexFrom` (every
// argument from that index on is judged — merge sinks
// judge their sources from index 1, `$.extend` from index
// 2), a config may set `flagAssignmentKeys` (a computed
// member assignment whose key is tainted, and an
// assignment whose target chain carries a dangerous
// prototype key), a config may set `flagTaintedSpread` (a
// spread of a tainted value inside an object literal), and
// a sink entry may carry `nullProtoTargetSafe` (a merge
// into an object created by `Object.create(null)` is not
// a finding). All four extensions are config-driven and
// additive; detectors that declare none of them behave
// exactly as before.
//
// A sink is reported ONLY when it carries information the
// regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT merge call whose judged source argument is
//     tainted (kind 'tainted-arg', evidence carries the
//     taint chain — since round 101 the chain may cross
//     function boundaries: call-site values -> callee
//     parameter -> sink);
//   - an ALIASED merge call (`const a = Object.assign`,
//     `const { merge } = _`) with any argument (kind
//     'aliased-call', evidence carries the alias binding
//     — the regex detector cannot see these calls at
//     all);
//   - a DYNAMIC-KEY assignment (`obj[key] = value`,
//     `obj[key] += value`) whose key expression is
//     tainted (kind 'tainted-key-assign', evidence
//     carries the key's taint chain);
//   - a DANGEROUS-KEY assignment whose target chain
//     carries a prototype key (`__proto__` anywhere,
//     the ordered pair `constructor` -> `prototype`, or
//     a root of `Object.prototype`) — a static pattern,
//     not a taint flow (kind 'dangerous-key-assign',
//     evidence carries the key path, identifier names
//     only, and no taint chain);
//   - an OBJECT SPREAD (`{...tainted}`) whose spread
//     value is tainted (kind 'tainted-spread', evidence
//     carries the taint chain).
// A direct sink call with clean judged arguments is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — prototype pollution, CWE-1321).
// Only the listed shapes are sinks:
//   - `Object.assign(target, ...sources)`: every source
//     argument (from index 1) is judged. A tainted source
//     can carry a `__proto__` key, and `Object.assign`
//     writes it through [[Set]], so the target's
//     prototype changes. A merge into a target created
//     by `Object.create(null)` is NOT a finding (no
//     `__proto__` setter — the write lands as an own
//     property).
//   - `_.merge(target, ...sources)` / `_.defaultsDeep
//     (target, ...sources)` (lodash): every source
//     argument (from index 1) is judged. The recursive
//     merge follows a `constructor` -> `prototype` path
//     in the source, so a tainted source pollutes
//     `Object.prototype` itself. Same null-prototype
//     target exemption as `Object.assign`.
//   - `_.set(obj, path, value)` (lodash): the path
//     (argument 1) is judged — a tainted path can be
//     `__proto__.polluted`. Same null-prototype target
//     exemption (the target is argument 0).
//   - `$.extend(true, target, ...sources)` (jQuery): every
//     source argument (from index 2 — the deep flag
//     occupies index 0) is judged. The two-argument
//     shallow form is NOT judged (its sources start at
//     index 1), and jQuery 3.4.0+ skips `__proto__` in
//     `extend` anyway, so the finding needs
//     version-specific verification. No null-prototype
//     exemption: the deep flag makes the target position
//     ambiguous.
//   - `merge(a, b)` (deepmerge, bare name): every source
//     argument (from index 1) is judged. Both arguments
//     are sources and the result is a new object, so
//     there is no target to exempt.
//   - `merge.all([a, b, ...])` (deepmerge): the array
//     argument (index 0) is judged.
// A bare `merge(...)` is a sink by name (like bare
// `fetch` / `unserialize` in the earlier detectors) — a
// user-defined function named `merge` would be flagged
// the same way, and the finding stays confidence
// `potential` for exactly that reason. `Object.defineProperty`
// is NOT a sink (it defines an own property, it does not
// trigger the `__proto__` setter). `delete` is not a
// write. `__defineGetter__` / `__defineSetter__` are not
// sinks in this round.
//
// Safe patterns (NOT findings, pinned by tests):
//   - A static key that is not dangerous (`obj.name = v`,
//     `obj[key] = v` with a clean key).
//   - A lone leaf `constructor` or `prototype`
//     (`Foo.prototype.constructor = Foo`,
//     `fn.prototype = {...}` — ordinary JavaScript).
//   - A write onto an object created by
//     `Object.create(null)` — directly, or through an
//     identifier copy of one — for the key checks and
//     for the merge sinks that carry
//     `nullProtoTargetSafe`. A write onto a NESTED
//     property of such an object (`o.nested['__proto__']
//     = v`) IS a finding: only the null-prototype object
//     itself is safe.
//   - A spread of a clean value; an array spread
//     (`[...tainted]`); a call spread (`f(...tainted)`).
//   - `Object.assign` / `_.merge` with a clean source;
//     `_.set` with a clean path.
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
// NAMES, never a literal value, never a source line; one
// finding per distinct sink call site per record; caps,
// determinism, and the no-regex-fallback rule are enforced
// by the shared engine. The dangerous-key check inspects
// property names only for a boolean decision; no literal
// value appears in a finding. The spread finding is
// conservative by design: spread copies `__proto__` as an
// own property (no prototype change), so the merged object
// is flagged because it carries attacker-controlled keys
// into any later [[Set]]-based merge — stated in the
// detector doc, not hidden.
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

// Canonical sink name -> { label, argIndex | argIndexFrom, nullProtoTargetSafe? }.
// Merge sinks judge their SOURCE arguments: every argument
// from `argIndexFrom` on (`Object.assign` / `_.merge` /
// `_.defaultsDeep` / `merge` from index 1, `$.extend`
// from index 2 — its deep flag occupies index 0).
// `_.set` judges its path (argument 1). `merge.all`
// judges its array argument (index 0). A sink carrying
// `nullProtoTargetSafe` is not a finding when its target
// argument (index 0) is an object created by
// `Object.create(null)`.
const SINKS = {
  'Object.assign': {
    label: 'Object.assign() call',
    argIndexFrom: 1,
    nullProtoTargetSafe: true,
  },
  '_.merge': {
    label: '_.merge() call',
    argIndexFrom: 1,
    nullProtoTargetSafe: true,
  },
  '_.defaultsDeep': {
    label: '_.defaultsDeep() call',
    argIndexFrom: 1,
    nullProtoTargetSafe: true,
  },
  '_.set': {
    label: '_.set() call',
    argIndex: 1,
    nullProtoTargetSafe: true,
  },
  '$.extend': {
    label: '$.extend() call',
    argIndexFrom: 2,
  },
  merge: {
    label: 'merge() call',
    argIndexFrom: 1,
  },
  'merge.all': {
    label: 'merge.all() call',
    argIndex: 0,
  },
};

// Object roots whose destructured members resolve to sinks:
// `const { merge } = _` binds `merge` to `_.merge`,
// `const { assign } = Object` binds `assign` to
// `Object.assign`, `const { all } = merge` binds `all` to
// `merge.all`.
const SINK_ROOTS = {
  _: ['merge', 'set', 'defaultsDeep'],
  Object: ['assign'],
  $: ['extend'],
  merge: ['all'],
};

// Import resolution (round 106): module name -> sink root
// (`require('lodash')` binds its result to the `_` root;
// `require('jquery')` to the `$` root), and module name
// -> bare sink (`require('deepmerge')` IS the `merge`
// sink).
const MODULE_ROOTS = {
  lodash: '_',
  jquery: '$',
};

const MODULE_BARE_SINKS = {
  deepmerge: 'merge',
};

const CONFIG = {
  detectorName: 'tainted-prototype-pollution',
  vulnerabilityType: 'prototype pollution',
  severity: 'high',
  cweId: 'CWE-1321',
  impact: 'These calls and assignments merge attacker-controlled keys into an object, so a key naming a prototype property (__proto__, or the constructor -> prototype path) writes onto a prototype instead of an own property: pollution of Object.prototype affects every object in the process, and pollution of a single object\'s prototype changes what it inherits.',
  remediation: 'Never merge untrusted keys without filtering them: reject or strip the keys __proto__, constructor, and prototype (and any dotted path containing them) before merging or assigning a dynamic key; prefer merging into an object created with Object.create(null); use library versions that guard prototype keys (lodash 4.17.11+ guards __proto__ in assign paths; jQuery 3.4.0+ skips __proto__ in extend), and validate dynamic keys against an allow-list.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
  moduleBareSinks: MODULE_BARE_SINKS,
  flagAssignmentKeys: true,
  flagTaintedSpread: true,
};

const taintedPrototypePollutionDetector = createTaintDetector(CONFIG);

module.exports = taintedPrototypePollutionDetector;
module.exports.taintedPrototypePollutionDetector = taintedPrototypePollutionDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MODULE_BARE_SINKS = MODULE_BARE_SINKS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-prototype-pollution', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
