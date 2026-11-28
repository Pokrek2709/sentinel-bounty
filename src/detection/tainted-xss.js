// Ninth REAL detector (Phase 5, round 104): tainted-xss.
//
// The fourth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to HTML
// sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round 101);
// this module only supplies the detector's config (sink
// tables, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §8 for the
// scoping (XSS was the next named AST class after tainted
// SQL) and docs/detection-tainted-xss-v1.md for the
// detector doc.
//
// Round 104 is the first round to EXTEND the shared engine
// for a new sink shape (round 103 needed no engine change):
// XSS sinks are not all calls. `innerHTML` / `outerHTML`
// are ASSIGNMENT sinks (`el.innerHTML = x`), judged on the
// assigned value, and `insertAdjacentHTML` is a METHOD sink
// (matched by method name alone, whatever the receiver)
// that judges its SECOND argument — the HTML — because its
// first is the position constant. Both shapes are config
// tables in the engine (`assignmentSinks`, `methodSinks`)
// plus a per-sink `argIndex`; the three earlier AST
// detectors define neither table and behave exactly as
// before.
//
// A sink is reported ONLY when it carries information the
// regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose judged argument is tainted
//     (kind 'tainted-arg', evidence carries the taint chain
//     — since round 101 the chain may cross function
//     boundaries: call-site values -> callee parameter ->
//     sink);
//   - an ASSIGNMENT to a sink property whose assigned value
//     is tainted (kind 'tainted-assign', evidence carries
//     the taint chain and the assigned-to target —
//     `el.innerHTML = x`, `document.body.innerHTML = x`,
//     `el['innerHTML'] = x`, `el.innerHTML += x`);
//   - an ALIASED sink call (`const w = document.write`,
//     `const { write } = document`,
//     `const f = el.insertAdjacentHTML`) with any argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these
//     calls at all).
// A direct sink call with a clean judged argument, and an
// assignment of a clean value, are NOT reported: the regex
// detector already flags those call sites, and the AST
// detector adds nothing. A value that passed a sanitizer
// (`Number`, `parseInt`, `parseFloat`, `Boolean` — see
// docs/sanitizer-modeling-v1.md) is clean, so a sink on it
// is not reported.
//
// Sinks (JavaScript): `document.write` / `document.writeln`
// (fixed-root calls — the first argument is the written
// markup), `insertAdjacentHTML` (any receiver — the method
// exists only on DOM elements — judging the second
// argument, the HTML), and the assignment properties
// `innerHTML` / `outerHTML` (any receiver). jQuery `.html()`
// is NOT a sink in this round (a no-argument `.html()` is a
// getter, and the detector does not model jQuery semantics).
// `textContent` / `innerText` are safe by construction and
// are not sinks. Other languages' XSS APIs stay
// regex-covered by dangerous-call — this parser is
// JavaScript-only by design.
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
// finding per distinct sink site per record; caps,
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
  memberPropertyName,
  createTaintDetector,
} = require('./taint-engine');

// Canonical sink name -> { label } for fixed calls.
const SINKS = {
  'document.write': { label: 'document.write() call' },
  'document.writeln': { label: 'document.writeln() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { write } = document` binds `write` to
// `document.write`.
const SINK_ROOTS = {
  document: ['write', 'writeln'],
};

// Method sinks: matched by method name alone, whatever the
// receiver. `insertAdjacentHTML(position, html)` judges its
// SECOND argument (argIndex 1) — the HTML — because the
// first is the position constant ('beforebegin',
// 'afterbegin', 'beforeend', 'afterend').
const METHOD_SINKS = {
  insertAdjacentHTML: { label: 'insertAdjacentHTML() call', argIndex: 1 },
};

// Assignment sinks: properties whose assignment is a sink,
// judged on the assigned value. The receiver is irrelevant
// (`el.innerHTML`, `document.body.innerHTML`,
// `el['innerHTML']` all match).
const ASSIGNMENT_SINKS = {
  innerHTML: { label: 'innerHTML assignment' },
  outerHTML: { label: 'outerHTML assignment' },
};

const CONFIG = {
  detectorName: 'tainted-xss',
  vulnerabilityType: 'cross-site scripting',
  severity: 'high',
  cweId: 'CWE-79',
  impact: 'These sinks hand a string to the HTML parser, so attacker-controlled input reaching them is cross-site scripting: script execution in the victim browser, session theft, and actions taken as the victim.',
  remediation: 'Never assign untrusted input to innerHTML/outerHTML or pass it to document.write/insertAdjacentHTML: use textContent/innerText for text, create elements and set attributes explicitly, or sanitize with a trusted HTML sanitizer (DOMPurify) before insertion.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  methodSinks: METHOD_SINKS,
  assignmentSinks: ASSIGNMENT_SINKS,
};

const taintedXssDetector = createTaintDetector(CONFIG);

module.exports = taintedXssDetector;
module.exports.taintedXssDetector = taintedXssDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.METHOD_SINKS = METHOD_SINKS;
module.exports.ASSIGNMENT_SINKS = ASSIGNMENT_SINKS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-xss', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
module.exports.memberPropertyName = memberPropertyName;
