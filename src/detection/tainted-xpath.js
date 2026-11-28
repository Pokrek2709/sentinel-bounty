// Fourteenth REAL detector (Phase 5, round 107): tainted-xpath.
//
// The ninth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to XPath
// evaluation sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §11 for the
// scoping (XPath was one of the three named AST classes
// after tainted SSRF) and docs/detection-tainted-xpath-v1.md
// for the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the XPath
//     expression) is tainted (kind 'tainted-arg', evidence
//     carries the taint chain — since round 101 the chain
//     may cross function boundaries: call-site values ->
//     callee parameter -> sink);
//   - an ALIASED sink call (`const s = xpath.select`,
//     `const { select } = xpath`) with any argument (kind
//     'aliased-call', evidence carries the alias binding
//     — the regex detector cannot see these calls at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — XPath evaluation). Only the listed
// two-part member calls are sinks: a bare `select(...)`
// or `evaluate(...)` is deliberately NOT a sink (both
// names are too generic — they would false-positive on
// non-XPath `select` / `evaluate` calls), and a
// three-part call (`app.xpath.select(...)`) is not
// resolved either. `xpath.parse` is NOT a sink (it parses
// an expression into an AST; it does not evaluate it
// against a document). `document.querySelector` is NOT a
// sink (CSS selectors, not XPath). Other XPath shapes
// stay regex-covered by dangerous-call — this parser is
// JavaScript-only by design. Only the FIRST argument is
// judged (the expression): a tainted second argument
// (the context node) is NOT covered in this round — the
// node is data the query runs against, not the query
// itself — documented limitation.
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
// (the XPath expression) is judged.
const SINKS = {
  'xpath.select': { label: 'xpath.select() call' },
  'xpath.select1': { label: 'xpath.select1() call' },
  'xpath.evaluate': { label: 'xpath.evaluate() call' },
  'document.evaluate': { label: 'document.evaluate() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { select } = xpath` binds `select` to
// `xpath.select`.
const SINK_ROOTS = {
  xpath: ['select', 'select1', 'evaluate'],
  document: ['evaluate'],
};

// Import resolution (round 106): module name -> sink root.
const MODULE_ROOTS = {
  'xpath': 'xpath',
};

const CONFIG = {
  detectorName: 'tainted-xpath',
  vulnerabilityType: 'xpath injection',
  severity: 'high',
  cweId: 'CWE-643',
  impact: 'These calls hand an XPath expression to an XML evaluator, so attacker-controlled input reaching them is XPath injection: queries the attacker controls, authentication bypass through crafted expressions, and disclosure of XML nodes the application did not intend to expose.',
  remediation: 'Never pass untrusted input as an XPath expression: use parameterized XPath (bind user values as variables, never interpolate them into the expression string), or query by a fixed expression and filter the result in code.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
};

const taintedXpathDetector = createTaintDetector(CONFIG);

module.exports = taintedXpathDetector;
module.exports.taintedXpathDetector = taintedXpathDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-xpath', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
