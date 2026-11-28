// Tenth REAL detector (Phase 5, round 105): tainted-ssti.
//
// The fifth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to
// server-side template-engine sinks. It reuses the shared
// taint engine (`src/detection/taint-engine.js`, extracted
// in round 101); this module only supplies the detector's
// config (sink table, finding metadata) and re-exports the
// shared constants. See docs/parser-taint-scope-v1.md §9
// for the scoping (SSTI was one of the three named AST
// classes after tainted XSS) and
// docs/detection-tainted-ssti-v1.md for the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the template
//     string) is tainted (kind 'tainted-arg', evidence
//     carries the taint chain — since round 101 the chain
//     may cross function boundaries: call-site values ->
//     callee parameter -> sink);
//   - an ALIASED sink call (`const r = ejs.render`,
//     `const { render } = ejs`) with any first argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these
//     calls at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — the template engines the regex
// detector already names: EJS, Pug, Nunjucks,
// Handlebars). Only the listed two-part member calls are
// sinks: a bare `render(...)` is deliberately NOT a sink
// (the name is too generic — it would false-positive on
// non-template `render` calls), and a three-part call
// (`app.ejs.render(...)`) is not resolved either.
// `ejs.renderFile` / `pug.renderFile` are NOT sinks in
// this round (their first argument is a file path, not a
// template string — a tainted path there is path
// traversal, not SSTI); `nunjucks.render` is NOT a sink
// either (its first argument is a template NAME, not a
// template string); `res.render` is NOT a sink (an
// Express view name, not a template string). Other
// engines' shapes stay regex-covered by dangerous-call —
// this parser is JavaScript-only by design. Only the
// FIRST argument is judged (the template string): a
// tainted second argument (the data object) is NOT
// covered in this round — data injection into a constant
// template is a different class (template data is
// escaped by the engine), documented limitation.
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

// Canonical sink name -> { label }.
const SINKS = {
  'ejs.render': { label: 'ejs.render() call' },
  'ejs.compile': { label: 'ejs.compile() call' },
  'pug.compile': { label: 'pug.compile() call' },
  'pug.render': { label: 'pug.render() call' },
  'nunjucks.renderString': { label: 'nunjucks.renderString() call' },
  'handlebars.compile': { label: 'handlebars.compile() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { render } = ejs` binds `render` to `ejs.render`.
const SINK_ROOTS = {
  ejs: ['render', 'compile'],
  pug: ['compile', 'render'],
  nunjucks: ['renderString'],
  handlebars: ['compile'],
};

// Import resolution (round 106): module name -> sink root.
const MODULE_ROOTS = {
  'ejs': 'ejs',
  'pug': 'pug',
  'nunjucks': 'nunjucks',
  'handlebars': 'handlebars',
};

const CONFIG = {
  detectorName: 'tainted-ssti',
  vulnerabilityType: 'server-side template injection',
  severity: 'high',
  cweId: 'CWE-1336',
  impact: 'These calls hand a template string to a template engine, so attacker-controlled input reaching them is server-side template injection: template logic executed with server privileges, and in many engines arbitrary code execution, file access, or data exfiltration.',
  remediation: 'Never pass untrusted input as a template string: keep templates as constant files or constant literals and pass user data only as the render data object; if a template must be dynamic, validate it against an allow-list of known templates.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
};

const taintedSstiDetector = createTaintDetector(CONFIG);

module.exports = taintedSstiDetector;
module.exports.taintedSstiDetector = taintedSstiDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-ssti', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
