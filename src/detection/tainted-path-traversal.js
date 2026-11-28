// Eleventh REAL detector (Phase 5, round 105):
// tainted-path-traversal.
//
// The sixth PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to
// filesystem path sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §9 for the
// scoping (path traversal was one of the three named AST
// classes after tainted XSS) and
// docs/detection-tainted-path-traversal-v1.md for the
// detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the path)
//     is tainted (kind 'tainted-arg', evidence carries the
//     taint chain — since round 101 the chain may cross
//     function boundaries: call-site values -> callee
//     parameter -> sink);
//   - an ALIASED sink call (`const rf = fs.readFile`,
//     `const { readFile } = fs`) with any first argument
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
// Sinks (JavaScript — the `fs` module's path-taking
// calls). Only the listed two-part member calls are sinks:
// a bare `readFile(...)` is deliberately NOT a sink (the
// name is too generic — it would false-positive on
// non-filesystem `readFile` calls), and a three-part call
// (`app.fs.readFile(...)`) is not resolved either.
// `fs.promises.readFile` is NOT resolved in this round
// (three-part — the promises namespace is not modeled).
// `fs.existsSync` is NOT a sink (it only checks
// existence; a tainted path there cannot read or write a
// file). `fs.mkdir` is NOT a sink in this round (directory
// creation is a different shape — future work).
// `res.sendFile` is NOT a sink in this round (Express file
// serving is a different receiver — future work). Other
// shapes stay regex-covered by dangerous-call — this
// parser is JavaScript-only by design. Only the FIRST
// argument is judged (the path): a tainted second
// argument (options, callback data) is NOT covered in
// this round, documented limitation.
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
  'fs.readFile': { label: 'fs.readFile() call' },
  'fs.readFileSync': { label: 'fs.readFileSync() call' },
  'fs.writeFile': { label: 'fs.writeFile() call' },
  'fs.writeFileSync': { label: 'fs.writeFileSync() call' },
  'fs.createReadStream': { label: 'fs.createReadStream() call' },
  'fs.createWriteStream': { label: 'fs.createWriteStream() call' },
  'fs.readdir': { label: 'fs.readdir() call' },
  'fs.readdirSync': { label: 'fs.readdirSync() call' },
  'fs.unlink': { label: 'fs.unlink() call' },
  'fs.unlinkSync': { label: 'fs.unlinkSync() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { readFile } = fs` binds `readFile` to
// `fs.readFile`.
const SINK_ROOTS = {
  fs: [
    'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
    'createReadStream', 'createWriteStream', 'readdir',
    'readdirSync', 'unlink', 'unlinkSync',
  ],
};

// Import resolution (round 106): module name -> sink root.
const MODULE_ROOTS = {
  'fs': 'fs',
  'node:fs': 'fs',
};

const CONFIG = {
  detectorName: 'tainted-path-traversal',
  vulnerabilityType: 'path traversal',
  severity: 'high',
  cweId: 'CWE-22',
  impact: 'These calls hand a path to the filesystem, so attacker-controlled input reaching them is path traversal: reading, writing, or deleting files outside the intended directory, including secrets and configuration.',
  remediation: 'Never pass untrusted input as a filesystem path: resolve the path against an allow-listed base directory and verify the resolved path stays inside it (path.resolve + startsWith check), or map user input to an allow-list of known files.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
};

const taintedPathTraversalDetector = createTaintDetector(CONFIG);

module.exports = taintedPathTraversalDetector;
module.exports.taintedPathTraversalDetector = taintedPathTraversalDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-path-traversal', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
