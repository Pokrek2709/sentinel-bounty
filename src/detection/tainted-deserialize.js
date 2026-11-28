// Sixth REAL detector (Phase 5, round 95): tainted-deserialize.
//
// The first PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to unsafe
// deserialization sinks. Since round 101 the analyzer is the
// shared taint engine (`src/detection/taint-engine.js`);
// this module only supplies the detector's config (sink
// table, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md for the
// scoping and docs/detection-tainted-deserialize-v1.md for
// the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument is tainted
//     (kind 'tainted-arg', evidence carries the taint chain
//     — since round 101 the chain may cross function
//     boundaries: call-site values -> callee parameter ->
//     sink);
//   - an ALIASED sink call (`const l = yaml.load`,
//     `const { load } = yaml`) with any first argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these calls
//     at all).
// A direct sink call with a clean argument is NOT reported:
// the regex detector already flags that call site, and the
// AST detector adds nothing. `JSON.parse` and
// `yaml.safeLoad` are not sinks (safe loaders). A value
// that passed a sanitizer (`Number`, `parseInt`,
// `parseFloat`, `Boolean` — see
// docs/sanitizer-modeling-v1.md) is clean, so a sink call
// on it is not reported.
//
// Sinks (JavaScript): yaml.load, YAML.load, yaml.loadAll,
// unserialize (js-yaml / phpjs-style). Python's pickle /
// marshal / shelve stay regex-covered by dangerous-call —
// this parser is JavaScript-only by design.
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
  'yaml.load': { label: 'yaml.load() call' },
  'YAML.load': { label: 'YAML.load() call' },
  'yaml.loadAll': { label: 'yaml.loadAll() call' },
  unserialize: { label: 'unserialize() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { load } = yaml` binds `load` to `yaml.load`.
const SINK_ROOTS = {
  yaml: ['load', 'loadAll'],
  YAML: ['load', 'loadAll'],
};

// Import resolution (round 106): module name -> sink root.
// Only `js-yaml` maps here: its API really is
// `yaml.load` / `loadAll`. The `yaml` package is NOT
// mapped — its API is `parse`, not `load`, so mapping it
// would manufacture findings for calls that cannot be
// `yaml.load` at runtime.
const MODULE_ROOTS = {
  'js-yaml': 'yaml',
};

const CONFIG = {
  detectorName: 'tainted-deserialize',
  vulnerabilityType: 'insecure deserialization',
  severity: 'high',
  cweId: 'CWE-502',
  impact: 'These calls reconstruct objects from untrusted bytes, so attacker-controlled input reaching them can instantiate arbitrary classes and execute code during deserialization (in Python, pickle/marshal/shelve; in PHP, unserialize; yaml.load without a safe Loader).',
  remediation: 'Never deserialize untrusted input with these calls: use a data-only format (JSON) or a safe loader (yaml.safe_load, pickle only on bytes you produced yourself) and validate the result.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  moduleRoots: MODULE_ROOTS,
};

const taintedDeserializeDetector = createTaintDetector(CONFIG);

module.exports = taintedDeserializeDetector;
module.exports.taintedDeserializeDetector = taintedDeserializeDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-deserialize', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
