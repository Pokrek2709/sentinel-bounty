// Twenty-sixth REAL detector (Phase 5, round 113): tainted-xxe.
//
// The eleventh PARSER-BASED detector. It parses the `content`
// string of a local input record as JavaScript (hand-written
// stdlib-only subset parser, `src/detection/js-parser.js` —
// never a regex, never executed) and tracks taint to XML
// parser sinks. It reuses the shared taint engine
// (`src/detection/taint-engine.js`, extracted in round
// 101); this module only supplies the detector's config
// (sink tables, finding metadata) and re-exports the shared
// constants. See docs/parser-taint-scope-v1.md §17 for the
// scoping (XXE was the first of the two JavaScript classes
// of round 113, the return to JavaScript after the
// Solidity set closed in round 112) and
// docs/detection-tainted-xxe-v1.md for the detector doc.
//
// Round 113 is the second round to EXTEND the shared engine
// for a new sink shape (round 104 was the first): one sink
// family is gated on a dangerous options literal — a sink
// entry may carry `dangerousOptions` { argIndex, props },
// and the finding fires only when the named argument is an
// object literal carrying one of the named properties with
// a strictly equal literal value. The same round makes
// `new` expressions sink-checked like calls. Both
// extensions are config-driven and additive; detectors
// that declare neither behave exactly as before.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument (the XML
//     string) is tainted (kind 'tainted-arg', evidence
//     carries the taint chain — since round 101 the chain
//     may cross function boundaries: call-site values ->
//     callee parameter -> sink);
//   - an ALIASED sink call (`const p = libxmljs.parseXml`,
//     `const { parseXml } = libxmljs`) with any argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these calls
//     at all).
// A direct sink call with a clean first argument is NOT
// reported: the regex detector already flags that call
// site, and the AST detector adds nothing. A value that
// passed a sanitizer (`Number`, `parseInt`, `parseFloat`,
// `Boolean` — see docs/sanitizer-modeling-v1.md) is clean,
// so a sink call on it is not reported.
//
// Sinks (JavaScript — XML parsing, CWE-611). Only the
// listed shapes are sinks, and the libxmljs pair is gated:
//   - `libxmljs.parseXml` / `libxmljs.parseXmlString`:
//     flagged ONLY when the options argument (second) is
//     an object literal containing `noent: true` —
//     libxmljs substitutes entities only then; the
//     library default (`noent` false, or no options at
//     all) does not substitute them, so a plain call is
//     NOT a finding. An options object held in a variable
//     is not inspected (the gate needs a literal), so it
//     is not a finding either — a documented false
//     negative, not a silent skip: the gate is stated in
//     the detector doc and pinned by tests.
//   - `DOMParser.parseFromString` (xmldom, a method sink
//     matched by method name alone, whatever the
//     receiver): flagged on a tainted first argument.
//     xmldom expands internal entities by default and
//     does not fetch external entities in current
//     versions, so the finding is a potential
//     entity-expansion / XXE vector that needs
//     version-specific verification — stated in the doc,
//     not hidden.
//   - `parseString` / `parseStringPromise` (xml2js, method
//     sinks): flagged on a tainted first argument. The
//     underlying sax parser expands internal entities by
//     default; same version-specific caveat as xmldom.
//   - `parser.write` (sax, a fixed two-part name like
//     `client.search` in the LDAP detector): flagged on a
//     tainted first argument. Any other receiver
//     (`.write` on anything not named `parser`) is not a
//     sink — `write` alone is far too generic.
// A bare `parseString(...)` / `parseFromString(...)` call
// matches the method sink by name alone (the engine's
// method-sink rule, same as `insertAdjacentHTML` in the
// XSS detector) and is flagged; `JSON.parse` is NOT a
// sink (JSON has no entities). Other XML shapes stay
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
// finding per distinct sink call site per record; caps,
// determinism, and the no-regex-fallback rule are enforced
// by the shared engine. The `dangerousOptions` gate
// inspects a literal option value only for a boolean
// decision; the value never appears in a finding.
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

// Canonical sink name -> { label, dangerousOptions? }.
// The first argument (the XML string) is judged. The
// libxmljs pair fires ONLY when the options argument
// (second) is an object literal containing `noent: true`
// — libxmljs substitutes entities only then; the default
// (no options, or `noent: false`) is safe and is not a
// finding.
const SINKS = {
  'libxmljs.parseXml': {
    label: 'libxmljs.parseXml() call',
    dangerousOptions: { argIndex: 1, props: { noent: true } },
  },
  'libxmljs.parseXmlString': {
    label: 'libxmljs.parseXmlString() call',
    dangerousOptions: { argIndex: 1, props: { noent: true } },
  },
  'parser.write': { label: 'parser.write() call' },
};

// Method sinks: matched by method name alone, whatever the
// receiver. `parseFromString` (xmldom DOMParser) and
// `parseString` / `parseStringPromise` (xml2js Parser)
// judge their first argument (the XML string).
const METHOD_SINKS = {
  parseFromString: { label: 'DOMParser.parseFromString() call' },
  parseString: { label: 'xml2js Parser.parseString() call' },
  parseStringPromise: { label: 'xml2js Parser.parseStringPromise() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { parseXml } = libxmljs` binds `parseXml` to
// `libxmljs.parseXml`.
const SINK_ROOTS = {
  libxmljs: ['parseXml', 'parseXmlString'],
};

// Import resolution (round 106): module name -> sink root.
const MODULE_ROOTS = {
  'libxmljs': 'libxmljs',
};

const CONFIG = {
  detectorName: 'tainted-xxe',
  vulnerabilityType: 'xml external entity injection',
  severity: 'high',
  cweId: 'CWE-611',
  impact: 'These calls hand an XML document to a parser that resolves entities, so attacker-controlled input reaching them is XML external entity injection: disclosure of local files and server-side request forgery through external entities, and denial of service through entity expansion.',
  remediation: 'Never parse untrusted XML with entity resolution enabled: disable external entities and DTD processing in the parser (libxmljs: leave `noent` off; xmldom/xml2js: strip or reject DOCTYPE declarations before parsing), or parse untrusted input as JSON instead of XML.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
  methodSinks: METHOD_SINKS,
  moduleRoots: MODULE_ROOTS,
};

const taintedXxeDetector = createTaintDetector(CONFIG);

module.exports = taintedXxeDetector;
module.exports.taintedXxeDetector = taintedXxeDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.METHOD_SINKS = METHOD_SINKS;
module.exports.MODULE_ROOTS = MODULE_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-xxe', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
