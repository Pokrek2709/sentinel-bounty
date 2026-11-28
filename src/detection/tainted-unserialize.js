// Thirty-first REAL detector (Phase 5, round 116): tainted-unserialize.
//
// The SECOND PHP detector. It parses the `content` string
// of a local input record as PHP (hand-written stdlib-only
// subset parser, `src/detection/php-parser.js` — never a
// regex, never executed) and tracks taint to the
// `unserialize()` deserialization sink (CWE-502,
// Deserialization of Untrusted Data), reporting a sink
// call only when its judged data is tainted or the call
// is reached through a `use function` alias — never
// carrying a literal value or a source line into a
// finding; every finding is confidence `potential`
// because the detector cannot prove the call is
// reachable or attacker-controlled. See
// docs/php-parser-v1.md for the parser scope and
// docs/detection-tainted-unserialize-v1.md for the
// detector doc.
//
// This is a SEPARATE analysis path: it runs on the PHP
// subset AST, NOT on the JavaScript taint engine
// (`src/detection/taint-engine.js`), which is
// JavaScript-specific, and NOT on the Python analyzer
// (`src/detection/tainted-pickle.js`), whose sources and
// sinks are Python-specific. The taint analysis itself is
// the shared PHP analyzer (`src/detection/php-taint.js`),
// configured here with this detector's sink predicate,
// sanitizers, and options gate; the only other shared code
// is the finding-id helper (findingIdFor), the content /
// finding caps, and the finding normalizer
// (normalizeRawFinding) — all language-neutral. Even the
// envelope is its own function following
// createTaintDetector's pattern, because that factory's
// scanRecord parses JavaScript and runs TaintAnalyzer;
// this detector's scanRecord parses PHP instead. The CLI
// and the finding record look identical to a caller
// either way.
//
// Analysis model (PHP taint, shared with
// `tainted-include` — see `src/detection/php-taint.js`
// for the full model): sources are function parameters,
// the superglobals `$_GET` / `$_POST` / `$_REQUEST` /
// `$_COOKIE` / `$_FILES` (bare and subscripted), and
// `file_get_contents('php://input')`; `$_SERVER`,
// `$_SESSION`, `$GLOBALS` and `$_ENV` are NOT sources.
// Taint flows inter-procedurally through known functions
// (memoized per tainted-parameter mask, recursion cut,
// call-graph depth capped at 8); methods are not
// resolved through the call graph.
//
// Sinks (PHP): `unserialize($data)` — the judged
// argument is positional argument 0, or the named
// keyword `data:` when no positional argument is given
// (the same judged-argument rule the Python pickle
// detector applies). A bare `unserialize` always resolves
// to the global sink (the PHP fallback for unqualified
// function names); `\unserialize` is a sink; a qualified
// `Foo\unserialize` is NOT a sink; a call reached through
// a `use function` alias (`use function unserialize as
// u;`) is a sink of kind `aliased-call`, reported with ANY
// argument. `json_decode` is NOT a sink (a data-only
// format).
//
// The options gate: `unserialize($data,
// ['allowed_classes' => false])` — positional argument 1
// or the named keyword `options:` — is CLEAN: with no
// classes allowed, no attacker class can be instantiated.
// An empty allow-list (`['allowed_classes' => []]`) is
// likewise clean (it allows no classes at all). A
// non-empty allow-list is still flagged (the listed
// classes can carry `__wakeup` / `__unserialize` gadgets
// — an allow-list is a scope reduction, not a proof of
// safety); options passed as a variable are flagged (no
// constant propagation); no options argument at all is
// flagged. This mirrors the `yaml.load` SafeLoader gate
// of the Python pickle detector.
//
// Clean patterns (NOT findings) besides the gate:
// `(int)` / `(float)` / `(bool)` / `(array)` casts and
// `intval` / `floatval` / `boolval` (the data becomes a
// scalar or a plain array, which cannot be a serialized
// object graph); `json_decode` / `json_encode` (the
// output is JSON syntax, which cannot be a valid PHP
// serialized object graph). A `(string)` cast is NOT a
// sanitizer (the attacker string passes through
// unchanged). Allow-list guards do NOT apply to this
// detector: checking the data against a list does not
// make deserializing it safe.
//
// Safety properties (tested, not assumed): a finding
// carries only the sink name, position, and a taint chain
// of IDENTIFIER NAMES, never a literal value or a source
// line; one finding per distinct sink call site per
// record; caps, determinism, and the no-regex-fallback
// rule are enforced by this module's own envelope.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const { PhpParseError } = require('./php-parser.js');
const {
  analyzePhp,
  memberChain,
  resolveChain,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./php-taint.js');
const { normalizeRawFinding } = require('./normalized-record.js');

const DETECTOR_NAME = 'tainted-unserialize';

// The unserialize sink predicate: a Call whose resolved
// chain is exactly 'unserialize'. A bare `unserialize`
// resolves to the global sink (the PHP fallback);
// `\unserialize` is a sink (the leading backslash is
// stripped by resolveChain); a qualified
// `Foo\unserialize` resolves to itself and is NOT a
// sink. The kind is 'aliased-call' when the call went
// through a `use function` binding whose local name
// differs from the sink name (`use function unserialize
// as u;` — `u($x)`), and 'tainted-arg' otherwise. The
// judged argument is positional argument 0, or the named
// keyword `data:` when no positional argument is given.
function unserializeSink(node, state) {
  if (node.type !== 'Call') return null;
  if (node.func.type !== 'Name' && node.func.type !== 'QualifiedName') return null;
  const chain = memberChain(node.func);
  const resolved = resolveChain(chain, state.bindings);
  if (resolved !== 'unserialize') return null;
  let kind = 'tainted-arg';
  if (node.func.type === 'Name') {
    const called = node.func.id;
    const first = called.split('\\')[0];
    const bound = state.bindings.get(first);
    if (bound !== undefined && bound !== called) kind = 'aliased-call';
  }
  let judged = null;
  if (node.args.length > 0) {
    const first = node.args[0];
    judged = first.type === 'Spread' ? first.value : first;
  } else {
    const kw = (node.keywords || []).find((k) => k.arg === 'data');
    if (kw) judged = kw.value;
  }
  return {
    sink: 'unserialize',
    kind,
    judged,
    line: node.line,
    column: node.column,
  };
}

// Does this `unserialize` call pass an options argument
// that forbids every class? `['allowed_classes' =>
// false]` (or an empty allow-list `[]`) — as positional
// argument 1 or the named keyword `options:` — makes the
// call clean. A non-empty allow-list, options passed as
// a variable, or no options argument at all does not.
function hasAllowedClassesFalse(node) {
  let options = null;
  if (node.args.length > 1) options = node.args[1];
  else {
    const kw = (node.keywords || []).find((k) => k.arg === 'options');
    if (kw) options = kw.value;
  }
  if (!options) return false;
  if (options.type === 'Spread') options = options.value;
  if (!options || options.type !== 'Array') return false;
  for (const element of options.elements || []) {
    if (!element || element.spread) continue;
    if (element.key && element.key.type === 'Constant'
      && element.key.kind === 'string' && element.key.value === 'allowed_classes') {
      const value = element.value;
      if (value && value.type === 'Constant'
        && value.kind === 'boolean' && value.value === 'false') return true;
      if (value && value.type === 'Array' && (value.elements || []).length === 0) return true;
      return false;
    }
  }
  return false;
}

// Sanitizer calls: the result cannot be a serialized
// object graph (a scalar, or data parsed from / encoded
// to a data-only format).
const SANITIZER_CALLS = new Set([
  'intval', 'floatval', 'boolval', 'json_decode', 'json_encode',
]);

// Sanitizer casts (lowercased): the data becomes a
// scalar or a plain array. `(string)` is deliberately
// NOT here — the attacker string passes through
// unchanged.
const SANITIZER_CASTS = new Set([
  'int', 'integer', 'float', 'double', 'real',
  'bool', 'boolean', 'array',
]);

const UNSERIALIZE_CONFIG = {
  checkSink: unserializeSink,
  sanitizerCalls: SANITIZER_CALLS,
  sanitizerCasts: SANITIZER_CASTS,
  useGuards: false,
  optionsGate: hasAllowedClassesFalse,
};

const IMPACT = 'These calls reconstruct objects from untrusted bytes, so attacker-controlled input reaching them can instantiate arbitrary classes and execute code during deserialization (unserialize executes __wakeup / __unserialize / __destruct on attacker-chosen classes by design).';
const REMEDIATION = 'Never unserialize untrusted input: use a data-only format (JSON via json_decode) or pass [\'allowed_classes\' => false] so no class can be instantiated, and validate the result before use.';
const PHP_LANGUAGES = new Set(['php']);

// --- findings ------------------------------------------------------------

function makeFinding(raw) {
  const { sink, kind, line, column, chain, functionName } = raw;
  const label = `${sink}() call`;
  const where = `line ${line}, column ${column}`;
  const chainText = chain && chain.length > 0 ? chain.join(' -> ') : 'an alias binding';
  const notes = `${label} at ${where} in function ${functionName}; taint flows via ${chainText}`;
  const finding = {
    finding_id: findingIdFor(DETECTOR_NAME, sink, line, column, kind),
    title: `Unsafe deserialization: tainted data reaches ${sink}`,
    vulnerability_type: 'insecure deserialization',
    description: `Tainted data reaches ${sink} (${label}), which reconstructs objects from untrusted bytes. An attacker who controls the input can instantiate arbitrary classes and execute code during deserialization.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-502',
    steps_to_reproduce: [
      'Run `sentinel detect --detector tainted-unserialize --input <record.json>` over the record carrying the PHP source.',
      `Observe the finding for ${sink} at ${where}.`,
      'Verify out of band whether the input is really attacker-controlled and the deserialized object is used, before reporting — the detector never executes the code, so exploitability is unproven.',
    ],
    proof_of_concept: `Matched ${sink} at ${where}: ${kind} via ${chainText}`,
    evidence: [{
      type: 'ast-call',
      sink,
      kind,
      line,
      column,
      call: sink,
      function: functionName,
      chain: chain || [],
      notes,
    }],
    discovery_tool: DETECTOR_NAME,
  };
  // Ids come from the record (attached to the raw hit by
  // scanRecord); the normalizer reads them from the
  // finding itself, falling back to `defaults`.
  for (const field of ['session_id', 'target_id', 'asset_id']) {
    if (typeof raw[field] === 'string' && raw[field].trim() !== '') {
      finding[field] = raw[field];
    }
  }
  return finding;
}

// --- detector ------------------------------------------------------------

function analyzePhpUnserialize(source) {
  return analyzePhp(source, UNSERIALIZE_CONFIG);
}

// Scan one content record into raw findings. Throws on a
// record that cannot be scanned; the caller counts those
// in `skipped`. Returns { rawFindings, truncated }.
//
// This envelope follows createTaintDetector's pattern
// (batch / single, content cap, finding cap, ids from
// the record, normalization through normalizeRawFinding)
// but it is its OWN function: createTaintDetector's
// scanRecord is JavaScript-specific — it parses with
// parseJavaScript, rejects non-JavaScript languages, and
// runs TaintAnalyzer. None of that applies to PHP, so
// reusing it would mean parsing PHP as JavaScript.
function scanRecord(record) {
  if (typeof record.content !== 'string' || record.content.trim() === '') {
    throw new Error(`${DETECTOR_NAME}: record has no non-empty string "content" to scan.`);
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`${DETECTOR_NAME}: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.language !== undefined && record.language !== null) {
    if (typeof record.language !== 'string' || !PHP_LANGUAGES.has(record.language.toLowerCase())) {
      throw new Error(`${DETECTOR_NAME}: record language is "${String(record.language)}", not PHP.`);
    }
  }
  let rawFindings;
  try {
    rawFindings = analyzePhpUnserialize(record.content);
  } catch (error) {
    if (error instanceof PhpParseError) {
      throw new Error(`${DETECTOR_NAME}: failed to parse content as PHP: ${error.message}`);
    }
    throw error;
  }
  const truncated = Math.max(0, rawFindings.length - MAX_FINDINGS_PER_RECORD);
  const kept = rawFindings.slice(0, MAX_FINDINGS_PER_RECORD);

  // Ids come from the record itself (else from `defaults`
  // at normalization); a detector never invents them.
  for (const raw of kept) {
    if (typeof record.session_id === 'string' && record.session_id.trim() !== '') raw.session_id = record.session_id;
    if (typeof record.target_id === 'string' && record.target_id.trim() !== '') raw.target_id = record.target_id;
    if (typeof record.asset_id === 'string' && record.asset_id.trim() !== '') raw.asset_id = record.asset_id;
  }
  return { rawFindings: kept, truncated };
}

// Build the detector envelope for this detector:
// detector(input, defaults) -> { findings, skipped, errors }.
// A batch record `{ tool, results: [...] }` scans each result
// with the batch tool forced as discovery_tool (the stub
// convention); any other object is treated as a single
// content record. A non-object input throws
// DETECTOR_INVALID_INPUT. Bad records are counted in
// `skipped`, never thrown.
function taintedUnserializeDetector(input, defaults) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('DETECTOR_INVALID_INPUT: detector input must be an object (a content record or a { tool, results } batch).');
  }
  let records;
  let tool;
  if (Array.isArray(input.results)) {
    if (input.tool !== undefined && input.tool !== null && (typeof input.tool !== 'string' || input.tool.trim() === '')) {
      throw new Error('DETECTOR_INVALID_INPUT: batch tool must be a non-empty string when present.');
    }
    records = input.results;
    tool = typeof input.tool === 'string' && input.tool.trim() !== '' ? input.tool : undefined;
  } else {
    records = [input];
    tool = undefined;
  }

  const findings = [];
  const errors = [];
  let skipped = 0;
  for (const record of records) {
    try {
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new Error(`${DETECTOR_NAME}: each record must be an object with a "content" string.`);
      }
      const { rawFindings, truncated } = scanRecord(record);
      for (const raw of rawFindings) {
        const finding = makeFinding(raw);
        if (tool) finding.discovery_tool = tool;
        findings.push(normalizeRawFinding(finding, defaults));
      }
      if (truncated > 0) {
        errors.push(`${DETECTOR_NAME}: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = taintedUnserializeDetector;
module.exports.taintedUnserializeDetector = taintedUnserializeDetector;
module.exports.analyzePhpUnserialize = analyzePhpUnserialize;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
