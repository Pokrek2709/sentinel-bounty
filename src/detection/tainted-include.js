// Thirtieth REAL detector (Phase 5, round 116): tainted-include.
//
// The FIRST PHP detector. It parses the `content` string
// of a local input record as PHP (hand-written stdlib-only
// subset parser, `src/detection/php-parser.js` — never a
// regex, never executed) and tracks taint to include /
// require sinks (`include`, `require`, `include_once`,
// `require_once` — CWE-98, PHP Remote File Inclusion),
// reporting a sink only when its judged path is tainted
// and not guarded — never carrying a literal value or a
// source line into a finding; every finding is confidence
// `potential` because the detector cannot prove the call
// is reachable or attacker-controlled. See
// docs/php-parser-v1.md for the parser scope and
// docs/detection-tainted-include-v1.md for the detector doc.
//
// This is a SEPARATE analysis path: it runs on the PHP
// subset AST, NOT on the JavaScript taint engine
// (`src/detection/taint-engine.js`), which is
// JavaScript-specific, and NOT on the Python analyzer
// (`src/detection/tainted-pickle.js`), whose sources and
// sinks are Python-specific. Reusing either for PHP would
// mean lying about what the analysis models. The taint
// analysis itself is the shared PHP analyzer
// (`src/detection/php-taint.js`), configured here with
// this detector's sink predicate, sanitizers, and guards;
// the only other shared code is the finding-id helper
// (findingIdFor), the content / finding caps, and the
// finding normalizer (normalizeRawFinding) — all
// language-neutral. Even the envelope is its own function
// following createTaintDetector's pattern, because that
// factory's scanRecord parses JavaScript and runs
// TaintAnalyzer; this detector's scanRecord parses PHP
// instead. The CLI and the finding record look identical
// to a caller either way.
//
// Analysis model (PHP taint, shared with
// `tainted-unserialize` — see `src/detection/php-taint.js`
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
// Sinks (PHP): `include`, `require`, `include_once`,
// `require_once` — as a statement (`include $path`) and
// as an expression (`include($path)`, `$x = include
// $path`). The judged value is the included path. The
// kind is always `tainted-arg` (an include construct
// cannot be aliased — `use function` cannot import a
// language construct).
//
// Clean patterns (NOT findings):
// - a constant path (`include 'config.php'`, `include
//   __DIR__ . '/lib.php'` — a constant concatenation is
//   clean because every part is a Constant);
// - `basename($path)` — strips the directory, so the
//   included file is confined to one directory (a
//   documented caveat: a same-directory file chosen by
//   the attacker is still includable);
// - `(int)` / `(float)` / `(bool)` casts and
//   `intval` / `floatval` / `boolval` (the path becomes
//   a number, which cannot name an attacker file);
// - an allow-list guard on the path: `in_array($x,
//   $allowed, true)` (strict `true` REQUIRED — a
//   non-strict call proves nothing about the type),
//   `array_key_exists($x, $allowed)`, or
//   `isset($allowed[$x])` in an enclosing `if` test,
//   guarding the consequent branch; or a `switch ($x)`
//   with NO `default` case, guarding `$x` inside its
//   cases. A guard applies only to the judged
//   expression's variable leaves (a Variable, a `.`
//   concatenation of guarded parts, an interpolated
//   string of guarded parts).
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
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('./php-taint.js');
const { normalizeRawFinding } = require('./normalized-record.js');

const DETECTOR_NAME = 'tainted-include';

// The include sink predicate: an Include node (any of
// the four constructs) is a sink; the judged value is
// its path. The kind is always 'tainted-arg'.
function includeSink(node) {
  if (node.type !== 'Include') return null;
  return {
    sink: node.kind,
    kind: 'tainted-arg',
    judged: node.value,
    line: node.line,
    column: node.column,
  };
}

// Sanitizer calls: the result cannot name an attacker
// file (basename strips the directory; the numeric
// converters return a number).
const SANITIZER_CALLS = new Set([
  'basename', 'intval', 'floatval', 'boolval',
]);

// Sanitizer casts (lowercased): the path becomes a
// number. `(string)` is deliberately NOT here — the
// attacker string passes through unchanged.
const SANITIZER_CASTS = new Set([
  'int', 'integer', 'float', 'double', 'real',
  'bool', 'boolean',
]);

const INCLUDE_CONFIG = {
  checkSink: includeSink,
  sanitizerCalls: SANITIZER_CALLS,
  sanitizerCasts: SANITIZER_CASTS,
  useGuards: true,
  optionsGate: null,
};

const IMPACT = 'A tainted include path lets an attacker choose which file the application loads and executes, so a remote or local file of their choosing runs as application code (remote file inclusion when allow_url_include is on, local file inclusion otherwise — including log files and uploaded files).';
const REMEDIATION = 'Never include a path built from untrusted input: include a fixed file, map the input through an allow-list of known files (strict in_array against the list, or a switch with no default), or strip the directory with basename() and confine the include to one directory.';
const PHP_LANGUAGES = new Set(['php']);

// --- findings ------------------------------------------------------------

function makeFinding(raw) {
  const { sink, kind, line, column, chain, functionName } = raw;
  const label = `${sink} statement`;
  const where = `line ${line}, column ${column}`;
  const chainText = chain && chain.length > 0 ? chain.join(' -> ') : 'an alias binding';
  const notes = `${label} at ${where} in function ${functionName}; taint flows via ${chainText}`;
  const finding = {
    finding_id: findingIdFor(DETECTOR_NAME, sink, line, column, kind),
    title: `Unsafe include: tainted path reaches ${sink}`,
    vulnerability_type: 'improper control of filename for include/require statement',
    description: `Tainted data reaches ${sink} (${label}), which loads and executes the named file as PHP code. An attacker who controls the path can choose which file runs — a remote file when allow_url_include is on, or a local file (log files, uploaded files, wrappers) otherwise.`,
    impact: IMPACT,
    remediation: REMEDIATION,
    severity: 'high',
    cwe_id: 'CWE-98',
    steps_to_reproduce: [
      'Run `sentinel detect --detector tainted-include --input <record.json>` over the record carrying the PHP source.',
      `Observe the finding for ${sink} at ${where}.`,
      'Verify out of band whether the path is really attacker-controlled and the included file is executed, before reporting — the detector never executes the code, so exploitability is unproven.',
    ],
    proof_of_concept: `Matched ${sink} at ${where}: ${kind} via ${chainText}`,
    evidence: [{
      type: 'ast-include',
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

function analyzePhpInclude(source) {
  return analyzePhp(source, INCLUDE_CONFIG);
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
    rawFindings = analyzePhpInclude(record.content);
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
function taintedIncludeDetector(input, defaults) {
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

module.exports = taintedIncludeDetector;
module.exports.taintedIncludeDetector = taintedIncludeDetector;
module.exports.analyzePhpInclude = analyzePhpInclude;
module.exports.DETECTOR_NAME = DETECTOR_NAME;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor(DETECTOR_NAME, sink, lineNumber, column, kind)
);
