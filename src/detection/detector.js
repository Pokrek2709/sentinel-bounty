// Pluggable detector interface (Phase 5, round 51): the CONTRACT a
// finding detector must satisfy, plus the built-in stub detector and
// a safe loader for custom detector modules.
//
// This round does NOT build a real detector and does NOT invoke a
// scanner. It defines the interface so a real detector can be
// plugged in later, mirroring what round 50 did for AI verdicts:
// the stub detector (round 31) becomes the reference implementation
// of the contract, and `sentinel detect` runs any conforming
// detector over a local input record.
//
// The interface contract:
//   A detector is a SYNCHRONOUS function
//     detector(input, defaults) -> { findings, skipped, errors }
//   where `input` is a raw detector-input record — the shape
//   `normalizeRawFinding()` accepts (a raw finding-shaped object:
//   finding_id, title, vulnerability_type, description,
//   steps_to_reproduce, impact, remediation, severity or
//   cvss_score, plus optional evidence/references/cwe_id/...) —
//   or a BATCH record `{ tool, results: [ <raw>, ... ] }` (the
//   shape of the round-31 stub fixtures), and `defaults` is the
//   `{ session_id, target_id, asset_id }` fallback object from
//   `normalizeRawFinding()` (a detector that needs those ids must
//   take them from `defaults`, never invent them). The return value
//   is an envelope: `findings` is an array of NORMALIZED finding
//   records (the shape the validator expects — every finding is
//   re-normalized on validation, so a detector that returns a
//   non-conformant finding is refused, not silently repaired),
//   `skipped` is a non-negative integer counting raw inputs that
//   failed normalization, and `errors` is an array of strings
//   naming each skipped input's failure. The function must return
//   its result synchronously: a detector that returns a Promise is
//   refused as an invalid result, because the pipeline is
//   synchronous and deterministic — an async detector belongs to a
//   future round or to an adapter that pre-computes findings.
//
//   A detector MUST NOT: make network requests; write anywhere
//   outside its own return value; or invent data — normalization
//   never invents a field, so a finding can only cite evidence
//   present in the input record. A detector that needs to drop a
//   bad input counts it in `skipped` with the error recorded,
//   exactly as the stub does; it never aborts the run over one bad
//   record, and never pads a finding to make it pass.
//
// The built-in stub detector is the default detector: it
// normalizes its input record(s) through `normalizeRawFinding()`
// and nothing else — it performs NO detection against any target.
// A single raw record yields one finding (or one skip); a batch
// record yields one finding per well-formed result, with the
// batch `tool` recorded as `discovery_tool` on every finding (the
// fixture-level tool is authoritative, as in round 31). The stub
// is used when a detector is requested without naming a custom
// module (`--detector stub`, or the string 'stub' in code).
//
// Loader safety (loadDetector): a detector module is loaded only
// from inside the skill directory. An absolute path must resolve
// inside the skill root; a relative path is resolved under the
// skill root. The file itself must not be a symlink, and its
// realpath must stay inside the real skill root (so a symlinked
// parent directory cannot smuggle in a file from outside). The
// module's export must be a function, or an object with a `detect`
// function; anything else is refused with a named error, and the
// module is never executed beyond its top-level require. That
// top-level code DOES run on load — the loader validates the export
// shape but cannot sandbox it — so only load detector modules from
// authors you trust, exactly as you would trust any other code in
// the skill directory.
//
// A detector that throws, or returns a result that fails
// validation, is caught, never crashes the caller: `runDetector`
// returns an error envelope (`findings: []`, `skipped: 0`, the
// failure in `errors`, and the `error` field set).
//
// Node stdlib only. No network requests, no scanner, no live data.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { normalizeRawFinding } = require('./normalized-record');
const { secretScanDetector } = require('./secret-scan');

// The skill root: src/detection/detector.js sits two levels below it.
const DEFAULT_SKILL_ROOT = path.resolve(__dirname, '..', '..');

function isThenable(value) {
  return value !== null
    && (typeof value === 'object' || typeof value === 'function')
    && typeof value.then === 'function';
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

// Normalize a list of raw records into the detector envelope.
// `tool` (when a non-empty string) is forced as discovery_tool on
// every finding, so the batch-level tool is authoritative; a single
// bad record never aborts the batch — it is counted in `skipped`
// with its error recorded. Shared by the stub detector and by
// runStubDetector (round 31), so both paths normalize identically.
function runDetectorOnRecords(records, tool, defaults) {
  if (!Array.isArray(records)) {
    throw new Error('DETECTOR_INVALID_INPUT: detector input records must be an array.');
  }
  const findings = [];
  const errors = [];
  let skipped = 0;
  for (const record of records) {
    try {
      const raw = tool && isNonEmptyString(tool)
        ? { ...record, tool, discovery_tool: tool }
        : record;
      findings.push(normalizeRawFinding(raw, defaults));
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

// Validate a detector's returned envelope against the interface
// contract. Returns a normalized copy: every finding is
// re-normalized through normalizeRawFinding() (which proves it
// conforms to schemas/finding.schema.json and drops any unknown
// fields the detector smuggled in), `skipped` and `errors` are
// copied. Throws a named error on any violation: a Promise return,
// a non-object, findings that are not an array, a finding that
// fails re-normalization, a skipped count that is not a
// non-negative integer, or errors that are not an array of strings.
function validateDetectorResult(result) {
  if (isThenable(result)) {
    throw new Error('DETECTOR_INVALID_RESULT: detector must return a result synchronously (returned a Promise).');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('DETECTOR_INVALID_RESULT: detector result must be an object.');
  }
  if (!Array.isArray(result.findings)) {
    throw new Error('DETECTOR_INVALID_RESULT: detector result findings must be an array.');
  }
  if (typeof result.skipped !== 'number' || !Number.isInteger(result.skipped) || result.skipped < 0) {
    throw new Error('DETECTOR_INVALID_RESULT: detector result skipped must be a non-negative integer.');
  }
  if (!Array.isArray(result.errors) || result.errors.some((error) => typeof error !== 'string')) {
    throw new Error('DETECTOR_INVALID_RESULT: detector result errors must be an array of strings.');
  }
  const findings = [];
  for (let index = 0; index < result.findings.length; index += 1) {
    try {
      findings.push(normalizeRawFinding(result.findings[index], {}));
    } catch (error) {
      throw new Error(`DETECTOR_INVALID_RESULT: finding at index ${index} is not a valid normalized finding: ${error.message}`);
    }
  }
  return { findings, skipped: result.skipped, errors: [...result.errors] };
}

// The built-in stub detector (the default, and the reference
// implementation of the contract): it normalizes its input and
// nothing else. A batch record `{ tool, results: [...] }`
// normalizes each result with the batch tool forced as
// discovery_tool; any other object is treated as a single raw
// record. A non-object input throws DETECTOR_INVALID_INPUT. Bad
// records are counted in `skipped`, never thrown.
function stubDetector(input, defaults) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('DETECTOR_INVALID_INPUT: detector input must be an object (a raw record or a { tool, results } batch).');
  }
  if (Array.isArray(input.results)) {
    if (input.tool !== undefined && input.tool !== null && !isNonEmptyString(input.tool)) {
      throw new Error('DETECTOR_INVALID_INPUT: batch tool must be a non-empty string when present.');
    }
    return runDetectorOnRecords(input.results, input.tool, defaults);
  }
  return runDetectorOnRecords([input], undefined, defaults);
}

// Run a detector against an input record and normalize its result.
// The detector receives a defensive copy of the input (JSON
// round-trip for JSON-shaped input; a shallow copy if that fails),
// so a buggy or hostile detector cannot mutate the caller's
// record. A detector that throws, or returns an invalid result,
// is caught: the returned envelope is `findings: []`, `skipped:
// 0`, the failure in `errors`, and the `error` field set — the
// caller never crashes because of a detector.
function runDetector(detector, input, defaults) {
  if (typeof detector !== 'function') {
    throw new Error('DETECTOR_INVALID_DETECTOR: detector must be a function.');
  }
  let copy;
  try {
    copy = JSON.parse(JSON.stringify(input));
  } catch {
    copy = { ...(input && typeof input === 'object' ? input : {}) };
  }
  try {
    return validateDetectorResult(detector(copy, defaults));
  } catch (error) {
    return {
      findings: [],
      skipped: 0,
      errors: [`detector error: ${error.message}`],
      error: error.message,
    };
  }
}

// Resolve a detector specification to { detector, source }:
//   - undefined / null -> null (no detector configured).
//   - 'stub' -> the built-in stub detector, source 'stub'.
//   - 'secret-scan' -> the first real detector (round 86),
//     source 'secret-scan'.
//   - a function -> the function itself, source 'inline'.
//   - a string path -> loadDetector(path, skillRoot).
// Anything else throws DETECTOR_INVALID_DETECTOR.
function getDetector(spec, skillRoot) {
  if (spec === undefined || spec === null) return null;
  if (spec === 'stub') return { detector: stubDetector, source: 'stub' };
  if (spec === 'secret-scan') return { detector: secretScanDetector, source: 'secret-scan' };
  if (typeof spec === 'function') return { detector: spec, source: 'inline' };
  if (typeof spec === 'string') return loadDetector(spec, skillRoot);
  throw new Error('DETECTOR_INVALID_DETECTOR: detector must be "stub", a function, or a module path string.');
}

// Load a detector module from inside the skill directory.
// Returns { detector, source } where source is the file basename
// (or the module's `name` property when it is a non-empty string).
// Refusals, all named:
//   DETECTOR_NOT_FOUND — the path does not exist.
//   DETECTOR_NOT_A_FILE — the path exists but is not a file.
//   DETECTOR_SYMLINK_REFUSED — the file itself is a symlink, or
//     its realpath escapes the real skill root.
//   DETECTOR_PATH_OUTSIDE_SKILL — an absolute path outside the
//     skill root (relative paths are resolved under the root).
//   DETECTOR_LOAD_FAILED — require() failed.
//   DETECTOR_INVALID_MODULE — the export is not a function and
//     has no `detect` function.
function loadDetector(modulePath, skillRoot) {
  const root = skillRoot || DEFAULT_SKILL_ROOT;
  const resolved = path.isAbsolute(modulePath)
    ? path.resolve(modulePath)
    : path.resolve(root, modulePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`DETECTOR_PATH_OUTSIDE_SKILL: detector path ${modulePath} resolves outside the skill directory.`);
  }
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    throw new Error(`DETECTOR_NOT_FOUND: detector module not found: ${modulePath}.`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`DETECTOR_SYMLINK_REFUSED: detector path ${modulePath} is a symlink; load the real file instead.`);
  }
  if (!stat.isFile()) {
    throw new Error(`DETECTOR_NOT_A_FILE: detector path ${modulePath} is not a file.`);
  }
  let realRoot;
  let realPath;
  try {
    realRoot = fs.realpathSync(root);
    realPath = fs.realpathSync(resolved);
  } catch (error) {
    throw new Error(`DETECTOR_LOAD_FAILED: cannot resolve detector path ${modulePath}: ${error.message}`);
  }
  if (realPath !== realRoot && !realPath.startsWith(`${realRoot}${path.sep}`)) {
    throw new Error(`DETECTOR_SYMLINK_REFUSED: detector path ${modulePath} resolves outside the skill directory.`);
  }
  let exported;
  try {
    exported = require(resolved);
  } catch (error) {
    throw new Error(`DETECTOR_LOAD_FAILED: cannot load detector module ${modulePath}: ${error.message}`);
  }
  let detector = null;
  if (typeof exported === 'function') {
    detector = exported;
  } else if (exported && typeof exported === 'object' && typeof exported.detect === 'function') {
    detector = exported.detect;
  }
  if (!detector) {
    throw new Error(`DETECTOR_INVALID_MODULE: detector module ${modulePath} must export a function (or an object with a detect function).`);
  }
  let source = path.basename(resolved);
  if (exported && typeof exported === 'object' && typeof exported.name === 'string' && exported.name.trim() !== '') {
    source = exported.name.trim();
  }
  return { detector, source };
}

module.exports = {
  DEFAULT_SKILL_ROOT,
  runDetectorOnRecords,
  validateDetectorResult,
  stubDetector,
  runDetector,
  getDetector,
  loadDetector,
};
