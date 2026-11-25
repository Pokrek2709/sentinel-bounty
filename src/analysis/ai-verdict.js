// Pluggable AI-verdict interface (Phase 6, round 50): the CONTRACT a
// model-based finding verifier must satisfy, plus the built-in stub
// and a safe loader for custom verifier modules.
//
// This round does NOT choose a model and does NOT call one. It defines
// the interface so a model can be plugged in later, and wires it in as
// ADVISORY ONLY: the rule-based verdict from validateFinding() never
// changes because of an AI verdict — the AI result is recorded
// alongside it (as `ai_verdict` + `ai_verdict_source` on the finding)
// and rendered distinctly, labelled advisory, in the report.
//
// The interface contract:
//   A verifier is a SYNCHRONOUS function
//     verifier(finding) -> { verdict, confidence, reasons }
//   where `finding` is a normalized finding record (the verifier
//   receives a DEFENSIVE COPY and cannot mutate the finding being
//   reported), `verdict` is one of 'valid' | 'false_positive' |
//   'needs_evidence', `confidence` is a finite number in [0, 1], and
//   `reasons` is an array of strings (possibly empty). The function
//   must return its result synchronously: a verifier that returns a
//   Promise is refused as an invalid result, because the validator
//   and the report generator are synchronous and deterministic — an
//   async model call belongs to a future round (async validator) or
//   to an adapter that pre-computes verdicts before the run.
//
// The built-in stub verifier is the default verifier: it always
// returns 'needs_evidence' with confidence 0 and the reason "no AI
// model configured". It NEVER claims a finding valid or
// false_positive. The stub is used when a verifier is requested
// without naming a custom module (`--verifier stub`, or the string
// 'stub' in code). When NO verifier is requested at all, no
// `ai_verdict` is attached — a report without a verifier is
// byte-identical to the pre-round-50 output (the round-44 golden
// hashes still pass).
//
// Loader safety (loadVerifier): a verifier module is loaded only
// from inside the skill directory. An absolute path must resolve
// inside the skill root; a relative path is resolved under the
// skill root. The file itself must not be a symlink, and its
// realpath must stay inside the real skill root (so a symlinked
// parent directory cannot smuggle in a file from outside). The
// module's export must be a function, or an object with a `verify`
// function; anything else is refused with a named error, and the
// module is never executed beyond its top-level require. That
// top-level code DOES run on load — the loader validates the export
// shape but cannot sandbox it — so only load verifier modules from
// authors you trust, exactly as you would trust any other code in
// the skill directory.
//
// A verifier that throws, or returns a result that fails validation,
// is caught, never crashes the validator: the recorded result is
// 'needs_evidence' with confidence 0, a reason naming the failure,
// and the `error` field set to the failure message.
//
// Node stdlib only. No network requests, no model calls, no live data.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const AI_VERDICTS = ['valid', 'false_positive', 'needs_evidence'];

// The skill root: src/analysis/ai-verdict.js sits two levels below it.
const DEFAULT_SKILL_ROOT = path.resolve(__dirname, '..', '..');

// The built-in stub verifier (the default): deterministic, always
// 'needs_evidence' with confidence 0. It ignores its argument —
// the finding is taken for signature compatibility only — and it
// never claims a finding valid or false_positive.
function stubVerifier() {
  return { verdict: 'needs_evidence', confidence: 0, reasons: ['no AI model configured'] };
}

function isThenable(value) {
  return value !== null
    && (typeof value === 'object' || typeof value === 'function')
    && typeof value.then === 'function';
}

// Validate a verifier's returned result against the interface
// contract. Returns a normalized copy ({ verdict, confidence,
// reasons }) so a caller can never be handed the verifier's own
// object to mutate later. Throws a named error on any violation:
// a Promise return, a non-object, an unknown verdict, a confidence
// outside [0, 1] or not a finite number, or reasons that are not an
// array of strings.
function validateAiVerdictResult(result) {
  if (isThenable(result)) {
    throw new Error('AI_VERDICT_INVALID_RESULT: verifier must return a result synchronously (returned a Promise).');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('AI_VERDICT_INVALID_RESULT: verifier result must be an object.');
  }
  if (!AI_VERDICTS.includes(result.verdict)) {
    throw new Error(`AI_VERDICT_INVALID_RESULT: verdict must be one of ${AI_VERDICTS.join(', ')} (got ${JSON.stringify(result.verdict)}).`);
  }
  if (typeof result.confidence !== 'number' || !Number.isFinite(result.confidence) || result.confidence < 0 || result.confidence > 1) {
    throw new Error(`AI_VERDICT_INVALID_RESULT: confidence must be a finite number in [0, 1] (got ${JSON.stringify(result.confidence)}).`);
  }
  if (!Array.isArray(result.reasons) || result.reasons.some((reason) => typeof reason !== 'string')) {
    throw new Error('AI_VERDICT_INVALID_RESULT: reasons must be an array of strings.');
  }
  return { verdict: result.verdict, confidence: result.confidence, reasons: [...result.reasons] };
}

// Run a verifier against a finding and normalize its result. The
// verifier receives a defensive copy of the finding (JSON round-trip
// for JSON-shaped findings; a shallow copy if that fails), so a
// buggy or hostile verifier cannot mutate the finding being
// reported. A verifier that throws, or returns an invalid result,
// is caught: the recorded result is 'needs_evidence' with confidence
// 0, a reason naming the failure, and the `error` field set — the
// validator never crashes because of a verifier.
function runVerifier(verifier, finding) {
  if (typeof verifier !== 'function') {
    throw new Error('AI_VERDICT_INVALID_VERIFIER: verifier must be a function.');
  }
  let input;
  try {
    input = JSON.parse(JSON.stringify(finding));
  } catch {
    input = { ...(finding && typeof finding === 'object' ? finding : {}) };
  }
  try {
    return validateAiVerdictResult(verifier(input));
  } catch (error) {
    return {
      verdict: 'needs_evidence',
      confidence: 0,
      reasons: [`ai verifier error: ${error.message}`],
      error: error.message,
    };
  }
}

// Resolve a verifier specification to { verifier, source }:
//   - undefined / null -> null (no verifier configured).
//   - 'stub' -> the built-in stub verifier, source 'stub'.
//   - a function -> the function itself, source 'inline'.
//   - a string path -> loadVerifier(path, skillRoot).
// Anything else throws AI_VERDICT_INVALID_VERIFIER.
function getVerifier(spec, skillRoot) {
  if (spec === undefined || spec === null) return null;
  if (spec === 'stub') return { verifier: stubVerifier, source: 'stub' };
  if (typeof spec === 'function') return { verifier: spec, source: 'inline' };
  if (typeof spec === 'string') return loadVerifier(spec, skillRoot);
  throw new Error('AI_VERDICT_INVALID_VERIFIER: verifier must be "stub", a function, or a module path string.');
}

// Load a verifier module from inside the skill directory.
// Returns { verifier, source } where source is the file basename
// (or the module's `name` property when it is a non-empty string).
// Refusals, all named:
//   AI_VERDICT_NOT_FOUND — the path does not exist.
//   AI_VERDICT_NOT_A_FILE — the path exists but is not a file.
//   AI_VERDICT_SYMLINK_REFUSED — the file itself is a symlink, or
//     its realpath escapes the real skill root.
//   AI_VERDICT_PATH_OUTSIDE_SKILL — an absolute path outside the
//     skill root (relative paths are resolved under the root).
//   AI_VERDICT_LOAD_FAILED — require() failed.
//   AI_VERDICT_INVALID_MODULE — the export is not a function and
//     has no `verify` function.
function loadVerifier(modulePath, skillRoot) {
  const root = skillRoot || DEFAULT_SKILL_ROOT;
  const resolved = path.isAbsolute(modulePath)
    ? path.resolve(modulePath)
    : path.resolve(root, modulePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`AI_VERDICT_PATH_OUTSIDE_SKILL: verifier path ${modulePath} resolves outside the skill directory.`);
  }
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    throw new Error(`AI_VERDICT_NOT_FOUND: verifier module not found: ${modulePath}.`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`AI_VERDICT_SYMLINK_REFUSED: verifier path ${modulePath} is a symlink; load the real file instead.`);
  }
  if (!stat.isFile()) {
    throw new Error(`AI_VERDICT_NOT_A_FILE: verifier path ${modulePath} is not a file.`);
  }
  let realRoot;
  let realPath;
  try {
    realRoot = fs.realpathSync(root);
    realPath = fs.realpathSync(resolved);
  } catch (error) {
    throw new Error(`AI_VERDICT_LOAD_FAILED: cannot resolve verifier path ${modulePath}: ${error.message}`);
  }
  if (realPath !== realRoot && !realPath.startsWith(`${realRoot}${path.sep}`)) {
    throw new Error(`AI_VERDICT_SYMLINK_REFUSED: verifier path ${modulePath} resolves outside the skill directory.`);
  }
  let exported;
  try {
    exported = require(resolved);
  } catch (error) {
    throw new Error(`AI_VERDICT_LOAD_FAILED: cannot load verifier module ${modulePath}: ${error.message}`);
  }
  let verifier = null;
  if (typeof exported === 'function') {
    verifier = exported;
  } else if (exported && typeof exported === 'object' && typeof exported.verify === 'function') {
    verifier = exported.verify;
  }
  if (!verifier) {
    throw new Error(`AI_VERDICT_INVALID_MODULE: verifier module ${modulePath} must export a function (or an object with a verify function).`);
  }
  let source = path.basename(resolved);
  if (exported && typeof exported === 'object' && typeof exported.name === 'string' && exported.name.trim() !== '') {
    source = exported.name.trim();
  }
  return { verifier, source };
}

// Attach an AI verdict to a finding: returns a COPY of the finding
// with `ai_verdict` (the verifier's normalized result, or the
// needs_evidence error record when the verifier failed) and
// `ai_verdict_source`. When `resolved` is null (no verifier
// configured) the finding is returned unchanged. The original
// finding is never mutated; a finding that already carries an
// ai_verdict has it overwritten by the latest run.
function attachAiVerdict(finding, resolved) {
  if (!resolved) return finding;
  const result = runVerifier(resolved.verifier, finding);
  return { ...finding, ai_verdict: result, ai_verdict_source: resolved.source };
}

module.exports = {
  AI_VERDICTS,
  DEFAULT_SKILL_ROOT,
  stubVerifier,
  validateAiVerdictResult,
  runVerifier,
  getVerifier,
  loadVerifier,
  attachAiVerdict,
};
