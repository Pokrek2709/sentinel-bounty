// CVSS 3.1 base-vector parser and scorer (Phase 6, analysis layer).
//
// Pure, deterministic, lab-local: no model call, no network, no scanner.
// Metric values and severity bands are loaded from
// knowledge/cvss/cvss-calc.json at runtime, so the numbers stay
// single-sourced — this module holds the FORMULAS, not the tables.
//
// Formulas (FIRST CVSS v3.1 specification, base metrics only):
//   ISCBase        = 1 - [(1 - C) x (1 - I) x (1 - A)]
//   Scope U: Impact = 6.42 x ISCBase
//   Scope C: Impact = 7.52 x [ISCBase - 0.029] - 3.25 x [ISCBase - 0.02]^15
//   Exploitability = 8.22 x AV x AC x PR x UI
//     (PR uses the scope-changed table when S is C, else the unchanged one)
//   Impact <= 0            -> base score 0.0
//   Scope U: Roundup(min(Impact + Exploitability, 10))
//   Scope C: Roundup(min(1.08 x (Impact + Exploitability), 10))
//
// Roundup is the FIRST reference implementation's algorithm: the smallest
// number with one decimal place that is equal to or higher than the input,
// computed in integer space so float noise (e.g. 6.9000000001) does not
// round a score up. Roundup(4.02) = 4.1; Roundup(4.00) = 4.0.
//
// Temporal and environmental metrics are OUT of scope for this module:
// only the eight base metrics (AV, AC, PR, UI, S, C, I, A) are parsed
// and scored. A vector carrying temporal/environmental parts is rejected
// as an unknown metric, not silently truncated.
//
// Errors: every failure throws an Error with a `code` property
// (CVSS_INVALID_TYPE, CVSS_EMPTY_VECTOR, CVSS_INVALID_PREFIX,
// CVSS_MALFORMED_PART, CVSS_UNKNOWN_METRIC, CVSS_DUPLICATE_METRIC,
// CVSS_UNKNOWN_VALUE, CVSS_MISSING_METRIC) and a message starting
// with "invalid cvss_vector: ...", so callers can match on the code
// or on the message prefix.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

// The eight base metrics, in vector order. S carries no numeric value
// (it selects the PR table and the impact formula instead).
const METRIC_KEYS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

let cachedCalc = null;

function loadCalc() {
  if (cachedCalc) return cachedCalc;
  const calcPath = path.resolve(__dirname, '..', '..', 'knowledge', 'cvss', 'cvss-calc.json');
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(calcPath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load CVSS calculation data: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.metrics || !Array.isArray(parsed.severity_ratings)) {
    throw new Error('Unable to load CVSS calculation data: metrics or severity_ratings missing.');
  }
  cachedCalc = parsed;
  return cachedCalc;
}

function cvssError(code, detail) {
  const error = new Error(`invalid cvss_vector: ${detail}`);
  error.code = code;
  return error;
}

// Allowed values per metric, taken from the loaded tables. PR accepts
// the union of its unchanged/changed values (N, L, H either way); S
// accepts U/C.
function allowedValues(metric) {
  const calc = loadCalc();
  if (metric === 'PR') {
    const tables = calc.metrics.PR.values;
    return new Set([...Object.keys(tables.unchanged), ...Object.keys(tables.changed)]);
  }
  if (metric === 'S') return new Set(Object.keys(calc.metrics.S.values));
  return new Set(Object.keys(calc.metrics[metric].values));
}

// Parse a CVSS 3.1 base vector string into its eight base metrics.
// Returns { AV, AC, PR, UI, S, C, I, A } with one-letter values.
// Throws a coded error on any malformed input; never returns a partial
// parse. Matching is case-sensitive: the specification's vector grammar
// uses uppercase metric keys and values only.
function parseCvssVector(vector) {
  if (typeof vector !== 'string') {
    throw cvssError('CVSS_INVALID_TYPE', `expected a string, got ${vector === null ? 'null' : typeof vector}`);
  }
  const trimmed = vector.trim();
  if (trimmed === '') {
    throw cvssError('CVSS_EMPTY_VECTOR', 'empty vector string');
  }
  const parts = trimmed.split('/');
  if (parts[0] !== 'CVSS:3.1') {
    throw cvssError('CVSS_INVALID_PREFIX', `expected prefix "CVSS:3.1", got "${parts[0]}"`);
  }
  const metrics = {};
  for (let index = 1; index < parts.length; index += 1) {
    const part = parts[index];
    const match = /^([A-Z]{1,2}):([A-Z])$/.exec(part);
    if (!match) {
      throw cvssError('CVSS_MALFORMED_PART', `malformed metric part "${part}" (expected KEY:VALUE)`);
    }
    const [, key, value] = match;
    if (!METRIC_KEYS.includes(key)) {
      throw cvssError('CVSS_UNKNOWN_METRIC', `unknown metric "${key}" (expected one of ${METRIC_KEYS.join(', ')})`);
    }
    if (Object.prototype.hasOwnProperty.call(metrics, key)) {
      throw cvssError('CVSS_DUPLICATE_METRIC', `duplicate metric "${key}"`);
    }
    if (!allowedValues(key).has(value)) {
      throw cvssError('CVSS_UNKNOWN_VALUE', `unknown value "${value}" for metric "${key}"`);
    }
    metrics[key] = value;
  }
  const missing = METRIC_KEYS.filter((key) => !Object.prototype.hasOwnProperty.call(metrics, key));
  if (missing.length > 0) {
    throw cvssError('CVSS_MISSING_METRIC', `missing metric(s): ${missing.join(', ')}`);
  }
  return metrics;
}

// FIRST reference Roundup: smallest one-decimal number >= input.
// Integer-space arithmetic absorbs float noise (6.9000000001 -> 6.9).
// Domain is [0, 10]; callers only pass base-score candidates.
function roundUp(value) {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  const floorInput = Math.floor(intInput / 10000) * 10000;
  const rest = intInput - floorInput;
  if (rest > 0) return (Math.floor(intInput / 10000) + 1) / 10;
  return intInput / 100000;
}

function metricValue(metric, value, scopeChanged) {
  const calc = loadCalc();
  if (metric === 'PR') {
    const table = scopeChanged ? calc.metrics.PR.values.changed : calc.metrics.PR.values.unchanged;
    return table[value];
  }
  return calc.metrics[metric].values[value];
}

// Base score for already-parsed metrics (see parseCvssVector). Returns
// a number with exactly one decimal place (0.0–10.0).
function computeBaseScore(metrics) {
  const scopeChanged = metrics.S === 'C';
  const av = metricValue('AV', metrics.AV, scopeChanged);
  const ac = metricValue('AC', metrics.AC, scopeChanged);
  const pr = metricValue('PR', metrics.PR, scopeChanged);
  const ui = metricValue('UI', metrics.UI, scopeChanged);
  const c = metricValue('C', metrics.C, scopeChanged);
  const i = metricValue('I', metrics.I, scopeChanged);
  const a = metricValue('A', metrics.A, scopeChanged);
  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  } else {
    impact = 6.42 * iscBase;
  }
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0.0;
  if (scopeChanged) return roundUp(Math.min(1.08 * (impact + exploitability), 10));
  return roundUp(Math.min(impact + exploitability, 10));
}

// The severity band name a CVSS score belongs to, or null when the score
// cannot be banded (not a finite number). Scores are rounded to one
// decimal place first, matching the validator's banding; a computed
// score is already at one decimal, so this is exact for it.
function severityForScore(score) {
  if (typeof score !== 'number' || !Number.isFinite(score)) return null;
  const rounded = Math.round(score * 10) / 10;
  const band = loadCalc().severity_ratings.find((entry) => rounded >= entry.min && rounded <= entry.max);
  return band ? band.name : null;
}

// Parse a vector string and score it in one step. Returns
// { vector, metrics, score, severity }.
function scoreCvssVector(vector) {
  const metrics = parseCvssVector(vector);
  const score = computeBaseScore(metrics);
  return { vector: vector.trim(), metrics, score, severity: severityForScore(score) };
}

// Resolve the effective CVSS score for a finding record, shared by the
// validator (collects reasons) and the report generator (throws).
// Returns { effectiveScore, vectorScore, error }:
//   - error: a short reason string when the vector is present but
//     malformed ('invalid cvss_vector: ...'), or when the vector and
//     the declared score disagree
//     ('cvss_vector/cvss_score mismatch: vector computes to X but
//     cvss_score is Y'). Null when neither applies. A malformed vector
//     never also produces a mismatch: with no computed score there is
//     nothing to compare against.
//   - effectiveScore: the declared score when it is present and a
//     finite number in [0, 10]; otherwise the vector-derived score
//     when the vector parses; otherwise null. A declared score that is
//     present but invalid (not a number, out of range) is ignored here
//     — the callers report it as 'invalid cvss_score' themselves —
//     and the vector score is used instead, so one bad field does not
//     hide the other.
//   - vectorScore: the computed score when the vector parses, else null.
// A missing or empty-string vector is absent, not an error; a
// non-string vector (number, object) is an error.
function resolveCvss(finding) {
  const record = finding && typeof finding === 'object' && !Array.isArray(finding) ? finding : {};
  const vector = record.cvss_vector;
  const declared = record.cvss_score;
  let vectorScore = null;
  let error = null;
  if (typeof vector === 'string') {
    if (vector.trim() !== '') {
      try {
        vectorScore = computeBaseScore(parseCvssVector(vector));
      } catch (err) {
        error = err.message;
      }
    }
  } else if (vector !== undefined && vector !== null) {
    error = `invalid cvss_vector: expected a string, got ${typeof vector}`;
  }
  let effectiveScore = null;
  if (typeof declared === 'number' && Number.isFinite(declared) && declared >= 0 && declared <= 10) {
    effectiveScore = declared;
    if (vectorScore !== null && Math.round(declared * 10) / 10 !== vectorScore) {
      error = `cvss_vector/cvss_score mismatch: vector computes to ${vectorScore} but cvss_score is ${declared}`;
    }
  } else if (vectorScore !== null) {
    effectiveScore = vectorScore;
  }
  return { effectiveScore, vectorScore, error };
}

module.exports = { parseCvssVector, computeBaseScore, severityForScore, scoreCvssVector, resolveCvss, roundUp };
