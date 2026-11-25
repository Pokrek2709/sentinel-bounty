// CVSS 3.1 vector parser and scorer (Phase 6, analysis layer).
//
// Pure, deterministic, lab-local: no model call, no network, no scanner.
// Metric values and severity bands are loaded from
// knowledge/cvss/cvss-calc.json at runtime, so the numbers stay
// single-sourced — this module holds the FORMULAS, not the tables.
//
// Formulas (FIRST CVSS v3.1 specification):
//   ISCBase        = 1 - [(1 - C) x (1 - I) x (1 - A)]
//   Scope U: Impact = 6.42 x ISCBase
//   Scope C: Impact = 7.52 x [ISCBase - 0.029] - 3.25 x [ISCBase - 0.02]^15
//   Exploitability = 8.22 x AV x AC x PR x UI
//     (PR uses the scope-changed table when S is C, else the unchanged one)
//   Impact <= 0            -> base score 0.0
//   Scope U: Roundup(min(Impact + Exploitability, 10))
//   Scope C: Roundup(min(1.08 x (Impact + Exploitability), 10))
//
//   TemporalScore  = Roundup(BaseScore x E x RL x RC)
//     (a missing temporal metric is X = 1.00, so a base-only vector
//     scores its temporal score equal to its base score)
//
//   ModifiedISCBase = min(1 - [(1 - MC x CR) x (1 - MI x IR) x (1 - MA x AR)], 0.915)
//   Modified scope U: ModifiedImpact = 6.42 x ModifiedISCBase
//   Modified scope C: ModifiedImpact = 7.52 x [ModifiedISCBase - 0.029]
//                                  - 3.25 x [ModifiedISCBase - 0.02]^15
//   ModifiedExploitability = 8.22 x MAV x MAC x MPR x MUI
//     (MPR uses the scope-changed table when MS is C, else the unchanged one)
//   ModifiedImpact <= 0   -> environmental score 0.0
//   Modified scope U: EnvironmentalScore =
//     Roundup(Roundup(min(ModifiedImpact + ModifiedExploitability, 10)) x E x RL x RC)
//   Modified scope C: EnvironmentalScore =
//     Roundup(Roundup(min(1.08 x (ModifiedImpact + ModifiedExploitability), 10)) x E x RL x RC)
//   (a modified metric of X falls back to its base metric; MS of X falls
//   back to S; a requirement of X is 1.00 — so a base-only vector scores
//   its environmental score equal to its base score)
//
// Roundup is the FIRST reference implementation's algorithm: the smallest
// number with one decimal place that is equal to or higher than the input,
// computed in integer space so float noise (e.g. 6.9000000001) does not
// round a score up. Roundup(4.02) = 4.1; Roundup(4.00) = 4.0.
//
// The eight base metrics are required; temporal (E, RL, RC) and
// environmental (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA)
// metrics are optional and default to X (Not Defined) when absent.
// A vector carrying an unknown metric or a bad value is rejected,
// never silently truncated.
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
const BASE_METRIC_KEYS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
// Temporal metrics: E, RL, RC. Environmental metrics: CR, IR, AR
// (requirements, X = 1.00) and MAV, MAC, MPR, MUI, MS, MC, MI, MA
// (modified base metrics, X = fall back to the base metric).
const TEMPORAL_METRIC_KEYS = ['E', 'RL', 'RC'];
const ENVIRONMENTAL_METRIC_KEYS = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
const ALL_METRIC_KEYS = [...BASE_METRIC_KEYS, ...TEMPORAL_METRIC_KEYS, ...ENVIRONMENTAL_METRIC_KEYS];

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
  if (!parsed || typeof parsed !== 'object' || !parsed.metrics || !parsed.temporal || !parsed.environmental || !Array.isArray(parsed.severity_ratings)) {
    throw new Error('Unable to load CVSS calculation data: metrics, temporal, environmental, or severity_ratings missing.');
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
// accepts U/C. Temporal metrics (E, RL, RC) and environmental
// requirements (CR, IR, AR) accept their table keys including X.
// Modified base metrics accept their concrete values plus X (the X
// entry in the table is null — it means "fall back to the base metric",
// not a number, so it is accepted as a value here and resolved by the
// scorers). MPR accepts the union of its unchanged/changed values
// plus X; MS accepts U/C plus X.
function allowedValues(metric) {
  const calc = loadCalc();
  if (metric === 'PR') {
    const tables = calc.metrics.PR.values;
    return new Set([...Object.keys(tables.unchanged), ...Object.keys(tables.changed)]);
  }
  if (metric === 'S') return new Set(Object.keys(calc.metrics.S.values));
  if (TEMPORAL_METRIC_KEYS.includes(metric)) {
    return new Set(Object.keys(calc.temporal[metric].values));
  }
  if (['CR', 'IR', 'AR'].includes(metric)) {
    return new Set(Object.keys(calc.environmental[metric].values));
  }
  if (metric === 'MPR') {
    const tables = calc.environmental.MPR.values;
    return new Set([...Object.keys(tables.unchanged), ...Object.keys(tables.changed)]);
  }
  if (metric === 'MS') return new Set(Object.keys(calc.environmental.MS.values));
  if (ENVIRONMENTAL_METRIC_KEYS.includes(metric)) {
    return new Set(Object.keys(calc.environmental[metric].values));
  }
  return new Set(Object.keys(calc.metrics[metric].values));
}

// Parse a CVSS 3.1 vector string into its metrics. Returns a flat
// object with the eight base metrics (always present) plus any
// temporal (E, RL, RC) and environmental (CR, IR, AR, MAV, MAC, MPR,
// MUI, MS, MC, MI, MA) metrics the vector carries; a temporal or
// environmental metric absent from the vector is absent from the
// object and scores as X (Not Defined). The eight base metrics are
// required — a vector without all of them is rejected, as before.
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
    const match = /^([A-Z]{1,3}):([A-Z])$/.exec(part);
    if (!match) {
      throw cvssError('CVSS_MALFORMED_PART', `malformed metric part "${part}" (expected KEY:VALUE)`);
    }
    const [, key, value] = match;
    if (!ALL_METRIC_KEYS.includes(key)) {
      throw cvssError('CVSS_UNKNOWN_METRIC', `unknown metric "${key}" (expected one of ${ALL_METRIC_KEYS.join(', ')})`);
    }
    if (Object.prototype.hasOwnProperty.call(metrics, key)) {
      throw cvssError('CVSS_DUPLICATE_METRIC', `duplicate metric "${key}"`);
    }
    if (!allowedValues(key).has(value)) {
      throw cvssError('CVSS_UNKNOWN_VALUE', `unknown value "${value}" for metric "${key}"`);
    }
    metrics[key] = value;
  }
  const missing = BASE_METRIC_KEYS.filter((key) => !Object.prototype.hasOwnProperty.call(metrics, key));
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

// Temporal metric value: the table value, or 1.00 when the metric is
// absent (X = Not Defined). `metrics` is a flat parsed vector object.
function temporalValue(metric, metrics) {
  const calc = loadCalc();
  const value = metrics[metric];
  if (value === undefined || value === 'X') return calc.temporal[metric].values.X;
  return calc.temporal[metric].values[value];
}

// Temporal score for a base score and parsed metrics:
// Roundup(BaseScore x E x RL x RC). A base-only vector (no temporal
// metrics) scores its temporal score equal to its base score.
function computeTemporalScore(baseScore, metrics) {
  return roundUp(baseScore * temporalValue('E', metrics) * temporalValue('RL', metrics) * temporalValue('RC', metrics));
}

// Modified base metric value: the table value for the modified metric,
// or the BASE metric's value when the modified metric is absent or X.
// `modifiedScopeChanged` selects the MPR table, like PR in the base
// score; MS itself resolves to the base scope when absent or X.
function modifiedMetricValue(modifiedMetric, baseMetric, metrics, modifiedScopeChanged) {
  const calc = loadCalc();
  const modified = metrics[modifiedMetric];
  if (modified === undefined || modified === 'X') {
    return metricValue(baseMetric, metrics[baseMetric], modifiedScopeChanged);
  }
  if (modifiedMetric === 'MPR') {
    const table = modifiedScopeChanged
      ? calc.environmental.MPR.values.changed
      : calc.environmental.MPR.values.unchanged;
    return table[modified];
  }
  return calc.environmental[modifiedMetric].values[modified];
}

function modifiedScope(metrics) {
  const ms = metrics.MS;
  if (ms === undefined || ms === 'X') return metrics.S;
  return ms;
}

// Environmental requirement value: the table value, or 1.00 when the
// requirement is absent (X = Not Defined).
function requirementValue(metric, metrics) {
  const calc = loadCalc();
  const value = metrics[metric];
  if (value === undefined || value === 'X') return calc.environmental[metric].values.X;
  return calc.environmental[metric].values[value];
}

// Environmental score for parsed metrics (flat object from
// parseCvssVector). Modified metrics fall back to their base metric
// when absent or X; MS falls back to S; requirements default to 1.00;
// temporal metrics default to 1.00. The modified base score is
// rounded up BEFORE the temporal multipliers are applied (the
// specification's double-Roundup), and a modified impact of 0 or
// below scores 0.0. A base-only vector scores its environmental
// score equal to its base score.
function computeEnvironmentalScore(metrics) {
  const scopeChanged = modifiedScope(metrics) === 'C';
  const mc = modifiedMetricValue('MC', 'C', metrics, scopeChanged);
  const mi = modifiedMetricValue('MI', 'I', metrics, scopeChanged);
  const ma = modifiedMetricValue('MA', 'A', metrics, scopeChanged);
  const cr = requirementValue('CR', metrics);
  const ir = requirementValue('IR', metrics);
  const ar = requirementValue('AR', metrics);
  const modifiedIscBase = Math.min(1 - (1 - mc * cr) * (1 - mi * ir) * (1 - ma * ar), 0.915);
  let modifiedImpact;
  if (scopeChanged) {
    modifiedImpact = 7.52 * (modifiedIscBase - 0.029) - 3.25 * Math.pow(modifiedIscBase - 0.02, 15);
  } else {
    modifiedImpact = 6.42 * modifiedIscBase;
  }
  const modifiedExploitability = 8.22
    * modifiedMetricValue('MAV', 'AV', metrics, scopeChanged)
    * modifiedMetricValue('MAC', 'AC', metrics, scopeChanged)
    * modifiedMetricValue('MPR', 'PR', metrics, scopeChanged)
    * modifiedMetricValue('MUI', 'UI', metrics, scopeChanged);
  if (modifiedImpact <= 0) return 0.0;
  const modifiedBase = scopeChanged
    ? roundUp(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10))
    : roundUp(Math.min(modifiedImpact + modifiedExploitability, 10));
  return roundUp(modifiedBase * temporalValue('E', metrics) * temporalValue('RL', metrics) * temporalValue('RC', metrics));
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
// { vector, metrics, score, severity, temporalScore,
//   environmentalScore }. The temporal score is present only when the
// vector carries at least one temporal metric (an explicit X counts
// as present); otherwise it is null — the score would equal the base
// score if computed (all X), but a missing metric is not reported as
// a computed score. The environmental score follows the same rule
// for environmental metrics.
function scoreCvssVector(vector) {
  const metrics = parseCvssVector(vector);
  const score = computeBaseScore(metrics);
  const hasTemporal = TEMPORAL_METRIC_KEYS.some((key) => key in metrics);
  const hasEnvironmental = ENVIRONMENTAL_METRIC_KEYS.some((key) => key in metrics);
  return {
    vector: vector.trim(),
    metrics,
    score,
    severity: severityForScore(score),
    temporalScore: hasTemporal ? computeTemporalScore(score, metrics) : null,
    environmentalScore: hasEnvironmental ? computeEnvironmentalScore(metrics) : null,
  };
}

// Resolve the effective CVSS scores for a finding record, shared by the
// validator (collects reasons) and the report generator (throws).
// Returns { effectiveScore, vectorScore, error, temporalScore,
//   environmentalScore, temporalError, environmentalError }:
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
//   - vectorScore: the computed base score when the vector parses, else null.
//   - temporalScore / environmentalScore: the computed scores when the
//     vector parses AND carries at least one metric of that group,
//     else null. A vector with no temporal (environmental) metrics
//     reports null here — the score would equal the base score if
//     computed (all X), but an absent metric is not reported as a
//     computed score, so the generator does not fill in or render
//     values the analyst never stated.
//   - temporalError / environmentalError: a mismatch reason when a
//     declared cvss_temporal_score / cvss_environmental_score (a valid
//     number in [0, 10]) disagrees with the computed score, else null.
//     A declared temporal/environmental score that is present but
//     invalid is ignored here — the callers report it as 'invalid
//     cvss_temporal_score' / 'invalid cvss_environmental_score'
//     themselves. The severity band is checked against the BASE score
//     only (effectiveScore); temporal and environmental scores never
//     re-band a finding's severity.
// A missing or empty-string vector is absent, not an error; a
// non-string vector (number, object) is an error.
function resolveCvss(finding) {
  const record = finding && typeof finding === 'object' && !Array.isArray(finding) ? finding : {};
  const vector = record.cvss_vector;
  const declared = record.cvss_score;
  const declaredTemporal = record.cvss_temporal_score;
  const declaredEnvironmental = record.cvss_environmental_score;
  let vectorScore = null;
  let temporalScore = null;
  let environmentalScore = null;
  let error = null;
  let temporalError = null;
  let environmentalError = null;
  if (typeof vector === 'string') {
    if (vector.trim() !== '') {
      try {
        const metrics = parseCvssVector(vector);
        vectorScore = computeBaseScore(metrics);
        const hasTemporal = TEMPORAL_METRIC_KEYS.some((key) => key in metrics);
        const hasEnvironmental = ENVIRONMENTAL_METRIC_KEYS.some((key) => key in metrics);
        temporalScore = hasTemporal ? computeTemporalScore(vectorScore, metrics) : null;
        environmentalScore = hasEnvironmental ? computeEnvironmentalScore(metrics) : null;
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
  if (typeof declaredTemporal === 'number' && Number.isFinite(declaredTemporal) && declaredTemporal >= 0 && declaredTemporal <= 10) {
    if (temporalScore !== null && Math.round(declaredTemporal * 10) / 10 !== temporalScore) {
      temporalError = `cvss_vector/cvss_temporal_score mismatch: vector computes to ${temporalScore} but cvss_temporal_score is ${declaredTemporal}`;
    }
  }
  if (typeof declaredEnvironmental === 'number' && Number.isFinite(declaredEnvironmental) && declaredEnvironmental >= 0 && declaredEnvironmental <= 10) {
    if (environmentalScore !== null && Math.round(declaredEnvironmental * 10) / 10 !== environmentalScore) {
      environmentalError = `cvss_vector/cvss_environmental_score mismatch: vector computes to ${environmentalScore} but cvss_environmental_score is ${declaredEnvironmental}`;
    }
  }
  return { effectiveScore, vectorScore, error, temporalScore, environmentalScore, temporalError, environmentalError };
}

module.exports = {
  BASE_METRIC_KEYS,
  parseCvssVector,
  computeBaseScore,
  computeTemporalScore,
  computeEnvironmentalScore,
  severityForScore,
  scoreCvssVector,
  resolveCvss,
  roundUp,
};
