// Phase 6 finding validation: pure, deterministic classification over local
// finding records. No model call, no network, no live verification — the
// validator only reads the fields on the finding itself.
//
// The finding record is schemas/finding.schema.json. Required fields are
// taken from that schema (in schema order); the severity bands come from
// knowledge/cvss/cvss-calc.json `severity_ratings`.
//
// Verdict precedence (first match wins, except where noted):
//   1. Not an object, or missing a required field -> 'needs_evidence'
//      with one `missing required field: <name>` reason per missing field.
//      The validator classifies; it never throws and never rejects input.
//   2. confidence 'false_positive' -> 'false_positive'. The analyst's own
//      judgement wins over every other rule, including a severity/cvss
//      mismatch (a dead finding's label is moot).
//   3. confidence 'needs_manual_review' -> 'needs_evidence'
//      ('manual review required').
//   4. Unknown severity (not one of the five band names: critical, high,
//      medium, low, informational) -> 'needs_evidence'
//      ('unknown severity: <value>'). Checked after the confidence
//      short-circuits above, so a false_positive still wins, and before
//      the mismatch/evidence collection below: a non-band severity
//      cannot be band-checked at all, and with an unbandable cvss_score
//      it previously slipped through as 'valid' — while the report
//      generator rejects it outright ('has invalid severity').
//   5. severity/cvss mismatch, a present-but-invalid cvss_score, a
//      malformed or disagreeing cvss_vector, and missing
//      reproducibility evidence are collected together: a finding can
//      report e.g. 'severity/cvss mismatch' and 'missing
//      proof_of_concept'. The severity is never silently re-labelled.
//      A present cvss_score that is not a finite number in [0, 10]
//      is reported as 'invalid cvss_score' on its own; it is not a
//      *mismatch*. A cvss_vector that is present but malformed is
//      reported as 'invalid cvss_vector: ...' on its own; a vector
//      whose computed score disagrees with a declared cvss_score is
//      reported as 'cvss_vector/cvss_score mismatch: ...'. When the
//      vector parses and no valid declared score exists, the
//      vector-derived score is the effective score: the severity is
//      checked against it instead of going unchecked. A missing
//      cvss_score AND a missing vector stay unchecked entirely.
//   6. confidence 'confirmed' with proof_of_concept + non-empty evidence +
//      non-empty steps_to_reproduce (and no mismatch) -> 'valid'.
//   7. confidence 'potential' with the same complete evidence (and no
//      mismatch) -> 'valid', with a reason noting it was potential but
//      fully evidenced.
//   8. Any other confidence value -> 'needs_evidence'
//      ('unknown confidence: <value>').
//
// Definitions:
//   - "missing" means the key is absent, undefined, or null. An empty
//     string or empty array is present-but-empty: it is not a missing
//     field, but it does fail the evidence checks that need it (a PoC
//     must be a non-empty string; evidence/steps must be non-empty
//     arrays).
//   - Severity/cvss agreement is checked only when severity is one of
//     the five band names and an effective score exists: the declared
//     cvss_score when it is a finite number in [0, 10], otherwise
//     the score computed from cvss_vector when the vector parses
//     (see resolveCvss in ./cvss.js). The score is rounded to one
//     decimal place first (CVSS 3.1 scores carry one decimal; this
//     also absorbs float noise such as 6.9000000001). A severity
//     outside the five band names is not a mismatch — it is reported
//     as unknown severity (precedence step 4). A cvss_score that is
//     present but not a finite number in [0, 10] is reported as
//     invalid cvss_score (precedence step 5); a missing cvss_score
//     AND a missing vector leave the severity unchecked entirely.
'use strict';

const { severity_ratings: SEVERITY_RATINGS } = require('../../knowledge/cvss/cvss-calc.json');
const { resolveCvss } = require('./cvss');

// The five band names a severity must be one of (schema enum; also the
// report generator's SEVERITY_ORDER). Derived from the ratings so the
// band names have a single source of truth.
const SEVERITY_NAMES = new Set(SEVERITY_RATINGS.map((entry) => entry.name));

// Required fields of schemas/finding.schema.json, in schema order.
const REQUIRED_FIELDS = [
  'finding_id',
  'session_id',
  'target_id',
  'asset_id',
  'title',
  'vulnerability_type',
  'severity',
  'confidence',
  'validation_status',
  'description',
  'steps_to_reproduce',
  'impact',
  'remediation',
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isNonEmptyArray(value) {
  return Array.isArray(value) && value.length > 0;
}

// The band name a CVSS score belongs to, or null when the score cannot be
// banded (not a finite number). Scores are rounded to one decimal place
// first; after rounding every score in [0, 10] falls in exactly one band.
function bandForScore(score) {
  if (typeof score !== 'number' || !Number.isFinite(score)) return null;
  const rounded = Math.round(score * 10) / 10;
  const band = SEVERITY_RATINGS.find((entry) => rounded >= entry.min && rounded <= entry.max);
  return band ? band.name : null;
}

function severityMatchesCvss(severity, cvssScore) {
  const expected = bandForScore(cvssScore);
  if (expected === null) return true; // Cannot check: not a mismatch.
  return severity === expected;
}

// A cvss_score that is present but unusable: not a finite number in
// [0, 10] (a string, NaN, Infinity, or out of range). This mirrors the
// schema (type number, minimum 0, maximum 10) and the report
// generator, which rejects such a score. A missing score (undefined
// or null) is not invalid — it stays unchecked, as documented.
function hasInvalidCvssScore(finding) {
  const score = finding.cvss_score;
  if (score === undefined || score === null) return false;
  return typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10;
}

// Missing reproducibility evidence, one reason per missing piece.
function missingEvidenceReasons(finding) {
  const reasons = [];
  if (!isNonEmptyString(finding.proof_of_concept)) reasons.push('missing proof_of_concept');
  if (!isNonEmptyArray(finding.evidence)) reasons.push('missing evidence');
  if (!isNonEmptyArray(finding.steps_to_reproduce)) reasons.push('missing steps_to_reproduce');
  return reasons;
}

function validateFinding(finding) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
    return { verdict: 'needs_evidence', reasons: ['missing required field: finding_id'] };
  }

  const missing = REQUIRED_FIELDS.filter((field) => finding[field] === undefined || finding[field] === null);
  if (missing.length > 0) {
    return {
      verdict: 'needs_evidence',
      reasons: missing.map((field) => `missing required field: ${field}`),
    };
  }

  if (finding.confidence === 'false_positive') {
    return { verdict: 'false_positive', reasons: ['confidence field says false_positive'] };
  }

  if (finding.confidence === 'needs_manual_review') {
    return { verdict: 'needs_evidence', reasons: ['manual review required'] };
  }

  // Unknown severity: not a band name, so it cannot be band-checked and
  // must not reach 'valid' — the report generator rejects it outright.
  // Placed here (after the missing-field check and the confidence
  // short-circuits, before the mismatch/evidence collection) so a
  // false_positive still wins and the reason names the severity
  // instead of misreporting it as a severity/cvss mismatch.
  if (!SEVERITY_NAMES.has(finding.severity)) {
    return { verdict: 'needs_evidence', reasons: [`unknown severity: ${finding.severity}`] };
  }

  const reasons = [];
  // Vector resolution (see ./cvss.js resolveCvss): a malformed vector
  // or a vector that disagrees with the declared score is a reason of
  // its own; the effective score is the declared score when valid,
  // else the vector-derived score, else null (unchecked).
  const cvss = resolveCvss(finding);
  if (cvss.error) {
    reasons.push(cvss.error);
  }
  if (!severityMatchesCvss(finding.severity, cvss.effectiveScore)) {
    reasons.push('severity/cvss mismatch');
  }
  if (hasInvalidCvssScore(finding)) {
    reasons.push('invalid cvss_score');
  }
  reasons.push(...missingEvidenceReasons(finding));

  if (finding.confidence === 'confirmed') {
    if (reasons.length === 0) {
      return {
        verdict: 'valid',
        reasons: ['confirmed with complete evidence (proof_of_concept, evidence, steps_to_reproduce)'],
      };
    }
    return { verdict: 'needs_evidence', reasons };
  }

  if (finding.confidence === 'potential') {
    if (reasons.length === 0) {
      return {
        verdict: 'valid',
        reasons: ['potential but fully evidenced (proof_of_concept, evidence, steps_to_reproduce)'],
      };
    }
    return { verdict: 'needs_evidence', reasons };
  }

  return { verdict: 'needs_evidence', reasons: [`unknown confidence: ${finding.confidence}`] };
}

// Root-cause key: vulnerability type + asset + normalized first
// reproduction step. Normalization trims, collapses runs of whitespace to
// one space, and lowercases, so the same step written with different
// spacing or casing still dedupes. The vulnerability type is a
// free-form string in the schema (not an enum), so it is normalized
// the same way (trim + lowercase) — 'Cross-Site Scripting' and
// 'cross-site scripting' are the same root cause. The asset_id is an
// identifier and stays EXACT (case-sensitive): 'lab-asset-01' and
// 'Lab-Asset-01' are different assets and must not dedupe. An empty
// or missing steps array uses the literal key part '(no-steps)'.
function normalizeStep(step) {
  const normalized = String(step).trim().replace(/\s+/g, ' ').toLowerCase();
  return normalized === '' ? '(no-steps)' : normalized;
}

function rootCauseKey(finding) {
  const record = finding && typeof finding === 'object' ? finding : {};
  const vulnerabilityType = record.vulnerability_type == null ? '' : String(record.vulnerability_type).trim().toLowerCase();
  const assetId = record.asset_id == null ? '' : String(record.asset_id);
  let firstStep = '(no-steps)';
  if (Array.isArray(record.steps_to_reproduce) && record.steps_to_reproduce.length > 0 && record.steps_to_reproduce[0] != null) {
    firstStep = normalizeStep(record.steps_to_reproduce[0]);
  }
  return `${vulnerabilityType}|${assetId}|${firstStep}`;
}

function dedupeFindings(findings) {
  if (!Array.isArray(findings)) return { groups: [], duplicates: 0 };
  const groups = [];
  const byKey = new Map();
  for (const finding of findings) {
    const key = rootCauseKey(finding);
    let group = byKey.get(key);
    if (!group) {
      group = { key, findings: [] };
      byKey.set(key, group);
      groups.push(group);
    }
    group.findings.push(finding);
  }
  const duplicates = findings.length - groups.length;
  return { groups, duplicates };
}

// Evidence checklist. Every item is always listed with present true/false;
// items are never omitted. Presence definitions:
//   proof_of_concept / impact / remediation / cwe_id / cvss_vector:
//     a non-empty string.
//   evidence / steps_to_reproduce: a non-empty array.
// The item set does not vary by confidence: the same seven items are what
// a reviewer checks whatever the finding claims.
const CHECKLIST = [
  { item: 'proof_of_concept', present: (finding) => isNonEmptyString(finding.proof_of_concept) },
  { item: 'evidence', present: (finding) => isNonEmptyArray(finding.evidence) },
  { item: 'steps_to_reproduce', present: (finding) => isNonEmptyArray(finding.steps_to_reproduce) },
  { item: 'impact', present: (finding) => isNonEmptyString(finding.impact) },
  { item: 'remediation', present: (finding) => isNonEmptyString(finding.remediation) },
  { item: 'cwe_id', present: (finding) => isNonEmptyString(finding.cwe_id) },
  { item: 'cvss_vector', present: (finding) => isNonEmptyString(finding.cvss_vector) },
];

function evidenceChecklist(finding) {
  const record = finding && typeof finding === 'object' && !Array.isArray(finding) ? finding : {};
  return CHECKLIST.map(({ item, present }) => ({ item, present: present(record) }));
}

module.exports = { validateFinding, dedupeFindings, evidenceChecklist, rootCauseKey };
