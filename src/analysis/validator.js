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
//   4. severity/cvss mismatch and missing reproducibility evidence are
//      collected together: a finding can report both
//      'severity/cvss mismatch' and e.g. 'missing proof_of_concept'.
//      The severity is never silently re-labelled.
//   5. confidence 'confirmed' with proof_of_concept + non-empty evidence +
//      non-empty steps_to_reproduce (and no mismatch) -> 'valid'.
//   6. confidence 'potential' with the same complete evidence (and no
//      mismatch) -> 'valid', with a reason noting it was potential but
//      fully evidenced.
//   7. Any other confidence value -> 'needs_evidence'
//      ('unknown confidence: <value>').
//
// Definitions:
//   - "missing" means the key is absent, undefined, or null. An empty
//     string or empty array is present-but-empty: it is not a missing
//     field, but it does fail the evidence checks that need it (a PoC
//     must be a non-empty string; evidence/steps must be non-empty
//     arrays).
//   - Severity/cvss agreement is checked only when severity is one of
//     the five band names and cvss_score is a finite number. The score
//     is rounded to one decimal place first (CVSS 3.1 scores carry one
//     decimal; this also absorbs float noise such as 6.9000000001).
'use strict';

const { severity_ratings: SEVERITY_RATINGS } = require('../../knowledge/cvss/cvss-calc.json');

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

  const reasons = [];
  if (!severityMatchesCvss(finding.severity, finding.cvss_score)) {
    reasons.push('severity/cvss mismatch');
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
// spacing or casing still dedupes. An empty or missing steps array uses
// the literal key part '(no-steps)'.
function normalizeStep(step) {
  const normalized = String(step).trim().replace(/\s+/g, ' ').toLowerCase();
  return normalized === '' ? '(no-steps)' : normalized;
}

function rootCauseKey(finding) {
  const record = finding && typeof finding === 'object' ? finding : {};
  const vulnerabilityType = record.vulnerability_type == null ? '' : String(record.vulnerability_type);
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
