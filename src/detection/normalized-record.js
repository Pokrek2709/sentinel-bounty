// Normalizes a raw detector-style output object into a record conforming
// to schemas/finding.schema.json.
//
// STUB / scaffolding only (Phase 5, round 31): this module performs NO
// detection and invokes NO scanner. It only reshapes data a detector (real
// or stub) already produced into the shared finding record, so phases 6-7
// have a stable shape to consume.
//
// Normalization is STRICT: it never invents data. A required string field
// that is missing or empty throws an Error naming the field, and optional
// fields are copied only when present in the raw input.
//
// Severity bands come from knowledge/cvss/cvss-calc.json `severity_ratings`
// (critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9,
// informational 0.0). Scores are mapped with inclusive lower bounds
// (>= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low, 0 informational)
// so one-decimal scores in the gaps between the published band edges
// (e.g. 8.95) still land in exactly one band.
'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const CONFIDENCES = ['confirmed', 'potential', 'false_positive', 'needs_manual_review'];
const VALIDATION_STATUSES = ['detected', 'needs_review', 'validated', 'false_positive', 'duplicate', 'rejected'];

// Required string fields that must be present in the raw input itself.
// session_id / target_id / asset_id are required too, but may come from
// `defaults` (see normalizeRawFinding). severity / confidence /
// validation_status / steps_to_reproduce have their own rules below.
// impact and remediation are required by schemas/finding.schema.json, so
// they are required here as well: they are copied when present and never
// invented, so a raw finding without them throws instead of being padded.
const REQUIRED_STRING_FIELDS = [
  'finding_id',
  'title',
  'vulnerability_type',
  'description',
  'impact',
  'remediation',
];

// Optional string fields copied through only when present.
const OPTIONAL_STRING_FIELDS = ['cwe_id', 'cvss_vector', 'proof_of_concept', 'created_at', 'asset_url'];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function requireNonEmptyString(raw, field) {
  if (!isNonEmptyString(raw[field])) {
    throw new Error(`missing or empty required field: ${field}`);
  }
  return raw[field];
}

function severityForScore(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'informational';
}

function normalizeSteps(raw) {
  const steps = raw.steps_to_reproduce;
  let list;
  if (typeof steps === 'string') {
    list = steps.split('\n').map((line) => line.trim()).filter((line) => line !== '');
  } else if (Array.isArray(steps)) {
    for (const step of steps) {
      if (typeof step !== 'string') {
        throw new Error('steps_to_reproduce must be a string or an array of strings');
      }
    }
    list = steps.map((step) => step.trim()).filter((step) => step !== '');
  } else {
    throw new Error('steps_to_reproduce must be a string or an array of strings');
  }
  if (list.length === 0) {
    throw new Error('missing or empty required field: steps_to_reproduce');
  }
  return list;
}

function normalizeRawFinding(raw, defaults) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('raw finding must be an object');
  }
  const fallback = defaults && typeof defaults === 'object' && !Array.isArray(defaults) ? defaults : {};

  const record = {};

  for (const field of REQUIRED_STRING_FIELDS) {
    record[field] = requireNonEmptyString(raw, field);
  }

  // session_id / target_id / asset_id: raw wins, defaults fill the gap,
  // still missing after that is an error (never invented).
  for (const field of ['session_id', 'target_id', 'asset_id']) {
    if (isNonEmptyString(raw[field])) {
      record[field] = raw[field];
    } else if (isNonEmptyString(fallback[field])) {
      record[field] = fallback[field];
    } else {
      throw new Error(`missing or empty required field: ${field}`);
    }
  }

  // Severity: derive from cvss_score when severity is absent; when both
  // are present they must agree; when neither is present, throw.
  const hasSeverity = isNonEmptyString(raw.severity);
  const hasScore = typeof raw.cvss_score === 'number';
  if (raw.cvss_score !== undefined && raw.cvss_score !== null && !hasScore) {
    throw new Error('cvss_score must be a number');
  }
  let score;
  if (hasScore) {
    score = raw.cvss_score;
    if (!Number.isFinite(score) || score < 0 || score > 10) {
      throw new Error('cvss_score must be a number between 0 and 10');
    }
  }
  if (hasSeverity && !SEVERITIES.includes(raw.severity)) {
    throw new Error(`severity must be one of: ${SEVERITIES.join(', ')}`);
  }
  if (hasSeverity && hasScore) {
    const derived = severityForScore(score);
    if (derived !== raw.severity) {
      throw new Error(
        `severity mismatch: severity is "${raw.severity}" but cvss_score ${score} derives severity "${derived}"`,
      );
    }
    record.severity = raw.severity;
  } else if (hasSeverity) {
    record.severity = raw.severity;
  } else if (hasScore) {
    record.severity = severityForScore(score);
  } else {
    throw new Error('missing or empty required field: severity (provide severity or cvss_score)');
  }
  if (hasScore) {
    record.cvss_score = score;
  }

  // confidence / validation_status default; a provided value must be a
  // valid enum member.
  if (raw.confidence === undefined || raw.confidence === null) {
    record.confidence = 'potential';
  } else if (CONFIDENCES.includes(raw.confidence)) {
    record.confidence = raw.confidence;
  } else {
    throw new Error(`confidence must be one of: ${CONFIDENCES.join(', ')}`);
  }
  if (raw.validation_status === undefined || raw.validation_status === null) {
    record.validation_status = 'detected';
  } else if (VALIDATION_STATUSES.includes(raw.validation_status)) {
    record.validation_status = raw.validation_status;
  } else {
    throw new Error(`validation_status must be one of: ${VALIDATION_STATUSES.join(', ')}`);
  }

  record.steps_to_reproduce = normalizeSteps(raw);

  // Optional string fields: copy only when present and non-empty; a
  // present-but-wrong-type value is an error, not silently dropped.
  for (const field of OPTIONAL_STRING_FIELDS) {
    if (raw[field] === undefined || raw[field] === null) continue;
    if (!isNonEmptyString(raw[field])) {
      throw new Error(`${field} must be a non-empty string when present`);
    }
    record[field] = raw[field];
  }

  // discovery_tool: raw.discovery_tool wins, raw.tool is the alias; when
  // neither is present the field stays absent (never a fake tool name).
  const discoveryTool = raw.discovery_tool !== undefined && raw.discovery_tool !== null
    ? raw.discovery_tool
    : raw.tool;
  if (discoveryTool !== undefined && discoveryTool !== null) {
    if (!isNonEmptyString(discoveryTool)) {
      throw new Error('discovery_tool must be a non-empty string when present');
    }
    record.discovery_tool = discoveryTool;
  }

  // references: array of strings, copied only when present.
  if (raw.references !== undefined && raw.references !== null) {
    if (!Array.isArray(raw.references) || raw.references.some((ref) => typeof ref !== 'string')) {
      throw new Error('references must be an array of strings');
    }
    record.references = [...raw.references];
  }

  // evidence: array of objects, copied only when present. Items are
  // shallow-copied so the returned record owns its own array.
  if (raw.evidence !== undefined && raw.evidence !== null) {
    if (
      !Array.isArray(raw.evidence)
      || raw.evidence.some((item) => !item || typeof item !== 'object' || Array.isArray(item))
    ) {
      throw new Error('evidence must be an array of objects');
    }
    record.evidence = raw.evidence.map((item) => ({ ...item }));
  }

  // The returned object contains ONLY fields defined in
  // schemas/finding.schema.json: unknown keys in raw are dropped, never
  // carried through. (Every field assigned above is a schema field.)
  return record;
}

module.exports = { normalizeRawFinding, severityForScore };
