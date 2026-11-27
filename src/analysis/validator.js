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
//   5. severity/cvss mismatch, a present-but-invalid cvss_score,
//      cvss_temporal_score, or cvss_environmental_score, a
//      malformed or disagreeing cvss_vector, and missing
//      reproducibility evidence are collected together: a finding can
//      report e.g. 'severity/cvss mismatch' and 'missing
//      proof_of_concept'. The severity is never silently re-labelled.
//      A present cvss_score that is not a finite number in [0, 10]
//      is reported as 'invalid cvss_score' on its own; it is not a
//      *mismatch*. A cvss_vector that is present but malformed is
//      reported as 'invalid cvss_vector: ...' on its own; a vector
//      whose computed score disagrees with a declared cvss_score is
//      reported as 'cvss_vector/cvss_score mismatch: ...'. The same
//      strict rule applies to the temporal and environmental scores:
//      a vector whose computed temporal (environmental) score
//      disagrees with a declared cvss_temporal_score
//      (cvss_environmental_score) is reported as
//      'cvss_vector/cvss_temporal_score mismatch: ...'
//      ('cvss_vector/cvss_environmental_score mismatch: ...'), and a
//      present-but-invalid declared temporal/environmental score is
//      reported as 'invalid cvss_temporal_score' /
//      'invalid cvss_environmental_score'. The severity is checked
//      against the BASE score only — temporal and environmental
//      scores never re-band a finding's severity. When the
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

const fs = require('node:fs');
const path = require('node:path');

const { parseCvssVector, resolveCvss, BASE_METRIC_KEYS } = require('./cvss');
const { stubVerifier, runVerifier } = require('./ai-verdict');

// The five band names a severity must be one of (schema enum; also the
// report generator's SEVERITY_ORDER). The ratings are loaded LAZILY
// from knowledge/cvss/cvss-calc.json on first use, never at module
// load: the CLI requires this module eagerly (via the report
// generator), and the operator-CLI tests run a bin/+src/-only copy of
// the skill as nobody — a top-level require of the knowledge file
// would crash that copy with MODULE_NOT_FOUND before any command
// runs. The bands still have a single source of truth; they are just
// read when first needed. A missing ratings file now fails at
// validation time (the first call that needs the bands), not at
// require time — validateFinding's never-throws contract covers
// malformed FINDINGS, not a broken installation.
let cachedSeverityRatings = null;
function getSeverityRatings() {
  if (!cachedSeverityRatings) {
    cachedSeverityRatings = require('../../knowledge/cvss/cvss-calc.json').severity_ratings;
  }
  return cachedSeverityRatings;
}

function getSeverityNames() {
  return new Set(getSeverityRatings().map((entry) => entry.name));
}

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
  const band = getSeverityRatings().find((entry) => rounded >= entry.min && rounded <= entry.max);
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
// The same rule, per field, for the declared temporal and
// environmental scores.
function hasInvalidCvssScore(finding) {
  const score = finding.cvss_score;
  if (score === undefined || score === null) return false;
  return typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10;
}

function hasInvalidCvssTemporalScore(finding) {
  const score = finding.cvss_temporal_score;
  if (score === undefined || score === null) return false;
  return typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10;
}

function hasInvalidCvssEnvironmentalScore(finding) {
  const score = finding.cvss_environmental_score;
  if (score === undefined || score === null) return false;
  return typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10;
}

// Missing reproducibility evidence, one reason per missing piece.
// The required set comes from the finding's evidence class
// (knowledge/evidence-checklists.json): the generic three
// (proof_of_concept, evidence, steps_to_reproduce) plus any
// class-specific extras (e.g. response_log for XSS). The generic
// reasons keep their exact round-31 strings so existing callers are
// unaffected; a class extra is named with the class that required it.
// One redundancy rule: an item derived from the evidence array
// (request_log, response_log, evidence_notes) is only checked when
// the evidence array itself is present — when evidence is missing,
// 'missing evidence' already covers it, and reporting the derived
// item too would be noise, not information.
function missingEvidenceReasons(finding) {
  const reasons = [];
  if (!isNonEmptyString(finding.proof_of_concept)) reasons.push('missing proof_of_concept');
  const evidencePresent = isNonEmptyArray(finding.evidence);
  if (!evidencePresent) reasons.push('missing evidence');
  if (!isNonEmptyArray(finding.steps_to_reproduce)) reasons.push('missing steps_to_reproduce');
  if (evidencePresent) {
    const spec = evidenceChecklistForClass(finding);
    for (const entry of spec.items) {
      if (!entry.required || entry.present) continue;
      if (entry.item === 'proof_of_concept' || entry.item === 'evidence' || entry.item === 'steps_to_reproduce') continue;
      reasons.push(`missing ${entry.item} (required for ${spec.classId})`);
    }
  }
  return reasons;
}

// The rule-based verdict only. This is the whole precedence chain
// above, unchanged: the AI verdict (see validateFinding below) is
// computed AFTER this returns and can never change its outcome.
function validateFindingRule(finding) {
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
  if (!getSeverityNames().has(finding.severity)) {
    return { verdict: 'needs_evidence', reasons: [`unknown severity: ${finding.severity}`] };
  }

  const reasons = [];
  // Vector resolution (see ./cvss.js resolveCvss): a malformed vector
  // or a vector that disagrees with a declared score is a reason of
  // its own; the effective score is the declared score when valid,
  // else the vector-derived score, else null (unchecked). The same
  // applies to the declared temporal and environmental scores: a
  // mismatch is a reason of its own, and a present-but-invalid
  // declared temporal/environmental score is reported as invalid.
  // The severity is checked against the BASE score only.
  const cvss = resolveCvss(finding);
  if (cvss.error) {
    reasons.push(cvss.error);
  }
  if (cvss.temporalError) {
    reasons.push(cvss.temporalError);
  }
  if (cvss.environmentalError) {
    reasons.push(cvss.environmentalError);
  }
  if (!severityMatchesCvss(finding.severity, cvss.effectiveScore)) {
    reasons.push('severity/cvss mismatch');
  }
  if (hasInvalidCvssScore(finding)) {
    reasons.push('invalid cvss_score');
  }
  if (hasInvalidCvssTemporalScore(finding)) {
    reasons.push('invalid cvss_temporal_score');
  }
  if (hasInvalidCvssEnvironmentalScore(finding)) {
    reasons.push('invalid cvss_environmental_score');
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

// Validate a finding and, when a verifier is configured, record its
// advisory AI verdict alongside the rule verdict.
//
//   validateFinding(finding) — no verifier: returns exactly the
//     rule result { verdict, reasons }, as before.
//   validateFinding(finding, { verifier }) — verifier is a function
//     or the string 'stub' (see src/analysis/ai-verdict.js): the
//     rule verdict is computed first, unchanged, and the verifier
//     then runs against the finding; the result adds `aiVerdict`
//     (the verifier's normalized result, or the needs_evidence
//     error record when the verifier threw or returned an invalid
//     result) and `aiVerdictSource` ('stub', 'inline', or the
//     module basename). The rule verdict NEVER changes because of
//     the AI verdict — a verifier that disagrees with the rule
//     verdict is recorded, not obeyed. A verifier option that is
//     neither a function nor 'stub' is recorded as a verifier
//     failure (aiVerdict needs_evidence, aiVerdictSource 'invalid'),
//     so this function keeps its never-throws contract: it throws
//     for nothing a finding or a verifier option can do. Path
//     strings are NOT accepted here — loading a module from a path
//     is I/O and belongs to the caller (getVerifier/loadVerifier);
//     pass the loaded function instead.
function validateFinding(finding, options = {}) {
  const rule = validateFindingRule(finding);
  const spec = options && typeof options === 'object' ? options.verifier : undefined;
  if (spec === undefined || spec === null) return rule;
  if (spec === 'stub') {
    return { ...rule, aiVerdict: runVerifier(stubVerifier, finding), aiVerdictSource: 'stub' };
  }
  if (typeof spec === 'function') {
    return { ...rule, aiVerdict: runVerifier(spec, finding), aiVerdictSource: 'inline' };
  }
  const message = 'AI_VERDICT_INVALID_VERIFIER: verifier must be "stub" or a function.';
  return {
    ...rule,
    aiVerdict: {
      verdict: 'needs_evidence',
      confidence: 0,
      reasons: [`ai verifier error: ${message}`],
      error: message,
    },
    aiVerdictSource: 'invalid',
  };
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

// Conservative semantic dedup (round 48): a SECOND dedup pass, run
// AFTER the exact-key dedup above, over that pass's representatives
// (first finding of each exact group). Two findings merge ONLY when
// ALL of these hold:
//   (a) same normalized vulnerability_type (trim + lowercase — the
//       same normalization rootCauseKey uses);
//   (b) same asset_id (exact, case-sensitive — assets are identifiers);
//   (c) same CVSS base vector (the eight base metrics, parsed —
//       temporal and environmental metrics are ignored for the
//       comparison) AND the same severity; OR, when NEITHER finding
//       carries a vector, the same severity band;
//   (d) at least one shared evidence entry (same entry value).
// The same-severity requirement in the vector branch is a deliberate
// tightening beyond the brief's minimum: identical base vectors imply
// identical computed scores, so two valid findings with the same
// vector always share a severity — a pair that differs there is
// mislabelled input, and merging it would silently drop one label.
//
// Deliberately OUT of scope: fuzzy text similarity, same type +
// asset without shared evidence, and any looser matching. Those need
// the user's policy decision (see docs/semantic-dedup-v1.md).
//
// Grouping is greedy in input order: each finding is compared against
// the representative (first finding) of each existing group, and joins
// the first group it matches. That is deterministic for a given input
// order, and deliberately NOT transitive-closure: A~B and B~C with
// A!~C leaves C in its own group rather than pulling it into A's
// group on B's say-so. The representative is the first finding in
// input order, so the merged finding's title/description/impact/
// remediation/vector are the representative's; only the evidence,
// steps, references, and (where safe) scores are combined — see
// mergeFindingGroup. A merged finding is only built for groups with
// two or more members; a singleton group's `merged` is the finding
// itself, so no report gains a spurious `merged_from`.
function normalizedVulnerabilityType(finding) {
  const record = finding && typeof finding === 'object' ? finding : {};
  return record.vulnerability_type == null ? '' : String(record.vulnerability_type).trim().toLowerCase();
}

function hasCvssVector(finding) {
  return finding && typeof finding === 'object'
    && typeof finding.cvss_vector === 'string' && finding.cvss_vector.trim() !== '';
}

// Canonical base-metrics key ('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
// or null when the finding carries no vector or its vector does not
// parse. A malformed vector never merges: it cannot prove "same base
// vector", and it is not vector-less either, so neither branch of
// rule (c) can hold for it.
function baseMetricsKey(finding) {
  if (!hasCvssVector(finding)) return null;
  let metrics;
  try {
    metrics = parseCvssVector(finding.cvss_vector);
  } catch {
    return null;
  }
  return BASE_METRIC_KEYS.map((key) => `${key}:${metrics[key]}`).join('/');
}

// Canonical evidence entry key, with a round-96 fallback for
// structured evidence. Classic entries carry request/response/
// notes; an entry counts only when at least one of those is a
// non-empty string, and the key is exactly those three fields
// (extra fields do not distinguish entries — unchanged
// behavior). Entries that carry NONE of the three classic
// subfields were invisible to rule (d): they could never be the
// shared entry, so findings from a detector with that evidence
// shape (the round-95 AST detector's {type, sink, kind, line,
// column, call, taint} entries) could never merge — the policy
// silently did not apply to a whole detector class, and the
// evidence union in mergeFindingGroup collapsed distinct AST
// entries onto one key. The fallback canonicalizes the FULL
// entry with sorted keys, and it counts only when the entry
// carries at least one non-empty string leaf, so an empty or
// all-blank entry still can never be the shared item. The four
// merge conditions do not change: (d) still requires a shared
// entry — the fallback only recognizes entries the classic
// shape could not see. A fallback key never collides with a
// classic key (it carries the `full:` prefix).
function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => (item === undefined ? 'null' : stableStringify(item))).join(',')}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

function hasNonEmptyStringLeaf(value) {
  if (typeof value === 'string') return value.trim() !== '';
  if (Array.isArray(value)) return value.some(hasNonEmptyStringLeaf);
  if (value && typeof value === 'object') return Object.values(value).some(hasNonEmptyStringLeaf);
  return false;
}

function canonicalEvidenceEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { key: JSON.stringify(entry), meaningful: false };
  }
  const field = (name) => (typeof entry[name] === 'string' && entry[name].trim() !== '' ? entry[name] : null);
  const request = field('request');
  const response = field('response');
  const notes = field('notes');
  if (request !== null || response !== null || notes !== null) {
    return { key: JSON.stringify({ request, response, notes }), meaningful: true };
  }
  return { key: `full:${stableStringify(entry)}`, meaningful: hasNonEmptyStringLeaf(entry) };
}

function meaningfulEvidenceKeys(finding) {
  if (!finding || typeof finding !== 'object' || !Array.isArray(finding.evidence)) return new Set();
  const keys = new Set();
  for (const entry of finding.evidence) {
    const { key, meaningful } = canonicalEvidenceEntry(entry);
    if (meaningful) keys.add(key);
  }
  return keys;
}

function sharesEvidence(a, b) {
  const keysA = meaningfulEvidenceKeys(a);
  if (keysA.size === 0) return false;
  const keysB = meaningfulEvidenceKeys(b);
  for (const key of keysA) {
    if (keysB.has(key)) return true;
  }
  return false;
}

function semanticallyDuplicates(a, b) {
  if (!a || typeof a !== 'object' || Array.isArray(a) || !b || typeof b !== 'object' || Array.isArray(b)) return false;
  const typeA = normalizedVulnerabilityType(a);
  if (typeA === '' || typeA !== normalizedVulnerabilityType(b)) return false;
  const assetA = a.asset_id == null ? '' : String(a.asset_id);
  const assetB = b.asset_id == null ? '' : String(b.asset_id);
  if (assetA === '' || assetA !== assetB) return false;
  if (a.severity !== b.severity) return false;
  const aHasVector = hasCvssVector(a);
  const bHasVector = hasCvssVector(b);
  if (aHasVector || bHasVector) {
    if (!aHasVector || !bHasVector) return false;
    const keyA = baseMetricsKey(a);
    const keyB = baseMetricsKey(b);
    if (keyA === null || keyB === null || keyA !== keyB) return false;
  }
  return sharesEvidence(a, b);
}

function semanticKeyFor(finding) {
  const type = normalizedVulnerabilityType(finding);
  const asset = finding && typeof finding === 'object' && finding.asset_id != null ? String(finding.asset_id) : '';
  if (hasCvssVector(finding)) {
    const key = baseMetricsKey(finding);
    return `${type}|${asset}|vector:${key === null ? 'unparseable' : key}`;
  }
  return `${type}|${asset}|band:${finding && typeof finding === 'object' ? String(finding.severity) : ''}`;
}

// Union of list items, first-seen order, deduped by a key function.
// The first occurrence's object identity is kept (no copies made).
function unionByKey(items, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

// Build the merged finding for a group of two or more members: a copy
// of the representative (first member) with the union of evidence,
// steps_to_reproduce, and references (first-seen order, exact-value
// dedup), the highest effective base score, and `merged_from` listing
// every member id including the representative's. Score safety:
//   - With a shared vector, the merged cvss_score is the score the
//     VECTOR computes (all members share the base metrics, so the
//     computed score is the same for every member) — never the max of
//     declared scores, because a declared score that disagrees with
//     the vector would make the merged finding fail the generator's
//     strict vector rule. Temporal/environmental declared scores stay
//     the representative's, matching its kept full vector string.
//   - Without a vector, cvss_score is the max of the declared scores
//     present, and temporal/environmental scores are the max of the
//     declared values present (no vector exists to disagree with).
// The merged finding is built from validated-shape members, so it
// still validates: same severity (rule (c) enforces it), a score that
// agrees with its vector, and evidence that is the union of members
// that each carried the required items.
function mergeFindingGroup(members) {
  const representative = members[0];
  const merged = { ...representative };
  const allEvidence = members.flatMap((member) => (Array.isArray(member.evidence) ? member.evidence : []));
  if (allEvidence.length > 0) {
    merged.evidence = unionByKey(allEvidence, (entry) => canonicalEvidenceEntry(entry).key);
  }
  const allSteps = members.flatMap((member) => (Array.isArray(member.steps_to_reproduce) ? member.steps_to_reproduce : []));
  merged.steps_to_reproduce = unionByKey(allSteps, (step) => (typeof step === 'string' ? step : JSON.stringify(step)));
  const allReferences = members.flatMap((member) => (Array.isArray(member.references) ? member.references : []));
  if (allReferences.length > 0) {
    merged.references = unionByKey(allReferences, (ref) => (typeof ref === 'string' ? ref : JSON.stringify(ref)));
  }
  const anyVector = members.some(hasCvssVector);
  if (anyVector) {
    const vectorScore = resolveCvss(representative).vectorScore;
    if (vectorScore !== null) merged.cvss_score = vectorScore;
  } else {
    const scores = members
      .map((member) => resolveCvss(member).effectiveScore)
      .filter((score) => typeof score === 'number');
    if (scores.length > 0) merged.cvss_score = Math.max(...scores);
    const temporal = members
      .map((member) => member.cvss_temporal_score)
      .filter((score) => typeof score === 'number');
    if (temporal.length > 0) merged.cvss_temporal_score = Math.max(...temporal);
    else delete merged.cvss_temporal_score;
    const environmental = members
      .map((member) => member.cvss_environmental_score)
      .filter((score) => typeof score === 'number');
    if (environmental.length > 0) merged.cvss_environmental_score = Math.max(...environmental);
    else delete merged.cvss_environmental_score;
  }
  // merged_from is an id SET (round 96): two members can share
  // one finding_id (deterministic detector ids — e.g. two
  // identical tainted-deserialize records) and the merged
  // finding lists it once, matching how report-diff treats
  // merged_from as an id set.
  merged.merged_from = [...new Set(members
    .map((member) => member.finding_id)
    .filter((id) => typeof id === 'string'))];
  return merged;
}

function semanticDedupeFindings(findings) {
  if (!Array.isArray(findings)) return { groups: [], duplicates: 0 };
  const groups = [];
  for (const finding of findings) {
    let target = null;
    for (const group of groups) {
      if (semanticallyDuplicates(group.findings[0], finding)) {
        target = group;
        break;
      }
    }
    if (target) {
      target.findings.push(finding);
    } else {
      groups.push({ key: semanticKeyFor(finding), findings: [finding], merged: finding });
    }
  }
  let duplicates = 0;
  for (const group of groups) {
    if (group.findings.length > 1) {
      group.merged = mergeFindingGroup(group.findings);
      duplicates += group.findings.length - 1;
    }
  }
  return { groups, duplicates };
}

// Evidence checklist. Per-class, loaded at runtime from
// knowledge/evidence-checklists.json (see docs/evidence-checklists-v1.md).
// Every item is always listed with present true/false and a required
// flag; items are never omitted. Presence definitions:
//   proof_of_concept / impact / remediation / cwe_id / cvss_vector:
//     a non-empty string.
//   evidence / steps_to_reproduce: a non-empty array.
//   request_log / response_log / evidence_notes: at least one evidence
//     entry carrying a non-empty request / response / notes string.
// The item set varies by class: the class's required items first (in
// file order), then its recommended items. A finding whose
// vulnerability_type matches no class — including a missing or
// non-string type — gets the generic checklist, which is exactly the
// round-31/32 seven-item list in the same order, so existing callers
// are unaffected. Class matching normalizes the type the same way
// rootCauseKey does (trim + lowercase) and matches when the normalized
// type equals, or contains, one of the class's match strings — so
// 'Stored Cross-Site Scripting' and 'xss' both resolve to the XSS
// class. The first class whose match strings hit wins; the file order
// is the precedence order.
//
// Loading contract: loadEvidenceChecklists() THROWS on a missing,
// unparseable, or malformed spec (fail loud, so a bad edit to the
// knowledge file is caught by the tests, not silently shipped).
// evidenceChecklistForClass() catches load failures and falls back to
// the generic checklist, so validateFinding() keeps its never-throws
// contract: a broken knowledge file degrades validation to the generic
// checklist instead of crashing it. The fallback is documented, not
// silent — see docs/evidence-checklists-v1.md.
const ITEM_CHECKS = {
  proof_of_concept: (finding) => isNonEmptyString(finding.proof_of_concept),
  evidence: (finding) => isNonEmptyArray(finding.evidence),
  steps_to_reproduce: (finding) => isNonEmptyArray(finding.steps_to_reproduce),
  impact: (finding) => isNonEmptyString(finding.impact),
  remediation: (finding) => isNonEmptyString(finding.remediation),
  cwe_id: (finding) => isNonEmptyString(finding.cwe_id),
  cvss_vector: (finding) => isNonEmptyString(finding.cvss_vector),
  request_log: (finding) => hasEvidenceSubfield(finding, 'request'),
  response_log: (finding) => hasEvidenceSubfield(finding, 'response'),
  evidence_notes: (finding) => hasEvidenceSubfield(finding, 'notes'),
};

function hasEvidenceSubfield(finding, field) {
  if (!Array.isArray(finding.evidence)) return false;
  return finding.evidence.some(
    (entry) => entry && typeof entry === 'object' && isNonEmptyString(entry[field]),
  );
}

function loadEvidenceChecklists(filePath) {
  const specPath = filePath || path.resolve(__dirname, '..', '..', 'knowledge', 'evidence-checklists.json');
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(specPath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load evidence checklists: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Unable to load evidence checklists: spec must be an object.');
  }
  if (!parsed.generic || !Array.isArray(parsed.generic.required) || !Array.isArray(parsed.generic.recommended)) {
    throw new Error('Unable to load evidence checklists: generic required/recommended missing or not arrays.');
  }
  if (!Array.isArray(parsed.classes)) {
    throw new Error('Unable to load evidence checklists: classes missing or not an array.');
  }
  const knownItems = new Set(Object.keys(ITEM_CHECKS));
  const checkItems = (items, where) => {
    for (const item of items) {
      if (typeof item !== 'string' || !knownItems.has(item)) {
        throw new Error(`Unable to load evidence checklists: unknown checklist item ${JSON.stringify(item)} in ${where}.`);
      }
    }
  };
  checkItems(parsed.generic.required, 'generic.required');
  checkItems(parsed.generic.recommended, 'generic.recommended');
  for (const entry of parsed.classes) {
    if (!entry || typeof entry.id !== 'string' || entry.id.trim() === '') {
      throw new Error('Unable to load evidence checklists: every class needs a non-empty id.');
    }
    if (!Array.isArray(entry.match) || entry.match.length === 0
      || entry.match.some((alias) => typeof alias !== 'string' || alias.trim() === '')) {
      throw new Error(`Unable to load evidence checklists: class ${entry.id} needs a non-empty match list.`);
    }
    if (!Array.isArray(entry.required) || !Array.isArray(entry.recommended)) {
      throw new Error(`Unable to load evidence checklists: class ${entry.id} required/recommended missing or not arrays.`);
    }
    checkItems(entry.required, `${entry.id}.required`);
    checkItems(entry.recommended, `${entry.id}.recommended`);
    const seen = new Set([...entry.required, ...entry.recommended]);
    if (seen.size !== entry.required.length + entry.recommended.length) {
      throw new Error(`Unable to load evidence checklists: class ${entry.id} lists an item twice.`);
    }
  }
  return parsed;
}

let cachedChecklists = null;

function getChecklists() {
  if (cachedChecklists) return cachedChecklists;
  try {
    cachedChecklists = loadEvidenceChecklists();
  } catch {
    cachedChecklists = null;
  }
  return cachedChecklists;
}

// Resolve the evidence class for a vulnerability_type string, or null
// for the generic fallback. Matching is trim + lowercase, then
// equals-or-contains against the class's match strings; first match
// in file order wins.
function resolveEvidenceClass(vulnerabilityType) {
  const normalized = typeof vulnerabilityType === 'string' ? vulnerabilityType.trim().toLowerCase() : '';
  if (normalized === '') return null;
  const spec = getChecklists();
  if (!spec) return null;
  for (const entry of spec.classes) {
    for (const alias of entry.match) {
      const match = alias.trim().toLowerCase();
      if (normalized === match || normalized.includes(match)) return entry;
    }
  }
  return null;
}

function buildChecklistItems(entry, finding) {
  const required = new Set(entry.required);
  const items = [];
  for (const item of [...entry.required, ...entry.recommended]) {
    items.push({ item, present: ITEM_CHECKS[item](finding), required: required.has(item) });
  }
  return items;
}

// The per-class evidence checklist for a finding: { classId, label,
// items: [{ item, present, required }] }. classId is 'generic' and the
// label says so when no class matches (or the spec failed to load).
function evidenceChecklistForClass(finding) {
  const record = finding && typeof finding === 'object' && !Array.isArray(finding) ? finding : {};
  const spec = getChecklists();
  const entry = resolveEvidenceClass(record.vulnerability_type);
  if (!entry || !spec) {
    const generic = spec ? spec.generic : { id: 'generic', label: 'Generic (no class match)', required: ['proof_of_concept', 'evidence', 'steps_to_reproduce'], recommended: ['impact', 'remediation', 'cwe_id', 'cvss_vector'] };
    return { classId: generic.id, label: generic.label, items: buildChecklistItems(generic, record) };
  }
  return { classId: entry.id, label: entry.label || entry.id, items: buildChecklistItems(entry, record) };
}

function evidenceChecklist(finding) {
  return evidenceChecklistForClass(finding).items.map(({ item, present }) => ({ item, present }));
}

module.exports = { validateFinding, dedupeFindings, semanticDedupeFindings, semanticallyDuplicates, evidenceChecklist, evidenceChecklistForClass, loadEvidenceChecklists, resolveEvidenceClass, rootCauseKey };
