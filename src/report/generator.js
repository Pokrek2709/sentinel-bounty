// Reporting engine (Phase 7): renders VALIDATED finding objects into a
// deterministic bug-bounty report (Markdown or JSON).
//
// Determinism: the same input always produces byte-identical output. No
// wall-clock timestamp is ever generated here: `generated_at` comes from
// the caller (the `--generated-at` flag, or the newest `created_at` among
// the findings); when neither is available the report records that the
// generation time was not specified instead of inventing one.
//
// Strict severity rule: severity is derived from the effective CVSS
// score using the bands in `knowledge/cvss/cvss-calc.json`
// (`severity_ratings`). The effective score is the declared
// `cvss_score` when present, otherwise the score computed from
// `cvss_vector` (see `src/analysis/cvss.js`). When a finding carries
// both `severity` and a score and they disagree, the report FAILS with
// an error; when a vector disagrees with a declared score, or the
// vector itself is malformed, the report FAILS too. A report must
// never carry a wrong severity label, so the generator refuses to
// guess which of the two is right — and a vector-derived score is
// written into the rendered finding instead of "Not scored".
//
// Completeness: a finding missing any field required by
// `schemas/finding.schema.json` fails validation with an error naming the
// missing field(s), before any output is produced, so a failed run can
// never leave a half-written report file behind.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { loadTemplate, renderTemplateReport } = require('./templates');
const { resolveCvss } = require('../analysis/cvss');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

let cachedSeverityRatings = null;
let cachedRequiredFields = null;

// Severity bands are loaded from the shared CVSS knowledge file at
// runtime, never hard-coded, so the bands stay single-sourced.
function loadSeverityRatings() {
  if (cachedSeverityRatings) return cachedSeverityRatings;
  const ratingsPath = path.resolve(__dirname, '..', '..', 'knowledge', 'cvss', 'cvss-calc.json');
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(ratingsPath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load CVSS severity ratings: ${error.message}`);
  }
  if (!parsed || !Array.isArray(parsed.severity_ratings) || parsed.severity_ratings.length === 0) {
    throw new Error('Unable to load CVSS severity ratings: severity_ratings missing or empty.');
  }
  cachedSeverityRatings = parsed.severity_ratings;
  return cachedSeverityRatings;
}

// Required finding fields are loaded from the finding schema at runtime,
// so the completeness check can never drift from the schema.
function loadRequiredFields() {
  if (cachedRequiredFields) return cachedRequiredFields;
  const schemaPath = path.resolve(__dirname, '..', '..', 'schemas', 'finding.schema.json');
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load finding schema: ${error.message}`);
  }
  if (!parsed || !Array.isArray(parsed.required) || parsed.required.length === 0) {
    throw new Error('Unable to load finding schema: required fields missing or empty.');
  }
  cachedRequiredFields = parsed.required;
  return cachedRequiredFields;
}

// Derive a severity label from a CVSS base score using the loaded bands.
// Bands are matched on their lower bound (the first band whose `min` the
// score reaches, scanning from the highest band down): a score of 3.95
// has not reached the medium band's 4.0, so it stays low; 8.95 stays high.
// Every band-boundary score (0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0,
// 10.0) maps exactly onto its band.
function severityForScore(score) {
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10) {
    throw new Error(`Invalid cvss_score: ${String(score)} (expected a number from 0 to 10).`);
  }
  const ratings = [...loadSeverityRatings()].sort((a, b) => b.min - a.min);
  for (const rating of ratings) {
    if (score >= rating.min) return rating.name;
  }
  // Unreachable when the ratings include the 0.0 informational band.
  throw new Error(`No severity band covers cvss_score ${score}.`);
}

function isMissing(value) {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string') return value.trim() === '';
  if (Array.isArray(value)) return value.length === 0;
  return false;
}

// Validate one finding against the finding schema's required fields and
// the strict severity rule. Throws an Error naming every problem found;
// returns the finding unchanged when it is valid.
function validateFinding(finding, index) {
  const label = finding && typeof finding.finding_id === 'string' && finding.finding_id
    ? `Finding ${finding.finding_id}`
    : `Finding at index ${index}`;
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
    throw new Error(`${label} is not an object.`);
  }
  const missing = loadRequiredFields().filter((field) => isMissing(finding[field]));
  if (missing.length > 0) {
    throw new Error(`${label} is missing required field(s): ${missing.join(', ')}.`);
  }
  if (!SEVERITY_ORDER.includes(finding.severity)) {
    throw new Error(`${label} has invalid severity: ${String(finding.severity)}.`);
  }
  // Vector resolution (see ../analysis/cvss.js resolveCvss): a malformed
  // vector or a vector that disagrees with the declared score fails the
  // report — a report must never carry a score the vector contradicts.
  // When only the vector is present, its computed score is derived and
  // the finding is returned with cvss_score filled in, so the rendered
  // report shows the derived score instead of "Not scored".
  const cvss = resolveCvss(finding);
  if (cvss.error) {
    throw new Error(`${label} has ${cvss.error}.`);
  }
  let effectiveScore = null;
  let scoreFromVector = false;
  if (finding.cvss_score !== undefined && finding.cvss_score !== null) {
    if (typeof finding.cvss_score !== 'number' || !Number.isFinite(finding.cvss_score) || finding.cvss_score < 0 || finding.cvss_score > 10) {
      throw new Error(`${label} has invalid cvss_score: ${String(finding.cvss_score)} (expected a number from 0 to 10).`);
    }
    effectiveScore = finding.cvss_score;
  } else if (cvss.vectorScore !== null) {
    effectiveScore = cvss.vectorScore;
    scoreFromVector = true;
  }
  if (effectiveScore !== null) {
    const derived = severityForScore(effectiveScore);
    if (derived !== finding.severity) {
      const source = scoreFromVector
        ? `cvss_vector (computed score ${effectiveScore})`
        : `cvss_score ${effectiveScore}`;
      throw new Error(
        `${label} severity/score mismatch: severity is "${finding.severity}" but ${source} maps to "${derived}". ` +
        'Refusing to report a finding whose severity label disagrees with its CVSS score.',
      );
    }
  }
  if (!Array.isArray(finding.steps_to_reproduce) || finding.steps_to_reproduce.some((step) => typeof step !== 'string' || step.trim() === '')) {
    throw new Error(`${label} has invalid steps_to_reproduce: expected a non-empty array of strings.`);
  }
  return scoreFromVector ? { ...finding, cvss_score: effectiveScore } : finding;
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  for (const finding of findings) {
    // Defensive: only schema severities are counted. generateReport
    // validates first, so this only matters for direct callers — a
    // hostile severity such as '__proto__' must never reach a bucket,
    // and must not silently inflate `total` either (the increment is
    // a no-op on the prototype setter, so the count would be lost).
    if (!SEVERITY_ORDER.includes(finding.severity)) continue;
    counts[finding.severity] += 1;
    counts.total += 1;
  }
  return counts;
}

// Deterministic report id: a hash of the program name and the sorted
// finding ids only, so the same findings under the same program always
// get the same id, independent of when the report was generated.
function deriveReportId(programName, findings) {
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify({ program: programName, ids: findings.map((f) => f.finding_id).sort() }))
    .digest('hex');
  return `RPT-${digest.slice(0, 12)}`;
}

function executiveSummary(counts, programName) {
  const parts = SEVERITY_ORDER.map((severity) => `${counts[severity]} ${severity}`);
  const top = SEVERITY_ORDER.find((severity) => counts[severity] > 0) || 'informational';
  return `Program ${programName}: ${counts.total} validated finding(s) — ${parts.join(', ')}. ` +
    `Highest severity: ${top}. All findings in this report were validated against the finding schema before rendering.`;
}

function formatValue(value, fallback = 'Not provided') {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'string') return value.trim() === '' ? fallback : value;
  return String(value);
}

function markdownFinding(finding, number) {
  const lines = [];
  lines.push(`## ${number}. ${finding.title} [${finding.severity.toUpperCase()}]`);
  lines.push('');
  lines.push(`- **Finding ID:** ${finding.finding_id}`);
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push(`- **CVSS:** ${finding.cvss_score !== undefined && finding.cvss_score !== null ? String(finding.cvss_score) : 'Not scored'}${finding.cvss_vector ? ` (${finding.cvss_vector})` : ''}`);
  lines.push(`- **CWE:** ${formatValue(finding.cwe_id)}`);
  lines.push(`- **Vulnerability type:** ${finding.vulnerability_type}`);
  lines.push(`- **Affected component:** ${finding.asset_id}${finding.asset_url ? ` (${finding.asset_url})` : ''}`);
  lines.push(`- **Confidence:** ${finding.confidence}`);
  lines.push(`- **Validation status:** ${finding.validation_status}`);
  lines.push('');
  lines.push('### Description');
  lines.push('');
  lines.push(finding.description);
  lines.push('');
  lines.push('### Steps to Reproduce');
  lines.push('');
  finding.steps_to_reproduce.forEach((step, index) => {
    lines.push(`${index + 1}. ${step}`);
  });
  lines.push('');
  lines.push('### Proof of Concept');
  lines.push('');
  lines.push(formatValue(finding.proof_of_concept));
  if (Array.isArray(finding.evidence) && finding.evidence.length > 0) {
    lines.push('');
    finding.evidence.forEach((item, index) => {
      lines.push(`Evidence ${index + 1}:`);
      if (item.request) lines.push(`- Request: ${item.request}`);
      if (item.response) lines.push(`- Response: ${item.response}`);
      if (item.notes) lines.push(`- Notes: ${item.notes}`);
    });
  }
  lines.push('');
  lines.push('### Impact');
  lines.push('');
  lines.push(finding.impact);
  lines.push('');
  lines.push('### Remediation');
  lines.push('');
  lines.push(finding.remediation);
  lines.push('');
  lines.push('### References');
  lines.push('');
  if (Array.isArray(finding.references) && finding.references.length > 0) {
    finding.references.forEach((reference) => lines.push(`- ${reference}`));
  } else {
    lines.push('Not provided');
  }
  lines.push('');
  return lines.join('\n');
}

function renderMarkdown({ programName, generatedAt, counts, findings }) {
  const lines = [];
  lines.push(`# Bug Bounty Report — ${programName}`);
  lines.push('');
  lines.push(`Generated: ${generatedAt || 'Not specified'}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | ---: |');
  SEVERITY_ORDER.forEach((severity) => {
    lines.push(`| ${severity} | ${counts[severity]} |`);
  });
  lines.push(`| total | ${counts.total} |`);
  lines.push('');
  lines.push(executiveSummary(counts, programName));
  lines.push('');
  findings.forEach((finding, index) => {
    lines.push(markdownFinding(finding, index + 1));
  });
  return `${lines.join('\n').trimEnd()}\n`;
}

function renderJson({ reportId, targetId, sessionId, programName, generatedAt, counts, findings, summary, template }) {
  const report = {
    report_id: reportId,
    target_id: targetId,
    program_name: programName,
    generated_at: generatedAt,
    executive_summary: summary,
    findings_summary: counts,
    findings,
  };
  if (sessionId) report.session_id = sessionId;
  if (template) report.template = template;
  return `${JSON.stringify(report, null, 2)}\n`;
}

// Generate a report from one or more validated findings.
// options: { programName, generatedAt, format, template } — format is
// 'markdown' (default) or 'json'; template is 'generic' (default) or the
// name of a platform template (see src/report/templates.js). A named
// template renders exactly one finding per report — the platforms accept
// one bug per submission — and its required sections fail cleanly when
// their source field is missing, instead of inventing content. Throws on
// any validation failure; nothing is written by this function, so a
// failure can never leave a half-written output file.
function generateReport(findings, options = {}) {
  if (!Array.isArray(findings) || findings.length === 0) {
    throw new Error('At least one finding is required to generate a report.');
  }
  const validated = findings.map((finding, index) => validateFinding(finding, index));
  const programName = typeof options.programName === 'string' && options.programName.trim()
    ? options.programName.trim()
    : 'Unnamed Program';
  // generated_at is caller-supplied, else the newest finding created_at,
  // else omitted (never invented from the wall clock).
  let generatedAt = typeof options.generatedAt === 'string' && options.generatedAt.trim()
    ? options.generatedAt.trim()
    : null;
  if (generatedAt && !Number.isFinite(Date.parse(generatedAt))) {
    throw new Error(`Invalid generated_at: ${generatedAt} (expected an ISO 8601 timestamp).`);
  }
  if (!generatedAt) {
    const created = validated
      .map((finding) => finding.created_at)
      .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
    if (created.length > 0) generatedAt = created.sort().at(-1);
  }
  const counts = countBySeverity(validated);
  const summary = executiveSummary(counts, programName);
  const format = options.format || 'markdown';
  if (format !== 'markdown' && format !== 'json') {
    throw new Error(`Invalid format: ${format} (expected "markdown" or "json").`);
  }
  if (format === 'json' && !generatedAt) {
    // schemas/report.schema.json requires generated_at as a date-time
    // string, so a JSON report cannot be produced without one: pass
    // --generated-at or give the findings created_at values.
    throw new Error('JSON output requires a generated_at timestamp: pass --generated-at or include created_at on the findings.');
  }
  const templateName = typeof options.template === 'string' && options.template.trim()
    ? options.template.trim()
    : 'generic';
  if (templateName !== 'generic') {
    const template = loadTemplate(templateName);
    if (validated.length !== 1) {
      throw new Error(
        `Template "${templateName}" renders one finding per report; got ${validated.length} findings. ` +
        'Generate one report per finding, or use the generic template.',
      );
    }
    if (format === 'json') {
      return renderJson({
        reportId: deriveReportId(programName, validated),
        targetId: validated[0].target_id,
        sessionId: validated[0].session_id,
        programName,
        generatedAt,
        counts,
        findings: validated,
        summary,
        template: templateName,
      });
    }
    return renderTemplateReport(template, validated[0], { programName, generatedAt });
  }
  if (format === 'json') {
    return renderJson({
      reportId: deriveReportId(programName, validated),
      targetId: validated[0].target_id,
      sessionId: validated[0].session_id,
      programName,
      generatedAt,
      counts,
      findings: validated,
      summary,
    });
  }
  return renderMarkdown({ programName, generatedAt, counts, findings: validated });
}

module.exports = { generateReport, validateFinding, severityForScore, countBySeverity, SEVERITY_ORDER };
