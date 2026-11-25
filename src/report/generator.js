// Reporting engine (Phase 7): renders VALIDATED finding objects into a
// deterministic bug-bounty report (Markdown, JSON, standalone HTML, or
// flat CSV).
//
// Grouping: findings are grouped by `asset_id` before rendering.
// Groups are ordered by asset_id ascending (plain string order, never
// locale-dependent), findings inside a group by severity (critical
// first) then finding_id. The order is a pure function of the finding
// SET, never of the input order, so the same findings in any input
// order produce byte-identical output. A finding whose asset_id is
// missing, empty, or not a string falls into the "unassigned" group;
// in practice `validateFinding` rejects such a finding first (asset_id
// is a required schema field), so the unassigned bucket is defensive
// for direct callers of `groupFindingsByAsset`. Grouping never changes
// a verdict: validation and deduplication happen before grouping, and
// the validator's verdict is carried per finding, untouched.
//
// Mixed targets: a report input covering more than one distinct
// `target_id` is REFUSED by default (`REPORT_MIXED_TARGETS_REFUSED`)
// — a mixed-target report that names only one target would
// misattribute findings, and the pre-round-49 generator did exactly
// that: it rendered mixed input silently and put only the first
// finding's target into JSON `target_id`, dropping the rest. The
// operator may opt in with `allowMixedTargets` (CLI
// `--allow-mixed-targets`): the report then groups by target first,
// then by asset within each target, and states the full target list
// in its header (Markdown, JSON, and HTML). Platform templates render
// one finding per report, so they can never be mixed-target; the
// mixed-target check runs before the template branch.
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
// vector itself is malformed, the report FAILS too. The same strict
// rule applies to the declared `cvss_temporal_score` and
// `cvss_environmental_score`: a vector whose computed temporal
// (environmental) score disagrees with the declared one fails the
// report, and a present-but-invalid declared temporal/environmental
// score fails it as well. When only the vector is present, its
// computed base, temporal, and environmental scores are all derived
// and written into the rendered finding. The severity is checked
// against the BASE score only — temporal and environmental scores
// never re-band a finding. A report must never carry a wrong severity
// label, so the generator refuses to guess which of the two is right
// — and a vector-derived score is written into the rendered finding
// instead of "Not scored".
//
// Merged findings: a finding produced by the semantic dedup pass
// (`src/analysis/validator.js` `semanticDedupeFindings`) carries
// `merged_from`, the list of finding ids it was merged from. The
// Markdown and HTML renderers show it as a "Merged from" line right
// after the finding id; the JSON renderer carries it through the
// spread, so it appears on the finding in both the flat `findings`
// array and the grouped `groups`. A finding without `merged_from`
// renders exactly as before — no line is added for singletons, so an
// unmerged report is byte-identical to the pre-round-48 output.
//
// Completeness: a finding missing any field required by
// `schemas/finding.schema.json` fails validation with an error naming the
// missing field(s), before any output is produced, so a failed run can
// never leave a half-written report file behind.
//
// Evidence checklist: every rendered finding carries its per-class
// evidence checklist (see `src/analysis/validator.js`
// `evidenceChecklistForClass`): the Markdown report renders it as an
// "Evidence Checklist" section naming the class and marking each item
// present/missing and required/recommended; the JSON report attaches
// it as `evidence_checklist` on each finding; the HTML report renders
// it as a list with the same [x]/[ ] marks. Platform templates
// (Immunefi/Code4rena) render their own fixed sections and do not
// carry the checklist in Markdown; their JSON form still does.
//
// AI verdict (round 50): when a verifier is configured
// (`sentinel report --verifier ...`, generator option `verifier`),
// each finding carries an advisory `ai_verdict` + `ai_verdict_source`
// (see `src/analysis/ai-verdict.js`). The AI verdict NEVER changes
// the rule-based verdict or any rendered score — it is recorded
// alongside them and labelled advisory in all three formats
// (Markdown line, HTML row, JSON field carried by the spread).
// When no verifier is configured, no `ai_verdict` is attached and
// the report is byte-identical to the pre-round-50 output (the
// round-44 golden hashes still pass). Platform templates render
// their own fixed sections and do not carry the AI verdict in
// Markdown — the same precedent as the evidence checklist — but
// their JSON form still does, via the spread.
//
// CSV output (round 55): one row per finding plus a header row
// (see CSV_COLUMNS / renderCsv). The column order is fixed and
// documented in docs/report-csv-v1.md; rows follow the same
// grouped order as Markdown/JSON (target, then asset, then
// severity, then finding_id), so the same finding set in any input
// order produces byte-identical CSV. Every field is RFC 4180
// escaped (see escapeCsvField). Finding content is untrusted, so
// hostile values (`<script>`, `=cmd`, `+cmd`, `@cmd`) are rendered
// verbatim as inert text — the file itself never executes anything
// — and the doc warns that spreadsheet consumers must still treat
// the file as untrusted (formula injection is a consumer risk:
// open with data-import, not double-click, when findings carry
// untrusted strings). An empty finding set renders the header row
// only; a platform template with CSV output is refused, like HTML.
//
// HTML output: a single self-contained file (inline CSS only, no
// JavaScript, no external resources). Finding content is UNTRUSTED —
// it can contain attacker-controlled strings — so every interpolated
// value is HTML-escaped before it reaches the output (see
// `escapeHtml`); references and asset URLs render as inert text, never
// as links, so no `href`/`src` attribute exists anywhere in the file.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { loadTemplate, renderTemplateReport } = require('./templates');
const { resolveCvss } = require('../analysis/cvss');
const { evidenceChecklistForClass } = require('../analysis/validator');
const { getVerifier, attachAiVerdict } = require('../analysis/ai-verdict');

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
  // vector or a vector that disagrees with a declared score fails the
  // report — a report must never carry a score the vector contradicts.
  // The same strict rule applies to the declared temporal and
  // environmental scores. When only the vector is present, its computed
  // base, temporal, and environmental scores are derived and the
  // finding is returned with the missing ones filled in, so the
  // rendered report shows the derived scores instead of "Not scored".
  const cvss = resolveCvss(finding);
  if (cvss.error) {
    throw new Error(`${label} has ${cvss.error}.`);
  }
  if (cvss.temporalError) {
    throw new Error(`${label} has ${cvss.temporalError}.`);
  }
  if (cvss.environmentalError) {
    throw new Error(`${label} has ${cvss.environmentalError}.`);
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
  if (finding.cvss_temporal_score !== undefined && finding.cvss_temporal_score !== null) {
    if (typeof finding.cvss_temporal_score !== 'number' || !Number.isFinite(finding.cvss_temporal_score) || finding.cvss_temporal_score < 0 || finding.cvss_temporal_score > 10) {
      throw new Error(`${label} has invalid cvss_temporal_score: ${String(finding.cvss_temporal_score)} (expected a number from 0 to 10).`);
    }
  }
  if (finding.cvss_environmental_score !== undefined && finding.cvss_environmental_score !== null) {
    if (typeof finding.cvss_environmental_score !== 'number' || !Number.isFinite(finding.cvss_environmental_score) || finding.cvss_environmental_score < 0 || finding.cvss_environmental_score > 10) {
      throw new Error(`${label} has invalid cvss_environmental_score: ${String(finding.cvss_environmental_score)} (expected a number from 0 to 10).`);
    }
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
  // Fill in every score the vector computed that the finding did not
  // declare: base, temporal, and environmental. A declared score is
  // never overwritten — a mismatch above already failed the report.
  const filled = { ...finding };
  let filledAnything = false;
  if (scoreFromVector) {
    filled.cvss_score = effectiveScore;
    filledAnything = true;
  }
  if ((finding.cvss_temporal_score === undefined || finding.cvss_temporal_score === null) && cvss.temporalScore !== null) {
    filled.cvss_temporal_score = cvss.temporalScore;
    filledAnything = true;
  }
  if ((finding.cvss_environmental_score === undefined || finding.cvss_environmental_score === null) && cvss.environmentalScore !== null) {
    filled.cvss_environmental_score = cvss.environmentalScore;
    filledAnything = true;
  }
  return filledAnything ? filled : finding;
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

const UNASSIGNED_ASSET = 'unassigned';

// Plain string comparison (never localeCompare, which is
// locale-dependent): the group order must be identical on every host.
function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// Group findings by asset_id. Returns [{ asset_id, findings }] with
// groups ordered by asset_id ascending and findings inside a group
// ordered by severity (critical first) then finding_id. The input
// array is never mutated. A missing, empty, whitespace-only, or
// non-string asset_id maps to the "unassigned" group.
function groupFindingsByAsset(findings) {
  if (!Array.isArray(findings)) {
    throw new Error('groupFindingsByAsset expects an array of findings.');
  }
  const byAsset = new Map();
  for (const finding of findings) {
    const raw = finding && typeof finding.asset_id === 'string' ? finding.asset_id.trim() : '';
    const key = raw === '' ? UNASSIGNED_ASSET : raw;
    if (!byAsset.has(key)) byAsset.set(key, []);
    byAsset.get(key).push(finding);
  }
  const groups = [...byAsset.entries()]
    .sort((a, b) => compareStrings(a[0], b[0]))
    .map(([assetId, groupFindings]) => ({
      asset_id: assetId,
      findings: [...groupFindings].sort((a, b) => {
        const severityDelta = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        if (severityDelta !== 0) return severityDelta;
        return compareStrings(String(a.finding_id), String(b.finding_id));
      }),
    }));
  return groups;
}

// Group findings by target_id first, then by asset_id within each
// target. Returns [{ target_id, groups }] with targets ordered by
// target_id ascending (plain string order) and asset groups in the
// round-42 order (groupFindingsByAsset). The input array is never
// mutated. A missing, empty, whitespace-only, or non-string
// target_id maps to the "unassigned" target; in practice
// `validateFinding` rejects such a finding first (target_id is a
// required schema field), so the unassigned bucket is defensive for
// direct callers — generateReport never sees it.
function groupFindingsByTarget(findings) {
  if (!Array.isArray(findings)) {
    throw new Error('groupFindingsByTarget expects an array of findings.');
  }
  const byTarget = new Map();
  for (const finding of findings) {
    const raw = finding && typeof finding.target_id === 'string' ? finding.target_id.trim() : '';
    const key = raw === '' ? 'unassigned' : raw;
    if (!byTarget.has(key)) byTarget.set(key, []);
    byTarget.get(key).push(finding);
  }
  return [...byTarget.entries()]
    .sort((a, b) => compareStrings(a[0], b[0]))
    .map(([targetId, targetFindings]) => ({
      target_id: targetId,
      groups: groupFindingsByAsset(targetFindings),
    }));
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

// Escape a value for HTML text content. Every interpolated value in
// the HTML report goes through this — finding content is untrusted and
// may contain markup, quotes, or `javascript:`-style strings, which
// must render as inert text, never as executable markup. Attribute
// contexts do not exist in the HTML report at all (no href/src), so
// text escaping is the only context that needs covering; the single
// quote is escaped anyway, so a future attribute would not silently
// become safe by accident — it would still need its own review.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function htmlText(value, fallback = 'Not provided') {
  return escapeHtml(formatValue(value, fallback));
}

// The advisory AI verdict line for a finding, or null when the
// finding carries none. Defensive: a finding read from a file can
// carry a malformed ai_verdict, and rendering must never crash on
// it — unknown parts render as 'unknown' instead. The reasons are
// joined with '; '; an empty reasons list renders as 'no reasons
// given'. The verifier-error case needs no special handling here:
// a failed verifier records its failure in the reasons already.
function formatAiVerdict(finding) {
  const result = finding.ai_verdict;
  if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
  const verdict = typeof result.verdict === 'string' && result.verdict !== '' ? result.verdict : 'unknown';
  const confidence = typeof result.confidence === 'number' && Number.isFinite(result.confidence) ? String(result.confidence) : 'unknown';
  const reasons = Array.isArray(result.reasons) && result.reasons.length > 0 ? result.reasons.join('; ') : 'no reasons given';
  const source = typeof finding.ai_verdict_source === 'string' && finding.ai_verdict_source !== '' ? finding.ai_verdict_source : 'unknown';
  return `${verdict} (confidence ${confidence}, source: ${source}) — ${reasons}`;
}

// CSV export (round 55): one row per finding, header row first. The
// column order is fixed — see docs/report-csv-v1.md — and the
// `verdict` column carries the finding's `validation_status` value.
// The evidence checklist renders as a compact summary: present/total
// plus the missing items joined with '; ' (or "(complete)" when
// nothing is missing). `merged_from` joins with '; '; `ai_verdict`
// uses the same advisory line as Markdown, or an empty cell when
// the finding carries none. Scores render as plain numbers; a
// missing score renders as an empty cell, never "Not scored" —
// "Not scored" is display text, not data.
const CSV_COLUMNS = [
  'finding_id',
  'target_id',
  'asset_id',
  'severity',
  'cvss_base_score',
  'cvss_temporal_score',
  'cvss_environmental_score',
  'verdict',
  'evidence_checklist',
  'merged_from',
  'ai_verdict',
];

// RFC 4180 field escaping: a field containing a double quote, a
// comma, or a line break is wrapped in double quotes with inner
// quotes doubled. Every other field is written verbatim — including
// a value that starts with `=`, `+`, or `@`. The file is inert
// text and never executes anything on its own; a spreadsheet that
// interprets a leading `=` as a formula is a consumer risk, and
// the doc (docs/report-csv-v1.md) warns operators about it instead
// of silently altering the finding's data.
function escapeCsvField(value) {
  const text = value === undefined || value === null ? '' : String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function evidenceChecklistSummary(finding) {
  const checklist = evidenceChecklistForClass(finding);
  const present = checklist.items.filter((entry) => entry.present).length;
  const missing = checklist.items.filter((entry) => !entry.present).map((entry) => entry.item);
  return missing.length === 0
    ? `${present}/${checklist.items.length} (complete)`
    : `${present}/${checklist.items.length} (missing: ${missing.join('; ')})`;
}

function csvScore(value) {
  return value !== undefined && value !== null ? String(value) : '';
}

function csvFindingRow(finding) {
  const aiVerdict = formatAiVerdict(finding);
  const fields = [
    finding.finding_id,
    finding.target_id,
    finding.asset_id,
    finding.severity,
    csvScore(finding.cvss_score),
    csvScore(finding.cvss_temporal_score),
    csvScore(finding.cvss_environmental_score),
    finding.validation_status,
    evidenceChecklistSummary(finding),
    Array.isArray(finding.merged_from) ? finding.merged_from.join('; ') : '',
    aiVerdict === null ? '' : aiVerdict,
  ];
  return fields.map(escapeCsvField).join(',');
}

// Render the findings (already in grouped order — see generateReport)
// as flat CSV: header row, then one row per finding, LF line endings,
// trailing newline. An empty array renders the header only.
function renderCsv(orderedFindings) {
  const lines = [CSV_COLUMNS.join(',')];
  orderedFindings.forEach((finding) => lines.push(csvFindingRow(finding)));
  return `${lines.join('\n')}\n`;
}

function markdownFinding(finding, number) {
  const lines = [];
  lines.push(`## ${number}. ${finding.title} [${finding.severity.toUpperCase()}]`);
  lines.push('');
  lines.push(`- **Finding ID:** ${finding.finding_id}`);
  if (Array.isArray(finding.merged_from) && finding.merged_from.length > 0) {
    lines.push(`- **Merged from:** ${finding.merged_from.join(', ')}`);
  }
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push(`- **CVSS:** ${finding.cvss_score !== undefined && finding.cvss_score !== null ? String(finding.cvss_score) : 'Not scored'}${finding.cvss_vector ? ` (${finding.cvss_vector})` : ''}`);
  if (finding.cvss_temporal_score !== undefined && finding.cvss_temporal_score !== null) {
    lines.push(`- **CVSS temporal:** ${String(finding.cvss_temporal_score)}`);
  }
  if (finding.cvss_environmental_score !== undefined && finding.cvss_environmental_score !== null) {
    lines.push(`- **CVSS environmental:** ${String(finding.cvss_environmental_score)}`);
  }
  lines.push(`- **CWE:** ${formatValue(finding.cwe_id)}`);
  lines.push(`- **Vulnerability type:** ${finding.vulnerability_type}`);
  lines.push(`- **Affected component:** ${finding.asset_id}${finding.asset_url ? ` (${finding.asset_url})` : ''}`);
  lines.push(`- **Confidence:** ${finding.confidence}`);
  lines.push(`- **Validation status:** ${finding.validation_status}`);
  const aiVerdict = formatAiVerdict(finding);
  if (aiVerdict !== null) {
    lines.push(`- **AI verdict (advisory):** ${aiVerdict}`);
  }
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
  lines.push('### Evidence Checklist');
  lines.push('');
  const checklist = evidenceChecklistForClass(finding);
  lines.push(`- Class: ${checklist.label}${checklist.classId === 'generic' ? ' — the vulnerability type matched no class, so the generic checklist applies' : ''}`);
  checklist.items.forEach((entry) => {
    const box = entry.present ? '[x]' : '[ ]';
    const suffix = entry.present ? '' : ' — missing';
    lines.push(`- ${box} ${entry.item} (${entry.required ? 'required' : 'recommended'})${suffix}`);
  });
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

function renderMarkdown({ programName, generatedAt, counts, groups, targetGroups, multiTarget, targetIds }) {
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
  if (multiTarget) {
    lines.push(`This report covers multiple targets: ${targetIds.join(', ')}.`);
    lines.push('');
  }
  // Findings render grouped by asset; the finding number is global
  // and sequential across groups, so a single-finding report keeps
  // its existing numbering (only the group header is new). In
  // multi-target mode the same asset sections nest under a
  // `## Target:` section per target, and the finding number stays
  // global across targets. The single-target rendering below is
  // byte-identical to the pre-round-49 output: no target header is
  // added when there is only one target.
  let number = 0;
  const renderAssetGroup = (group, heading) => {
    const groupCounts = countBySeverity(group.findings);
    const severitySummary = SEVERITY_ORDER.map((severity) => `${severity}: ${groupCounts[severity]}`).join(', ');
    const noun = group.findings.length === 1 ? 'finding' : 'findings';
    lines.push(`${heading} Asset: ${group.asset_id} — ${group.findings.length} ${noun} (${severitySummary})`);
    lines.push('');
    group.findings.forEach((finding) => {
      number += 1;
      lines.push(markdownFinding(finding, number));
    });
  };
  if (multiTarget) {
    targetGroups.forEach((targetGroup) => {
      lines.push(`## Target: ${targetGroup.target_id}`);
      lines.push('');
      targetGroup.groups.forEach((group) => renderAssetGroup(group, '###'));
    });
  } else {
    groups.forEach((group) => renderAssetGroup(group, '##'));
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

// Inline stylesheet for the HTML report. Kept deliberately small and
// static: no external fonts, images, or stylesheets, no JavaScript.
// Severity colours are the only semantic styling; the page stays
// readable with styles disabled because every value is also present
// as text (the severity label, the [x]/[ ] marks).
const HTML_STYLES = [
  'body{font-family:system-ui,sans-serif;margin:2em auto;max-width:60em;padding:0 1em;color:#111}',
  'h1{font-size:1.5em}h2{font-size:1.25em;border-bottom:1px solid #999;padding-bottom:.25em}',
  'h3{font-size:1.1em}h4{font-size:1em;margin-bottom:.25em}',
  'table{border-collapse:collapse}th,td{border:1px solid #999;padding:.25em .75em;text-align:left}',
  'td.num{text-align:right}.sev{font-weight:bold;padding:.1em .4em;border-radius:.25em}',
  '.sev-critical{background:#f8d7da}.sev-high{background:#ffe0b3}.sev-medium{background:#fff3cd}',
  '.sev-low{background:#d1ecf1}.sev-informational{background:#e2e3e5}',
  'article{border:1px solid #999;padding:0 1em;margin-bottom:1em}',
  'dt{font-weight:bold}dd{margin:0 0 .5em 0}',
].join('\n');

function htmlFinding(finding, number) {
  const lines = [];
  lines.push('<article>');
  lines.push(`<h3>${number}. ${escapeHtml(finding.title)} <span class="sev sev-${finding.severity}">${escapeHtml(finding.severity.toUpperCase())}</span></h3>`);
  lines.push('<dl>');
  lines.push(`<dt>Finding ID</dt><dd>${escapeHtml(finding.finding_id)}</dd>`);
  if (Array.isArray(finding.merged_from) && finding.merged_from.length > 0) {
    lines.push(`<dt>Merged from</dt><dd>${escapeHtml(finding.merged_from.join(', '))}</dd>`);
  }
  lines.push(`<dt>Severity</dt><dd>${escapeHtml(finding.severity)}</dd>`);
  const cvssLine = finding.cvss_score !== undefined && finding.cvss_score !== null
    ? escapeHtml(String(finding.cvss_score)) + (finding.cvss_vector ? ` (${escapeHtml(finding.cvss_vector)})` : '')
    : 'Not scored';
  lines.push(`<dt>CVSS</dt><dd>${cvssLine}</dd>`);
  if (finding.cvss_temporal_score !== undefined && finding.cvss_temporal_score !== null) {
    lines.push(`<dt>CVSS temporal</dt><dd>${escapeHtml(String(finding.cvss_temporal_score))}</dd>`);
  }
  if (finding.cvss_environmental_score !== undefined && finding.cvss_environmental_score !== null) {
    lines.push(`<dt>CVSS environmental</dt><dd>${escapeHtml(String(finding.cvss_environmental_score))}</dd>`);
  }
  lines.push(`<dt>CWE</dt><dd>${htmlText(finding.cwe_id)}</dd>`);
  lines.push(`<dt>Vulnerability type</dt><dd>${escapeHtml(finding.vulnerability_type)}</dd>`);
  const component = finding.asset_url
    ? `${escapeHtml(finding.asset_id)} (${escapeHtml(finding.asset_url)})`
    : escapeHtml(finding.asset_id);
  lines.push(`<dt>Affected component</dt><dd>${component}</dd>`);
  lines.push(`<dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd>`);
  lines.push(`<dt>Validation status</dt><dd>${escapeHtml(finding.validation_status)}</dd>`);
  const aiVerdict = formatAiVerdict(finding);
  if (aiVerdict !== null) {
    lines.push(`<dt>AI verdict (advisory)</dt><dd>${escapeHtml(aiVerdict)}</dd>`);
  }
  lines.push('</dl>');
  lines.push('<h4>Description</h4>');
  lines.push(`<p>${escapeHtml(finding.description)}</p>`);
  lines.push('<h4>Steps to Reproduce</h4>');
  lines.push('<ol>');
  finding.steps_to_reproduce.forEach((step) => {
    lines.push(`<li>${escapeHtml(step)}</li>`);
  });
  lines.push('</ol>');
  lines.push('<h4>Proof of Concept</h4>');
  lines.push(`<p>${htmlText(finding.proof_of_concept)}</p>`);
  if (Array.isArray(finding.evidence) && finding.evidence.length > 0) {
    finding.evidence.forEach((item, index) => {
      lines.push(`<p>Evidence ${index + 1}:</p>`);
      lines.push('<ul>');
      if (item.request) lines.push(`<li>Request: ${escapeHtml(item.request)}</li>`);
      if (item.response) lines.push(`<li>Response: ${escapeHtml(item.response)}</li>`);
      if (item.notes) lines.push(`<li>Notes: ${escapeHtml(item.notes)}</li>`);
      lines.push('</ul>');
    });
  }
  lines.push('<h4>Evidence Checklist</h4>');
  const checklist = evidenceChecklistForClass(finding);
  const classNote = checklist.classId === 'generic'
    ? ' — the vulnerability type matched no class, so the generic checklist applies'
    : '';
  lines.push(`<p>Class: ${escapeHtml(checklist.label)}${escapeHtml(classNote)}</p>`);
  lines.push('<ul>');
  checklist.items.forEach((entry) => {
    const box = entry.present ? '[x]' : '[ ]';
    const suffix = entry.present ? '' : ' — missing';
    lines.push(`<li>${box} ${escapeHtml(entry.item)} (${entry.required ? 'required' : 'recommended'})${suffix}</li>`);
  });
  lines.push('</ul>');
  lines.push('<h4>Impact</h4>');
  lines.push(`<p>${escapeHtml(finding.impact)}</p>`);
  lines.push('<h4>Remediation</h4>');
  lines.push(`<p>${escapeHtml(finding.remediation)}</p>`);
  lines.push('<h4>References</h4>');
  if (Array.isArray(finding.references) && finding.references.length > 0) {
    lines.push('<ul>');
    finding.references.forEach((reference) => lines.push(`<li>${escapeHtml(reference)}</li>`));
    lines.push('</ul>');
  } else {
    lines.push('<p>Not provided</p>');
  }
  lines.push('</article>');
  return lines.join('\n');
}

// Render the same grouped findings as Markdown, as one self-contained
// HTML file: inline CSS only, no JavaScript, no external resources.
// Deterministic: the same input always produces byte-identical output
// (grouping order comes from groupFindingsByAsset; `generated_at` is
// caller-supplied or "Not specified", never the wall clock).
function renderHtml({ reportId, programName, generatedAt, counts, groups, targetGroups, multiTarget, targetIds, summary }) {
  const lines = [];
  lines.push('<!DOCTYPE html>');
  lines.push('<html lang="en">');
  lines.push('<head>');
  lines.push('<meta charset="utf-8">');
  lines.push(`<title>Bug Bounty Report — ${escapeHtml(programName)}</title>`);
  lines.push('<style>');
  lines.push(HTML_STYLES);
  lines.push('</style>');
  lines.push('</head>');
  lines.push('<body>');
  lines.push(`<h1>Bug Bounty Report — ${escapeHtml(programName)}</h1>`);
  lines.push(`<p>Report ID: ${escapeHtml(reportId)}</p>`);
  lines.push(`<p>Generated: ${escapeHtml(generatedAt || 'Not specified')}</p>`);
  lines.push('<h2>Summary</h2>');
  lines.push('<table>');
  lines.push('<tr><th>Severity</th><th>Count</th></tr>');
  SEVERITY_ORDER.forEach((severity) => {
    lines.push(`<tr><td>${severity}</td><td class="num">${counts[severity]}</td></tr>`);
  });
  lines.push(`<tr><td>total</td><td class="num">${counts.total}</td></tr>`);
  lines.push('</table>');
  lines.push(`<p>${escapeHtml(summary)}</p>`);
  if (multiTarget) {
    lines.push(`<p>This report covers multiple targets: ${targetIds.map((targetId) => escapeHtml(targetId)).join(', ')}</p>`);
  }
  // Single-target rendering is byte-identical to the pre-round-49
  // output: no target heading is added when there is only one target.
  // Multi-target mode nests the asset sections under a per-target
  // heading, with the same global finding numbering.
  let number = 0;
  const renderAssetGroup = (group, headingTag) => {
    const groupCounts = countBySeverity(group.findings);
    const severitySummary = SEVERITY_ORDER.map((severity) => `${severity}: ${groupCounts[severity]}`).join(', ');
    const noun = group.findings.length === 1 ? 'finding' : 'findings';
    lines.push(`<${headingTag}>Asset: ${escapeHtml(group.asset_id)} — ${group.findings.length} ${noun} (${severitySummary})</${headingTag}>`);
    group.findings.forEach((finding) => {
      number += 1;
      lines.push(htmlFinding(finding, number));
    });
  };
  if (multiTarget) {
    targetGroups.forEach((targetGroup) => {
      lines.push(`<h2>Target: ${escapeHtml(targetGroup.target_id)}</h2>`);
      targetGroup.groups.forEach((group) => renderAssetGroup(group, 'h3'));
    });
  } else {
    groups.forEach((group) => renderAssetGroup(group, 'h2'));
  }
  lines.push('</body>');
  lines.push('</html>');
  return `${lines.join('\n')}\n`;
}

function renderJson({ reportId, targetId, sessionId, programName, generatedAt, counts, findings, summary, template, groups, targetGroups, multiTarget, targetIds }) {
  // Each finding carries its per-class evidence checklist (see
  // src/analysis/validator.js evidenceChecklistForClass): the class
  // that matched, and every checklist item with present/required.
  // Platform templates render their own fixed sections and do not
  // carry the checklist in Markdown; their JSON form still does.
  const findingsWithChecklist = findings.map((finding) => ({
    ...finding,
    evidence_checklist: evidenceChecklistForClass(finding),
  }));
  const report = {
    report_id: reportId,
    target_id: targetId,
    program_name: programName,
    generated_at: generatedAt,
    executive_summary: summary,
    findings_summary: counts,
    findings: findingsWithChecklist,
  };
  // Multi-target reports state the full target list explicitly:
  // `target_id` is still required by schemas/report.schema.json, so
  // it holds the first target in sorted order (the same value the
  // single-target path carries); `target_ids` is the authoritative
  // list, and `mixed_targets` marks the report so no consumer can
  // mistake it for a single-target report.
  if (multiTarget) {
    report.target_ids = [...targetIds];
    report.mixed_targets = true;
  }
  // Generic reports carry the asset grouping alongside the flat
  // findings array (which stays in grouped order). Platform-template
  // JSON keeps its previous flat shape: a template renders one
  // finding per report, so grouping adds nothing and is omitted.
  // In multi-target mode each group also carries its target_id, so
  // a group can never be read as belonging to the wrong target.
  if (groups) {
    if (multiTarget) {
      report.groups = targetGroups.flatMap((targetGroup) => targetGroup.groups.map((group) => ({
        target_id: targetGroup.target_id,
        asset_id: group.asset_id,
        findings_count: group.findings.length,
        findings_summary: countBySeverity(group.findings),
        findings: group.findings.map((finding) => ({
          ...finding,
          evidence_checklist: evidenceChecklistForClass(finding),
        })),
      })));
    } else {
      report.groups = groups.map((group) => ({
        asset_id: group.asset_id,
        findings_count: group.findings.length,
        findings_summary: countBySeverity(group.findings),
        findings: group.findings.map((finding) => ({
          ...finding,
          evidence_checklist: evidenceChecklistForClass(finding),
        })),
      }));
    }
  }
  if (sessionId) report.session_id = sessionId;
  if (template) report.template = template;
  return `${JSON.stringify(report, null, 2)}\n`;
}

// Platform templates are Markdown-only. A named template with HTML
// or CSV output fails cleanly with the same message in both places
// it is checked (the empty-set early return and the template branch
// below), so the refusal never depends on how many findings there
// are.
function assertTemplateAllowsFormat(templateName, format) {
  if (templateName === 'generic') return;
  if (format === 'html') {
    throw new Error(`Template "${templateName}" renders Markdown only; HTML output uses the generic template.`);
  }
  if (format === 'csv') {
    throw new Error(`Template "${templateName}" renders Markdown only; CSV output uses the generic template.`);
  }
}

// Generate a report from one or more validated findings.
// options: { programName, generatedAt, format, template,
// allowMixedTargets, verifier } — format is 'markdown' (default), 'json',
// 'html', or 'csv'; template is 'generic' (default) or the name of a
// platform template (see src/report/templates.js). verifier is 'stub', a
// verifier function, or a module path (CLI --verifier); when set,
// each finding carries an advisory ai_verdict (see
// src/analysis/ai-verdict.js) that never changes the rule-based
// verdict or any rendered score. A named template renders
// exactly one finding per report — the platforms accept one bug per
// submission — and its required sections fail cleanly when their
// source field is missing, instead of inventing content. Platform
// templates are Markdown-only: requesting one with `--format html`
// or `--format csv` fails cleanly. Findings are grouped by target first, then by
// asset_id within each target (see groupFindingsByTarget); the flat
// JSON `findings` array follows the same grouped order, and
// `target_id` / `session_id` come from the first finding in grouped
// order. By default a report covering more than one distinct
// `target_id` is refused (`REPORT_MIXED_TARGETS_REFUSED`); pass
// `allowMixedTargets: true` (CLI `--allow-mixed-targets`) to opt in
// explicitly. An empty finding set renders the CSV header row only
// when the format is csv (and no template is requested); every other
// format still requires at least one finding. Throws on any validation failure; nothing is written
// by this function, so a failure can never leave a half-written
// output file.
function generateReport(findings, options = {}) {
  if (!Array.isArray(findings)) {
    throw new Error('generateReport expects an array of findings.');
  }
  const format = options.format || 'markdown';
  if (format !== 'markdown' && format !== 'json' && format !== 'html' && format !== 'csv') {
    throw new Error(`Invalid format: ${format} (expected "markdown", "json", "html", or "csv").`);
  }
  const templateName = typeof options.template === 'string' && options.template.trim()
    ? options.template.trim()
    : 'generic';
  if (findings.length === 0) {
    // CSV is a flat export: the header row is meaningful on its own
    // (an empty export for a triage import), so an empty set renders
    // just the header. Every other format is a report about
    // findings and still requires at least one. The template check
    // runs first, so an empty set with a template is refused as a
    // template error, not as a missing-findings error.
    assertTemplateAllowsFormat(templateName, format);
    if (format === 'csv') return renderCsv([]);
    throw new Error('At least one finding is required to generate a report.');
  }
  const validated = findings.map((finding, index) => validateFinding(finding, index));
  // AI verdict (round 50): when a verifier is configured
  // (options.verifier: 'stub', a function, or a module path), each
  // validated finding gets its advisory ai_verdict attached (see
  // src/analysis/ai-verdict.js getVerifier/attachAiVerdict). No
  // verifier configured means no ai_verdict at all — the report is
  // byte-identical to the pre-round-50 output. The attachment
  // happens after validation, so a verifier can never change a
  // verdict, a score, or the mixed-target check below; it only adds
  // the advisory fields the renderers show. A verifier that fails
  // to load throws a named error here, before any output is
  // produced, so a bad --verifier can never leave a half-written
  // report behind.
  let reported = validated;
  if (options.verifier !== undefined && options.verifier !== null) {
    const resolved = getVerifier(options.verifier, path.resolve(__dirname, '..', '..'));
    reported = validated.map((finding) => attachAiVerdict(finding, resolved));
  }
  // Mixed-target refusal (round 49): the distinct targets are the
  // trimmed target_ids in sorted order. The check runs after
  // validation, so a missing target_id still fails as a missing
  // required field first. A template report can never trip this
  // check: templates render one finding, which carries one target.
  const targetIds = [...new Set(reported.map((finding) => String(finding.target_id).trim()))].sort(compareStrings);
  const allowMixedTargets = options.allowMixedTargets === true;
  if (targetIds.length > 1 && !allowMixedTargets) {
    throw new Error(
      `REPORT_MIXED_TARGETS_REFUSED: report covers ${targetIds.length} targets (${targetIds.join(', ')}). ` +
      'Refusing to render a multi-target report by default: a report that names only one target would misattribute findings. ' +
      'Pass --allow-mixed-targets to opt in explicitly.',
    );
  }
  const multiTarget = targetIds.length > 1;
  // Grouping is a pure reorder of the reported set: verdicts were
  // already computed by the validator (and deduplication, when the
  // caller runs it, happens before this call), so grouping cannot
  // change what a finding says — only where it renders.
  const targetGroups = groupFindingsByTarget(reported);
  const groups = targetGroups.flatMap((targetGroup) => targetGroup.groups);
  const orderedFindings = groups.flatMap((group) => group.findings);
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
    const created = reported
      .map((finding) => finding.created_at)
      .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
    if (created.length > 0) generatedAt = created.sort().at(-1);
  }
  const counts = countBySeverity(reported);
  const summary = executiveSummary(counts, programName);
  if (format === 'json' && !generatedAt) {
    // schemas/report.schema.json requires generated_at as a date-time
    // string, so a JSON report cannot be produced without one: pass
    // --generated-at or give the findings created_at values.
    throw new Error('JSON output requires a generated_at timestamp: pass --generated-at or include created_at on the findings.');
  }
  if (templateName !== 'generic') {
    assertTemplateAllowsFormat(templateName, format);
    const template = loadTemplate(templateName);
    if (reported.length !== 1) {
      throw new Error(
        `Template "${templateName}" renders one finding per report; got ${reported.length} findings. ` +
        'Generate one report per finding, or use the generic template.',
      );
    }
    if (format === 'json') {
      return renderJson({
        reportId: deriveReportId(programName, reported),
        targetId: orderedFindings[0].target_id,
        sessionId: orderedFindings[0].session_id,
        programName,
        generatedAt,
        counts,
        findings: orderedFindings,
        summary,
        template: templateName,
      });
    }
    return renderTemplateReport(template, orderedFindings[0], { programName, generatedAt });
  }
  if (format === 'json') {
    return renderJson({
      reportId: deriveReportId(programName, reported),
      targetId: orderedFindings[0].target_id,
      sessionId: orderedFindings[0].session_id,
      programName,
      generatedAt,
      counts,
      findings: orderedFindings,
      summary,
      groups,
      targetGroups,
      multiTarget,
      targetIds,
    });
  }
  if (format === 'html') {
    return renderHtml({
      reportId: deriveReportId(programName, reported),
      programName,
      generatedAt,
      counts,
      groups,
      targetGroups,
      multiTarget,
      targetIds,
      summary,
    });
  }
  if (format === 'csv') {
    // Flat export: the rows follow the same grouped order as the
    // flat JSON `findings` array (target, then asset, then severity,
    // then finding_id). No generated_at is needed — a CSV row set
    // carries no report header beyond the column names.
    return renderCsv(orderedFindings);
  }
  return renderMarkdown({ programName, generatedAt, counts, groups, targetGroups, multiTarget, targetIds });
}

module.exports = { generateReport, validateFinding, severityForScore, countBySeverity, groupFindingsByAsset, groupFindingsByTarget, escapeHtml, escapeCsvField, CSV_COLUMNS, SEVERITY_ORDER };
