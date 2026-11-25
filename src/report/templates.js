// Platform report templates (Phase 7): render a single validated finding
// into the section layout a bounty platform expects (Immunefi, Code4rena).
//
// Templates are DATA, not code: each template lives in
// `knowledge/report-templates/<name>.json` and declares its sections, the
// finding fields that feed each section, and which sections are required.
// Adding a platform is a data change — a new JSON file — not a code change.
// This module only loads the data, validates its shape, and renders fields
// by type; it never invents content. A required section whose source field
// is missing fails with a named error, and an optional section with no
// source data is omitted from the output.
//
// A named template renders exactly one finding per report: the platforms
// accept one bug per submission, so `--findings` with more than one entry
// fails cleanly instead of concatenating reports.
//
// Node stdlib only. No network requests, no scanners, no live data.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const TEMPLATES_DIRECTORY = path.resolve(__dirname, '..', '..', 'knowledge', 'report-templates');
const TEMPLATE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

let cachedTemplates = null;

function isMissing(value) {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string') return value.trim() === '';
  if (Array.isArray(value)) return value.length === 0;
  return false;
}

// List the template names available on disk, sorted. Throws a named
// error when the templates directory itself cannot be read.
function listTemplates() {
  let entries;
  try {
    entries = fs.readdirSync(TEMPLATES_DIRECTORY, { withFileTypes: true });
  } catch (error) {
    throw new Error(`Unable to list report templates: ${error.message}`);
  }
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => entry.name.slice(0, -'.json'.length))
    .filter((name) => TEMPLATE_NAME_PATTERN.test(name))
    .sort();
}

// Validate a parsed template object's shape. Throws a named error on the
// first problem found, so a malformed data file fails loudly at load
// time instead of producing a broken report.
function validateTemplateShape(parsed, name) {
  const fail = (reason) => {
    throw new Error(`Invalid report template "${name}": ${reason}`);
  };
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail('expected a JSON object.');
  if (parsed.name !== name) fail(`"name" is ${JSON.stringify(parsed.name)} but the file is "${name}.json".`);
  if (typeof parsed.platform !== 'string' || parsed.platform.trim() === '') fail('"platform" must be a non-empty string.');
  if (!Array.isArray(parsed.sections) || parsed.sections.length === 0) fail('"sections" must be a non-empty array.');
  const seenIds = new Set();
  for (const section of parsed.sections) {
    if (!section || typeof section !== 'object' || Array.isArray(section)) fail('every section must be an object.');
    if (typeof section.id !== 'string' || section.id.trim() === '') fail('every section needs a non-empty string "id".');
    if (seenIds.has(section.id)) fail(`duplicate section id "${section.id}".`);
    seenIds.add(section.id);
    if (section.heading !== null && (typeof section.heading !== 'string' || section.heading.trim() === '')) {
      fail(`section "${section.id}" needs a "heading" string or null.`);
    }
    if (!Array.isArray(section.fields) || section.fields.length === 0
      || section.fields.some((field) => typeof field !== 'string' || field.trim() === '')) {
      fail(`section "${section.id}" needs a non-empty "fields" array of strings.`);
    }
    if (typeof section.required !== 'boolean') fail(`section "${section.id}" needs a boolean "required".`);
    if (!Array.isArray(section.required_fields)
      || section.required_fields.some((field) => typeof field !== 'string')) {
      fail(`section "${section.id}" needs a "required_fields" array of strings.`);
    }
    for (const field of section.required_fields) {
      if (!section.fields.includes(field)) {
        fail(`section "${section.id}" lists required field "${field}" which is not in its "fields".`);
      }
    }
  }
  return parsed;
}

// Load one template by name from its data file. The name is validated
// against a strict pattern before it ever reaches the filesystem, so a
// value like "../finding" can never escape the templates directory.
// Unknown names fail with the available list, so the operator can see
// what exists instead of guessing.
function loadTemplate(name) {
  if (typeof name !== 'string' || !TEMPLATE_NAME_PATTERN.test(name)) {
    throw new Error(`Unknown report template: ${JSON.stringify(name)} (available: ${listTemplates().join(', ') || 'none'}).`);
  }
  if (!cachedTemplates) cachedTemplates = new Map();
  if (cachedTemplates.has(name)) return cachedTemplates.get(name);
  const filePath = path.join(TEMPLATES_DIRECTORY, `${name}.json`);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`Unknown report template: "${name}" (available: ${listTemplates().join(', ') || 'none'}).`);
    }
    throw new Error(`Unable to load report template "${name}": ${error.message}`);
  }
  const template = validateTemplateShape(parsed, name);
  cachedTemplates.set(name, template);
  return template;
}

function formatValue(value, fallback = 'Not provided') {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'string') return value.trim() === '' ? fallback : value;
  return String(value);
}

// Render one finding field into lines. Returns null when the field has
// no source data (the caller omits it); rendering is by field type, so
// the template data never has to describe how a field looks.
function renderField(field, finding) {
  const value = finding[field];
  if (isMissing(value)) return null;
  switch (field) {
    case 'title':
      return [`# ${value} [${finding.severity.toUpperCase()}]`];
    case 'severity':
      return [`- **Severity:** ${value}`];
    case 'cvss_score': {
      const vector = typeof finding.cvss_vector === 'string' && finding.cvss_vector.trim() !== ''
        ? ` (${finding.cvss_vector})`
        : '';
      return [`- **CVSS:** ${String(value)}${vector}`];
    }
    case 'cvss_temporal_score':
      return [`- **CVSS temporal:** ${String(value)}`];
    case 'cvss_environmental_score':
      return [`- **CVSS environmental:** ${String(value)}`];
    case 'cvss_vector':
      return null; // Rendered with cvss_score; a lone vector has no line of its own.
    case 'cwe_id':
      return [`- **CWE:** ${value}`];
    case 'vulnerability_type':
      return [`- **Vulnerability type:** ${value}`];
    case 'asset_id': {
      const url = typeof finding.asset_url === 'string' && finding.asset_url.trim() !== ''
        ? ` (${finding.asset_url})`
        : '';
      return [`- **Affected component:** ${value}${url}`];
    }
    case 'asset_url':
      return null; // Rendered with asset_id.
    case 'finding_id':
      return [`- **Finding ID:** ${value}`];
    case 'confidence':
      return [`- **Confidence:** ${value}`];
    case 'validation_status':
      return [`- **Validation status:** ${value}`];
    case 'description':
    case 'impact':
    case 'remediation':
    case 'proof_of_concept':
      return [String(value)];
    case 'steps_to_reproduce':
      return value.map((step, index) => `${index + 1}. ${step}`);
    case 'evidence': {
      const lines = [];
      value.forEach((item, index) => {
        lines.push(`Evidence ${index + 1}:`);
        if (item && typeof item === 'object') {
          if (item.request) lines.push(`- Request: ${item.request}`);
          if (item.response) lines.push(`- Response: ${item.response}`);
          if (item.notes) lines.push(`- Notes: ${item.notes}`);
        }
      });
      return lines;
    }
    case 'references':
      return value.map((reference) => `- ${reference}`);
    default:
      return [String(value)];
  }
}

// Render one section. Returns null when the section has no source data
// at all. A required section with a missing required field throws a
// named error instead of rendering an empty or invented section.
function renderSection(template, section, finding) {
  const missingRequired = section.required_fields.filter((field) => isMissing(finding[field]));
  if (missingRequired.length > 0) {
    const label = typeof finding.finding_id === 'string' && finding.finding_id
      ? `finding ${finding.finding_id}`
      : 'the finding';
    throw new Error(
      `Template "${template.name}" requires field(s) ${missingRequired.map((field) => `"${field}"`).join(', ')} ` +
      `for section "${section.heading || section.id}" but ${label} does not provide them.`,
    );
  }
  const lines = [];
  for (const field of section.fields) {
    const rendered = renderField(field, finding);
    if (rendered) lines.push(...rendered);
  }
  if (lines.length === 0) return null;
  if (section.heading === null) return lines;
  return [`## ${section.heading}`, '', ...lines];
}

// Render a single validated finding into the template's Markdown layout.
// context: { programName, generatedAt } — both caller-supplied; the
// generated line records "Not specified" when neither is available, never
// a wall-clock timestamp, so the output stays deterministic.
function renderTemplateReport(template, finding, context = {}) {
  const lines = [];
  const programName = typeof context.programName === 'string' && context.programName.trim()
    ? context.programName.trim()
    : 'Unnamed Program';
  const generatedAt = typeof context.generatedAt === 'string' && context.generatedAt.trim()
    ? context.generatedAt.trim()
    : 'Not specified';
  for (const section of template.sections) {
    const rendered = renderSection(template, section, finding);
    if (!rendered) continue;
    if (lines.length > 0) lines.push('');
    lines.push(...rendered);
    // The header section is followed by the program/generated metadata.
    if (section.heading === null) {
      lines.push(`- **Program:** ${programName}`);
      lines.push(`- **Generated:** ${generatedAt}`);
    }
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

module.exports = { listTemplates, loadTemplate, renderTemplateReport };
