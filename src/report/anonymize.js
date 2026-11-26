// Report anonymize (round 69, Phase 7): strip internal identifiers
// from a JSON report so it can be shared with a program, a
// colleague, or a public write-up without leaking the internal
// environment.
//
// An operator who wants to share a report currently has no way to
// remove the identifiers in it — target_id, session_id, asset_id,
// and any internal hostnames in the evidence text all name the
// internal environment. `sentinel report anonymize <file.json>`
// answers that: one anonymized report, same findings, same
// severities, same scores, same verdicts.
//
// Identifier mapping: target_id, session_id, and every finding's
// asset_id are replaced with `anon-<sha256(salt + ':' +
// original).slice(0, 12)>`. The mapping is deterministic — the
// same original always maps to the same replacement within a run
// (and across runs with the same salt), so diffs and merges of
// anonymized reports still work, and re-running the command with
// the same salt reproduces the same output byte-for-byte. The
// salt defaults to the FIXED documented constant
// DEFAULT_SALT, so two runs with no --salt give byte-identical
// output; determinism matters more than secrecy here. `--salt
// <hex>` lets the operator supply their own salt (hex, 8-64
// chars, else REPORT_ANONYMIZE_INVALID_SALT). The salt is NEVER
// printed — not in the output, not in the summary line, not in
// an error message — and is NOT recorded in the output's
// metadata block (only `salt_source: "default" | "provided"`).
//
// This is de-identification for sharing, NOT cryptographic
// redaction: anyone holding the original report and the salt
// can recompute the mapping and reverse it. The default salt
// is public (it is in this file and in the doc), so the
// default mapping is reversible by anyone who has the
// original report. A provided salt only helps if it is kept
// private. The doc (docs/report-anonymize-v1.md) states this
// plainly; do not present the output as irreversibly
// anonymized.
//
// Text scrubbing: the scrub applies to `description` and to
// the `notes` field of each `evidence` entry (the evidence
// checklist item `evidence_notes` maps to
// `finding.evidence[].notes` — see
// src/analysis/validator.js hasEvidenceSubfield). Two
// conservative patterns, nothing else:
//   - IPv4 dotted quad: four 1-3 digit groups
//     (e.g. 10.0.4.17) -> `anon-ip`. Octets are deliberately
//     NOT range-validated (0-255): a version-looking string
//     like 1.2.3.4 in evidence text is scrubbed the same way.
//   - Hostname ending `.local` or `.internal`, one or more
//     labels (e.g. db01.corp.internal) -> `anon-host`.
// Arbitrary URLs, emails, and other hostnames are NOT
// scrubbed. `request` / `response` evidence entries are NOT
// scrubbed either: they are logs, and scrubbing them would
// destroy the evidence a program needs to reproduce the
// finding. `title`, `impact`, `remediation`,
// `steps_to_reproduce`, `proof_of_concept`, and `references`
// are likewise untouched. `asset_url` is NOT scrubbed: its
// host names the same asset `asset_id` names, so an
// `asset_url` like https://lab.example.internal/login still
// leaks the internal hostname even after `asset_id` is
// replaced — that is a known limitation of this round,
// documented in docs/report-anonymize-v1.md (a future round
// may extend the scrub to it); operators sharing a report
// with a sensitive asset_url should check it by hand.
//
// Everything else is preserved byte-for-byte in substance:
// severity, CVSS scores and vectors, verdict
// (validation_status), confidence, the evidence checklist,
// ai_verdict when present, finding_ids, merged_from, and
// the finding order (grouped order, as in the input). The
// output is re-rendered by generateReport itself (format
// 'json', allowMixedTargets: true), so the report_id is the
// generator's own derivation (SHA-256 of program + sorted
// finding ids) and the output is a valid round-31 JSON
// report by construction. Because the derivation inputs
// (program_name and finding_ids) are exactly what
// anonymization preserves, the recomputed report_id is the
// SAME as the input's — that is deliberate, not a bug: it
// lets the operator correlate the anonymized report with
// the original, and it means `report validate` (round 67)
// passes the anonymized report with report_id_matches:
// true. The output carries `anonymized: true` plus an
// `anonymization` metadata block (`salt_source` and the
// scrub `patterns` — never the salt itself) so no consumer
// can mistake it for the original.
//
// Inputs are read with readReportFile from report-diff.js
// (round 64): bounded (10 MiB, depth 100), symlinked input
// refused. Shape failures therefore carry REPORT_DIFF_*
// codes — the reader is shared, not re-implemented. Each
// finding is checked with validateOneFinding (round 67's
// path); a finding that fails the strict check is a
// REPORT_ANONYMIZE_INVALID_FINDING. An empty finding set
// fails with REPORT_ANONYMIZE_EMPTY (a report with no
// findings has nothing to share), and a report with no
// usable generated_at fails with
// REPORT_ANONYMIZE_NO_GENERATED_AT (the input's
// generated_at, else the newest finding created_at —
// generateReport never invents a timestamp from the wall
// clock, and neither does this module).
//
// The module never writes anything and never modifies its
// input object (the findings are deep-cloned before
// transformation). No network requests, no scanners, no
// live data. Node stdlib only.
'use strict';

const crypto = require('node:crypto');
const { generateReport, pickGeneratedAt } = require('./generator');
const { validateReportShape } = require('./report-diff');
const { validateOneFinding } = require('./validate');

// The default salt: a fixed, public, documented constant. It is
// public on purpose — determinism (same input, same output, no
// --salt) matters more than secrecy for a sharing aid, and the
// doc states plainly that the default mapping is reversible by
// anyone holding the original report.
const DEFAULT_SALT = 'sentinel-report-anonymize-v1';

// The scrub patterns, named for the output metadata block and
// the doc. The list is part of the output, so a consumer can
// see exactly what was scrubbed.
const SCRUB_PATTERNS = ['ipv4-dotted-quad', 'hostname-.local/.internal'];

// IPv4 dotted quad: four groups of 1-3 digits. Not
// octet-validated (see the header comment).
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// Hostname ending .local or .internal: one or more labels of
// letters, digits, and hyphens, then the suffix.
const HOSTNAME_PATTERN = /\b(?:[A-Za-z0-9-]+\.)+(?:local|internal)\b/g;

// Validate an operator-supplied salt: hex, 8-64 characters.
// The error message deliberately does NOT echo the supplied
// value — the command must never print the salt.
function validateSalt(salt) {
  if (typeof salt !== 'string' || !/^[0-9a-fA-F]+$/.test(salt) || salt.length < 8 || salt.length > 64) {
    throw new Error(
      'REPORT_ANONYMIZE_INVALID_SALT: --salt must be a hex string of 8-64 characters.',
    );
  }
  return salt;
}

// The anonymized form of one identifier value: `anon-` plus the
// first 12 hex chars of SHA-256(salt + ':' + original). The
// prefix keeps anonymized values visibly distinct from real
// ids in every consumer (diff, merge, validate, CSV).
function anonymizeValue(salt, original) {
  const digest = crypto.createHash('sha256')
    .update(`${salt}:${original}`)
    .digest('hex');
  return `anon-${digest.slice(0, 12)}`;
}

// Scrub one text value with the two documented patterns.
// Returns { text, substitutions }: the scrubbed text and the
// number of replacements made (0 when nothing matched, so the
// summary line can count them).
function scrubText(text) {
  let substitutions = 0;
  let out = String(text);
  out = out.replace(IPV4_PATTERN, () => {
    substitutions += 1;
    return 'anon-ip';
  });
  out = out.replace(HOSTNAME_PATTERN, () => {
    substitutions += 1;
    return 'anon-host';
  });
  return { text: out, substitutions };
}

// The generated_at for the anonymized report comes from the
// generator's shared pickGeneratedAt (round 73): the input's own
// generated_at when valid, else the newest finding created_at.
// The helper returns null when nothing is available; this module
// throws its OWN named error at the call site (a JSON report
// requires generated_at and the module never invents a timestamp
// from the wall clock).

// Anonymize one finding (deep-cloned by the caller): replace
// target_id, session_id, and asset_id with their mapped
// values, and scrub description plus each evidence entry's
// notes. Returns { finding, identifiers_replaced,
// text_substitutions }. Only non-empty string values are
// replaced; anything else is left untouched (the strict check
// has already run, so a missing required field cannot reach
// here).
function anonymizeFinding(finding, salt) {
  let identifiersReplaced = 0;
  let textSubstitutions = 0;
  const out = JSON.parse(JSON.stringify(finding));
  for (const field of ['target_id', 'session_id', 'asset_id']) {
    if (typeof out[field] === 'string' && out[field].trim() !== '') {
      out[field] = anonymizeValue(salt, out[field]);
      identifiersReplaced += 1;
    }
  }
  if (typeof out.description === 'string') {
    const scrubbed = scrubText(out.description);
    out.description = scrubbed.text;
    textSubstitutions += scrubbed.substitutions;
  }
  if (Array.isArray(out.evidence)) {
    for (const entry of out.evidence) {
      if (entry && typeof entry === 'object' && typeof entry.notes === 'string') {
        const scrubbed = scrubText(entry.notes);
        entry.notes = scrubbed.text;
        textSubstitutions += scrubbed.substitutions;
      }
    }
  }
  return { finding: out, identifiersReplaced, textSubstitutions };
}

// Anonymize a parsed JSON report object (report_id + findings
// array; shape-checked first, so a malformed report throws
// instead of returning a partial result). Options:
// { salt } — when omitted the documented default salt is used.
// Returns:
// {
//   report: <the anonymized JSON report, as a string>,
//   summary: { total, identifiers_replaced, text_substitutions, salt_source }
// }
// The report is rendered by generateReport itself (format
// 'json'), so its report_id, groups, counts, and mixed-target
// fields are the generator's own; the anonymization metadata
// block is added to the parsed render afterwards (appended
// last, so the render's own key order is untouched).
function anonymizeReport(report, options = {}) {
  validateReportShape(report, 'report');
  const salt = options.salt === undefined ? DEFAULT_SALT : validateSalt(options.salt);
  const saltSource = options.salt === undefined ? 'default' : 'provided';
  // Every finding is checked with round 67's path: the strict
  // generator check first (a throw is a structural defect),
  // then the rule verdict (counted, never fatal here — the
  // verdict itself is not part of the anonymization
  // decision).
  for (const finding of report.findings) {
    const checked = validateOneFinding(finding);
    if (checked.status === 'error') {
      throw new Error(
        `REPORT_ANONYMIZE_INVALID_FINDING: finding ${finding.finding_id} fails the strict check: ${checked.reasons.join('; ')}`,
      );
    }
  }
  if (report.findings.length === 0) {
    throw new Error('REPORT_ANONYMIZE_EMPTY: the report carries no findings; there is nothing to anonymize.');
  }
  let identifiersReplaced = 0;
  let textSubstitutions = 0;
  const anonymized = report.findings.map((finding) => {
    const result = anonymizeFinding(finding, salt);
    identifiersReplaced += result.identifiersReplaced;
    textSubstitutions += result.textSubstitutions;
    return result.finding;
  });
  const generatedAt = pickGeneratedAt([report], anonymized);
  if (generatedAt === null) {
    throw new Error(
      'REPORT_ANONYMIZE_NO_GENERATED_AT: the report carries no generated_at and no finding carries created_at; '
      + 'cannot produce a JSON report (generated_at is required).',
    );
  }
  const programName = typeof report.program_name === 'string' && report.program_name.trim() !== ''
    ? report.program_name.trim()
    : 'Unnamed Program';
  const renderOptions = {
    format: 'json',
    programName,
    generatedAt,
    allowMixedTargets: true,
  };
  // A platform-template report (one finding, template set)
  // keeps its template marker; anything else renders generic.
  // A multi-finding report with a template set is refused by
  // generateReport itself (a template renders one finding),
  // which is the correct fail-closed behaviour for a
  // hand-edited input.
  if (typeof report.template === 'string' && report.template.trim() !== '' && report.template.trim() !== 'generic') {
    renderOptions.template = report.template.trim();
  }
  const rendered = generateReport(anonymized, renderOptions);
  const parsed = JSON.parse(rendered);
  parsed.anonymized = true;
  parsed.anonymization = {
    salt_source: saltSource,
    patterns: [...SCRUB_PATTERNS],
  };
  return {
    report: `${JSON.stringify(parsed, null, 2)}\n`,
    summary: {
      total: anonymized.length,
      identifiers_replaced: identifiersReplaced,
      text_substitutions: textSubstitutions,
      salt_source: saltSource,
    },
  };
}

module.exports = {
  DEFAULT_SALT,
  SCRUB_PATTERNS,
  validateSalt,
  anonymizeValue,
  scrubText,
  anonymizeFinding,
  anonymizeReport,
};
