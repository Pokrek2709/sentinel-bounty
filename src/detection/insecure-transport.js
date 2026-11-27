// Fifth REAL detector (Phase 5, round 90): insecure-transport.
//
// The four earlier detectors proved the framework generalizes
// across credential formats, code sinks, weak crypto, and
// hardcoded credentials. This module proves it generalizes a
// fifth time, to insecure-transport call sites in
// operator-supplied local text: cleartext HTTP URLs and
// disabled TLS verification. It scans the `content` string
// of a local input record — text the operator already holds
// (for example source code or a code excerpt captured in the
// lab) and hands to
// `sentinel detect --detector insecure-transport --input
// <record.json>`. It never reads a file itself, never makes
// a request, and never executes the code it scans: a match
// proves the insecure-transport text is present in the
// supplied text; it does not prove sensitive data traverses
// the connection, that the endpoint is reachable, or that
// the weakness is exploitable in context. Every finding
// therefore carries the default confidence `potential`, and
// exploitability must be verified out of band before
// reporting.
//
// Patterns (call-site or configuration syntax, word-boundary
// anchored so lookalikes such as `https://`, `verify=True`,
// or `CERT_REQUIRED` do not match; no data-flow or taint
// analysis, which would need a parser and is out of scope
// for this detector):
//   cleartext-http        http:// URLs with a non-loopback  CWE-319, medium
//                         host (the URL's host only — never
//                         the path, query, or userinfo)
//   tls-verify-disabled   TLS verification switched off      CWE-295, high
//                         (rejectUnauthorized: false,
//                         verify = False, check_hostname =
//                         False, ssl._create_unverified_
//                         context(), verify_mode = CERT_NONE)
// A documentation example (for instance `http://example.com`
// in a how-to, or a test fixture disabling verification for
// a local mock) WILL match — the detector reports what it
// sees in the text; the operator triages it, and the
// validator's `false_positive` verdict exists for exactly
// that. A match in a comment or a string literal is the
// same: the detector has no parser and cannot tell code
// from prose, so a match is a lead, never a verdict. The
// `cleartext-http` pattern is the noisiest of the two by
// design: `http://` is fine for public documentation links
// and loopback traffic (both excluded — loopback hosts never
// match), and only a weakness when sensitive data traverses
// a network in cleartext — the finding says so in its
// description, and the operator's verification step decides.
//
// Safety properties (tested, not assumed):
// - A finding carries only the matched text, never the whole
//   source line — and for a cleartext URL it carries only
//   `http://<host>`: never the path, the query, or the
//   userinfo. A URL can hide credentials
//   (`http://user:pass@host/`) and tokens in its query, so
//   the match is rebuilt as scheme + host before any finding
//   is built; no credential can leak through this detector.
// - `finding_id` is deterministic: `insecure-transport-` +
//   the first 16 hex chars of SHA-256
//   (`insecure-transport:<pattern>:<line>:<column>:<match>`).
//   Identity is per call site, not per call text (unlike
//   secret-scan, where the secret value IS the identity):
//   the same URL on the same line at a different column is
//   a different finding, and the same URL on a different
//   line is a different finding.
// - One finding per distinct (pattern, line, column, match)
//   per record; the first occurrence line is reported. At
//   most MAX_FINDINGS_PER_RECORD (100) findings per record;
//   further matches are dropped and the drop is recorded in
//   `errors` so a truncated scan is visible, never silent.
// - Content over MAX_CONTENT_CHARS (1,000,000) is skipped,
//   not scanned; the CLI already bounds the input file to
//   10 MiB, this bound keeps the scan itself bounded.
// - A record without a non-empty string `content` is counted
//   in `skipped` with its error recorded, never thrown; a
//   bad record never aborts a batch. A non-object input
//   throws DETECTOR_INVALID_INPUT, exactly like the stub
//   detector.
// - Batch records `{ tool, results: [...] }` follow the stub
//   convention: the batch `tool`, when present, is forced as
//   `discovery_tool` on every finding; otherwise the finding
//   carries `discovery_tool: 'insecure-transport'`.
// - session_id / target_id / asset_id come from the record
//   itself, else from `defaults` (the CLI --session-id /
//   --target-id / --asset-id options); a record missing an id
//   after defaults is counted in `skipped`, never invented.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const crypto = require('node:crypto');
const { normalizeRawFinding } = require('./normalized-record');

const MAX_CONTENT_CHARS = 1_000_000;
const MAX_FINDINGS_PER_RECORD = 100;

// Hosts that never match the cleartext pattern: loopback
// traffic does not traverse a network, so it is not
// cleartext exposure. Compared case-insensitively, after
// stripping IPv6 brackets and a trailing dot.
function isLoopbackHost(host) {
  const bare = host.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (bare === 'localhost' || bare === '::1') return true;
  if (/^127\./.test(bare)) return true;
  return false;
}

// Rebuild a cleartext match as scheme + host only. The regex
// captures the host in group 1 (after an optional userinfo
// segment, which is discarded); loopback hosts return null
// (no finding). The path, query, fragment, port, and any
// userinfo never reach the finding.
function cleartextMatch(match) {
  const host = (match[1] || '').replace(/\.$/, '');
  if (host === '' || isLoopbackHost(host)) return null;
  return `http://${host}`;
}

// pattern id -> { label, regex (global), extract, vulnerability_type,
// severity, cwe_id, impact, remediation }. `extract`, when
// present, rebuilds the finding's match text from the regex
// match and returns null to skip the match entirely (the
// cleartext pattern uses it for the loopback exclusion and
// the host-only rebuild); without it the match text is the
// regex match itself. Severity is per pattern, not uniform:
// disabling TLS verification is high (the control itself is
// switched off — any data on the connection is exposed to a
// machine-in-the-middle); cleartext HTTP is medium (only
// exploitable when sensitive data traverses the connection,
// which this detector cannot prove). Neither class has a
// dedicated evidence-checklist class and both resolve to the
// generic checklist; that mapping is the validator's, not
// this module's.
const PATTERNS = [
  {
    id: 'cleartext-http',
    label: 'cleartext HTTP URL',
    regex: /\bhttp:\/\/(?:[^\s/'"?#@]+@)?([A-Za-z0-9._~-]+|\[[0-9A-Fa-f:]+\])/g,
    extract: cleartextMatch,
    vulnerability_type: 'cleartext transmission',
    severity: 'medium',
    cwe_id: 'CWE-319',
    impact: 'Data sent over plain HTTP is visible to anyone on the path between client and server (network operator, compromised router, open Wi-Fi): credentials, tokens, and personal data can be read and modified in transit. The URL itself is not proof that sensitive data traverses it — verify the use before reporting.',
    remediation: 'Use https:// for any endpoint that carries credentials, tokens, or personal data; keep http:// only for public documentation links and loopback traffic, and say so in a comment.',
  },
  {
    id: 'tls-verify-disabled',
    label: 'TLS verification disabled',
    regex: /(?:\brejectUnauthorized\s*[:=]\s*false\b|\bverify\s*[:=]\s*False\b|\bcheck_hostname\s*[:=]\s*False\b|\bssl\._create_unverified_context\s*\(|\bverify_mode\s*=\s*CERT_NONE\b)/g,
    vulnerability_type: 'improper certificate validation',
    severity: 'high',
    cwe_id: 'CWE-295',
    impact: 'With certificate verification switched off, the client accepts any certificate — including one presented by an attacker on the path — so the connection is encrypted to the wrong party and credentials or tokens sent over it can be intercepted. The setting itself is the weakness: it removes the authentication half of TLS.',
    remediation: 'Remove the verification override and let the client verify the server certificate against its trust store; for a lab-only self-signed certificate, add the lab CA to the trust store instead of disabling verification, and never ship the override.',
  },
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(patternId, lineNumber, column, match) {
  const digest = crypto
    .createHash('sha256')
    .update(`insecure-transport:${patternId}:${lineNumber}:${column}:${match}`, 'utf8')
    .digest('hex');
  return `insecure-transport-${digest.slice(0, 16)}`;
}

// Scan one content record into raw findings. Throws on a record
// that cannot be scanned (no usable content, oversized content,
// wrong-typed `source`); the caller counts those in `skipped`.
// Returns { rawFindings, truncated } where `truncated` is the
// count of matches dropped by the per-record cap (0 when none).
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('insecure-transport: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`insecure-transport: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('insecure-transport: "source" must be a non-empty string when present.');
  }
  const source = isNonEmptyString(record.source) ? record.source : null;

  const lines = record.content.split('\n');
  const seen = new Set();
  const rawFindings = [];
  let truncated = 0;

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = lines[index];
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        const value = typeof pattern.extract === 'function' ? pattern.extract(match) : match[0];
        if (value === null || value === undefined) continue;
        const column = match.index + 1;
        const key = `${pattern.id}:${lineNumber}:${column}:${value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (rawFindings.length >= MAX_FINDINGS_PER_RECORD) {
          truncated += 1;
          continue;
        }
        const where = source
          ? `source "${source}", line ${lineNumber}, column ${column}`
          : `line ${lineNumber}, column ${column}`;
        const extraNote = pattern.id === 'cleartext-http'
          ? ' This URL is only a weakness when sensitive data traverses the connection — verify the use before reporting.'
          : '';
        rawFindings.push({
          finding_id: findingIdFor(pattern.id, lineNumber, column, value),
          title: `Insecure ${pattern.label} in supplied text`,
          vulnerability_type: pattern.vulnerability_type,
          description: `A ${pattern.label} (${pattern.id}) was found in operator-supplied local text at ${where}. The detector scans only the text it is handed and never executes it; whether the connection carries anything sensitive is unproven — verify out of band before reporting.${extraNote}`,
          impact: pattern.impact,
          remediation: pattern.remediation,
          severity: pattern.severity,
          cwe_id: pattern.cwe_id,
          steps_to_reproduce: [
            'Run `sentinel detect --detector insecure-transport --input <record.json>` over the record carrying the text.',
            `Observe the finding for ${pattern.id} at ${where}.`,
            'Verify out of band whether the connection carries sensitive data before reporting — the detector never executes the code, so exploitability is unproven.',
          ],
          proof_of_concept: `Matched ${pattern.id} at ${where}: ${value}`,
          evidence: [
            {
              type: 'pattern-match',
              pattern: pattern.id,
              line: lineNumber,
              column,
              match: value,
              ...(source ? { source } : {}),
            },
          ],
          discovery_tool: tool || 'insecure-transport',
          ...(isNonEmptyString(record.session_id) ? { session_id: record.session_id } : {}),
          ...(isNonEmptyString(record.target_id) ? { target_id: record.target_id } : {}),
          ...(isNonEmptyString(record.asset_id) ? { asset_id: record.asset_id } : {}),
        });
      }
    }
  }

  return { rawFindings, truncated };
}

// The detector: insecureTransportDetector(input, defaults) ->
// { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any other
// object is treated as a single content record. A non-object
// input throws DETECTOR_INVALID_INPUT. Bad records are counted
// in `skipped`, never thrown.
function insecureTransportDetector(input, defaults) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('DETECTOR_INVALID_INPUT: detector input must be an object (a content record or a { tool, results } batch).');
  }
  let records;
  let tool;
  if (Array.isArray(input.results)) {
    if (input.tool !== undefined && input.tool !== null && !isNonEmptyString(input.tool)) {
      throw new Error('DETECTOR_INVALID_INPUT: batch tool must be a non-empty string when present.');
    }
    records = input.results;
    tool = isNonEmptyString(input.tool) ? input.tool : undefined;
  } else {
    records = [input];
    tool = undefined;
  }

  const findings = [];
  const errors = [];
  let skipped = 0;
  for (const record of records) {
    try {
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new Error('insecure-transport: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`insecure-transport: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = insecureTransportDetector;
module.exports.insecureTransportDetector = insecureTransportDetector;
module.exports.PATTERNS = PATTERNS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = findingIdFor;
module.exports.isLoopbackHost = isLoopbackHost;
