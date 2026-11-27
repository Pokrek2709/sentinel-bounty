// First REAL detector (Phase 5, round 86): secret-scan.
//
// This is the first detector that performs detection instead of
// merely normalizing input. It scans OPERATOR-SUPPLIED LOCAL TEXT
// for well-known credential formats and reports one finding per
// distinct matched secret. It is deliberately the smallest, safest
// detector scope from the 15 evidence classes: the
// "information disclosure" class, strict fixed-format patterns
// only, no network, no scanner, no target, no liveness check.
//
// What it scans: the `content` string field of a local input
// record — text the operator already holds (for example file
// contents or a response body captured in the lab) and hands to
// `sentinel detect --detector secret-scan --input <record.json>`.
// It never reads a file itself, never makes a request, and never
// contacts any service to check whether a matched credential is
// live: every finding therefore carries the default confidence
// `potential`, and liveness must be verified out of band before
// reporting. A match proves the secret string is present in the
// supplied text; it does not prove the credential works, is
// still valid, or was ever distributed.
//
// Patterns (all fixed-format, chosen for low false-positive rate;
// no generic entropy or key=value heuristics, which are
// false-positive prone):
//   aws-access-key-id        AKIA + 16 uppercase/digits (20 chars)
//   github-classic-token     ghp|gho|ghu|ghs|ghr + _ + 36 alphanumerics
//   github-fine-grained-token  github_pat_ + 82 alphanumerics/underscores
//   slack-token              xox[baprs]- + 10 or more alphanumerics/dashes
//   private-key-pem          -----BEGIN [RSA |EC |OPENSSH |DSA |PGP ]PRIVATE KEY-----
// A documentation example (for instance an AKIA key printed in a
// how-to) WILL match — the detector reports what it sees in the
// text; the operator triages it, and the validator's
// `false_positive` verdict exists for exactly that.
//
// Safety properties (tested, not assumed):
// - A finding NEVER contains the full matched secret. The
//   proof of concept and the evidence carry only a redacted
//   form: first 4 + '****' + last 4 characters. The PEM header
//   is not secret material, so it is carried verbatim.
// - `finding_id` is deterministic: `secret-scan-` + the first 16
//   hex chars of SHA-256(`secret-scan:<pattern>:<value>`). The
//   same secret in two records is the same finding (correct for
//   dedup); distinct secrets are distinct findings.
// - One finding per distinct (pattern, value) per record; the
//   first occurrence line is reported. At most
//   MAX_FINDINGS_PER_RECORD (100) findings per record; further
//   matches are dropped and the drop is recorded in `errors`
//   so a truncated scan is visible, never silent.
// - Content over MAX_CONTENT_CHARS (1,000,000) is skipped, not
//   scanned; the CLI already bounds the input file to 10 MiB,
//   this bound keeps the scan itself bounded.
// - A record without a non-empty string `content` is counted in
//   `skipped` with its error recorded, never thrown; a bad
//   record never aborts a batch. A non-object input throws
//   DETECTOR_INVALID_INPUT, exactly like the stub detector.
// - Batch records `{ tool, results: [...] }` follow the stub
//   convention: the batch `tool`, when present, is forced as
//   `discovery_tool` on every finding; otherwise the finding
//   carries `discovery_tool: 'secret-scan'`.
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

// pattern id -> { label, regex (global), title, impact, remediation }.
// The regexes are global so every occurrence on a line is found;
// each entry is anchored to a well-known fixed format.
const PATTERNS = [
  {
    id: 'aws-access-key-id',
    label: 'AWS access key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
    impact: 'Anyone holding the associated AWS secret key can act with the permissions of the AWS identity that owns this access key ID.',
    remediation: 'Deactivate and delete the exposed access key in the AWS console, issue a replacement key, and remove the key ID from every place the text was distributed.',
  },
  {
    id: 'github-classic-token',
    label: 'GitHub token',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/g,
    impact: 'Anyone holding this token can act on GitHub with the token\'s scopes until it expires or is revoked.',
    remediation: 'Revoke the token in GitHub settings, issue a replacement with the narrowest scopes needed, and remove the token from every place the text was distributed.',
  },
  {
    id: 'github-fine-grained-token',
    label: 'GitHub fine-grained token',
    regex: /github_pat_[A-Za-z0-9_]{82}/g,
    impact: 'Anyone holding this token can act on GitHub with the token\'s repository permissions until it expires or is revoked.',
    remediation: 'Revoke the token in GitHub settings, issue a replacement with the narrowest repository permissions needed, and remove the token from every place the text was distributed.',
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    impact: 'Anyone holding this token can act in the Slack workspace with the token\'s scopes until it is revoked.',
    remediation: 'Revoke the token in Slack app settings, issue a replacement, and remove the token from every place the text was distributed.',
  },
  {
    id: 'private-key-pem',
    label: 'private key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    impact: 'Anyone holding the private key material can impersonate the identity the key belongs to (decrypt, sign, or authenticate as that identity).',
    remediation: 'Treat the key as compromised: generate a new key pair, replace the public key everywhere it is trusted, and remove the private key from every place the text was distributed.',
  },
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

// Redact a matched secret for proof of concept and evidence: the
// first 4 and last 4 characters survive, the middle is masked.
// The PEM header carries no secret material, so it is returned
// verbatim. A match of 8 characters or fewer is returned as-is
// (no pattern in PATTERNS can produce one, but the guard keeps
// the function total).
function redactMatch(patternId, match) {
  if (patternId === 'private-key-pem') return match;
  if (match.length <= 8) return match;
  return `${match.slice(0, 4)}****${match.slice(-4)}`;
}

function findingIdFor(patternId, value) {
  const digest = crypto
    .createHash('sha256')
    .update(`secret-scan:${patternId}:${value}`, 'utf8')
    .digest('hex');
  return `secret-scan-${digest.slice(0, 16)}`;
}

// Scan one content record into raw findings. Throws on a record
// that cannot be scanned (no usable content, oversized content,
// wrong-typed `source`); the caller counts those in `skipped`.
// Returns { rawFindings, truncated } where `truncated` is the
// count of matches dropped by the per-record cap (0 when none).
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('secret-scan: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`secret-scan: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('secret-scan: "source" must be a non-empty string when present.');
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
        const value = match[0];
        const key = `${pattern.id}:${value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (rawFindings.length >= MAX_FINDINGS_PER_RECORD) {
          truncated += 1;
          continue;
        }
        const redacted = redactMatch(pattern.id, value);
        const where = source
          ? `source "${source}", line ${lineNumber}`
          : `line ${lineNumber}`;
        rawFindings.push({
          finding_id: findingIdFor(pattern.id, value),
          title: `Exposed ${pattern.label.toLowerCase()} in supplied text`,
          vulnerability_type: 'information disclosure',
          description: `A ${pattern.label.toLowerCase()} (${pattern.id}) was found in operator-supplied local text at ${where}. The detector scans only the text it is handed; it never contacts any service, so whether the credential is still live is unproven — verify out of band before reporting.`,
          impact: pattern.impact,
          remediation: pattern.remediation,
          severity: 'high',
          cwe_id: 'CWE-200',
          steps_to_reproduce: [
            'Run `sentinel detect --detector secret-scan --input <record.json>` over the record carrying the text.',
            `Observe the finding for ${pattern.id} at ${where}.`,
            'Verify out of band whether the credential is still live before reporting — the detector never contacts any service, so liveness is unproven.',
          ],
          proof_of_concept: `Matched ${pattern.id} at ${where}: ${redacted}`,
          evidence: [
            {
              type: 'pattern-match',
              pattern: pattern.id,
              line: lineNumber,
              match_redacted: redacted,
              ...(source ? { source } : {}),
            },
          ],
          discovery_tool: tool || 'secret-scan',
          ...(isNonEmptyString(record.session_id) ? { session_id: record.session_id } : {}),
          ...(isNonEmptyString(record.target_id) ? { target_id: record.target_id } : {}),
          ...(isNonEmptyString(record.asset_id) ? { asset_id: record.asset_id } : {}),
        });
      }
    }
  }

  return { rawFindings, truncated };
}

// The detector: secretScanDetector(input, defaults) ->
// { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any other
// object is treated as a single content record. A non-object
// input throws DETECTOR_INVALID_INPUT. Bad records are counted
// in `skipped`, never thrown.
function secretScanDetector(input, defaults) {
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
        throw new Error('secret-scan: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`secret-scan: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = secretScanDetector;
module.exports.secretScanDetector = secretScanDetector;
module.exports.PATTERNS = PATTERNS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.redactMatch = redactMatch;
module.exports.findingIdFor = findingIdFor;
