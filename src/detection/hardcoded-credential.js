// Fourth REAL detector (Phase 5, round 89): hardcoded-credential.
//
// secret-scan (round 86) proved the pipeline with credential
// FORMATS (an AWS key or a GitHub token is a secret wherever it
// appears). This module proves the framework generalizes to a
// different detection angle: the ASSIGNMENT context. It scans the
// `content` string of a local input record — text the operator
// already holds (for example source code or a code excerpt
// captured in the lab) and hands to
// `sentinel detect --detector hardcoded-credential --input
// <record.json>` — for a credential-named variable assigned a
// quoted string literal. A variable called `password` assigned
// `"hunter2"` is a hard-coded credential (CWE-798) even though
// the literal itself matches no known token format. It never
// reads a file itself, never makes a request, and never
// executes the code it scans: a match proves the assignment
// text is present in the supplied text; it does not prove the
// credential is live, used anywhere, or not a placeholder.
// Every finding therefore carries the default confidence
// `potential`, and liveness must be verified out of band
// before reporting.
//
// Patterns (all assignment syntax, matched per line; the name
// is a credential name, the operator is `=`, `:=`, or `:`, and
// the value is a non-empty quoted literal — no parser, no
// data flow, which would need one and is out of scope):
//   hardcoded-password    password|passwd|pwd = "..."   CWE-798, high
//   hardcoded-api-key     api_key|apikey|api-key|       CWE-798, high
//                         access_key|accesskey|
//                         secret_key|secretKey = "..."
//   hardcoded-secret      client_secret|clientSecret|   CWE-798, high
//                         secret|access_token|
//                         accessToken|auth_token|
//                         authToken|token = "..."
// All three patterns are class 'use of hard-coded credentials'
// and severity high: each names a directly usable credential.
// A documentation example (for instance `password = "hunter2"`
// in a how-to, or a test fixture assigning a fake token) WILL
// match — the detector reports what it sees in the text; the
// operator triages it, and the validator's `false_positive`
// verdict exists for exactly that. A match in a comment or a
// string literal is the same: the detector has no parser and
// cannot tell code from prose, so a match is a lead, never a
// verdict.
//
// Safety properties (tested, not assumed):
// - A finding NEVER carries the literal value. The matched
//   assignment is reconstructed as `<name><operator> "****"`
//   (fixed four asterisks, no length information): the
//   variable name and the fact of the assignment are the
//   evidence; the secret itself never leaves the scanned
//   text. This is the one detector whose raw match is itself
//   a secret, so the masking happens in the module, before
//   any finding is built — no other layer can leak it.
// - `finding_id` is deterministic: `hardcoded-credential-` +
//   the first 16 hex chars of SHA-256
//   (`hardcoded-credential:<pattern>:<line>:<column>:<masked
//   match>`). Identity is per assignment site (the masked
//   match carries no secret, so two different literals at
//   the same site are the same finding — they cannot occur
//   twice in one scan); the same assignment on the same line
//   at a different column is a different finding, and the
//   same assignment on a different line is a different
//   finding.
// - One finding per distinct (pattern, line, column, masked
//   match) per record. At most MAX_FINDINGS_PER_RECORD (100)
//   findings per record; further matches are dropped and the
//   drop is recorded in `errors` so a truncated scan is
//   visible, never silent.
// - Content over MAX_CONTENT_CHARS (1,000,000) is skipped,
//   not scanned; the CLI already bounds the input file to
//   10 MiB, this bound keeps the scan itself bounded.
// - A record without a non-empty string `content` is counted
//   in `skipped` with its error recorded, never thrown; a bad
//   record never aborts a batch. A non-object input throws
//   DETECTOR_INVALID_INPUT, exactly like the stub detector.
// - Batch records `{ tool, results: [...] }` follow the stub
//   convention: the batch `tool`, when present, is forced as
//   `discovery_tool` on every finding; otherwise the finding
//   carries `discovery_tool: 'hardcoded-credential'`.
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

// The value shown in place of the assigned literal, in the
// finding's match / proof of concept / finding_id input. Fixed
// four asterisks: no length information, no part of the secret.
const MASKED_LITERAL = '"****"';

// Name start: the name must begin a fresh identifier segment —
// at the start of a word, after a `_`/`-` separator, or at a
// camelCase hump (a lowercase letter followed by an uppercase
// one). This catches `password`, `user_password`,
// `userPassword`, and `API_KEY`, while `passwordHash`,
// `password_hash`, and `secretKey` do not match (the name is
// not followed by an assignment — see NAME_END). The
// case-insensitive flag makes the hump check letter-based,
// which is intended: `userpassword` is still a password
// variable, so it matches as a true positive.
const NAME_START = String.raw`(?:(?<![\w$])|(?<=[_-])|(?<=[a-z])(?=[A-Z]))`;
// Name end: the name must not continue into a longer identifier
// (`password2`, `password_confirmation`, `secretKey` are not
// matched — suffixed variants are out of scope, see the doc).
const NAME_END = String.raw`(?![\w$-])`;
// Operator: `=` (not `==`), `:=` (Go), or `:` (object literal /
// JSON / YAML / dict) — not `::`, not `!=`, `<=`, or `>=`. The
// name may be wrapped in quotes (JSON `"password": "..."`), so
// one optional closing quote is allowed between the name and
// the operator.
const ASSIGN = String.raw`\s*["']?\s*(=(?!=)|:=(?!=)|:(?![=:]))\s*`;
// Value: a non-empty quoted literal, single or double quotes,
// at most 200 characters. Empty literals (`""`) are not
// credentials; unquoted values (`password=abc123`, `.env`
// style) are out of scope — the bare-value surface overlaps
// with config placeholders and with secret-scan's format
// matching. Backtick template literals are out of scope:
// interpolation makes the literal only part of the value.
const LITERAL = String.raw`(?:"[^"\r\n]{1,200}"|'[^'\r\n]{1,200}')`;

function assignmentRegex(names) {
  return new RegExp(`${NAME_START}(${names})${NAME_END}${ASSIGN}${LITERAL}`, 'gi');
}

// pattern id -> { label, regex (global), vulnerability_type,
// severity, cwe_id, impact, remediation }.
// Severity is uniform high: every pattern names a directly
// usable credential (a password, an API key, a secret/token) —
// unlike dangerous-call / insecure-crypto, there is no
// pattern here whose primitive is only dangerous in context.
// The class 'use of hard-coded credentials' has no dedicated
// evidence-checklist class and resolves to the generic
// checklist; that mapping is the validator's, not this
// module's.
const PATTERNS = [
  {
    id: 'hardcoded-password',
    label: 'password assignment',
    regex: assignmentRegex('password|passwd|pwd'),
    vulnerability_type: 'use of hard-coded credentials',
    severity: 'high',
    cwe_id: 'CWE-798',
    impact: 'A password written literally in source code is readable by anyone who can read the code — including every future holder of the repository, a leaked archive, or a bundled artifact — and it cannot be rotated without a code change and a redeploy. Anyone holding it can authenticate as that account.',
    remediation: 'Remove the literal: read the password from the environment or a secret manager at runtime, and rotate the exposed password immediately — assume it is already known.',
  },
  {
    id: 'hardcoded-api-key',
    label: 'API key assignment',
    regex: assignmentRegex('api_key|api-key|apikey|access_key|accesskey|secret_key|secretKey'),
    vulnerability_type: 'use of hard-coded credentials',
    severity: 'high',
    cwe_id: 'CWE-798',
    impact: 'An API key written literally in source code is readable by anyone who can read the code — including every future holder of the repository, a leaked archive, or a bundled artifact — and it cannot be revoked without a code change and a redeploy. Anyone holding it can call the API as the key owner.',
    remediation: 'Remove the literal: read the key from the environment or a secret manager at runtime, and revoke and reissue the exposed key immediately — assume it is already known.',
  },
  {
    id: 'hardcoded-secret',
    label: 'secret/token assignment',
    regex: assignmentRegex('client_secret|clientSecret|access_token|accessToken|auth_token|authToken|secret|token'),
    vulnerability_type: 'use of hard-coded credentials',
    severity: 'high',
    cwe_id: 'CWE-798',
    impact: 'A secret or token written literally in source code is readable by anyone who can read the code — including every future holder of the repository, a leaked archive, or a bundled artifact — and it cannot be rotated without a code change and a redeploy. Anyone holding it can present it as the bearer.',
    remediation: 'Remove the literal: read the secret or token from the environment or a secret manager at runtime, and rotate the exposed value immediately — assume it is already known.',
  },
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(patternId, lineNumber, column, maskedMatch) {
  const digest = crypto
    .createHash('sha256')
    .update(`hardcoded-credential:${patternId}:${lineNumber}:${column}:${maskedMatch}`, 'utf8')
    .digest('hex');
  return `hardcoded-credential-${digest.slice(0, 16)}`;
}

// Rebuild the matched assignment with the literal masked.
// match[1] is the variable name as written in the source
// (not a secret), match[2] is the operator (`=`, `:=`, or
// `:`). The literal itself is never carried anywhere. Spacing
// is canonicalized: `password = "****"`, `password := "****"`,
// `password: "****"`.
function maskedMatchFor(match) {
  const operator = match[2] === ':' ? ': ' : ` ${match[2]} `;
  return `${match[1]}${operator}${MASKED_LITERAL}`;
}

// Scan one content record into raw findings. Throws on a record
// that cannot be scanned (no usable content, oversized content,
// wrong-typed `source`); the caller counts those in `skipped`.
// Returns { rawFindings, truncated } where `truncated` is the
// count of matches dropped by the per-record cap (0 when none).
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('hardcoded-credential: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`hardcoded-credential: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('hardcoded-credential: "source" must be a non-empty string when present.');
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
        const masked = maskedMatchFor(match);
        const column = match.index + 1;
        const key = `${pattern.id}:${lineNumber}:${column}:${masked}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (rawFindings.length >= MAX_FINDINGS_PER_RECORD) {
          truncated += 1;
          continue;
        }
        const where = source
          ? `source "${source}", line ${lineNumber}, column ${column}`
          : `line ${lineNumber}, column ${column}`;
        rawFindings.push({
          finding_id: findingIdFor(pattern.id, lineNumber, column, masked),
          title: `Hard-coded ${pattern.label} in supplied text`,
          vulnerability_type: pattern.vulnerability_type,
          description: `A ${pattern.label} (${pattern.id}) was found in operator-supplied local text at ${where}. The assigned literal is masked in this finding — the detector never carries a secret value, only the variable name and the fact of the assignment. The detector scans only the text it is handed and never executes it; whether the credential is live, used anywhere, or a placeholder is unproven — verify out of band before reporting.`,
          impact: pattern.impact,
          remediation: pattern.remediation,
          severity: pattern.severity,
          cwe_id: pattern.cwe_id,
          steps_to_reproduce: [
            'Run `sentinel detect --detector hardcoded-credential --input <record.json>` over the record carrying the text.',
            `Observe the finding for ${pattern.id} at ${where}.`,
            'Verify out of band whether the credential is live, used anywhere, or a placeholder before reporting — the detector never checks liveness, so a match is a lead, not a verdict.',
          ],
          proof_of_concept: `Matched ${pattern.id} at ${where}: ${masked}`,
          evidence: [
            {
              type: 'pattern-match',
              pattern: pattern.id,
              line: lineNumber,
              column,
              match: masked,
              ...(source ? { source } : {}),
            },
          ],
          discovery_tool: tool || 'hardcoded-credential',
          ...(isNonEmptyString(record.session_id) ? { session_id: record.session_id } : {}),
          ...(isNonEmptyString(record.target_id) ? { target_id: record.target_id } : {}),
          ...(isNonEmptyString(record.asset_id) ? { asset_id: record.asset_id } : {}),
        });
      }
    }
  }

  return { rawFindings, truncated };
}

// The detector: hardcodedCredentialDetector(input, defaults) ->
// { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any other
// object is treated as a single content record. A non-object
// input throws DETECTOR_INVALID_INPUT. Bad records are counted
// in `skipped`, never thrown.
function hardcodedCredentialDetector(input, defaults) {
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
        throw new Error('hardcoded-credential: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`hardcoded-credential: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = hardcodedCredentialDetector;
module.exports.hardcodedCredentialDetector = hardcodedCredentialDetector;
module.exports.PATTERNS = PATTERNS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = findingIdFor;
