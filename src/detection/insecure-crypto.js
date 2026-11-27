// Third REAL detector (Phase 5, round 88): insecure-crypto.
//
// dangerous-call (round 87) proved the framework generalizes to
// code sinks. This module proves it generalizes a third time, to
// weak-cryptography call sites in operator-supplied local text.
// It scans the `content` string of a local input record — text
// the operator already holds (for example source code or a code
// excerpt captured in the lab) and hands to
// `sentinel detect --detector insecure-crypto --input <record.json>`.
// It never reads a file itself, never makes a request, and never
// executes the code it scans: a match proves the weak-crypto call
// text is present in the supplied text; it does not prove the call
// guards anything sensitive, that its output feeds a secret or a
// token, or that the weakness is exploitable in context. Every
// finding therefore carries the default confidence `potential`,
// and exploitability must be verified out of band before
// reporting.
//
// Patterns (all call-site or cipher-selection syntax, word-
// boundary anchored so lookalikes such as `md5sum(`, `sha256(`,
// or `random.randint(` do not match; no data-flow or taint
// analysis, which would need a parser and is out of scope for
// this detector):
//   weak-hash-md5         md5 hash calls (hashlib.md5,        CWE-327, medium
//                         createHash('md5'), getInstance("MD5"),
//                         bare md5()
//   weak-hash-sha1        sha1 hash calls (same shapes)       CWE-327, medium
//   ecb-mode              ECB cipher mode (AES/ECB/...,       CWE-327, medium
//                         createCipheriv('...ecb...'))
//   weak-cipher-des-rc4   DES / 3DES / RC4 / ARC4 cipher      CWE-327, high
//                         instantiation (getInstance, 
//                         createCipheriv, ARC4.new)
//   deprecated-cipher     crypto.createCipher( /              CWE-327, medium
//                         crypto.createDecipher( (Node
//                         deprecated, MD5-based key derivation,
//                         no IV)
//   insecure-random       Math.random( / random.random(        CWE-338, medium
// A documentation example (for instance `hashlib.md5(data)` in
// a how-to, or a test fixture calling `Math.random()`) WILL
// match — the detector reports what it sees in the text; the
// operator triages it, and the validator's `false_positive`
// verdict exists for exactly that. A match in a comment or a
// string literal is the same: the detector has no parser and
// cannot tell code from prose, so a match is a lead, never a
// verdict. The `insecure-random` pattern is the noisiest of the
// six by design: `Math.random()` is fine for shuffling a UI
// list and only a weakness when its output feeds a secret, a
// token, or a session id — the finding says so in its
// description, and the operator's verification step decides.
//
// Safety properties (tested, not assumed):
// - A finding carries only the matched call text (for example
//   `hashlib.md5(`), never the whole source line: the line
//   could hold adjacent sensitive data, and the call itself is
//   the evidence. No secret can leak through this detector — it
//   matches call syntax, not credential formats — but the same
//   discipline as secret-scan applies: evidence is the match,
//   not the surrounding text.
// - `finding_id` is deterministic: `insecure-crypto-` + the
//   first 16 hex chars of SHA-256
//   (`insecure-crypto:<pattern>:<line>:<column>:<match>`). The
//   same call text on the same line at a different column is a
//   different finding (a different call site); the same call on
//   a different line is a different finding; only the exact same
//   (pattern, line, column, match) would dedupe, which cannot
//   occur twice in one scan — the identity is per call site,
//   not per call text (unlike secret-scan, where the secret
//   value IS the identity).
// - One finding per distinct (pattern, line, column, match)
//   per record; the first occurrence line is reported. At most
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
//   carries `discovery_tool: 'insecure-crypto'`.
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

// pattern id -> { label, regex (global), vulnerability_type,
// severity, cwe_id, impact, remediation }.
// Severity is per pattern, not uniform: DES/RC4 are high (the
// primitives themselves are practically broken — 56-bit DES is
// brute-forceable, RC4's biases are practical); the weak hashes,
// ECB mode, the deprecated cipher API, and the weak PRNG are
// medium (each is only exploitable in a sensitive context the
// detector cannot prove — a checksum, a non-secret use, or a
// UI shuffle). The class 'cryptographic failure' has no
// dedicated evidence-checklist class and resolves to the generic
// checklist; that mapping is the validator's, not this module's.
const PATTERNS = [
  {
    id: 'weak-hash-md5',
    label: 'MD5 hash call',
    regex: /(?:\bhashlib\.md5\s*\(|\bhashlib\.new\s*\(\s*['"]md5['"]\s*[,)]|\bcreateHash\s*\(\s*['"]md5['"]\s*\)|\bMessageDigest\.getInstance\s*\(\s*['"]MD5['"]\s*\)|\bmd5\s*\()/g,
    vulnerability_type: 'cryptographic failure',
    severity: 'medium',
    cwe_id: 'CWE-327',
    impact: 'MD5 is collision-broken: two different inputs can be crafted with the same MD5 digest, so MD5 cannot prove integrity or authenticate anything. Passwords or tokens hashed with MD5 are also fast to brute-force.',
    remediation: 'Replace MD5 with SHA-256 or better (SHA-256/SHA-512, or a password-hashing function such as bcrypt/argon2/scrypt for credentials); keep MD5 only for non-security checksums and say so in a comment.',
  },
  {
    id: 'weak-hash-sha1',
    label: 'SHA-1 hash call',
    regex: /(?:\bhashlib\.sha1\s*\(|\bhashlib\.new\s*\(\s*['"]sha1['"]\s*[,)]|\bcreateHash\s*\(\s*['"]sha1['"]\s*\)|\bMessageDigest\.getInstance\s*\(\s*['"]SHA-1['"]\s*\)|\bsha1\s*\()/g,
    vulnerability_type: 'cryptographic failure',
    severity: 'medium',
    cwe_id: 'CWE-327',
    impact: 'SHA-1 is collision-broken (the SHAttered attack produced a practical collision), so SHA-1 cannot prove integrity or authenticate anything. It must not guard signatures, certificates, or content identity.',
    remediation: 'Replace SHA-1 with SHA-256 or better; keep SHA-1 only for non-security checksums (for example legacy git object ids) and say so in a comment.',
  },
  {
    id: 'ecb-mode',
    label: 'ECB cipher mode',
    regex: /(?:\b(?:AES|DES|DESede|Blowfish|Camellia|SEED|IDEA|RC2)\s*\/\s*ECB\b|\bcreateCipheriv\s*\(\s*['"][^'"]*?ecb[^'"]*?['"])/gi,
    vulnerability_type: 'cryptographic failure',
    severity: 'medium',
    cwe_id: 'CWE-327',
    impact: 'ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks: patterns in the plaintext leak through the ciphertext (the classic ECB penguin), and an attacker can reorder or replay blocks undetected.',
    remediation: 'Use an authenticated mode with a random IV (AES-GCM, or CBC with HMAC over the ciphertext) instead of ECB; never select ECB for new code.',
  },
  {
    id: 'weak-cipher-des-rc4',
    label: 'DES/RC4 cipher',
    regex: /(?:\bCipher\.getInstance\s*\(\s*['"](?:DES|DESede|3DES|RC4|ARC4)[^'"]*['"]\s*\)|\bcreateCipheriv\s*\(\s*['"](?:des|des-ede|des3|rc4|arc4)[^'"]*['"]|\bARC4\.new\s*\()/gi,
    vulnerability_type: 'cryptographic failure',
    severity: 'high',
    cwe_id: 'CWE-327',
    impact: 'DES (56-bit key) is brute-forceable with commodity hardware and 3DES is deprecated; RC4/ARC4 has practical statistical biases that leak plaintext. Data encrypted with any of them is not confidential against a determined attacker.',
    remediation: 'Replace DES/3DES/RC4 with AES-GCM (or ChaCha20-Poly1305) and a random IV; treat any data already encrypted with them as compromised and re-encrypt.',
  },
  {
    id: 'deprecated-cipher',
    label: 'deprecated cipher call',
    regex: /\bcrypto\.create(?:Cipher|Decipher)\s*\(/g,
    vulnerability_type: 'cryptographic failure',
    severity: 'medium',
    cwe_id: 'CWE-327',
    impact: 'Node\'s crypto.createCipher()/createDecipher() are deprecated: they derive the key with a single MD5 iteration and no salt, and use a fixed (zero) IV, so the encryption is weak even when the named cipher is strong.',
    remediation: 'Use crypto.createCipheriv()/createDecipheriv() with a random IV and a key derived by a proper KDF (scrypt/pbkdf2) instead of createCipher()/createDecipher().',
  },
  {
    id: 'insecure-random',
    label: 'insecure random call',
    regex: /(?:\bMath\.random\s*\(|\brandom\.random\s*\()/g,
    vulnerability_type: 'cryptographic failure',
    severity: 'medium',
    cwe_id: 'CWE-338',
    impact: 'Math.random() and random.random() are not cryptographically secure: their output is predictable once the seed or a few outputs are known, so a token, password, or session id built from them can be guessed by an attacker.',
    remediation: 'Use a cryptographically secure generator for anything secret (crypto.randomBytes()/crypto.getRandomValues() in Node, secrets in Python) and keep Math.random()/random.random() for non-security uses only.',
  },
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(patternId, lineNumber, column, match) {
  const digest = crypto
    .createHash('sha256')
    .update(`insecure-crypto:${patternId}:${lineNumber}:${column}:${match}`, 'utf8')
    .digest('hex');
  return `insecure-crypto-${digest.slice(0, 16)}`;
}

// Scan one content record into raw findings. Throws on a record
// that cannot be scanned (no usable content, oversized content,
// wrong-typed `source`); the caller counts those in `skipped`.
// Returns { rawFindings, truncated } where `truncated` is the
// count of matches dropped by the per-record cap (0 when none).
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('insecure-crypto: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`insecure-crypto: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('insecure-crypto: "source" must be a non-empty string when present.');
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
        const extraNote = pattern.id === 'insecure-random'
          ? ' This call is only a weakness when its output feeds a secret, a token, or a session id — verify the use before reporting.'
          : '';
        rawFindings.push({
          finding_id: findingIdFor(pattern.id, lineNumber, column, value),
          title: `Weak ${pattern.label} in supplied text`,
          vulnerability_type: pattern.vulnerability_type,
          description: `A ${pattern.label} (${pattern.id}) was found in operator-supplied local text at ${where}. The detector scans only the text it is handed and never executes it; whether the call guards anything sensitive is unproven — verify out of band before reporting.${extraNote}`,
          impact: pattern.impact,
          remediation: pattern.remediation,
          severity: pattern.severity,
          cwe_id: pattern.cwe_id,
          steps_to_reproduce: [
            'Run `sentinel detect --detector insecure-crypto --input <record.json>` over the record carrying the text.',
            `Observe the finding for ${pattern.id} at ${where}.`,
            'Verify out of band whether the call guards something sensitive before reporting — the detector never executes the code, so exploitability is unproven.',
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
          discovery_tool: tool || 'insecure-crypto',
          ...(isNonEmptyString(record.session_id) ? { session_id: record.session_id } : {}),
          ...(isNonEmptyString(record.target_id) ? { target_id: record.target_id } : {}),
          ...(isNonEmptyString(record.asset_id) ? { asset_id: record.asset_id } : {}),
        });
      }
    }
  }

  return { rawFindings, truncated };
}

// The detector: insecureCryptoDetector(input, defaults) ->
// { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any other
// object is treated as a single content record. A non-object
// input throws DETECTOR_INVALID_INPUT. Bad records are counted
// in `skipped`, never thrown.
function insecureCryptoDetector(input, defaults) {
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
        throw new Error('insecure-crypto: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`insecure-crypto: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = insecureCryptoDetector;
module.exports.insecureCryptoDetector = insecureCryptoDetector;
module.exports.PATTERNS = PATTERNS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = findingIdFor;
