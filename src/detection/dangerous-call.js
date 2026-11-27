// Second REAL detector (Phase 5, round 87): dangerous-call.
//
// secret-scan (round 86) proved the pipeline with one class
// (information disclosure) and strict fixed-format patterns. This
// module proves the framework generalizes to a second, different
// kind of detection: risky code sinks in operator-supplied local
// text. It scans the `content` string of a local input record —
// text the operator already holds (for example source code or a
// code excerpt captured in the lab) and hands to
// `sentinel detect --detector dangerous-call --input <record.json>`.
// It never reads a file itself, never makes a request, and never
// executes the code it scans: a match proves the call text is
// present in the supplied text; it does not prove the call is
// reachable, attacker-controlled, or exploitable. Every finding
// therefore carries the default confidence `potential`, and
// exploitability must be verified out of band before reporting.
//
// Patterns (all call-site syntax, word-boundary anchored so
// lookalikes such as `myeval(`, `evaluate(`, or `execution(`
// do not match; no data-flow or taint analysis, which would
// need a parser and is out of scope for this detector):
//   eval-call               eval(                          CWE-94, high
//   function-constructor    new Function(                  CWE-94, high
//   command-exec            exec/execSync/spawn/spawnSync/ CWE-78, high
//                           execFile/execFileSync/system/
//                           popen(, os.system/os.popen/
//                           os.exec*/os.spawn*, subprocess
//                           .call/.run/.Popen/.check_output/
//                           .check_call(
//   inner-html-assign       .innerHTML = / +=              CWE-79, medium
//   document-write          document.write(/writeln(       CWE-79, medium
//   unsafe-deserialize      pickle/marshal .load(s)(,       CWE-502, high
//                           shelve.open(, yaml.load(,
//                           unserialize(
// A documentation example (for instance `eval(userInput)` in a
// how-to, or a test fixture calling `pickle.loads`) WILL match —
// the detector reports what it sees in the text; the operator
// triages it, and the validator's `false_positive` verdict
// exists for exactly that. A match in a comment or a string
// literal is the same: the detector has no parser and cannot
// tell code from prose, so a match is a lead, never a verdict.
//
// Safety properties (tested, not assumed):
// - A finding carries only the matched call text (for example
//   `eval(`), never the whole source line: the line could hold
//   adjacent sensitive data, and the call itself is the
//   evidence. No secret can leak through this detector — it
//   matches call syntax, not credential formats — but the same
//   discipline as secret-scan applies: evidence is the match,
//   not the surrounding text.
// - `finding_id` is deterministic: `dangerous-call-` + the
//   first 16 hex chars of SHA-256
//   (`dangerous-call:<pattern>:<line>:<column>:<match>`). The
//   same call text on the same line at a different column is a
//   different finding (a different call site); the same call on
//   a different line is a different finding; only the exact same
//   (pattern, line, column, match) would dedupe, which cannot
//   occur twice in one scan — the identity is per call site,
//   not per call text (unlike secret-scan, where the secret
//   value IS the identity).
// - One finding per distinct (pattern, line, match) per record;
//   the first occurrence line is reported. At most
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
//   carries `discovery_tool: 'dangerous-call'`.
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
// severity, cwe_id, title, impact, remediation }.
// Severity is per pattern, not uniform: code-execution and
// deserialization sinks are high (the call itself is the
// dangerous primitive); the XSS sinks are medium (an
// innerHTML assignment or document.write() is only exploitable
// with attacker-controlled data, which this detector cannot
// prove). The two injection classes ('code injection',
// 'os command injection') have no dedicated evidence-checklist
// class and resolve to the generic checklist; 'cross-site
// scripting' and 'insecure deserialization' resolve to their
// classes. That mapping is the validator's, not this module's.
const PATTERNS = [
  {
    id: 'eval-call',
    label: 'eval() call',
    regex: /\beval\s*\(/g,
    vulnerability_type: 'code injection',
    severity: 'high',
    cwe_id: 'CWE-94',
    impact: 'Code passed to eval() runs with the full privileges of the surrounding program, so attacker-controlled input reaching eval() is arbitrary code execution.',
    remediation: 'Remove the eval() call: parse the input with a safe parser (JSON.parse for data, a real expression evaluator for expressions) instead of executing it.',
  },
  {
    id: 'function-constructor',
    label: 'Function() constructor',
    regex: /\bnew\s+Function\s*\(/g,
    vulnerability_type: 'code injection',
    severity: 'high',
    cwe_id: 'CWE-94',
    impact: 'The Function() constructor compiles a string into executable code with the full privileges of the surrounding program, so attacker-controlled input reaching it is arbitrary code execution — it is eval() under another name.',
    remediation: 'Remove the Function() constructor: use a real function, a safe expression evaluator, or a lookup table instead of compiling strings into code.',
  },
  {
    id: 'command-exec',
    label: 'command execution call',
    regex: /(?:\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen)\s*\(|\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\(|\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\()/g,
    vulnerability_type: 'os command injection',
    severity: 'high',
    cwe_id: 'CWE-78',
    impact: 'These calls hand a string (or arguments) to the operating-system shell or a new process, so attacker-controlled input reaching them is arbitrary command execution on the host.',
    remediation: 'Avoid shell execution: use an allow-listed argument vector with no shell (spawn/execFile with shell: false, subprocess.run with a list and shell=False) and never interpolate untrusted input into a command string.',
  },
  {
    id: 'inner-html-assign',
    label: 'innerHTML assignment',
    regex: /\.innerHTML\s*\+?=/g,
    vulnerability_type: 'cross-site scripting',
    severity: 'medium',
    cwe_id: 'CWE-79',
    impact: 'Assigning to innerHTML parses the value as HTML, so attacker-controlled data assigned here renders as markup and script in the victim browser (stored or reflected XSS).',
    remediation: 'Assign text with textContent (or a sanitizer that strips markup) instead of innerHTML, and never assign untrusted data to innerHTML.',
  },
  {
    id: 'document-write',
    label: 'document.write() call',
    regex: /\bdocument\.write(?:ln)?\s*\(/g,
    vulnerability_type: 'cross-site scripting',
    severity: 'medium',
    cwe_id: 'CWE-79',
    impact: 'document.write() inserts its argument as markup into the page, so attacker-controlled data written here renders as markup and script in the victim browser (XSS).',
    remediation: 'Build DOM nodes with createElement/textContent (or a sanitizer) instead of document.write(), and never write untrusted data to the document stream.',
  },
  {
    id: 'unsafe-deserialize',
    label: 'unsafe deserialization call',
    regex: /(?:\b(?:pickle|marshal)\.(?:loads?|load)\s*\(|\bshelve\.open\s*\(|\byaml\.load\s*\(|\bunserialize\s*\()/g,
    vulnerability_type: 'insecure deserialization',
    severity: 'high',
    cwe_id: 'CWE-502',
    impact: 'These calls reconstruct objects from untrusted bytes, so attacker-controlled input reaching them can instantiate arbitrary classes and execute code during deserialization (in Python, pickle/marshal/shelve; in PHP, unserialize; yaml.load without a safe Loader).',
    remediation: 'Never deserialize untrusted input with these calls: use a data-only format (JSON) or a safe loader (yaml.safe_load, pickle only on bytes you produced yourself) and validate the result.',
  },
];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function findingIdFor(patternId, lineNumber, column, match) {
  const digest = crypto
    .createHash('sha256')
    .update(`dangerous-call:${patternId}:${lineNumber}:${column}:${match}`, 'utf8')
    .digest('hex');
  return `dangerous-call-${digest.slice(0, 16)}`;
}

// Scan one content record into raw findings. Throws on a record
// that cannot be scanned (no usable content, oversized content,
// wrong-typed `source`); the caller counts those in `skipped`.
// Returns { rawFindings, truncated } where `truncated` is the
// count of matches dropped by the per-record cap (0 when none).
function scanRecord(record, tool) {
  if (!isNonEmptyString(record.content)) {
    throw new Error('dangerous-call: record has no non-empty string "content" to scan.');
  }
  if (record.content.length > MAX_CONTENT_CHARS) {
    throw new Error(`dangerous-call: content exceeds the ${MAX_CONTENT_CHARS} character limit.`);
  }
  if (record.source !== undefined && record.source !== null && !isNonEmptyString(record.source)) {
    throw new Error('dangerous-call: "source" must be a non-empty string when present.');
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
        rawFindings.push({
          finding_id: findingIdFor(pattern.id, lineNumber, column, value),
          title: `Dangerous ${pattern.label} in supplied text`,
          vulnerability_type: pattern.vulnerability_type,
          description: `A ${pattern.label} (${pattern.id}) was found in operator-supplied local text at ${where}. The detector scans only the text it is handed and never executes it; whether the call is reachable or attacker-controlled is unproven — verify out of band before reporting.`,
          impact: pattern.impact,
          remediation: pattern.remediation,
          severity: pattern.severity,
          cwe_id: pattern.cwe_id,
          steps_to_reproduce: [
            'Run `sentinel detect --detector dangerous-call --input <record.json>` over the record carrying the text.',
            `Observe the finding for ${pattern.id} at ${where}.`,
            'Verify out of band whether the call is reachable with attacker-controlled input before reporting — the detector never executes the code, so exploitability is unproven.',
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
          discovery_tool: tool || 'dangerous-call',
          ...(isNonEmptyString(record.session_id) ? { session_id: record.session_id } : {}),
          ...(isNonEmptyString(record.target_id) ? { target_id: record.target_id } : {}),
          ...(isNonEmptyString(record.asset_id) ? { asset_id: record.asset_id } : {}),
        });
      }
    }
  }

  return { rawFindings, truncated };
}

// The detector: dangerousCallDetector(input, defaults) ->
// { findings, skipped, errors }. A batch record
// `{ tool, results: [...] }` scans each result with the batch
// tool forced as discovery_tool (the stub convention); any other
// object is treated as a single content record. A non-object
// input throws DETECTOR_INVALID_INPUT. Bad records are counted
// in `skipped`, never thrown.
function dangerousCallDetector(input, defaults) {
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
        throw new Error('dangerous-call: each record must be an object with a "content" string.');
      }
      const { rawFindings, truncated } = scanRecord(record, tool);
      for (const raw of rawFindings) {
        findings.push(normalizeRawFinding(raw, defaults));
      }
      if (truncated > 0) {
        errors.push(`dangerous-call: ${truncated} additional match${truncated === 1 ? '' : 'es'} truncated in this record (first ${MAX_FINDINGS_PER_RECORD} reported).`);
      }
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
}

module.exports = dangerousCallDetector;
module.exports.dangerousCallDetector = dangerousCallDetector;
module.exports.PATTERNS = PATTERNS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = findingIdFor;
