// Second real detector (round 87, Phase 5): dangerous-call scans
// operator-supplied local text for risky code-sink calls (eval,
// Function, command execution, innerHTML, document.write, unsafe
// deserialization) and reports one finding per distinct call site
// — never executing the code it scans. No network, no scanner, no
// target: every finding is confidence `potential`.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const {
  dangerousCallDetector,
  PATTERNS,
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
} = require('../src/detection/dangerous-call');
const { getDetector, runDetector } = require('../src/detection/detector');
const { validateFinding, dedupeFindings, evidenceChecklistForClass } = require('../src/analysis/validator');
const { generateReport } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const DEFAULTS = { session_id: 'sess-1', target_id: 'tgt-1', asset_id: 'ast-1' };

// Test code excerpts only; no snippet here is executed by the
// detector or the tests — the detector matches call text.
const EVAL_CALL = 'eval(userInput)';
const FUNCTION_CALL = 'new Function("return " + code)';
const EXEC_CALL = 'exec("ls " + dir)';
const SUBPROCESS_CALL = 'subprocess.run(cmd, shell=True)';
const OS_SYSTEM_CALL = 'os.system("rm -rf " + path)';
const INNER_HTML = 'el.innerHTML = userName';
const DOC_WRITE = 'document.write(userName)';
const PICKLE_CALL = 'pickle.loads(payload)';

function scan(content, defaults = DEFAULTS, extra = {}) {
  return dangerousCallDetector({ content, ...extra }, defaults);
}

test('dangerous-call: an eval() call yields one high-severity code-injection finding', () => {
  const result = scan(`const a = 1\n${EVAL_CALL}\nend`);
  assert.equal(result.findings.length, 1);
  assert.equal(result.skipped, 0);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'code injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.confidence, 'potential');
  assert.equal(finding.discovery_tool, 'dangerous-call');
  assert.equal(finding.cwe_id, 'CWE-94');
  assert.equal(finding.evidence[0].pattern, 'eval-call');
  assert.equal(finding.evidence[0].line, 2);
  assert.equal(finding.evidence[0].column, 1);
  assert.equal(finding.evidence[0].match, 'eval(');
  assert.equal(finding.proof_of_concept, 'Matched eval-call at line 2, column 1: eval(');
  assert.match(finding.description, /line 2, column 1/);
  // Code injection has no dedicated evidence class, so the
  // validator resolves it to the generic checklist.
  assert.equal(evidenceChecklistForClass(finding).classId, 'generic');
});

test('dangerous-call: each pattern family is detected with its own pattern id, class, and severity', () => {
  const cases = [
    [FUNCTION_CALL, 'function-constructor', 'code injection', 'high', 'CWE-94'],
    [EXEC_CALL, 'command-exec', 'os command injection', 'high', 'CWE-78'],
    [SUBPROCESS_CALL, 'command-exec', 'os command injection', 'high', 'CWE-78'],
    [OS_SYSTEM_CALL, 'command-exec', 'os command injection', 'high', 'CWE-78'],
    [INNER_HTML, 'inner-html-assign', 'cross-site scripting', 'medium', 'CWE-79'],
    [DOC_WRITE, 'document-write', 'cross-site scripting', 'medium', 'CWE-79'],
    [PICKLE_CALL, 'unsafe-deserialize', 'insecure deserialization', 'high', 'CWE-502'],
    ['yaml.load(data)', 'unsafe-deserialize', 'insecure deserialization', 'high', 'CWE-502'],
    ['unserialize($_GET["x"])', 'unsafe-deserialize', 'insecure deserialization', 'high', 'CWE-502'],
  ];
  for (const [code, patternId, vulnType, severity, cwe] of cases) {
    const result = scan(`prefix ${code} suffix`);
    assert.equal(result.findings.length, 1, patternId);
    const finding = result.findings[0];
    assert.equal(finding.evidence[0].pattern, patternId);
    assert.equal(finding.vulnerability_type, vulnType);
    assert.equal(finding.severity, severity);
    assert.equal(finding.cwe_id, cwe);
  }
});

test('dangerous-call: line numbers are 1-based and the source label is carried into description and evidence', () => {
  const content = ['first line', 'second line', `run ${EVAL_CALL}`, 'last line'].join('\n');
  const result = scan(content, DEFAULTS, { source: 'lab-code.js' });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 3);
  assert.equal(result.findings[0].evidence[0].column, 5);
  assert.equal(result.findings[0].evidence[0].source, 'lab-code.js');
  assert.match(result.findings[0].description, /source "lab-code.js", line 3, column 5/);
});

test('dangerous-call: identity is per call site (pattern, line, column, match) — two eval() calls on one line are two findings', () => {
  const twoCalls = scan(`eval(a); eval(b); eval(a)`);
  assert.equal(twoCalls.findings.length, 3, 'three call sites at three columns, even with repeated text');
  assert.equal(twoCalls.findings[0].evidence[0].column, 1);
  assert.equal(twoCalls.findings[1].evidence[0].column, 10);
  assert.equal(twoCalls.findings[2].evidence[0].column, 19);
  const twoLines = scan(`eval(a)\neval(a)`);
  assert.equal(twoLines.findings.length, 2, 'same call text on two lines is two code sites');
  assert.notEqual(twoLines.findings[0].finding_id, twoLines.findings[1].finding_id);
  const mixed = scan(`eval(a); pickle.loads(x)`);
  assert.equal(mixed.findings.length, 2, 'different patterns on one line are distinct findings');
});

test('dangerous-call: finding_id is deterministic per call site and stable across runs', () => {
  const first = scan(EVAL_CALL);
  const second = scan(EVAL_CALL);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.equal(first.findings[0].finding_id, findingIdFor('eval-call', 1, 1, 'eval('));
  assert.match(first.findings[0].finding_id, /^dangerous-call-[0-9a-f]{16}$/);
  const otherLine = scan(`line one\n${EVAL_CALL}`);
  assert.notEqual(first.findings[0].finding_id, otherLine.findings[0].finding_id, 'line is part of the identity');
  const otherColumn = scan(`  ${EVAL_CALL}`);
  assert.notEqual(first.findings[0].finding_id, otherColumn.findings[0].finding_id, 'column is part of the identity');
});

test('dangerous-call: a record without usable content is skipped, never thrown; a non-object input throws', () => {
  for (const bad of [{}, { content: '' }, { content: '   ' }, { content: 42 }]) {
    const result = dangerousCallDetector(bad, DEFAULTS);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 1);
    assert.equal(result.errors.length, 1);
    assert.match(result.errors[0], /content/);
  }
  assert.throws(() => dangerousCallDetector(null, DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => dangerousCallDetector('not an object', DEFAULTS), /DETECTOR_INVALID_INPUT/);
  assert.throws(() => dangerousCallDetector([{}], DEFAULTS), /DETECTOR_INVALID_INPUT/);
});

test('dangerous-call: a record missing its ids is skipped without defaults and filled from defaults', () => {
  const noDefaults = dangerousCallDetector({ content: EVAL_CALL }, {});
  assert.equal(noDefaults.findings.length, 0);
  assert.equal(noDefaults.skipped, 1);
  assert.match(noDefaults.errors[0], /session_id|target_id|asset_id/);
  const withDefaults = dangerousCallDetector({ content: EVAL_CALL }, DEFAULTS);
  assert.equal(withDefaults.findings.length, 1);
  assert.equal(withDefaults.findings[0].session_id, 'sess-1');
  assert.equal(withDefaults.findings[0].target_id, 'tgt-1');
  assert.equal(withDefaults.findings[0].asset_id, 'ast-1');
  const perRecord = dangerousCallDetector(
    { content: EVAL_CALL, session_id: 's-9', target_id: 't-9', asset_id: 'a-9' },
    DEFAULTS,
  );
  assert.equal(perRecord.findings[0].session_id, 's-9', 'record ids win over defaults');
});

test('dangerous-call: oversized content is skipped, not scanned', () => {
  const big = dangerousCallDetector({ content: `x${' '.repeat(MAX_CONTENT_CHARS)}` }, DEFAULTS);
  assert.equal(big.findings.length, 0);
  assert.equal(big.skipped, 1);
  assert.match(big.errors[0], /exceeds the 1000000 character limit/);
});

test('dangerous-call: the per-record cap truncates visibly, never silently', () => {
  const lines = [];
  for (let index = 0; index < MAX_FINDINGS_PER_RECORD + 5; index += 1) {
    lines.push(`eval(x${index})`);
  }
  const result = scan(lines.join('\n'));
  assert.equal(result.findings.length, MAX_FINDINGS_PER_RECORD);
  assert.equal(result.skipped, 0);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /5 additional matches truncated/);
  assert.match(result.errors[0], /first 100 reported/);
});

test('dangerous-call: batch records follow the stub convention — batch tool is authoritative, bad results skipped', () => {
  const batch = {
    tool: 'lab-capture',
    results: [
      { content: EVAL_CALL },
      { content: '' },
      { content: PICKLE_CALL },
    ],
  };
  const result = dangerousCallDetector(batch, DEFAULTS);
  assert.equal(result.findings.length, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.findings[0].discovery_tool, 'lab-capture');
  assert.equal(result.findings[1].discovery_tool, 'lab-capture');
  assert.throws(
    () => dangerousCallDetector({ tool: '  ', results: [{ content: EVAL_CALL }] }, DEFAULTS),
    /DETECTOR_INVALID_INPUT: batch tool must be a non-empty string/,
  );
});

test('dangerous-call: getDetector resolves the built-in name and runDetector validates its envelope', () => {
  const resolved = getDetector('dangerous-call');
  assert.equal(resolved.source, 'dangerous-call');
  assert.equal(typeof resolved.detector, 'function');
  const result = runDetector(resolved.detector, { content: EVAL_CALL }, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal('error' in result, false);
});

test('dangerous-call: XSS and deserialization findings carry their classes and validate as needs_evidence', () => {
  const xss = scan(INNER_HTML).findings[0];
  assert.equal(evidenceChecklistForClass(xss).classId, 'cross-site scripting');
  assert.equal(validateFinding(xss).verdict, 'needs_evidence', 'no response_log yet — the operator must add the rendered-response evidence');
  const deser = scan(PICKLE_CALL).findings[0];
  assert.equal(evidenceChecklistForClass(deser).classId, 'insecure deserialization');
  assert.equal(validateFinding(deser).verdict, 'needs_evidence', 'no evidence_notes yet — the operator must add the payload/state evidence');
  const deduped = dedupeFindings([xss, xss]);
  assert.equal(deduped.groups.length, 1, 'the same call site dedupes to one finding');
  assert.equal(deduped.duplicates, 1);
});

test('dangerous-call: detect -> validate -> report end to end, JSON carries the evidence checklists', () => {
  const result = runDetector(dangerousCallDetector, { content: `a\n${EVAL_CALL}\n${PICKLE_CALL}` }, DEFAULTS);
  assert.equal(result.findings.length, 2);
  const json = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
    format: 'json',
  });
  const report = JSON.parse(json);
  assert.equal(report.findings.length, 2);
  const byPattern = {};
  for (const finding of report.findings) {
    byPattern[finding.evidence[0].pattern] = finding.evidence_checklist.classId;
  }
  assert.equal(byPattern['eval-call'], 'generic');
  assert.equal(byPattern['unsafe-deserialize'], 'insecure deserialization');
  const markdown = generateReport(result.findings, {
    programName: 'Lab Program',
    generatedAt: '2026-11-27T10:00:00+07:00',
  });
  assert.match(markdown, /code injection/i);
  assert.match(markdown, /insecure deserialization/i);
});

test('CLI detect with dangerous-call over a local record: JSON output, detector named, code never executed', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-dangerous-call-cli-');
  const inputPath = path.join(directory, 'record.json');
  fs.writeFileSync(inputPath, JSON.stringify({ content: `notes\n${EVAL_CALL}\n${PICKLE_CALL}\n`, source: 'lab.py' }), 'utf8');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'detect', '--detector', 'dangerous-call', '--input', inputPath,
    '--session-id', 'sess-1', '--target-id', 'tgt-1', '--asset-id', 'ast-1',
  ]);
  const output = JSON.parse(stdout);
  assert.equal(output.detector, 'dangerous-call');
  assert.equal(output.findings.length, 2);
  assert.equal(output.skipped, 0);
  assert.equal('error' in output, false);
  assert.equal(output.findings[0].evidence[0].source, 'lab.py');
});

test('dangerous-call: patterns are strict call-site syntax — lookalikes do not match', () => {
  const lookalikes = [
    'myeval(x)', // no word boundary before eval
    'evaluate(x)', // eval followed by 'u', not '('
    'execution(cmd)', // exec followed by 'u', not '('
    'EXEC(cmd)', // uppercase — the detector is case-sensitive by design
    'os.systemx(cmd)', // system followed by 'x'
    'pickle.loadss(data)', // loads followed by 's'
    'yaml.safe_load(data)', // safe loader, not yaml.load(
    'x = el.innerHTML', // a read, not an assignment
    'document.writeText(x)', // write followed by 'Text', not '('
    'child_process.execFileSync', // no call paren — a bare reference
  ];
  for (const lookalike of lookalikes) {
    const result = scan(lookalike);
    assert.equal(result.findings.length, 0, lookalike);
  }
  assert.equal(PATTERNS.length, 6, 'the documented pattern set');
});
