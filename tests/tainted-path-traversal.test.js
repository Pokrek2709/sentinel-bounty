// Tests for the eleventh real detector (Phase 5, round 105):
// tainted-path-traversal — the sixth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted paths, aliased calls,
// inter-procedural flow); negative cases prove the parser
// refuses what the regex detector would wrongly match
// (comments, strings) and what is genuinely safe
// (literals, sanitized values, non-sink receivers).
// Structural cases pin the envelope (batch, skipped, caps,
// determinism, no literal leakage) and the documented
// resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-path-traversal');
const { parseJavaScript } = require('../src/detection/js-parser');

const IDS = { session_id: 's1', target_id: 't1', asset_id: 'a1' };

function run(content, defaults = {}) {
  return detect({ content, ...IDS }, defaults);
}

function runRecord(record, defaults = {}) {
  return detect({ ...IDS, ...record }, defaults);
}

// ---------------------------------------------------------------- parser

test('parser: parses the subset the detector relies on', () => {
  const sources = [
    'function h(d) { return fs.readFile(d); }',
    'const rf = fs.readFile; rf(x);',
    'const { readFile } = fs; readFile(d);',
    'class H { handle(req) { return fs.readFile(req.body); } }',
    'const f = async (req) => fs.writeFile(req.query);',
    'for (const item of items) { fs.readFile(item); }',
    'try { fs.readFile(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: fs.readFile(a); break; default: fs.readFile(b); }',
    'const v = ok ? fs.readFile(a) : null;',
    'const r = fs?.readFile(x); const y = a?.b?.c;',
    'const m = `/var/${name}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(d) { return fs.readFile(d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'path traversal');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-22');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'fs.readFile');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { fs.readFile(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; fs.readFile(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `/var/${n}`; fs.readFile(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { fs.readFile("/var/" + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; fs.readFile(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return fs.readFile(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { fs.readFile(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { fs?.readFile(d); }', ["parameter 'd' of function 'h'"]],
    // path.join does not sanitize: the joined path is still
    // tainted when a component is tainted.
    ['path.join', 'function h(d) { fs.readFile(path.join("/var", d)); }',
      ["parameter 'd' of function 'h'", 'path.join(…)']],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync', 'fs.createReadStream', 'fs.createWriteStream', 'fs.readdir', 'fs.readdirSync', 'fs.unlink', 'fs.unlinkSync']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const rf = fs.readFile; rf("/etc/passwd");', 'rf', 'fs.readFile'],
    ['computed alias', 'const rf = fs["readFile"]; rf(x);', 'rf', 'fs.readFile'],
    ['destructured alias', 'const { readFile } = fs; readFile(userInput);', 'readFile', 'fs.readFile'],
    ['renamed destructured alias', 'const { readFile: rf } = fs; rf(x);', 'rf', 'fs.readFile'],
    ['alias through identifier', 'const rf = fs.readFile; const s = rf; s(x);', 's', 'fs.readFile'],
    ['destructured readFileSync', 'const { readFileSync } = fs; readFileSync("/etc/passwd");', 'readFileSync', 'fs.readFileSync'],
  ];
  for (const [label, content, aliasName, sink] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'aliased-call', label);
    assert.equal(result.findings[0].evidence[0].alias.name, aliasName, label);
    assert.equal(result.findings[0].evidence[0].alias.boundTo, sink, label);
  }
});

test('detector: branch join keeps taint from either path', () => {
  const result = run('function h(d, c) { let x = "/etc/passwd"; if (c) { x = d; } fs.readFile(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${fs.readFile(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(p) { return fs.readFile(p); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'p' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); fs.readFile(y); }');
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'x' of function 'id'",
    'y',
  ]);
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'fs.readFile("/etc/passwd");',
    'const p = "/etc/passwd"; fs.readFile(p);',
    // A sanitized value interpolated into a path is clean.
    'function h(x) { fs.readFile("/var/" + Number(x)); }',
    // existsSync only checks existence; it cannot read or
    // write a file.
    'function h(d) { fs.existsSync(d); }',
    // mkdir is not a sink in this round.
    'function h(d) { fs.mkdir(d); }',
    // res.sendFile is not a sink in this round.
    'function h(d) { res.sendFile(d); }',
    // A bare readFile() call is not a sink (too generic).
    'function h(d) { readFile(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.fs.readFile(d); }',
    'function h(d) { fs.promises.readFile(d); }',
    'function h(d) { myfs.readFile(d); }',
    '// fs.readFile(userInput)\nconst a = 1;',
    'const s = "fs.readFile(userInput)";',
    'const s = `fs.readFile(userInput)`;',
    '/* fs.readFile(userInput) */ const a = 1;',
    'function h(d) { fs.readFile(); }',
    'let rf = fs.readFile; rf = 5; rf(x);',
    'const notFs = { readFile(x) { return x; } }; function h(d) { notFs.readFile(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// fs.readFile(userInput)\nfunction h(d) { return fs.readFile(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted second argument (options / callback data)
    // is NOT judged in this round — only the first
    // argument (the path) is.
    'function h(a) { fs.readFile("/etc/passwd", a); }',
    // require('fs').readFile is not resolved (no import
    // resolution in this round).
    'function h(d) { require("fs").readFile(d); }',
    // An object alias of the fs root is not resolved
    // either.
    'const myfs = fs; function h(d) { myfs.readFile(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

// ------------------------------------------------------------- envelope

test('detector: batch records follow the stub convention', () => {
  const result = detect({
    tool: 'my-tool',
    results: [
      { content: 'function h(d) { return fs.readFile(d); }', ...IDS },
      { content: 'fs.readFile("/etc/passwd");', ...IDS },
      { content: '', ...IDS },
    ],
  }, {});
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].discovery_tool, 'my-tool');
  assert.equal(result.skipped, 1);
  assert.equal(result.errors.length, 1);
});

test('detector: non-object input throws DETECTOR_INVALID_INPUT', () => {
  for (const bad of [null, 'x', 42, ['a']]) {
    assert.throws(() => detect(bad, {}), /DETECTOR_INVALID_INPUT/);
  }
});

test('detector: missing content, oversized content, non-JS language, and parse errors skip', () => {
  assert.equal(runRecord({ content: '' }).skipped, 1);
  assert.equal(runRecord({ content: 'x'.repeat(1_000_001) }).skipped, 1);
  assert.equal(runRecord({ content: 'fs.readFile(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return fs.readFile(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return fs.readFile(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return fs.readFile(d)'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  fs.readFile(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-path-traversal', () => {
  const resolved = getDetector('tainted-path-traversal', process.cwd());
  assert.equal(resolved.source, 'tainted-path-traversal');
  assert.equal(typeof resolved.detector, 'function');
});
