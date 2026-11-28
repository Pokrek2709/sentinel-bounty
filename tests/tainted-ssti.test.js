// Tests for the tenth real detector (Phase 5, round 105):
// tainted-ssti — the fifth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted template strings, aliased calls,
// inter-procedural flow); negative cases prove the parser
// refuses what the regex detector would wrongly match
// (comments, strings) and what is genuinely safe
// (literals, constant templates with tainted data,
// sanitized values, non-sink receivers). Structural cases
// pin the envelope (batch, skipped, caps, determinism, no
// literal leakage) and the documented resolution limits of
// this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-ssti');
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
    'function h(d) { return ejs.render(d); }',
    'const r = ejs.render; r(x);',
    'const { render } = pug; render(d);',
    'class H { handle(req) { return nunjucks.renderString(req.body); } }',
    'const f = async (req) => handlebars.compile(req.query);',
    'for (const item of items) { ejs.render(item); }',
    'try { ejs.render(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: ejs.render(a); break; default: ejs.render(b); }',
    'const v = ok ? ejs.render(a) : null;',
    'const r = ejs?.render(x); const y = a?.b?.c;',
    'const m = `Hello ${name}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(d) { return ejs.render(d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'server-side template injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-1336');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'ejs.render');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { ejs.render(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; ejs.render(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `Hello ${n}`; ejs.render(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { ejs.render("Hello " + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; ejs.render(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return ejs.render(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { ejs.render(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { ejs?.render(d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['ejs.render', 'ejs.compile', 'pug.compile', 'pug.render', 'nunjucks.renderString', 'handlebars.compile']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const r = ejs.render; r("tpl");', 'r', 'ejs.render'],
    ['computed alias', 'const r = ejs["render"]; r(x);', 'r', 'ejs.render'],
    ['destructured alias', 'const { render } = pug; render(userInput);', 'render', 'pug.render'],
    ['renamed destructured alias', 'const { render: r } = ejs; r(x);', 'r', 'ejs.render'],
    ['alias through identifier', 'const r = ejs.render; const s = r; s(x);', 's', 'ejs.render'],
    ['destructured compile', 'const { compile } = handlebars; compile("tpl");', 'compile', 'handlebars.compile'],
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
  const result = run('function h(d, c) { let x = "Hello"; if (c) { x = d; } ejs.render(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${ejs.render(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(t) { return ejs.render(t); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 't' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); ejs.render(y); }');
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
    'ejs.render("Hello");',
    'const t = "Hello"; ejs.render(t);',
    // A constant template with a tainted DATA object is
    // not flagged: only the first argument (the template
    // string) is judged, and it is constant here.
    'function h(d) { ejs.render("Hello <%= name %>", { name: d }); }',
    // A sanitized value interpolated into a template is clean.
    'function h(x) { ejs.render("Hello " + Number(x)); }',
    // renderFile takes a file path, not a template string.
    'function h(d) { ejs.renderFile(d); }',
    'function h(d) { pug.renderFile(d); }',
    // nunjucks.render takes a template NAME, not a string.
    'function h(d) { nunjucks.render(d); }',
    // res.render takes an Express view name, not a template.
    'function h(d) { res.render(d); }',
    // A bare render() call is not a sink (too generic).
    'function h(d) { render(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.ejs.render(d); }',
    'function h(d) { myengine.render(d); }',
    '// ejs.render(userInput)\nconst a = 1;',
    'const s = "ejs.render(userInput)";',
    'const s = `ejs.render(userInput)`;',
    '/* ejs.render(userInput) */ const a = 1;',
    'function h(d) { ejs.render(); }',
    'let r = ejs.render; r = 5; r(x);',
    'const notEjs = { render(x) { return x; } }; function h(d) { notEjs.render(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// ejs.render(userInput)\nfunction h(d) { return ejs.render(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted second argument (the data object) is NOT
    // judged in this round — only the first argument (the
    // template string) is.
    'function h(a) { ejs.render("Hello", a); }',
    // require('ejs').render is not resolved (no import
    // resolution in this round).
    'function h(d) { require("ejs").render(d); }',
    // An object alias of the ejs root is not resolved
    // either.
    'const myejs = ejs; function h(d) { myejs.render(d); }',
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
      { content: 'function h(d) { return ejs.render(d); }', ...IDS },
      { content: 'ejs.render("Hello");', ...IDS },
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
  assert.equal(runRecord({ content: 'ejs.render(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return ejs.render(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return ejs.render(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return ejs.render(d)'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  ejs.render(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-ssti', () => {
  const resolved = getDetector('tainted-ssti', process.cwd());
  assert.equal(resolved.source, 'tainted-ssti');
  assert.equal(typeof resolved.detector, 'function');
});
