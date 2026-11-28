// Tests for the fourteenth real detector (Phase 5, round 107):
// tainted-xpath — the ninth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted XPath expression, aliased
// calls, inter-procedural flow, import-resolved calls);
// negative cases prove the parser refuses what the regex
// detector would wrongly match (comments, strings) and
// what is genuinely safe (literals, sanitized values, a
// tainted context node — only the first argument is judged
// — non-sink methods). Structural cases pin the envelope
// (batch, skipped, caps, determinism, no literal leakage)
// and the documented resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-xpath');
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
    'function h(d) { return xpath.select(d, doc); }',
    'const s = xpath.select; s(x, doc);',
    'const { select } = xpath; select(d, doc);',
    'const x = require("xpath"); x.select(d, doc);',
    'class H { handle(req) { return xpath.select(req.body, doc); } }',
    'const f = async (req) => xpath.select(req.query, doc);',
    'for (const item of items) { xpath.select(item, doc); }',
    'try { xpath.select(x, doc); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: xpath.select(a, doc); break; default: xpath.select(b, doc); }',
    'const v = ok ? xpath.select(a, doc) : null;',
    'const r = xpath?.select(x, doc); const y = a?.b?.c;',
    'const m = `//user[name="${id}"]`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted expression argument', () => {
  const result = run('function h(d) { return xpath.select(d, doc); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'xpath injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-643');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'xpath.select');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { xpath.select(req.body, doc); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; xpath.select(b, doc); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `//user[name="${n}"]`; xpath.select(m, doc); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { xpath.select("//user[name=\'" + d + "\']", doc); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; xpath.select(d, doc);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return xpath.select(req.body, doc); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { xpath.select(item, doc); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { xpath?.select(d, doc); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['xpath.select', 'xpath.select1', 'xpath.evaluate', 'document.evaluate']) {
    const result = run(`function h(d) { return ${sink}(d, doc); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const s = xpath.select; s("//x", doc);', 's', 'xpath.select'],
    ['computed alias', 'const s = xpath["select"]; s(x, doc);', 's', 'xpath.select'],
    ['destructured alias', 'const { select } = xpath; select(userInput, doc);', 'select', 'xpath.select'],
    ['renamed destructured alias', 'const { select: s } = xpath; s(x, doc);', 's', 'xpath.select'],
    ['alias through identifier', 'const s = xpath.select; const t = s; t(x, doc);', 't', 'xpath.select'],
    ['document.evaluate alias', 'const e = document.evaluate; e("//x", doc);', 'e', 'document.evaluate'],
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
  const result = run('function h(d, c) { let x = "//x"; if (c) { x = d; } xpath.select(x, doc); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${xpath.select(d, doc)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return xpath.select(u, doc); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); xpath.select(y, doc); }');
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'x' of function 'id'",
    'y',
  ]);
});

test('detector: import-resolved sink calls are reported', () => {
  const cases = [
    ['namespace alias', 'const x = require("xpath"); function h(d) { x.select(d, doc); }', 'tainted-arg'],
    ['direct require member', 'function h(d) { require("xpath").select(d, doc); }', 'tainted-arg'],
    ['destructured require', 'const { select } = require("xpath"); function h(d) { select(d, doc); }', 'aliased-call'],
    ['ESM default import', 'import xpath from "xpath"; function h(d) { xpath.select(d, doc); }', 'tainted-arg'],
    ['ESM named import', 'import { select } from "xpath"; function h(d) { select(d, doc); }', 'aliased-call'],
    ['ESM namespace import', 'import * as xpath from "xpath"; function h(d) { xpath.select(d, doc); }', 'tainted-arg'],
  ];
  for (const [label, content, kind] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].sink, 'xpath.select', label);
    assert.equal(result.findings[0].evidence[0].kind, kind, label);
  }
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'xpath.select("//x", doc);',
    'const e = "//x"; xpath.select(e, doc);',
    // A sanitized value is clean.
    'function h(x) { xpath.select(Number(x), doc); }',
    // A TAINTED SECOND argument (the context node) is not
    // judged in this round — only the first argument (the
    // expression) is.
    'function h(d) { xpath.select("//x", d); }',
    // A bare select is too generic to be a sink.
    'function h(d) { select(d, doc); }',
    // A bare evaluate is too generic to be a sink.
    'function h(d) { evaluate(d, doc); }',
    // CSS selectors are not XPath.
    'function h(d) { document.querySelector(d); }',
    // Parsing an expression is not evaluating it.
    'function h(d) { xpath.parse(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.xpath.select(d, doc); }',
    'function h(d) { myxpath.select(d, doc); }',
    '// xpath.select(userInput, doc)\nconst a = 1;',
    'const s = "xpath.select(userInput, doc)";',
    'const s = `xpath.select(userInput, doc)`;',
    '/* xpath.select(userInput, doc) */ const a = 1;',
    'function h(d) { xpath.select(); }',
    'let s = xpath.select; s = 5; s(x, doc);',
    'const notXpath = { select(x, y) { return x; } }; function h(d) { notXpath.select(d, doc); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// xpath.select(userInput, doc)\nfunction h(d) { return xpath.select(d, doc); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted context node (second argument) is NOT
    // judged — only the expression (first argument) is.
    'function h(d) { xpath.select("//x", d); }',
    // An unknown module carries no import mapping.
    'function h(d) { const x = require("unknown-xpath"); x.select(d, doc); }',
    // A relative path carries no import mapping.
    'function h(d) { const x = require("./xpath"); x.select(d, doc); }',
    // A dynamic require carries no import mapping.
    'function h(m, d) { require(m).select(d, doc); }',
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
      { content: 'function h(d) { return xpath.select(d, doc); }', ...IDS },
      { content: 'xpath.select("//x", doc);', ...IDS },
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
  assert.equal(runRecord({ content: 'xpath.select(x, doc);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return xpath.select(d, doc); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return xpath.select(d, doc); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return xpath.select'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  xpath.select(d, doc);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-xpath', () => {
  const resolved = getDetector('tainted-xpath', process.cwd());
  assert.equal(resolved.source, 'tainted-xpath');
  assert.equal(typeof resolved.detector, 'function');
});
