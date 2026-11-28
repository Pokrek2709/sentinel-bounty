// Tests for the twenty-sixth real detector (Phase 5, round 113):
// tainted-xxe — the eleventh parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted XML string, aliased calls,
// inter-procedural flow, import-resolved calls, and the
// libxmljs `noent: true` gate); negative cases prove the
// parser refuses what the regex detector would wrongly
// match (comments, strings) and what is genuinely safe
// (literals, sanitized values, libxmljs WITHOUT the
// `noent: true` literal — the library default does not
// substitute entities — JSON parsing, non-sink methods).
// Structural cases pin the envelope (batch, skipped, caps,
// determinism, no literal leakage) and the documented
// resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-xxe');
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
    'function h(d) { return libxmljs.parseXml(d, { noent: true }); }',
    'const p = libxmljs.parseXml; p(d, { noent: true });',
    'const { parseXml } = libxmljs; parseXml(d, { noent: true });',
    'const x = require("libxmljs"); x.parseXml(d, { noent: true });',
    'class H { handle(req) { return libxmljs.parseXml(req.body, { noent: true }); } }',
    'const f = async (req) => libxmljs.parseXml(req.query, { noent: true });',
    'for (const item of items) { libxmljs.parseXml(item, { noent: true }); }',
    'try { libxmljs.parseXml(x, { noent: true }); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: libxmljs.parseXml(a, { noent: true }); break; default: libxmljs.parseXml(b, { noent: true }); }',
    'const v = ok ? libxmljs.parseXml(a, { noent: true }) : null;',
    'const r = libxmljs?.parseXml(x, { noent: true }); const y = a?.b?.c;',
    'const m = `<root>${id}</root>`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted XML argument', () => {
  const result = run('function h(d) { return libxmljs.parseXml(d, { noent: true }); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'xml external entity injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-611');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'libxmljs.parseXml');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { libxmljs.parseXml(req.body, { noent: true }); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; libxmljs.parseXml(b, { noent: true }); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `<root>${n}</root>`; libxmljs.parseXml(m, { noent: true }); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { libxmljs.parseXml("<root>" + d + "</root>", { noent: true }); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; libxmljs.parseXml(d, { noent: true });', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return libxmljs.parseXml(req.body, { noent: true }); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { libxmljs.parseXml(item, { noent: true }); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { libxmljs?.parseXml(d, { noent: true }); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  const cases = [
    ['libxmljs.parseXml', 'function h(d) { return libxmljs.parseXml(d, { noent: true }); }'],
    ['libxmljs.parseXmlString', 'function h(d) { return libxmljs.parseXmlString(d, { noent: true }); }'],
    ['parseFromString', 'function h(d) { return parser.parseFromString(d, "text/xml"); }'],
    ['parseString', 'function h(d) { return parser.parseString(d); }'],
    ['parseStringPromise', 'function h(d) { return parser.parseStringPromise(d); }'],
    ['parser.write', 'function h(d) { return parser.write(d); }'],
    // A bare method-sink name matches by name alone.
    ['parseFromString', 'function h(d) { return parseFromString(d, "text/xml"); }'],
    ['parseString', 'function h(d) { return parseString(d); }'],
    // A DOMParser constructed inline still reaches the
    // method sink by name.
    ['parseFromString', 'function h(d) { return new DOMParser().parseFromString(d, "text/xml"); }'],
  ];
  for (const [sink, content] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: a string-keyed `noent` literal enables the libxmljs gate too', () => {
  const result = run('function h(d) { return libxmljs.parseXml(d, { "noent": true }); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].sink, 'libxmljs.parseXml');
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const p = libxmljs.parseXml; p(d, { noent: true });', 'p', 'libxmljs.parseXml'],
    ['computed alias', 'const p = libxmljs["parseXml"]; p(d, { noent: true });', 'p', 'libxmljs.parseXml'],
    ['destructured alias', 'const { parseXml } = libxmljs; parseXml(d, { noent: true });', 'parseXml', 'libxmljs.parseXml'],
    ['renamed destructured alias', 'const { parseXml: p } = libxmljs; p(d, { noent: true });', 'p', 'libxmljs.parseXml'],
    ['alias through identifier', 'const p = libxmljs.parseXml; const q = p; q(d, { noent: true });', 'q', 'libxmljs.parseXml'],
    ['method-sink alias', 'const pf = parser.parseFromString; pf(d, "text/xml");', 'pf', 'parseFromString'],
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
  const result = run('function h(d, c) { let x = "<a/>"; if (c) { x = d; } libxmljs.parseXml(x, { noent: true }); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${libxmljs.parseXml(d, { noent: true })}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return libxmljs.parseXml(u, { noent: true }); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); libxmljs.parseXml(y, { noent: true }); }');
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
    ['namespace alias', 'const x = require("libxmljs"); function h(d) { x.parseXml(d, { noent: true }); }', 'tainted-arg'],
    ['direct require member', 'function h(d) { require("libxmljs").parseXml(d, { noent: true }); }', 'tainted-arg'],
    ['destructured require', 'const { parseXml } = require("libxmljs"); function h(d) { parseXml(d, { noent: true }); }', 'aliased-call'],
    ['ESM default import', 'import libxmljs from "libxmljs"; function h(d) { libxmljs.parseXml(d, { noent: true }); }', 'tainted-arg'],
    ['ESM named import', 'import { parseXml } from "libxmljs"; function h(d) { parseXml(d, { noent: true }); }', 'aliased-call'],
    ['ESM namespace import', 'import * as libxmljs from "libxmljs"; function h(d) { libxmljs.parseXml(d, { noent: true }); }', 'tainted-arg'],
  ];
  for (const [label, content, kind] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].sink, 'libxmljs.parseXml', label);
    assert.equal(result.findings[0].evidence[0].kind, kind, label);
  }
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'libxmljs.parseXml("<a/>", { noent: true });',
    'const e = "<a/>"; libxmljs.parseXml(e, { noent: true });',
    // A sanitized value is clean.
    'function h(x) { libxmljs.parseXml(Number(x), { noent: true }); }',
    // The libxmljs gate: WITHOUT the `noent: true` literal
    // the library does not substitute entities, so the
    // call is not a finding — no options, `noent: false`,
    // an options object without `noent`, or options held
    // in a variable (not a literal) all stay clean.
    'function h(d) { libxmljs.parseXml(d); }',
    'function h(d) { libxmljs.parseXml(d, { noent: false }); }',
    'function h(d) { libxmljs.parseXml(d, { dtdload: true }); }',
    'function h(d, opts) { libxmljs.parseXml(d, opts); }',
    'function h(d) { const opts = { noent: true }; libxmljs.parseXml(d, opts); }',
    // A bare parseXml is too generic to be a sink (only
    // the libxmljs root is).
    'function h(d) { parseXml(d, { noent: true }); }',
    // A non-libxmljs root is not a sink.
    'function h(d) { mylib.parseXml(d, { noent: true }); }',
    // `.write` on anything not named `parser` is not a sink.
    'function h(d) { writer.write(d); }',
    'function h(d) { parser.read(d); }',
    // JSON has no entities.
    'function h(d) { JSON.parse(d); }',
    // Parsing an expression is not evaluating it.
    'function h(d) { xpath.parse(d); }',
    // CSS selectors are not XML.
    'function h(d) { document.querySelector(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.libxmljs.parseXml(d, { noent: true }); }',
    '// libxmljs.parseXml(userInput, { noent: true })\nconst a = 1;',
    'const s = "libxmljs.parseXml(userInput, { noent: true })";',
    'const s = `libxmljs.parseXml(userInput, { noent: true })`;',
    '/* libxmljs.parseXml(userInput, { noent: true }) */ const a = 1;',
    'function h(d) { libxmljs.parseXml(); }',
    'let p = libxmljs.parseXml; p = 5; p(d, { noent: true });',
    'const o = { parseXml: libxmljs.parseXml }; function h(d) { o.parseXml(d, { noent: true }); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: an aliased libxmljs call without the `noent` literal is not a finding', () => {
  const contents = [
    'const p = libxmljs.parseXml; p(d);',
    'const p = libxmljs.parseXml; p(d, { noent: false });',
    'const { parseXml } = libxmljs; parseXml(d);',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// libxmljs.parseXml(userInput, { noent: true })\nfunction h(d) { return libxmljs.parseXml(d, { noent: true }); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // An unknown module carries no import mapping.
    'function h(d) { const x = require("unknown-xml"); x.parseXml(d, { noent: true }); }',
    // A relative path carries no import mapping.
    'function h(d) { const x = require("./libxmljs"); x.parseXml(d, { noent: true }); }',
    // A dynamic require carries no import mapping.
    'function h(m, d) { require(m).parseXml(d, { noent: true }); }',
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
      { content: 'function h(d) { return libxmljs.parseXml(d, { noent: true }); }', ...IDS },
      { content: 'libxmljs.parseXml("<a/>", { noent: true });', ...IDS },
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
  assert.equal(runRecord({ content: 'libxmljs.parseXml(x, { noent: true });', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return libxmljs.parseXml(d, { noent: true }); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return libxmljs.parseXml(d, { noent: true }); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return libxmljs.parseXml'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  libxmljs.parseXml(d, { noent: true });');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-xxe', () => {
  const resolved = getDetector('tainted-xxe', process.cwd());
  assert.equal(resolved.source, 'tainted-xxe');
  assert.equal(typeof resolved.detector, 'function');
});
