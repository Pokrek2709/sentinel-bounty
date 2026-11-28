// Tests for the twenty-seventh real detector (Phase 5, round 113):
// tainted-redos — the twelfth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted regex pattern, `new RegExp`,
// aliased calls, inter-procedural flow); negative cases
// prove the parser refuses what the regex detector would
// wrongly match (comments, strings) and what is genuinely
// safe (a clean pattern — however catastrophic it looks —
// a sanitized value, a tainted argument outside the judged
// index, `test` / `exec` / `matchAll`, arbitrary
// constructors). Structural cases pin the envelope (batch,
// skipped, caps, determinism, no literal leakage) and the
// documented resolution limits of this round.
//
// The honest limit, pinned here and in the detector doc:
// there is NO regex-complexity analysis — the engine never
// inspects pattern text, so a tainted pattern is flagged
// because the attacker controls it, not because the pattern
// is proven catastrophic.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-redos');
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
    'function h(d) { return RegExp(d); }',
    'function h(d) { return new RegExp(d); }',
    'const R = RegExp; R(d);',
    'const R = RegExp; new R(d);',
    'function h(d) { return s.match(d); }',
    'function h(d) { return s.search(d); }',
    'function h(d) { return s.replace(d, "x"); }',
    'function h(d) { return s.split(d); }',
    'class H { handle(req) { return RegExp(req.body); } }',
    'const f = async (req) => RegExp(req.query);',
    'for (const item of items) { RegExp(item); }',
    'try { RegExp(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: RegExp(a); break; default: RegExp(b); }',
    'const v = ok ? RegExp(a) : null;',
    'const r = RegExp?.(d); const y = a?.b?.c;',
    'const m = `(${id})+`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted pattern argument', () => {
  const result = run('function h(d) { return RegExp(d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'regular expression denial of service');
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.cwe_id, 'CWE-1333');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'RegExp');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { RegExp(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; RegExp(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `(${n})+`; RegExp(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { RegExp("(" + d + ")+"); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; RegExp(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return RegExp(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { RegExp(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { RegExp?.(d); }', ["parameter 'd' of function 'h'"]],
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
    ['RegExp', 'function h(d) { return RegExp(d); }'],
    ['RegExp', 'function h(d) { return new RegExp(d); }'],
    ['match', 'function h(d) { return s.match(d); }'],
    ['search', 'function h(d) { return s.search(d); }'],
    ['replace', 'function h(d) { return s.replace(d, "x"); }'],
    ['split', 'function h(d) { return s.split(d); }'],
    // A bare method-sink name matches by name alone.
    ['match', 'function h(d) { return match(d); }'],
    ['search', 'function h(d) { return search(d); }'],
  ];
  for (const [sink, content] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${sink} for: ${content}`);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const R = RegExp; R("(a+)+");', 'R', 'RegExp'],
    ['alias through identifier', 'const R = RegExp; const S = R; S(x);', 'S', 'RegExp'],
    ['alias constructed with new', 'const R = RegExp; new R(x);', 'R', 'RegExp'],
    ['method-sink alias', 'const m = s.match; m(x);', 'm', 'match'],
  ];
  for (const [label, content, aliasName, sink] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'aliased-call', label);
    assert.equal(result.findings[0].evidence[0].alias.name, aliasName, label);
    assert.equal(result.findings[0].evidence[0].alias.boundTo, sink, label);
  }
});

test('detector: a destructured `RegExp` still flags as the bare sink', () => {
  // The direct-sink check runs first: `RegExp` IS the sink
  // name, so a destructured binding from any module still
  // flags with kind 'tainted-arg' (the round-105 `request`
  // quirk, same rule) — import mapping is irrelevant to a
  // bare sink.
  const result = run('function h(d) { const { RegExp } = require("regexp"); RegExp(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.equal(result.findings[0].evidence[0].sink, 'RegExp');
});

test('detector: branch join keeps taint from either path', () => {
  const result = run('function h(d, c) { let x = "a"; if (c) { x = d; } RegExp(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${RegExp(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return RegExp(u); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); RegExp(y); }');
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
    // A CLEAN pattern is never flagged, however
    // catastrophic it looks: the pattern is
    // developer-controlled, so there is no attacker vector.
    'RegExp("(a+)+");',
    'const p = "(a+)+"; RegExp(p);',
    'new RegExp("(a|a)*");',
    'const p = "(a*)*"; s.match(p);',
    // A sanitized value is clean.
    'function h(x) { RegExp(Number(x)); }',
    // A TAINTED SECOND argument is not judged — only the
    // first argument (the pattern) is. `RegExp` flags and
    // `replace`'s replacement are both second arguments.
    'function h(d) { RegExp("x", d); }',
    'function h(d) { s.replace("a", d); }',
    // The danger of `test` / `exec` lives in the receiver
    // pattern, which the engine cannot analyze for
    // catastrophic backtracking — not sinks.
    'function h(re, d) { re.test(d); }',
    'function h(re, d) { re.exec(d); }',
    // `matchAll` is outside the brief's named scope (a
    // string argument to it throws).
    'function h(d) { s.matchAll(d); }',
    // A three-part name is not resolved.
    'function h(d) { window.RegExp(d); }',
    // `RegExp` as a value, not a call, is not a finding.
    'function h(d) { const r = RegExp; return r; }',
    // Arbitrary constructors are not sinks — the
    // round-113 `new`-expression extension flags only
    // declared constructor-like sinks.
    'function h(d) { new Foo(d); }',
    'function h(d) { new Date(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.RegExp(d); }',
    '// RegExp(userInput)\nconst a = 1;',
    'const s = "RegExp(userInput)";',
    'const s = `RegExp(userInput)`;',
    '/* RegExp(userInput) */ const a = 1;',
    'function h(d) { RegExp(); }',
    'function h(d) { new RegExp(); }',
    'let R = RegExp; R = 5; R(d);',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// RegExp(userInput)\nfunction h(d) { return RegExp(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // `RegExp` has no import mapping: it is a built-in,
    // not a module member.
    'function h(d) { const x = require("regexp"); x.RegExp(d); }',
    // A dynamic require carries no import mapping.
    'function h(m, d) { require(m).RegExp(d); }',
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
      { content: 'function h(d) { return RegExp(d); }', ...IDS },
      { content: 'RegExp("(a+)+");', ...IDS },
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
  assert.equal(runRecord({ content: 'RegExp(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return RegExp(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return RegExp(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return RegExp'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  RegExp(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-redos', () => {
  const resolved = getDetector('tainted-redos', process.cwd());
  assert.equal(resolved.source, 'tainted-redos');
  assert.equal(typeof resolved.detector, 'function');
});
