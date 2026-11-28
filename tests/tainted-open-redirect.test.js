// Tests for the fifteenth real detector (Phase 5, round 107):
// tainted-open-redirect — the tenth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted redirect URL, aliased calls,
// inter-procedural flow); negative cases prove the parser
// refuses what the regex detector would wrongly match
// (comments, strings) and what is genuinely safe
// (literals, sanitized values, a tainted URL in second
// position of the two-argument form — only the first
// argument is judged — non-sink methods). Structural cases
// pin the envelope (batch, skipped, caps, determinism, no
// literal leakage) and the documented resolution limits of
// this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-open-redirect');
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
    'function h(d) { return res.redirect(d); }',
    'const r = res.redirect; r(x);',
    'const { redirect } = res; redirect(d);',
    'class H { handle(req) { return res.redirect(req.body); } }',
    'const f = async (req) => res.redirect(req.query);',
    'for (const item of items) { res.redirect(item); }',
    'try { res.redirect(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: res.redirect(a); break; default: res.redirect(b); }',
    'const v = ok ? res.redirect(a) : null;',
    'const r = res?.redirect(x); const y = a?.b?.c;',
    'const m = `https://example.com/${id}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted URL argument', () => {
  const result = run('function h(d) { return res.redirect(d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'open redirect');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-601');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'res.redirect');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { res.redirect(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; res.redirect(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `https://example.com/${n}`; res.redirect(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { res.redirect("https://example.com/" + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; res.redirect(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return res.redirect(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { res.redirect(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { res?.redirect(d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['res.redirect', 'response.redirect', 'reply.redirect', 'ctx.redirect']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const r = res.redirect; r("/home");', 'r', 'res.redirect'],
    ['computed alias', 'const r = res["redirect"]; r(x);', 'r', 'res.redirect'],
    ['destructured alias', 'const { redirect } = res; redirect(userInput);', 'redirect', 'res.redirect'],
    ['renamed destructured alias', 'const { redirect: r } = res; r(x);', 'r', 'res.redirect'],
    ['alias through identifier', 'const r = res.redirect; const s = r; s(x);', 's', 'res.redirect'],
    ['reply alias', 'const r = reply.redirect; r("/home");', 'r', 'reply.redirect'],
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
  const result = run('function h(d, c) { let x = "/home"; if (c) { x = d; } res.redirect(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${res.redirect(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return res.redirect(u); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); res.redirect(y); }');
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
    'res.redirect("/home");',
    'const u = "/home"; res.redirect(u);',
    // A sanitized value is clean.
    'function h(x) { res.redirect(Number(x)); }',
    // The TWO-ARGUMENT form judges only its first
    // argument (the status): a tainted URL in second
    // position is not judged in this round.
    'function h(d) { res.redirect(302, d); }',
    // A bare redirect is too generic to be a sink.
    'function h(d) { redirect(d); }',
    // A view name is not a redirect URL.
    'function h(d) { res.render(d); }',
    // A location assignment is not a redirect call in
    // this round (an assignment shape, not a call).
    'function h(d) { window.location = d; }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.res.redirect(d); }',
    'function h(d) { myres.redirect(d); }',
    '// res.redirect(userInput)\nconst a = 1;',
    'const s = "res.redirect(userInput)";',
    'const s = `res.redirect(userInput)`;',
    '/* res.redirect(userInput) */ const a = 1;',
    'function h(d) { res.redirect(); }',
    'let r = res.redirect; r = 5; r(x);',
    'const notRes = { redirect(x) { return x; } }; function h(d) { notRes.redirect(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// res.redirect(userInput)\nfunction h(d) { return res.redirect(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted URL in second position of the
    // two-argument form is NOT judged — only the first
    // argument (the status) is.
    'function h(d) { res.redirect(302, d); }',
    'function h(d) { reply.redirect(301, d); }',
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
      { content: 'function h(d) { return res.redirect(d); }', ...IDS },
      { content: 'res.redirect("/home");', ...IDS },
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
  assert.equal(runRecord({ content: 'res.redirect(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return res.redirect(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return res.redirect(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return res.redirect'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  res.redirect(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-open-redirect', () => {
  const resolved = getDetector('tainted-open-redirect', process.cwd());
  assert.equal(resolved.source, 'tainted-open-redirect');
  assert.equal(typeof resolved.detector, 'function');
});
