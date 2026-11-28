// Tests for the twelfth real detector (Phase 5, round 105):
// tainted-ssrf — the seventh parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted URLs, aliased calls,
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
const detect = require('../src/detection/tainted-ssrf');
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
    'function h(d) { return fetch(d); }',
    'const g = http.get; g(x);',
    'const { request } = http; request(d);',
    'class H { handle(req) { return axios.get(req.body); } }',
    'const f = async (req) => fetch(req.query);',
    'for (const item of items) { fetch(item); }',
    'try { fetch(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: fetch(a); break; default: fetch(b); }',
    'const v = ok ? fetch(a) : null;',
    'const r = fetch?.(x); const y = a?.b?.c;',
    'const m = `https://example.com/${id}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(d) { return fetch(d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'server-side request forgery');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-918');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'fetch');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { fetch(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; fetch(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `https://example.com/${n}`; fetch(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { fetch("https://example.com/" + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; fetch(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return fetch(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { fetch(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { fetch?.(d); }', ["parameter 'd' of function 'h'"]],
    // An options object whose property is tainted is tainted
    // as a whole (the object join), so the URL argument is
    // judged tainted.
    ['options object', 'function h(d) { http.get({ hostname: d }); }',
      ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['fetch', 'request', 'http.get', 'http.request', 'https.get', 'https.request', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.request']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const g = http.get; g("https://example.com");', 'g', 'http.get'],
    ['computed alias', 'const g = http["get"]; g(x);', 'g', 'http.get'],
    ['destructured alias', 'const { put } = axios; put(userInput);', 'put', 'axios.put'],
    ['renamed destructured alias', 'const { get: g } = https; g(x);', 'g', 'https.get'],
    ['alias through identifier', 'const g = http.get; const s = g; s(x);', 's', 'http.get'],
    ['bare fetch alias', 'const f = fetch; f("https://example.com");', 'f', 'fetch'],
    ['destructured axios', 'const { post } = axios; post("https://example.com");', 'post', 'axios.post'],
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
  const result = run('function h(d, c) { let x = "https://example.com"; if (c) { x = d; } fetch(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${fetch(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return fetch(u); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); fetch(y); }');
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
    'fetch("https://example.com");',
    'const u = "https://example.com"; fetch(u);',
    // A sanitized value interpolated into a URL is clean.
    'function h(x) { fetch("https://example.com/" + Number(x)); }',
    // A tainted SECOND argument (options / body / config)
    // is not judged — only the first argument (the URL) is.
    'function h(d) { fetch("https://example.com", { body: d }); }',
    'function h(d) { axios.get("https://example.com", { data: d }); }',
    // window.fetch is not a sink in this round (the window
    // receiver is not in the sink list).
    'function h(d) { window.fetch(d); }',
    // XMLHttpRequest is client-side XHR, not a server-side
    // request.
    'function h(d) { const xhr = new XMLHttpRequest(); xhr.open("GET", d); }',
    // WebSocket is a different protocol, not a sink.
    'function h(d) { new WebSocket(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.http.get(d); }',
    'function h(d) { myaxios.get(d); }',
    '// fetch(userInput)\nconst a = 1;',
    'const s = "fetch(userInput)";',
    'const s = `fetch(userInput)`;',
    '/* fetch(userInput) */ const a = 1;',
    'function h(d) { fetch(); }',
    'let f = fetch; f = 5; f(x);',
    'const notHttp = { get(x) { return x; } }; function h(d) { notHttp.get(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// fetch(userInput)\nfunction h(d) { return fetch(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted second argument is NOT judged in this round
    // — only the first argument (the URL) is.
    'function h(a) { http.get("https://example.com", a); }',
    // Round 106 moved the import cases out of this list:
    // require('http').get and an object alias of the http
    // root now resolve (see
    // tests/import-resolution.test.js).
    // A destructured alias whose name collides with a
    // BARE sink name (`request`) is judged as the bare
    // sink, not as the alias: the direct-sink check runs
    // first, so a clean argument is not flagged even
    // though the alias binding exists.
    'const { request } = http; request("https://example.com");',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

// A bare identifier literally named `get` is a keyword to
// the subset parser (round-101 limitation), so a record
// calling `get(...)` directly does not parse at all — it
// is skipped, not silently scanned. Destructuring a member
// named `get` is therefore unusable in scanned code; the
// other members (`request`, `post`) resolve.

test('detector: a record calling a bare `get` is skipped, not scanned (parser keyword)', () => {
  const parsed = runRecord({ content: 'const { get } = http; get(userInput);' });
  assert.equal(parsed.findings.length, 0);
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /unexpected keyword get/);
});

// ------------------------------------------------------------- envelope

test('detector: batch records follow the stub convention', () => {
  const result = detect({
    tool: 'my-tool',
    results: [
      { content: 'function h(d) { return fetch(d); }', ...IDS },
      { content: 'fetch("https://example.com");', ...IDS },
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
  assert.equal(runRecord({ content: 'fetch(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return fetch(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return fetch(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return fetch(d)'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  fetch(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-ssrf', () => {
  const resolved = getDetector('tainted-ssrf', process.cwd());
  assert.equal(resolved.source, 'tainted-ssrf');
  assert.equal(typeof resolved.detector, 'function');
});
