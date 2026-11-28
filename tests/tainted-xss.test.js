// Tests for the ninth real detector (Phase 5, round 104):
// tainted-xss — the fourth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted HTML sinks, aliased calls,
// inter-procedural flow, and — new in this round —
// assignment sinks); negative cases prove the parser
// refuses what the regex detector would wrongly match
// (comments, strings) and what is genuinely safe
// (literals, sanitized values, textContent/innerText,
// jQuery .html(), non-sink receivers). Structural cases pin
// the envelope (batch, skipped, caps, determinism, no
// literal leakage) and the documented resolution limits of
// this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-xss');
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
    'function h(x) { el.innerHTML = x; }',
    'function h(x) { el.outerHTML = x; }',
    'function h(x) { el["innerHTML"] = x; }',
    'function h(x) { document.body.innerHTML = x; }',
    'function h(x) { el.innerHTML += x; }',
    'function h(x) { document.write(x); }',
    'function h(x) { document.writeln(x); }',
    'function h(x) { el.insertAdjacentHTML("beforeend", x); }',
    'const w = document.write; w(x);',
    'const { write } = document; write(x);',
    'const f = el.insertAdjacentHTML; f("beforeend", x);',
    'class H { handle(req) { el.innerHTML = req.body; } }',
    'const f = async (req) => { el.innerHTML = req.body; };',
    'for (const item of items) { el.innerHTML = item; }',
    'try { el.innerHTML = x; } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: el.innerHTML = a; break; default: el.innerHTML = b; }',
    'const v = ok ? document.write(a) : null;',
    'const r = document?.write(x);',
    'const m = `hi ${req.body}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(x) { document.write(x); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'cross-site scripting');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-79');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'document.write');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'x' of function 'h'"]);
  assert.match(finding.description, /parameter 'x' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { document.write(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; document.write(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `hi ${n}`; document.write(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { document.write("hi " + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; document.write(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return document.write(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { document.write(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { document?.write(d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every call sink spelling with a tainted argument', () => {
  for (const sink of ['document.write', 'document.writeln']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
  // insertAdjacentHTML judges its SECOND argument (the HTML);
  // the first is the position constant.
  const result = run('function h(d) { el.insertAdjacentHTML("beforeend", d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].sink, 'insertAdjacentHTML');
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.match(result.findings[0].description, /argument 2/);
});

test('detector: assignment sinks with a tainted assigned value', () => {
  const cases = [
    ['innerHTML', 'function h(x) { el.innerHTML = x; }', 'innerHTML', 'el.innerHTML'],
    ['outerHTML', 'function h(x) { el.outerHTML = x; }', 'outerHTML', 'el.outerHTML'],
    ['computed property', 'function h(x) { el["innerHTML"] = x; }', 'innerHTML', "el['innerHTML']"],
    ['deep receiver', 'function h(x) { document.body.innerHTML = x; }', 'innerHTML', 'document.body.innerHTML'],
    ['compound assignment', 'function h(x) { el.innerHTML += x; }', 'innerHTML', 'el.innerHTML'],
    ['template value', 'function h(req) { const m = `hi ${req.body}`; el.innerHTML = m; }', 'innerHTML', 'el.innerHTML'],
  ];
  for (const [label, content, sink, target] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-assign', label);
    assert.equal(result.findings[0].evidence[0].sink, sink, label);
    assert.equal(result.findings[0].evidence[0].type, 'ast-assign', label);
    assert.equal(result.findings[0].evidence[0].target, target, label);
    assert.equal(result.findings[0].evidence[0].property, sink, label);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const w = document.write; w("hi");', 'w', 'document.write'],
    ['computed alias', 'const w = document["write"]; w(x);', 'w', 'document.write'],
    ['destructured alias', 'const { write } = document; write(userInput);', 'write', 'document.write'],
    ['renamed destructured alias', 'const { writeln: w } = document; w(x);', 'w', 'document.writeln'],
    ['alias through identifier', 'const w = document.write; const r = w; r(x);', 'r', 'document.write'],
    ['alias of method sink', 'const f = el.insertAdjacentHTML; f("beforeend", x);', 'f', 'insertAdjacentHTML'],
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
  const result = run('function h(d, c) { let x = "safe"; if (c) { x = d; } el.innerHTML = x; }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-assign');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${document.write(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: assignment sink carries the right position', () => {
  const result = run('function h(d) {\n  el.innerHTML = d;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 3);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { render(req.body); } function render(v) { el.innerHTML = v; }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-assign');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'v' of function 'render'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); document.write(y); }');
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'x' of function 'id'",
    'y',
  ]);
});

// ------------------------------------------------------- negative cases

test('detector: clean values, safe sinks, and prose are not findings', () => {
  const contents = [
    'el.innerHTML = "static";',
    'const x = "static"; el.innerHTML = x;',
    'document.write("hi");',
    'el.insertAdjacentHTML("beforeend", "static");',
    // A sanitized value assigned to a sink is clean.
    'function h(x) { el.innerHTML = Number(x); }',
    'function h(x) { document.write(Number(x)); }',
    // textContent / innerText are safe by construction.
    'function h(d) { el.textContent = d; }',
    'function h(d) { el.innerText = d; }',
    // jQuery .html() is not a sink in this round (a
    // no-argument .html() is a getter; no jQuery modeling).
    'function h(d) { $(el).html(d); }',
    'function h(d) { el.html(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { other.write(d); }',
    'function h(d) { el.insertAdjacentHTML(d); }',
    '// el.innerHTML = userInput\nconst a = 1;',
    'const s = "el.innerHTML = userInput";',
    'const s = `document.write(userInput)`;',
    '/* document.write(userInput) */ const a = 1;',
    'function h(d) { document.write(); }',
    'let w = document.write; w = 5; w(x);',
    'const notDoc = { write(x) { return x; } }; function h(d) { notDoc.write(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// el.innerHTML = userInput\nfunction h(d) { el.innerHTML = d; }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted SECOND argument of document.write is NOT
    // judged in this round — only the first argument (the
    // written markup) is.
    'function h(a) { document.write("static", a); }',
    // A tainted FIRST argument of insertAdjacentHTML (the
    // position constant) is NOT judged — only the second
    // argument (the HTML) is.
    'function h(a) { el.insertAdjacentHTML(a, "static"); }',
    // window.document.write is not resolved (three-part
    // call, like the SQL round's app.db.query pin).
    'function h(d) { window.document.write(d); }',
    // A destructured method sink is not resolved: the
    // destructuring rule keys on the receiver name, and
    // insertAdjacentHTML has no fixed receiver.
    'const { insertAdjacentHTML } = el; insertAdjacentHTML("beforeend", x);',
    // Object.assign into innerHTML is not a sink in this
    // round (no assignment-expression shape).
    'function h(x) { Object.assign(el, {innerHTML: x}); }',
    // require('fs').write is not a sink (no import
    // resolution in this round).
    'function h(d) { require("fs").write(d); }',
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
      { content: 'function h(d) { document.write(d); }', ...IDS },
      { content: 'document.write("hi");', ...IDS },
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
  assert.equal(runRecord({ content: 'document.write(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { document.write(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; el.innerHTML = d; }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('el.innerHTML = d'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  el.innerHTML = d;');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-xss', () => {
  const resolved = getDetector('tainted-xss', process.cwd());
  assert.equal(resolved.source, 'tainted-xss');
  assert.equal(typeof resolved.detector, 'function');
});
