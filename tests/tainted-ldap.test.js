// Tests for the thirteenth real detector (Phase 5, round 107):
// tainted-ldap — the eighth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted filter in the second argument,
// aliased calls, inter-procedural flow, import-resolved
// calls); negative cases prove the parser refuses what the
// regex detector would wrongly match (comments, strings)
// and what is genuinely safe (literals, sanitized values,
// a tainted base — the first argument is not judged in
// this round — non-sink methods). Structural cases pin the
// envelope (batch, skipped, caps, determinism, no literal
// leakage) and the documented resolution limits of this
// round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-ldap');
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
    'function h(d) { client.search("dc=example,dc=com", d); }',
    'const s = client.search; s("dc=example,dc=com", x);',
    'const { search } = client; search("dc=example,dc=com", d);',
    'const c = require("ldapjs"); c.search("dc=example,dc=com", d);',
    'class H { handle(req) { return client.search("dc=example,dc=com", req.body); } }',
    'const f = async (req) => client.search("dc=example,dc=com", req.query);',
    'for (const item of items) { client.search("dc=example,dc=com", item); }',
    'try { client.search("dc=example,dc=com", x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: client.search("dc=example,dc=com", a); break; default: client.search("dc=example,dc=com", b); }',
    'const v = ok ? client.search("dc=example,dc=com", a) : null;',
    'const r = client?.search("dc=example,dc=com", x); const y = a?.b?.c;',
    'const m = `(cn=${id})`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted filter argument', () => {
  const result = run('function h(d) { client.search("dc=example,dc=com", d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'ldap injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-90');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'client.search');
  // The judged argument is the SECOND one (the filter):
  // the description names it ("argument 2") — the
  // evidence carries only the chain, not the index.
  assert.match(finding.description, /argument 2/);
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary, options object', () => {
  const cases = [
    ['req.body', 'function h(req) { client.search("dc=example,dc=com", req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; client.search("dc=example,dc=com", b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template filter', 'function h(n) { const m = `(cn=${n})`; client.search("dc=example,dc=com", m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary filter', 'function h(d) { client.search("dc=example,dc=com", "(cn=" + d + ")"); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; client.search("dc=example,dc=com", d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return client.search("dc=example,dc=com", req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { client.search("dc=example,dc=com", item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { client?.search("dc=example,dc=com", d); }', ["parameter 'd' of function 'h'"]],
    // An options object whose filter property is tainted
    // is tainted as a whole (the object join), so the
    // filter argument is judged tainted.
    ['options object', 'function h(d) { client.search("dc=example,dc=com", { filter: d }); }',
      ["parameter 'd' of function 'h'"]],
    ['options template', 'function h(d) { client.search("dc=example,dc=com", { filter: `(cn=${d})` }); }',
      ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const s = client.search; s("dc=example,dc=com", "(objectClass=*)");', 's', 'client.search'],
    ['computed alias', 'const s = client["search"]; s("dc=example,dc=com", x);', 's', 'client.search'],
    ['destructured alias', 'const { search } = client; search("dc=example,dc=com", userInput);', 'search', 'client.search'],
    ['renamed destructured alias', 'const { search: s } = client; s("dc=example,dc=com", x);', 's', 'client.search'],
    ['alias through identifier', 'const s = client.search; const t = s; t("dc=example,dc=com", x);', 't', 'client.search'],
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
  const result = run('function h(d, c) { let x = "(objectClass=*)"; if (c) { x = d; } client.search("dc=example,dc=com", x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${client.search("dc=example,dc=com", d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return client.search("dc=example,dc=com", u); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); client.search("dc=example,dc=com", y); }');
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
    ['namespace alias', 'const c = require("ldapjs"); function h(d) { c.search("dc=example,dc=com", d); }', 'tainted-arg'],
    ['direct require member', 'function h(d) { require("ldapjs").search("dc=example,dc=com", d); }', 'tainted-arg'],
    ['destructured require', 'const { search } = require("ldapjs"); function h(d) { search("dc=example,dc=com", d); }', 'aliased-call'],
    ['ESM default import', 'import client from "ldapjs"; function h(d) { client.search("dc=example,dc=com", d); }', 'tainted-arg'],
    ['ESM named import', 'import { search } from "ldapjs"; function h(d) { search("dc=example,dc=com", d); }', 'aliased-call'],
    ['ldapts module', 'const c = require("ldapts"); function h(d) { c.search("dc=example,dc=com", d); }', 'tainted-arg'],
  ];
  for (const [label, content, kind] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].sink, 'client.search', label);
    assert.equal(result.findings[0].evidence[0].kind, kind, label);
  }
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'client.search("dc=example,dc=com", "(objectClass=*)");',
    'const f = "(objectClass=*)"; client.search("dc=example,dc=com", f);',
    // A sanitized value is clean.
    'function h(x) { client.search("dc=example,dc=com", Number(x)); }',
    // A TAINTED BASE is not judged in this round — only
    // the second argument (the filter) is.
    'function h(d) { client.search(d, "(objectClass=*)"); }',
    // A single-argument call has no judged argument.
    'function h(d) { client.search(d); }',
    // Other client methods are not search queries.
    'function h(d) { client.bind(d, "secret"); }',
    'function h(d) { client.add(d, { cn: "x" }); }',
    // A bare search is too generic to be a sink.
    'function h(d) { search("dc=example,dc=com", d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { app.client.search("dc=example,dc=com", d); }',
    'function h(d) { myclient.search("dc=example,dc=com", d); }',
    '// client.search("dc=example,dc=com", userInput)\nconst a = 1;',
    'const s = "client.search(userInput)";',
    'const s = `client.search(userInput)`;',
    '/* client.search(userInput) */ const a = 1;',
    'function h(d) { client.search("dc=example,dc=com"); }',
    'let s = client.search; s = 5; s("dc=example,dc=com", x);',
    'const notLdap = { search(x, y) { return x; } }; function h(d) { notLdap.search("dc=example,dc=com", d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// client.search("dc=example,dc=com", userInput)\nfunction h(d) { return client.search("dc=example,dc=com", d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // A tainted base (first argument) is NOT judged —
    // only the filter (second argument) is.
    'function h(d) { client.search(d, "(objectClass=*)"); }',
    // An unknown module carries no import mapping.
    'function h(d) { const c = require("unknown-ldap"); c.search("dc=example,dc=com", d); }',
    // A relative path carries no import mapping.
    'function h(d) { const c = require("./ldap"); c.search("dc=example,dc=com", d); }',
    // A dynamic require carries no import mapping.
    'function h(m, d) { require(m).search("dc=example,dc=com", d); }',
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
      { content: 'function h(d) { return client.search("dc=example,dc=com", d); }', ...IDS },
      { content: 'client.search("dc=example,dc=com", "(objectClass=*)");', ...IDS },
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
  assert.equal(runRecord({ content: 'client.search("dc=example,dc=com", x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return client.search("dc=example,dc=com", d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return client.search("dc=example,dc=com", d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return client.search'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  client.search("dc=example,dc=com", d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-ldap', () => {
  const resolved = getDetector('tainted-ldap', process.cwd());
  assert.equal(resolved.source, 'tainted-ldap');
  assert.equal(typeof resolved.detector, 'function');
});
