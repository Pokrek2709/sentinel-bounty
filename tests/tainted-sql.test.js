// Tests for the eighth real detector (Phase 5, round 103):
// tainted-sql — the third parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted SQL strings, aliased calls,
// inter-procedural flow); negative cases prove the parser
// refuses what the regex detector would wrongly match
// (comments, strings) and what is genuinely safe
// (literals, parameterized queries, sanitized values,
// non-sink receivers). Structural cases pin the envelope
// (batch, skipped, caps, determinism, no literal leakage)
// and the documented resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-sql');
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
    'function h(id) { return db.query("SELECT * FROM users WHERE id = " + id); }',
    'const q = db.query; q(x);',
    'const { query } = pool; query(id);',
    'class H { handle(req) { return db.query(req.body); } }',
    'const f = async (req) => pool.query(req.query);',
    'for (const item of items) { db.query(item); }',
    'try { db.query(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: db.query(a); break; default: db.query(b); }',
    'const v = ok ? db.query(a) : null;',
    'const r = db?.query(x); const y = a?.b?.c;',
    'const m = `SELECT * FROM t WHERE id = ${id}`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(id) { return db.query("SELECT * FROM users WHERE id = " + id); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'sql injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-89');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'db.query');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'id' of function 'h'"]);
  assert.match(finding.description, /parameter 'id' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { db.query(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; db.query(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `SELECT * FROM t WHERE name = ${n}`; db.query(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { db.query("SELECT * FROM t WHERE id = " + d); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; db.query(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return db.query(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { db.query(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { db?.query(d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['db.query', 'db.execute', 'pool.query', 'pool.execute', 'connection.query', 'connection.execute', 'client.query', 'client.execute', 'conn.query', 'conn.execute']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const q = db.query; q("SELECT 1");', 'q', 'db.query'],
    ['computed alias', 'const q = db["query"]; q(x);', 'q', 'db.query'],
    ['destructured alias', 'const { query } = pool; query(userInput);', 'query', 'pool.query'],
    ['renamed destructured alias', 'const { query: q } = db; q(x);', 'q', 'db.query'],
    ['alias through identifier', 'const q = db.query; const r = q; r(x);', 'r', 'db.query'],
    ['destructured execute', 'const { execute } = connection; execute("SELECT 1");', 'execute', 'connection.execute'],
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
  const result = run('function h(d, c) { let x = "SELECT 1"; if (c) { x = d; } db.query(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${db.query(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(q) { return db.query(q); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'q' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); db.query(y); }');
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
    'db.query("SELECT 1");',
    'const x = "SELECT 1"; db.query(x);',
    // Parameterized queries: constant SQL with placeholders
    // plus a parameter array — even when the parameters are
    // tainted, the SQL string itself is constant, so only
    // the first argument is judged and it is clean.
    'function h(id) { db.query("SELECT * FROM users WHERE id = $1", [id]); }',
    'function h(id) { db.query("SELECT * FROM users WHERE id = ?", [id]); }',
    'function h(id) { const sql = "SELECT * FROM users WHERE id = $1"; db.query(sql, [id]); }',
    // A sanitized value interpolated into SQL is clean.
    'function h(x) { db.query("SELECT * FROM t WHERE id = " + Number(x)); }',
    // prepare is not a sink in this round.
    'function h(d) { db.prepare(d); }',
    // A bare query() call is not a sink (too generic).
    'function h(d) { query(d); }',
    // Receivers outside the sink list are not sinks.
    'function h(d) { elastic.query(d); }',
    'function h(d) { app.db.query(d); }',
    'function h(d) { knex.raw(d); }',
    '// db.query(userInput)\nconst a = 1;',
    'const s = "db.query(userInput)";',
    'const s = `db.query(userInput)`;',
    '/* db.query(userInput) */ const a = 1;',
    'function h(d) { db.query(); }',
    'let q = db.query; q = 5; q(x);',
    'const notDb = { query(x) { return x; } }; function h(d) { notDb.query(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// db.query(userInput)\nfunction h(d) { return db.query(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // Tainted second argument (the parameter vector) is
    // NOT judged in this round — only the first argument
    // (the SQL string) is.
    'function h(a) { db.query("SELECT 1", a); }',
    // require('pg').query is not a sink: `pg` is not a
    // known module for this detector — SQL has no import
    // mapping, because its sink roots are receiver
    // variable names (db/pool/connection/client/conn),
    // not modules. (Round 106.)
    'function h(d) { require("pg").query(d); }',
    // Round 106 moved the object-alias case out of this
    // list: an alias of the db root now resolves (see
    // tests/import-resolution.test.js).
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
      { content: 'function h(d) { return db.query(d); }', ...IDS },
      { content: 'db.query("SELECT 1");', ...IDS },
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
  assert.equal(runRecord({ content: 'db.query(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return db.query(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return db.query(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return db.query(d)'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  db.query(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-sql', () => {
  const resolved = getDetector('tainted-sql', process.cwd());
  assert.equal(resolved.source, 'tainted-sql');
  assert.equal(typeof resolved.detector, 'function');
});
