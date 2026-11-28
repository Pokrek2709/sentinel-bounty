// Tests for the seventh real detector (Phase 5, round 100):
// tainted-command-execution — the second parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (tainted command arguments, aliased calls);
// negative cases prove the parser refuses what the regex
// detector would wrongly match (comments, strings) and what
// is genuinely safe (literals, fork, non-child_process
// objects). Structural cases pin the envelope (batch, skipped,
// caps, determinism, no literal leakage) and the documented
// resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-command-execution');
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
    'function h(cmd) { return child_process.exec(cmd); }',
    'const e = child_process.exec; e(x);',
    'const { spawn } = child_process; spawn(cmd);',
    'class H { handle(req) { return child_process.exec(req.body); } }',
    'const f = async (req) => child_process.spawn(req.query);',
    'for (const item of items) { child_process.exec(item); }',
    'try { child_process.exec(x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: child_process.exec(a); break; default: child_process.exec(b); }',
    'const v = ok ? child_process.exec(a) : null;',
    'const r = child_process?.exec(x); const y = a?.b?.c;',
    'const m = `hi ${name} bye`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct sink call with a tainted parameter argument', () => {
  const result = run('function h(cmd) { return child_process.exec(cmd); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'os command injection');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-78');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'child_process.exec');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'cmd' of function 'h'"]);
  assert.match(finding.description, /parameter 'cmd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { child_process.exec(req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; child_process.exec(b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `hi ${n}`; child_process.exec(m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { child_process.exec(d + "!"); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; child_process.exec(d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return child_process.exec(req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { child_process.exec(item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { child_process?.exec(d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every sink spelling with a tainted argument', () => {
  for (const sink of ['child_process.exec', 'child_process.execSync', 'child_process.spawn', 'child_process.spawnSync', 'child_process.execFile', 'child_process.execFileSync']) {
    const result = run(`function h(d) { return ${sink}(d); }`);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink);
  }
});

test('detector: aliased sink calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const e = child_process.exec; e("ls");', 'e', 'child_process.exec'],
    ['computed alias', 'const e = child_process["exec"]; e(x);', 'e', 'child_process.exec'],
    ['destructured alias', 'const { exec } = child_process; exec(userInput);', 'exec', 'child_process.exec'],
    ['renamed destructured alias', 'const { exec: e } = child_process; e(x);', 'e', 'child_process.exec'],
    ['alias through identifier', 'const e = child_process.exec; const f = e; f(x);', 'f', 'child_process.exec'],
    ['destructured spawn', 'const { spawn } = child_process; spawn("ls");', 'spawn', 'child_process.spawn'],
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
  const result = run('function h(d, c) { let x = "ls"; if (c) { x = d; } child_process.exec(x); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${child_process.exec(d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'child_process.exec("ls");',
    'const x = "ls"; child_process.exec(x);',
    'function h(m) { return child_process.fork(m); }',
    'function h(c) { os.system(c); }',
    'function h(c) { subprocess.run(c); }',
    '// child_process.exec(userInput)\nconst a = 1;',
    'const s = "child_process.exec(userInput)";',
    'const s = `child_process.exec(userInput)`;',
    '/* child_process.exec(userInput) */ const a = 1;',
    'function h(d) { child_process.exec(); }',
    'let e = child_process.exec; e = 5; e(x);',
    'const notCp = { exec(x) { return x; } }; function h(d) { notCp.exec(d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// child_process.exec(userInput)\nfunction h(d) { return child_process.exec(d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // Tainted argument vector (second argument of spawn) is
    // NOT judged in this round — only the first argument is.
    'function h(a) { child_process.spawn("ls", a); }',
    // require('child_process').exec is not resolved (no
    // import resolution in this round).
    'function h(d) { require("child_process").exec(d); }',
    // An object alias of the child_process root is not
    // resolved either.
    'const cp = child_process; function h(d) { cp.exec(d); }',
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
      { content: 'function h(d) { return child_process.exec(d); }', ...IDS },
      { content: 'child_process.exec("ls");', ...IDS },
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
  assert.equal(runRecord({ content: 'child_process.exec(x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return child_process.exec(d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return child_process.exec(d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return child_process.exec(d)'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  child_process.exec(d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-command-execution', () => {
  const resolved = getDetector('tainted-command-execution', process.cwd());
  assert.equal(resolved.source, 'tainted-command-execution');
  assert.equal(typeof resolved.detector, 'function');
});
