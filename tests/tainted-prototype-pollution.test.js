// Tests for the twenty-eighth real detector (Phase 5, round 114):
// tainted-prototype-pollution — the thirteenth parser-based detector.
// Positive cases prove the taint engine sees what the regex
// detector cannot (a tainted merge source, a tainted dynamic
// key, a dangerous literal key, a tainted spread, aliased
// calls, inter-procedural flow, import-resolved calls, and
// the null-prototype exemptions); negative cases prove the
// parser refuses what the regex detector would wrongly
// match (comments, strings) and what is genuinely safe
// (literals, sanitized values, static safe keys, a lone
// leaf `constructor` / `prototype`, writes onto an object
// created by `Object.create(null)`, non-sink methods).
// Structural cases pin the envelope (batch, skipped, caps,
// determinism, no literal leakage) and the documented
// resolution limits of this round.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getDetector } = require('../src/detection/detector');
const detect = require('../src/detection/tainted-prototype-pollution');
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
    'function h(d) { return Object.assign({}, d); }',
    'function h(d) { return _.merge({}, d); }',
    'function h(d) { return _.set({}, d, 1); }',
    'function h(d) { return $.extend(true, {}, d); }',
    'function h(d) { return merge({}, d); }',
    'function h(d) { return merge.all([{}, d]); }',
    'function h(k) { const o = {}; o[k] = 1; }',
    'function h(k) { const o = {}; o[k] += 1; }',
    'function h(d) { const o = {}; o["__proto__"] = d; }',
    'function h(d) { const m = {...d}; }',
    'const o = Object.create(null); o["__proto__"] = 1;',
    'const a = Object.assign; a({}, d);',
    'const { merge } = _; merge({}, d);',
    'const x = require("lodash"); x.merge({}, d);',
    'class H { handle(req) { return Object.assign({}, req.body); } }',
    'const f = async (req) => Object.assign({}, req.query);',
    'for (const item of items) { Object.assign({}, item); }',
    'try { Object.assign({}, x); } catch (e) { console.log(e); } finally { done(); }',
    'switch (x) { case 1: Object.assign({}, a); break; default: Object.assign({}, b); }',
    'const v = ok ? Object.assign({}, a) : null;',
    'const r = Object?.assign({}, x); const y = a?.b?.c;',
    'const m = `<root>${id}</root>`;',
  ];
  for (const source of sources) {
    assert.doesNotThrow(() => parseJavaScript(source), `should parse: ${source}`);
  }
});

// ------------------------------------------------------- positive cases

test('detector: direct merge call with a tainted source argument', () => {
  const result = run('function h(d) { return Object.assign({}, d); }');
  assert.equal(result.skipped, 0);
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.equal(finding.vulnerability_type, 'prototype pollution');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-1321');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'Object.assign');
  assert.deepEqual(finding.evidence[0].taint.chain, ["parameter 'd' of function 'h'"]);
  assert.match(finding.description, /parameter 'd' of function 'h'/);
});

test('detector: taint flows through req.body, assignments, members, templates, binary', () => {
  const cases = [
    ['req.body', 'function h(req) { Object.assign({}, req.body); }', ["parameter 'req' of function 'h'", 'req.body']],
    ['assignment chain', 'function h(d) { const a = d; const b = a.name; Object.assign({}, b); }',
      ["parameter 'd' of function 'h'", 'a', 'a.name', 'b']],
    ['template', 'function h(n) { const m = `<root>${n}</root>`; Object.assign({}, m); }',
      ["parameter 'n' of function 'h'", 'm']],
    ['binary', 'function h(d) { Object.assign({}, "<root>" + d + "</root>"); }', ["parameter 'd' of function 'h'"]],
    ['argv', 'const d = process.argv[2]; Object.assign({}, d);', ['process.argv', 'process.argv[2]', 'd']],
    ['class method', 'class H { handle(req) { return Object.assign({}, req.body); } }',
      ["parameter 'req' of function 'handle'", 'req.body']],
    ['for-of', 'function h(items) { for (const item of items) { Object.assign({}, item); } }',
      ["parameter 'items' of function 'h'", 'item']],
    ['optional chain', 'function h(d) { Object?.assign({}, d); }', ["parameter 'd' of function 'h'"]],
  ];
  for (const [label, content, chain] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, chain, label);
  }
});

test('detector: every merge sink spelling with a tainted source', () => {
  const cases = [
    ['Object.assign', 'function h(d) { return Object.assign({}, d); }', 'tainted-arg'],
    ['_.merge', 'function h(d) { return _.merge({}, d); }', 'tainted-arg'],
    ['_.defaultsDeep', 'function h(d) { return _.defaultsDeep({}, d); }', 'tainted-arg'],
    ['_.set', 'function h(p) { return _.set({}, p, 1); }', 'tainted-arg'],
    ['$.extend', 'function h(d) { return $.extend(true, {}, d); }', 'tainted-arg'],
    ['merge', 'function h(d) { return merge({}, d); }', 'tainted-arg'],
    ['merge.all', 'function h(d) { return merge.all([{}, d]); }', 'tainted-arg'],
    // A second source is judged too (argIndexFrom): the
    // first source is clean, the second is tainted.
    ['Object.assign', 'function h(d) { return Object.assign({}, {}, d); }', 'tainted-arg'],
    ['_.merge', 'function h(d) { return _.merge({}, {}, d); }', 'tainted-arg'],
    ['$.extend', 'function h(d) { return $.extend(true, {}, {}, d); }', 'tainted-arg'],
  ];
  for (const [sink, content, kind] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, sink);
    assert.equal(result.findings[0].evidence[0].sink, sink, content);
    assert.equal(result.findings[0].evidence[0].kind, kind, content);
  }
});

test('detector: _.set judges its path (argument 1), not the target or the value', () => {
  const result = run('function h(p) { return _.set({}, p, 1); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].sink, '_.set');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, ["parameter 'p' of function 'h'"]);
});

test('detector: a tainted dynamic key is a finding even with a constant value', () => {
  const cases = [
    ['plain', 'function h(k) { const o = {}; o[k] = 1; }', 'o[k]'],
    ['compound', 'function h(k) { const o = {}; o[k] += 1; }', 'o[k]'],
    ['chained key', 'function h(d) { const o = {}; const k = d.key; o[k] = 1; }', 'o[k]'],
    ['for-in key', 'function h(d) { const o = {}; for (const k in d) { o[k] = 1; } }', 'o[k]'],
    ['member key', 'function h(d) { const o = {}; o[d.key] = 1; }', 'o[d.key]'],
  ];
  for (const [label, content, target] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-key-assign', label);
    assert.equal(result.findings[0].evidence[0].sink, 'dynamic-property-assignment', label);
    assert.equal(result.findings[0].evidence[0].target, target, label);
  }
});

test('detector: a dangerous literal key is a finding even with a clean value', () => {
  const cases = [
    ['computed __proto__', 'const o = {}; o["__proto__"] = { polluted: 1 };', "o['__proto__']"],
    ['static __proto__', 'const o = {}; o.__proto__ = { polluted: 1 };', 'o.__proto__'],
    ['through __proto__', 'const o = {}; o.__proto__.polluted = 1;', 'o.__proto__.polluted'],
    ['through __proto__ computed', 'const o = {}; o["__proto__"]["polluted"] = 1;', "o['__proto__']['polluted']"],
    ['constructor prototype path', 'const o = {}; o.constructor.prototype.polluted = 1;', 'o.constructor.prototype.polluted'],
    ['replace constructor prototype', 'const o = {}; o.constructor.prototype = {};', 'o.constructor.prototype'],
    ['direct Object.prototype write', 'Object.prototype.polluted = 1;', 'Object.prototype.polluted'],
  ];
  for (const [label, content, target] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'dangerous-key-assign', label);
    assert.equal(result.findings[0].evidence[0].sink, 'dynamic-property-assignment', label);
    assert.equal(result.findings[0].evidence[0].target, target, label);
    assert.equal(result.findings[0].evidence[0].property, target, label);
    assert.equal(result.findings[0].evidence[0].taint, undefined, `${label}: a static pattern carries no taint`);
  }
});

test('detector: a tainted object spread is a finding', () => {
  const cases = [
    ['direct', 'function h(d) { const m = {...d}; }'],
    ['nested literal', 'function h(d) { const m = { a: 1, ...d }; }'],
    ['spread then merge', 'function h(d) { const m = {...d}; Object.assign({}, m); }'],
  ];
  for (const [label, content] of cases) {
    const result = run(content);
    // The third case has two findings: the spread itself
    // and the merge of the (tainted) merged object.
    const want = label === 'spread then merge' ? 2 : 1;
    assert.equal(result.findings.length, want, `${label}: findings`);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-spread', label);
    assert.equal(result.findings[0].evidence[0].sink, 'object-spread', label);
    assert.deepEqual(result.findings[0].evidence[0].taint.chain, ["parameter 'd' of function 'h'"], label);
  }
});

test('detector: aliased merge calls are reported even with a clean argument', () => {
  const cases = [
    ['simple alias', 'const a = Object.assign; a({}, d);', 'a', 'Object.assign'],
    ['computed alias', 'const a = Object["assign"]; a({}, d);', 'a', 'Object.assign'],
    ['destructured alias', 'const { assign } = Object; assign({}, d);', 'assign', 'Object.assign'],
    ['renamed destructured alias', 'const { assign: a } = Object; a({}, d);', 'a', 'Object.assign'],
    ['alias through identifier', 'const a = Object.assign; const b = a; b({}, d);', 'b', 'Object.assign'],
    ['lodash alias', 'const m = _.merge; m({}, d);', 'm', '_.merge'],
    ['destructured lodash alias', 'const { merge } = _; merge({}, d);', 'merge', '_.merge'],
    // An alias shadows a bare sink of the same spelling:
    // `merge` bound to `_.merge` is judged as the lodash
    // sink, not as the bare `merge` deepmerge sink (the
    // reorder pin — before round 114 the direct bare-sink
    // path shadowed the alias and this was no finding).
    ['alias shadows bare sink', 'const merge = _.merge; merge({}, d);', 'merge', '_.merge'],
    ['destructured merge.all alias', 'const { all } = merge; all([{}, d]);', 'all', 'merge.all'],
    ['deepmerge alias', 'const m = merge; m({}, d);', 'm', 'merge'],
  ];
  for (const [label, content, aliasName, sink] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].kind, 'aliased-call', label);
    assert.equal(result.findings[0].evidence[0].alias.name, aliasName, label);
    assert.equal(result.findings[0].evidence[0].alias.boundTo, sink, label);
  }
});

test('detector: branch join keeps taint from either path (key and merge alike)', () => {
  const key = run('function h(d, c) { let x = "static"; if (c) { x = d; } const o = {}; o[x] = 1; }');
  assert.equal(key.findings.length, 1);
  assert.equal(key.findings[0].evidence[0].kind, 'tainted-key-assign');
  const merge = run('function h(d, c) { let x = {}; if (c) { x = d; } Object.assign({}, x); }');
  assert.equal(merge.findings.length, 1);
  assert.equal(merge.findings[0].evidence[0].kind, 'tainted-arg');
});

test('detector: sink call inside a template interpolation carries the right position', () => {
  const result = run('function h(d) {\n  const s = `a${Object.assign({}, d)}b`;\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 17);
});

test('detector: spread inside a literal carries the right position', () => {
  const result = run('function h(d) {\n  const m = {...d};\n}');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-spread');
  assert.equal(result.findings[0].evidence[0].line, 2);
  assert.equal(result.findings[0].evidence[0].column, 14);
});

test('detector: taint flows through a helper into the sink (inter-procedural)', () => {
  const result = run('function h(req) { run(req.body); } function run(u) { return Object.assign({}, u); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'u' of function 'run'",
  ]);
});

test('detector: a helper returning a tainted value propagates to the sink', () => {
  const result = run('function id(x) { return x; } function h(req) { const y = id(req.body); Object.assign({}, y); }');
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].evidence[0].taint.chain, [
    "parameter 'req' of function 'h'",
    'req.body',
    "parameter 'x' of function 'id'",
    'y',
  ]);
});

test('detector: import-resolved merge calls are reported', () => {
  const cases = [
    ['lodash namespace alias', 'const _ = require("lodash"); function h(d) { _.merge({}, d); }', 'tainted-arg', '_.merge'],
    ['lodash direct require member', 'function h(d) { require("lodash").merge({}, d); }', 'tainted-arg', '_.merge'],
    ['lodash destructured require', 'const { merge } = require("lodash"); function h(d) { merge({}, d); }', 'aliased-call', '_.merge'],
    ['lodash ESM default import', 'import _ from "lodash"; function h(d) { _.merge({}, d); }', 'tainted-arg', '_.merge'],
    ['lodash ESM named import', 'import { merge } from "lodash"; function h(d) { merge({}, d); }', 'aliased-call', '_.merge'],
    ['lodash ESM namespace import', 'import * as _ from "lodash"; function h(d) { _.merge({}, d); }', 'tainted-arg', '_.merge'],
    ['deepmerge namespace alias', 'const m = require("deepmerge"); function h(d) { m({}, d); }', 'aliased-call', 'merge'],
    ['deepmerge ESM default import', 'import merge from "deepmerge"; function h(d) { merge({}, d); }', 'aliased-call', 'merge'],
    ['jquery namespace alias', 'const $ = require("jquery"); function h(d) { $.extend(true, {}, d); }', 'tainted-arg', '$.extend'],
    ['jquery direct require member', 'function h(d) { require("jquery").extend(true, {}, d); }', 'tainted-arg', '$.extend'],
  ];
  for (const [label, content, kind, sink] of cases) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `${label}: one finding`);
    assert.equal(result.findings[0].evidence[0].sink, sink, label);
    assert.equal(result.findings[0].evidence[0].kind, kind, label);
  }
});

// ------------------------------------------------------- negative cases

test('detector: clean arguments, safe non-sinks, and prose are not findings', () => {
  const contents = [
    'Object.assign({}, {a: 1});',
    'const e = {}; Object.assign(e, {a: 1});',
    '_.merge({}, {});',
    '_.set({}, "name", 1);',
    'merge({}, {});',
    'merge.all([{}, {}]);',
    // A sanitized value is clean.
    'function h(x) { Object.assign({}, Number(x)); }',
    'function h(x) { const o = {}; o[Number(x)] = 1; }',
    // A static safe key is not dangerous.
    'const o = {}; o.name = 1;',
    'const o = {}; o["name"] = 1;',
    'const o = {}; o[0] = 1;',
    'const key = "name"; const o = {}; o[key] = 1;',
    // A lone leaf `constructor` or `prototype` is ordinary JavaScript.
    'Foo.prototype.constructor = Foo;',
    'function F() {}; F.prototype = {};',
    'const o = {}; o.constructor = Foo;',
    'const o = {}; o.prototype = {};',
    // A dynamic segment between `constructor` and
    // `prototype` breaks the pair (a documented false
    // negative: the engine does no constant propagation).
    'function h(k) { const o = {}; o.constructor[k].prototype.polluted = 1; }',
    // A read through a tainted key is not a write.
    'function h(k) { const o = {}; const v = o[k]; }',
    // `delete` is not a write.
    'function h(k) { const o = {}; delete o[k]; }',
    // A spread of a clean value, an array spread, and a
    // call spread are not object merges.
    'const m = {...{a: 1}};',
    'function h(d) { const a = [...d]; }',
    'function h(d) { f(...d); }',
    'function h(d) { const m = {a: d}; }',
    // defineProperty defines an own property — it does not
    // trigger the `__proto__` setter.
    'function h(d) { Object.defineProperty({}, "__proto__", {value: d}); }',
    // A merge call with no source argument cannot carry
    // attacker data.
    'function h(d) { Object.assign(d); }',
    'function h(d) { _.merge(d); }',
    // The shallow `$.extend` form is not judged (its
    // sources start at index 1, the deep form at 2).
    'function h(d) { $.extend({}, d); }',
    // A merge name on any other receiver is not a sink.
    'function h(d) { obj.merge(d); }',
    'function h(d) { mylib.merge({}, d); }',
    'function h(d) { app.Object.assign({}, d); }',
    // `_.extend` (underscore) is not a sink in this round.
    'function h(d) { _.extend({}, d); }',
    // A bare `merge` as a value, not a call, is not a sink.
    'function h(d) { const m = merge; }',
    // A literal `__proto__` key inside a clean source
    // object is not inspected (no constant propagation
    // into object literals).
    'Object.assign({}, {__proto__: {polluted: 1}});',
    // A literal path for `_.set` is not judged — only a
    // tainted path is.
    '_.set({}, "__proto__.polluted", 1);',
    '// Object.assign({}, userInput)\nconst a = 1;',
    'const s = "Object.assign({}, userInput)";',
    'const s = `obj[key] = userInput`;',
    '/* Object.assign({}, userInput) */ const a = 1;',
    'function h(d) { Object.assign(); }',
    'let a = Object.assign; a = 5; a({}, d);',
    'const o = { merge: _.merge }; function h(d) { o.merge({}, d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: writes onto an object created by Object.create(null) are not findings', () => {
  const contents = [
    'const o = Object.create(null); o["__proto__"] = 1;',
    'const o = Object.create(null); o.__proto__ = 1;',
    'const o = Object.create(null); o.__proto__.polluted = 1;',
    'function h(k) { const o = Object.create(null); o[k] = 1; }',
    'function h(d) { const o = Object.create(null); Object.assign(o, d); }',
    'function h(d) { const o = Object.create(null); _.merge(o, d); }',
    'function h(p) { const o = Object.create(null); _.set(o, p, 1); }',
    // An identifier copy of a null-prototype object stays exempt.
    'const p = Object.create(null); const q = p; q["__proto__"] = 1;',
    // A plain assignment re-binds the name, so a
    // null-prototype creation there exempts it too.
    'let o; o = Object.create(null); o["__proto__"] = 1;',
    // An inline creation as the merge target exempts it.
    'function h(d) { Object.assign(Object.create(null), d); }',
    // An inline creation as the assignment object exempts it.
    'Object.create(null)["__proto__"] = 1;',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 0, `no finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: the null-prototype exemption does not leak to nested objects or reassignments', () => {
  const contents = [
    // A nested property of a null-prototype object is an
    // ordinary object — its `__proto__` write pollutes.
    'const o = Object.create(null); o.nested["__proto__"] = 1;',
    'const o = Object.create(null); o.nested.__proto__.polluted = 1;',
    // Reassigning the name to an ordinary object clears
    // the exemption.
    'let o = Object.create(null); o = {}; o["__proto__"] = 1;',
    // A merge into an ordinary object after the exemption
    // was established elsewhere still flags.
    'function h(d) { const o = Object.create(null); const t = {}; Object.assign(t, d); }',
  ];
  for (const content of contents) {
    const result = run(content);
    assert.equal(result.findings.length, 1, `one finding for: ${content}`);
    assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  }
});

test('detector: a sink in a comment and a sink in code are told apart', () => {
  const result = run('// Object.assign({}, userInput)\nfunction h(d) { return Object.assign({}, d); }');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence[0].line, 2);
});

test('detector: documented resolution limits are pinned (no finding)', () => {
  const contents = [
    // An unknown module carries no import mapping.
    'function h(d) { const x = require("unknown-lib"); x.merge({}, d); }',
    // A relative path carries no import mapping.
    'function h(d) { const x = require("./lodash"); x.merge({}, d); }',
    // A dynamic require carries no import mapping.
    'function h(m, d) { require(m).merge({}, d); }',
    // A require call used directly as a callee is not
    // resolved (the callee must be an identifier or a
    // member expression).
    'function h(d) { require("deepmerge")({}, d); }',
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
      { content: 'function h(d) { return Object.assign({}, d); }', ...IDS },
      { content: 'Object.assign({}, {a: 1});', ...IDS },
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
  assert.equal(runRecord({ content: 'Object.assign({}, x);', language: 'python' }).skipped, 1);
  const parsed = runRecord({ content: 'const x = ;' });
  assert.equal(parsed.skipped, 1);
  assert.match(parsed.errors[0], /failed to parse content as JavaScript/);
  assert.match(parsed.errors[0], /line 1, column 11/);
});

test('detector: ids come from defaults when the record omits them', () => {
  const result = detect(
    { content: 'function h(d) { return Object.assign({}, d); }' },
    { session_id: 'ds', target_id: 'dt', asset_id: 'da' },
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].session_id, 'ds');
  assert.equal(result.findings[0].target_id, 'dt');
  assert.equal(result.findings[0].asset_id, 'da');
});

test('detector: finding ids are deterministic and carry no literal value', () => {
  const content = 'function h(d) { const secret = "hunter2-not-a-real-secret"; return Object.assign({}, d); }';
  const first = run(content);
  const second = run(content);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].finding_id, second.findings[0].finding_id);
  assert.ok(!JSON.stringify(first.findings).includes('hunter2-not-a-real-secret'),
    'no literal value may appear in a finding');
  assert.ok(!JSON.stringify(first.findings).includes('return Object.assign'),
    'no source line may appear in a finding');
});

test('detector: per-record cap truncates visibly, never silently', () => {
  const lines = ['function h(d) {'];
  for (let i = 0; i < 101; i += 1) lines.push('  Object.assign({}, d);');
  lines.push('}');
  const result = run(lines.join('\n'));
  assert.equal(result.findings.length, 100);
  assert.ok(result.errors.some((error) => /truncated/.test(error)), 'truncation must be recorded');
});

test('detector: resolves through getDetector as tainted-prototype-pollution', () => {
  const resolved = getDetector('tainted-prototype-pollution', process.cwd());
  assert.equal(resolved.source, 'tainted-prototype-pollution');
  assert.equal(typeof resolved.detector, 'function');
});
