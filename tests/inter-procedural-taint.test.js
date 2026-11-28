// Tests for round 101 (Phase 5): inter-procedural taint
// (call graph) + sanitizer modeling, on the shared taint
// engine all thirteen parser-based detectors run on.
//
// Positive cases prove taint flows from a call site into a
// callee (the chain names the cross-function flow), through
// return values, and through IIFEs, aliases, and hoisted
// calls. Negative cases prove a sanitizer cleanses taint
// (and that encoding / content-preserving calls do not),
// that a constant-returning wrapper does not propagate
// taint, and that recursion and deep call chains terminate
// instead of hanging. The round-95 fallback is pinned too:
// a helper never called, or called only with clean
// arguments, still flags its sink with parameters-as-sources.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../src/detection/taint-engine');
const deserialize = require('../src/detection/tainted-deserialize');
const commandExec = require('../src/detection/tainted-command-execution');
const sql = require('../src/detection/tainted-sql');
const xss = require('../src/detection/tainted-xss');
const ssti = require('../src/detection/tainted-ssti');
const pathTraversal = require('../src/detection/tainted-path-traversal');
const ssrf = require('../src/detection/tainted-ssrf');
const ldap = require('../src/detection/tainted-ldap');
const xpath = require('../src/detection/tainted-xpath');
const openRedirect = require('../src/detection/tainted-open-redirect');
const xxe = require('../src/detection/tainted-xxe');
const redos = require('../src/detection/tainted-redos');
const prototypePollution = require('../src/detection/tainted-prototype-pollution');

const IDS = { session_id: 's1', target_id: 't1', asset_id: 'a1' };

const DETECTORS = [
  {
    name: 'tainted-deserialize',
    detect: deserialize,
    sink: 'yaml.load',
    call: (arg) => `yaml.load(${arg})`,
    vuln: 'insecure deserialization',
    cwe: 'CWE-502',
  },
  {
    name: 'tainted-command-execution',
    detect: commandExec,
    sink: 'child_process.exec',
    call: (arg) => `child_process.exec(${arg})`,
    vuln: 'os command injection',
    cwe: 'CWE-78',
  },
  {
    name: 'tainted-sql',
    detect: sql,
    sink: 'db.query',
    call: (arg) => `db.query(${arg})`,
    vuln: 'sql injection',
    cwe: 'CWE-89',
  },
  {
    name: 'tainted-xss',
    detect: xss,
    sink: 'document.write',
    call: (arg) => `document.write(${arg})`,
    vuln: 'cross-site scripting',
    cwe: 'CWE-79',
  },
  {
    name: 'tainted-ssti',
    detect: ssti,
    sink: 'ejs.render',
    call: (arg) => `ejs.render(${arg})`,
    vuln: 'server-side template injection',
    cwe: 'CWE-1336',
  },
  {
    name: 'tainted-path-traversal',
    detect: pathTraversal,
    sink: 'fs.readFile',
    call: (arg) => `fs.readFile(${arg})`,
    vuln: 'path traversal',
    cwe: 'CWE-22',
  },
  {
    name: 'tainted-ssrf',
    detect: ssrf,
    sink: 'fetch',
    call: (arg) => `fetch(${arg})`,
    vuln: 'server-side request forgery',
    cwe: 'CWE-918',
  },
  {
    name: 'tainted-ldap',
    detect: ldap,
    sink: 'client.search',
    call: (arg) => `client.search('dc=example,dc=com', ${arg})`,
    vuln: 'ldap injection',
    cwe: 'CWE-90',
  },
  {
    name: 'tainted-xpath',
    detect: xpath,
    sink: 'xpath.select',
    call: (arg) => `xpath.select(${arg}, doc)`,
    vuln: 'xpath injection',
    cwe: 'CWE-643',
  },
  {
    name: 'tainted-open-redirect',
    detect: openRedirect,
    sink: 'res.redirect',
    call: (arg) => `res.redirect(${arg})`,
    vuln: 'open redirect',
    cwe: 'CWE-601',
  },
  {
    name: 'tainted-xxe',
    detect: xxe,
    sink: 'libxmljs.parseXml',
    call: (arg) => `libxmljs.parseXml(${arg}, { noent: true })`,
    vuln: 'xml external entity injection',
    cwe: 'CWE-611',
  },
  {
    name: 'tainted-redos',
    detect: redos,
    sink: 'RegExp',
    call: (arg) => `RegExp(${arg})`,
    vuln: 'regular expression denial of service',
    cwe: 'CWE-1333',
  },
  {
    name: 'tainted-prototype-pollution',
    detect: prototypePollution,
    sink: 'Object.assign',
    call: (arg) => `Object.assign({}, ${arg})`,
    vuln: 'prototype pollution',
    cwe: 'CWE-1321',
  },
];

function defineTests(det) {
  function run(content) {
    return det.detect({ content, ...IDS }, {});
  }

  function chainOf(result, index = 0) {
    return result.findings[index].evidence[0].taint.chain;
  }

  test(`${det.name}: taint flows from a call site into a helper, chain proves the flow`, () => {
    const content = `function handle(req) { parse(req.body); } function parse(d) { return ${det.call('d')}; }`;
    const result = run(content);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].vulnerability_type, det.vuln);
    assert.equal(result.findings[0].cwe_id, det.cwe);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'handle'",
      'req.body',
      "parameter 'd' of function 'parse'",
    ]);
  });

  test(`${det.name}: taint flows through several helpers (multi-hop)`, () => {
    const content = `function a(req) { b(req.body); } function b(x) { c(x); } function c(y) { ${det.call('y')}; }`;
    const result = run(content);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'a'",
      'req.body',
      "parameter 'x' of function 'b'",
      "parameter 'y' of function 'c'",
    ]);
  });

  test(`${det.name}: a call textually before the helper declaration still resolves (hoisting)`, () => {
    const content = `function outer(req) { inner(req.body); } function inner(d) { ${det.call('d')}; }`;
    const result = run(content);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'outer'",
      'req.body',
      "parameter 'd' of function 'inner'",
    ]);
  });

  test(`${det.name}: a helper called only with clean arguments still flags via the fallback`, () => {
    const result = run(`function parse(d) { return ${det.call('d')}; } parse('static');`);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
    assert.deepEqual(chainOf(result), ["parameter 'd' of function 'parse'"]);
  });

  test(`${det.name}: uncalled and clean-called helpers both flag (fallback), one finding each`, () => {
    const result = run(`function a(d) { ${det.call('d')}; } function b(d) { ${det.call('d')}; } a('x');`);
    assert.equal(result.findings.length, 2);
  });

  test(`${det.name}: when the fallback runs first, the first (fallback) chain wins deterministically`, () => {
    // parse is declared before h, so the fallback analyzes
    // parse (parameters-as-sources) before h's tainted call
    // is reached; the finding is the same sink site, and the
    // first chain wins — one finding, no duplicate.
    const result = run(`function parse(d) { return ${det.call('d')}; } function h(req) { parse(req.body); } parse('static');`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), ["parameter 'd' of function 'parse'"]);
  });

  test(`${det.name}: self-recursion terminates with one finding`, () => {
    const result = run(`function f(d) { if (d) { f(d); } return ${det.call('d')}; }`);
    assert.equal(result.findings.length, 1);
  });

  test(`${det.name}: mutual recursion terminates with one finding`, () => {
    const result = run(`function f(d) { g(d); } function g(d) { f(d); ${det.call('d')}; }`);
    assert.equal(result.findings.length, 1);
  });

  test(`${det.name}: a twelve-deep wrapper chain terminates (depth cap + fallback)`, () => {
    const parts = ['function entry(req) { w1(req.body); }'];
    for (let i = 1; i <= 12; i += 1) {
      parts.push(i === 12
        ? `function w${i}(x) { ${det.call('x')}; }`
        : `function w${i}(x) { w${i + 1}(x); }`);
    }
    const result = run(parts.join('\n'));
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].evidence[0].kind, 'tainted-arg');
    // The depth cap stops call-site analysis at w8; the
    // fallback analyzes w8..w12 with parameters-as-sources,
    // so the chain restarts at w8.
    assert.deepEqual(chainOf(result), [
      "parameter 'x' of function 'w8'",
      "parameter 'x' of function 'w9'",
      "parameter 'x' of function 'w10'",
      "parameter 'x' of function 'w11'",
      "parameter 'x' of function 'w12'",
    ]);
  });

  test(`${det.name}: an IIFE passes taint from its arguments into its body`, () => {
    const result = run(`function h(req) { (function(d) { ${det.call('d')}; })(req.body); }`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'h'",
      'req.body',
      "parameter 'd' of function 'anonymous'",
    ]);
  });

  test(`${det.name}: an arrow function bound to a variable is called through the graph`, () => {
    const result = run(`const run = (cmd) => ${det.call('cmd')}; function h(req) { run(req.body); }`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'h'",
      'req.body',
      "parameter 'cmd' of function 'run'",
    ]);
  });

  test(`${det.name}: a function alias resolves through the graph`, () => {
    const result = run(`const g = parse; function h(req) { g(req.body); } function parse(d) { return ${det.call('d')}; }`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'h'",
      'req.body',
      "parameter 'd' of function 'parse'",
    ]);
  });

  test(`${det.name}: a wrapper's return taint flows to the caller (identity)`, () => {
    const result = run(`function id(x) { return x; } function h(req) { const y = id(req.body); ${det.call('y')}; }`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), [
      "parameter 'req' of function 'h'",
      'req.body',
      "parameter 'x' of function 'id'",
      'y',
    ]);
  });

  test(`${det.name}: a wrapper returning a constant does not propagate taint`, () => {
    const result = run(`function c(x) { return 'static'; } function h(req) { const y = c(req.body); ${det.call('y')}; }`);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 0);
  });

  test(`${det.name}: a wrapper returning a global source propagates taint`, () => {
    const result = run(`function readArg() { return process.argv[2]; } const y = readArg(); ${det.call('y')};`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(chainOf(result), ['process.argv', 'process.argv[2]', 'y']);
  });

  test(`${det.name}: an unknown call still returns tainted for a tainted argument`, () => {
    const result = run(`function h(req) { const y = unknownFn(req.body); ${det.call('y')}; }`);
    assert.equal(result.findings.length, 1);
  });

  test(`${det.name}: sanitizers cleanse taint (Number, parseInt, parseFloat, Boolean, Number.parseInt)`, () => {
    for (const sanitizer of ['Number', 'parseInt', 'parseFloat', 'Boolean', 'Number.parseInt']) {
      const result = run(`function h(req) { const n = ${sanitizer}(req.body); ${det.call('n')}; }`);
      assert.equal(result.findings.length, 0, `${sanitizer}: no finding`);
      assert.equal(result.skipped, 0, `${sanitizer}: not skipped`);
    }
  });

  test(`${det.name}: encoding and content-preserving calls do NOT cleanse taint`, () => {
    for (const notSanitizer of ['encodeURIComponent', 'encodeURI', 'String', 'JSON.stringify']) {
      const result = run(`function h(req) { const n = ${notSanitizer}(req.body); ${det.call('n')}; }`);
      assert.equal(result.findings.length, 1, `${notSanitizer}: still a finding`);
    }
    for (const method of ['trim', 'toUpperCase']) {
      const result = run(`function h(req) { const n = req.body.${method}(); ${det.call('n')}; }`);
      assert.equal(result.findings.length, 1, `.${method}(): still a finding`);
    }
  });

  test(`${det.name}: a user binding shadowing a sanitizer name disables it`, () => {
    const result = run(`function Number(x) { return x; } function h(req) { const n = Number(req.body); ${det.call('n')}; }`);
    assert.equal(result.findings.length, 1);
  });

  test(`${det.name}: a sanitizer inside a wrapper cleanses through the wrapper`, () => {
    const result = run(`function clean(x) { return Number(x); } function h(req) { ${det.call('clean(req.body)')}; }`);
    assert.equal(result.findings.length, 0);
    assert.equal(result.skipped, 0);
  });

  test(`${det.name}: sanitizing one variable does not cleanse another`, () => {
    const result = run(`function h(req) { const n = Number(req.body); const m = req.body; ${det.call('m')}; }`);
    assert.equal(result.findings.length, 1);
  });

  test(`${det.name}: a sink nested inside a sanitizer argument is still flagged`, () => {
    const result = run(`function h(req) { const n = Number(${det.call('req.body')}); }`);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].evidence[0].sink, det.sink);
  });
}

for (const det of DETECTORS) defineTests(det);

test('engine: all thirteen detectors share one taint engine module', () => {
  assert.deepEqual([...engine.SANITIZERS].sort(), [
    'Boolean', 'Number', 'Number.parseFloat', 'Number.parseInt', 'parseFloat', 'parseInt',
  ]);
  assert.equal(deserialize.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(commandExec.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(sql.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(xss.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(ssti.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(pathTraversal.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(ssrf.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(ldap.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(xpath.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(openRedirect.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(xxe.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(redos.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(prototypePollution.MAX_CONTENT_CHARS, engine.MAX_CONTENT_CHARS);
  assert.equal(deserialize.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(commandExec.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(sql.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(xss.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(ssti.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(pathTraversal.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(ssrf.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(ldap.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(xpath.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(openRedirect.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(xxe.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(redos.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(prototypePollution.MAX_FINDINGS_PER_RECORD, engine.MAX_FINDINGS_PER_RECORD);
  assert.equal(typeof engine.createTaintDetector, 'function');
  assert.equal(typeof engine.TaintAnalyzer, 'function');
  assert.equal(engine.MAX_CALL_DEPTH, 8);
});
