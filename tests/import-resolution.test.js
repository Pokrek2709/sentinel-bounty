// Tests for round 106 (Phase 5): import resolution on the
// shared taint engine.
//
// A sink reached through an import resolves to its canonical
// sink: require('mod').method (direct), const alias =
// require('mod') (namespace), const { member } =
// require('mod') (destructured), and the ESM equivalents
// (import { member } / import Default / import * as ns).
// Only modules in each detector's import tables resolve
// (moduleRoots / moduleBareSinks); dynamic require, a
// relative path, an unknown module, and re-export stay
// unresolved, pinned here. Round 114 overturns the
// round-105 collision rule: a destructured name that
// collides with a bare sink (`request`) is now judged as
// the ALIAS (`http.request`), because the alias check runs
// before the bare-sink check — the old rule misattributed
// the sink and suppressed the alias finding for clean
// arguments, and the prototype-pollution detector needs
// the alias to win (`const { merge } = _` must resolve
// to `_.merge`, not to the bare `merge` sink).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const commandExec = require('../src/detection/tainted-command-execution');
const deserialize = require('../src/detection/tainted-deserialize');
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

function run(detect, content, defaults = {}) {
  return detect({ content, ...IDS }, defaults);
}

// One positive case: exactly one finding, for the canonical
// sink, of the expected kind, with no literal leakage.
function assertOneFinding(result, sink, kind, content) {
  assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  assert.equal(result.errors.length, 0, `no errors for: ${content}`);
  assert.equal(result.findings.length, 1, `one finding for: ${content}`);
  const finding = result.findings[0];
  assert.equal(finding.evidence[0].sink, sink, `sink for: ${content}`);
  assert.equal(finding.evidence[0].kind, kind, `kind for: ${content}`);
  assert.ok(!JSON.stringify(finding).includes('SECRET'), 'no literal leakage');
}

function assertNoFinding(result, content) {
  assert.equal(result.skipped, 0, `not skipped for: ${content}`);
  assert.equal(result.findings.length, 0, `no finding for: ${content}`);
}

test('import tables: the documented module allow-lists are exact', () => {
  assert.deepEqual(commandExec.MODULE_ROOTS, {
    'child_process': 'child_process',
    'node:child_process': 'child_process',
  });
  assert.deepEqual(pathTraversal.MODULE_ROOTS, {
    'fs': 'fs',
    'node:fs': 'fs',
  });
  assert.deepEqual(ssrf.MODULE_ROOTS, {
    'http': 'http',
    'node:http': 'http',
    'https': 'https',
    'node:https': 'https',
    'axios': 'axios',
  });
  assert.deepEqual(ssrf.MODULE_BARE_SINKS, {
    'request': 'request',
    'node-fetch': 'fetch',
  });
  assert.deepEqual(ssti.MODULE_ROOTS, {
    'ejs': 'ejs',
    'pug': 'pug',
    'nunjucks': 'nunjucks',
    'handlebars': 'handlebars',
  });
  assert.deepEqual(ldap.MODULE_ROOTS, {
    'ldapjs': 'client',
    'ldapts': 'client',
  });
  assert.deepEqual(xpath.MODULE_ROOTS, { 'xpath': 'xpath' });
  assert.deepEqual(xxe.MODULE_ROOTS, { 'libxmljs': 'libxmljs' });
  assert.deepEqual(prototypePollution.MODULE_ROOTS, {
    'lodash': '_',
    'jquery': '$',
  });
  assert.deepEqual(prototypePollution.MODULE_BARE_SINKS, {
    'deepmerge': 'merge',
  });
  // Only js-yaml maps to the yaml root: its API really is
  // yaml.load / loadAll. The `yaml` package is NOT mapped —
  // its API is `parse`, not `load`.
  assert.deepEqual(deserialize.MODULE_ROOTS, { 'js-yaml': 'yaml' });
  // SQL and XSS have no import mapping: SQL sink roots are
  // receiver variable names (db/pool/...), not modules, and
  // XSS sinks are DOM globals, not module members. Open
  // redirect has none either: res / response / reply / ctx
  // are request-handler parameters, not modules. ReDoS has
  // none either: `RegExp` and the string methods are
  // built-ins, not module members.
  assert.equal(sql.MODULE_ROOTS, undefined);
  assert.equal(xss.MODULE_ROOTS, undefined);
  assert.equal(openRedirect.MODULE_ROOTS, undefined);
  assert.equal(redos.MODULE_ROOTS, undefined);
});

// ------------------------------------------------------- pattern (a)

test('import resolution: direct require member calls resolve to the canonical sink', () => {
  const cases = [
    [commandExec, 'child_process.exec', 'function h(d) { require("child_process").exec(d); }'],
    [commandExec, 'child_process.exec', 'function h(d) { require("node:child_process").exec(d); }'],
    [pathTraversal, 'fs.readFile', 'function h(d) { require("fs").readFile(d); }'],
    [pathTraversal, 'fs.readFile', 'function h(d) { require("node:fs").readFile(d); }'],
    [ssrf, 'http.get', 'function h(d) { require("http").get(d); }'],
    [ssrf, 'https.request', 'function h(d) { require("https").request(d); }'],
    [ssrf, 'axios.get', 'function h(d) { require("axios").get(d); }'],
    [ssti, 'ejs.render', 'function h(d) { require("ejs").render(d); }'],
    [ssti, 'pug.compile', 'function h(d) { require("pug").compile(d); }'],
    [ssti, 'nunjucks.renderString', 'function h(d) { require("nunjucks").renderString(d); }'],
    [deserialize, 'yaml.load', 'function h(d) { require("js-yaml").load(d); }'],
    [ldap, 'client.search', 'function h(d) { require("ldapjs").search("dc=example,dc=com", d); }'],
    [xpath, 'xpath.select', 'function h(d) { require("xpath").select(d, doc); }'],
    [xxe, 'libxmljs.parseXml', 'function h(d) { require("libxmljs").parseXml(d, { noent: true }); }'],
    [prototypePollution, '_.merge', 'function h(d) { require("lodash").merge({}, d); }'],
    [prototypePollution, '$.extend', 'function h(d) { require("jquery").extend(true, {}, d); }'],
  ];
  for (const [detect, sink, content] of cases) {
    assertOneFinding(run(detect, content), sink, 'tainted-arg', content);
  }
  // A direct sink call with a clean argument is not a
  // finding (the regex detector already flags the call
  // site); only the judged argument's taint matters.
  assertNoFinding(
    run(commandExec, 'function h(d) { require("child_process").exec("ls"); }'),
    'clean direct require call',
  );
  // A sanitizer cleanses the judged argument even through
  // a require call.
  assertNoFinding(
    run(commandExec, 'function h(d) { require("child_process").exec(Number(d)); }'),
    'sanitized direct require call',
  );
  // A member that is not a sink member of the module does
  // not resolve, even though the module is known.
  assertNoFinding(
    run(pathTraversal, 'function h(d) { require("fs").write(d); }'),
    'known module, non-sink member',
  );
});

// ------------------------------------------------------- pattern (b)

test('import resolution: namespace aliases (require + bare-root identity) resolve', () => {
  const cases = [
    [commandExec, 'child_process.exec', 'const cp = require("child_process"); function h(d) { cp.exec(d); }'],
    [commandExec, 'child_process.exec', 'const cp = child_process; function h(d) { cp.exec(d); }'],
    [pathTraversal, 'fs.readFile', 'const f = require("fs"); function h(d) { f.readFile(d); }'],
    [pathTraversal, 'fs.readFile', 'const myfs = fs; function h(d) { myfs.readFile(d); }'],
    [ssrf, 'http.get', 'const h = require("http"); function u(d) { h.get(d); }'],
    [ssrf, 'http.get', 'const myhttp = http; function u(d) { myhttp.get(d); }'],
    [ssrf, 'axios.post', 'const ax = require("axios"); function u(d) { ax.post(d); }'],
    [ssti, 'ejs.render', 'const e = require("ejs"); function h(d) { e.render(d); }'],
    [ssti, 'ejs.render', 'const myejs = ejs; function h(d) { myejs.render(d); }'],
    [deserialize, 'yaml.load', 'const y = require("js-yaml"); function h(d) { y.load(d); }'],
    [ldap, 'client.search', 'const c = require("ldapjs"); function h(d) { c.search("dc=example,dc=com", d); }'],
    [xpath, 'xpath.select', 'const x = require("xpath"); function h(d) { x.select(d, doc); }'],
    [xxe, 'libxmljs.parseXml', 'const x = require("libxmljs"); function h(d) { x.parseXml(d, { noent: true }); }'],
    [xxe, 'libxmljs.parseXml', 'const mylib = libxmljs; function h(d) { mylib.parseXml(d, { noent: true }); }'],
    [prototypePollution, '_.merge', 'const _ = require("lodash"); function h(d) { _.merge({}, d); }'],
    [prototypePollution, '_.merge', 'const mylodash = _; function h(d) { mylodash.merge({}, d); }'],
    [prototypePollution, '$.extend', 'const $ = require("jquery"); function h(d) { $.extend(true, {}, d); }'],
    [sql, 'db.query', 'const mydb = db; function h(d) { mydb.query(d); }'],
  ];
  for (const [detect, sink, content] of cases) {
    assertOneFinding(run(detect, content), sink, 'tainted-arg', content);
  }
  // Assignment form binds the module too (`let cp; cp =
  // require('child_process')`).
  assertOneFinding(
    run(commandExec, 'let cp; cp = require("child_process"); function h(d) { cp.exec(d); }'),
    'child_process.exec', 'tainted-arg', 'assigned namespace alias',
  );
  // A single identifier re-alias propagates the module
  // binding (the same one-hop-per-bind rule as function
  // and sink aliases since rounds 95/101).
  assertOneFinding(
    run(commandExec, 'const cp = require("child_process"); const cp2 = cp; function h(d) { cp2.exec(d); }'),
    'child_process.exec', 'tainted-arg', 're-aliased namespace',
  );
  // A module that IS the sink resolves as the bare sink.
  assertOneFinding(
    run(ssrf, 'const rq = require("request"); function h(u) { rq(u); }'),
    'request', 'aliased-call', 'require of a bare-sink module',
  );
  assertOneFinding(
    run(ssrf, 'const nf = require("node-fetch"); function h(u) { nf(u); }'),
    'fetch', 'aliased-call', 'require of node-fetch',
  );
  assertOneFinding(
    run(prototypePollution, 'const m = require("deepmerge"); function h(d) { m({}, d); }'),
    'merge', 'aliased-call', 'require of a bare-sink module (deepmerge)',
  );
});

// ------------------------------------------------------- pattern (c)

test('import resolution: destructured require resolves to the canonical sink', () => {
  const cases = [
    [commandExec, 'child_process.exec', 'const { exec } = require("child_process"); function h(d) { exec(d); }'],
    [commandExec, 'child_process.exec', 'const { exec: e } = require("child_process"); function h(d) { e(d); }'],
    [pathTraversal, 'fs.readFile', 'const { readFile } = require("fs"); function h(d) { readFile(d); }'],
    [ssti, 'ejs.render', 'const { render } = require("ejs"); function h(d) { render(d); }'],
    [deserialize, 'yaml.load', 'const { load } = require("js-yaml"); function h(d) { load(d); }'],
    [deserialize, 'yaml.loadAll', 'const { loadAll } = require("js-yaml"); function h(d) { loadAll(d); }'],
    [ldap, 'client.search', 'const { search } = require("ldapjs"); function h(d) { search("dc=example,dc=com", d); }'],
    [xpath, 'xpath.select', 'const { select } = require("xpath"); function h(d) { select(d, doc); }'],
    [xxe, 'libxmljs.parseXml', 'const { parseXml } = require("libxmljs"); function h(d) { parseXml(d, { noent: true }); }'],
    [prototypePollution, '_.merge', 'const { merge } = require("lodash"); function h(d) { merge({}, d); }'],
  ];
  for (const [detect, sink, content] of cases) {
    assertOneFinding(run(detect, content), sink, 'aliased-call', content);
  }
  // Destructuring from an identifier bound to a module
  // root resolves too.
  assertOneFinding(
    run(commandExec, 'const cp = require("child_process"); const { exec } = cp; function h(d) { exec(d); }'),
    'child_process.exec', 'aliased-call', 'destructured from a module alias',
  );
  // A member alias taken from a require call resolves.
  assertOneFinding(
    run(commandExec, 'const e = require("child_process").exec; function h(d) { e(d); }'),
    'child_process.exec', 'aliased-call', 'member alias from a require call',
  );
  // Round 114 overturns the round-105 collision rule:
  // a destructured name colliding with a bare sink is now
  // judged as the ALIAS, not as the bare sink — the alias
  // check runs before the bare-sink check in
  // `checkSinkCall`. `const { request } = require('http')`
  // IS `http.request`, not the `request` package, so the
  // call flags as sink `http.request` (aliased-call) with
  // any argument, like every other aliased call. The old
  // rule misattributed the sink and suppressed the alias
  // finding for clean arguments; the prototype-pollution
  // detector made the overturn necessary (`const { merge }
  // = _` must resolve to `_.merge`, not to the bare
  // `merge` deepmerge sink).
  assertOneFinding(
    run(ssrf, 'const { request } = require("http"); function h(u) { request(u); }'),
    'http.request', 'aliased-call', 'colliding destructured name, tainted argument',
  );
  assertOneFinding(
    run(ssrf, 'const { request } = require("http"); request("https://example.com");'),
    'http.request', 'aliased-call', 'colliding destructured name, clean argument',
  );
});

// ------------------------------------------------------- pattern (d)

test('import resolution: ESM imports resolve (named, default, namespace)', () => {
  const cases = [
    [commandExec, 'child_process.exec', 'aliased-call', 'import { exec } from "child_process"; function h(d) { exec(d); }'],
    [commandExec, 'child_process.exec', 'aliased-call', 'import { exec as e } from "child_process"; function h(d) { e(d); }'],
    [commandExec, 'child_process.exec', 'tainted-arg', 'import cp from "child_process"; function h(d) { cp.exec(d); }'],
    [commandExec, 'child_process.exec', 'tainted-arg', 'import * as cp from "child_process"; function h(d) { cp.exec(d); }'],
    [commandExec, 'child_process.exec', 'tainted-arg', 'import cp, { exec } from "child_process"; function h(d) { cp.exec(d); }'],
    [pathTraversal, 'fs.readFile', 'aliased-call', 'import { readFile } from "fs"; function h(d) { readFile(d); }'],
    [pathTraversal, 'fs.readFile', 'tainted-arg', 'import fs from "fs"; function h(d) { fs.readFile(d); }'],
    [pathTraversal, 'fs.readFile', 'tainted-arg', 'import * as fs from "fs"; function h(d) { fs.readFile(d); }'],
    [ssti, 'ejs.render', 'aliased-call', 'import { render } from "ejs"; function h(d) { render(d); }'],
    [deserialize, 'yaml.load', 'aliased-call', 'import { load } from "js-yaml"; function h(d) { load(d); }'],
    [deserialize, 'yaml.load', 'tainted-arg', 'import y from "js-yaml"; function h(d) { y.load(d); }'],
    [ssrf, 'http.get', 'tainted-arg', 'import http from "http"; function h(d) { http.get(d); }'],
    [ssrf, 'http.request', 'aliased-call', 'import { request } from "http"; function h(u) { request(u); }'],
    [ssrf, 'request', 'aliased-call', 'import rq from "request"; function h(u) { rq(u); }'],
    [ldap, 'client.search', 'tainted-arg', 'import client from "ldapjs"; function h(d) { client.search("dc=example,dc=com", d); }'],
    [ldap, 'client.search', 'aliased-call', 'import { search } from "ldapjs"; function h(d) { search("dc=example,dc=com", d); }'],
    [xpath, 'xpath.select', 'tainted-arg', 'import xpath from "xpath"; function h(d) { xpath.select(d, doc); }'],
    [xpath, 'xpath.select', 'aliased-call', 'import { select } from "xpath"; function h(d) { select(d, doc); }'],
    [xpath, 'xpath.select', 'tainted-arg', 'import * as xpath from "xpath"; function h(d) { xpath.select(d, doc); }'],
    [xxe, 'libxmljs.parseXml', 'tainted-arg', 'import libxmljs from "libxmljs"; function h(d) { libxmljs.parseXml(d, { noent: true }); }'],
    [xxe, 'libxmljs.parseXml', 'aliased-call', 'import { parseXml } from "libxmljs"; function h(d) { parseXml(d, { noent: true }); }'],
    [xxe, 'libxmljs.parseXml', 'tainted-arg', 'import * as libxmljs from "libxmljs"; function h(d) { libxmljs.parseXml(d, { noent: true }); }'],
    [prototypePollution, '_.merge', 'tainted-arg', 'import _ from "lodash"; function h(d) { _.merge({}, d); }'],
    [prototypePollution, '_.merge', 'aliased-call', 'import { merge } from "lodash"; function h(d) { merge({}, d); }'],
    [prototypePollution, '_.merge', 'tainted-arg', 'import * as _ from "lodash"; function h(d) { _.merge({}, d); }'],
    [prototypePollution, 'merge', 'aliased-call', 'import merge from "deepmerge"; function h(d) { merge({}, d); }'],
  ];
  for (const [detect, sink, kind, content] of cases) {
    assertOneFinding(run(detect, content), sink, kind, content);
  }
  // Imports hoist like function declarations: a sink call
  // textually before its import still resolves.
  assertOneFinding(
    run(commandExec, 'function h(d) { cp.exec(d); } import cp from "child_process";'),
    'child_process.exec', 'tainted-arg', 'use before import',
  );
  // A side-effect import does not break the parse, and the
  // bare member call still resolves by name.
  assertOneFinding(
    run(commandExec, 'import "child_process"; function h(d) { child_process.exec(d); }'),
    'child_process.exec', 'tainted-arg', 'side-effect import',
  );
  // A named import of a non-sink member binds clean with
  // no sink info.
  assertNoFinding(
    run(sql, 'import { query } from "pg"; function h(d) { query(d); }'),
    'named import from an unmapped module',
  );
});

// ------------------------------------------------------- negatives

test('import resolution: dynamic, relative, unknown, and re-exported imports stay unresolved', () => {
  const cases = [
    [commandExec, 'function h(m) { require(m).exec("ls"); }'],
    [commandExec, 'function h(d) { require("child_" + "process").exec(d); }'],
    [commandExec, 'function h(d) { require("unknown-lib").exec(d); }'],
    [commandExec, 'function h(d) { require("./lib").exec(d); }'],
    [commandExec, 'function h(d) { require("../lib").exec(d); }'],
    [commandExec, 'export { exec } from "child_process"; function h(d) { exec(d); }'],
    [commandExec, 'export * from "child_process"; function h(d) { exec(d); }'],
    [commandExec, 'module.exports = require("child_process"); function h(d) { module.exports.exec(d); }'],
    // Object-property indirection is the deep-alias pin:
    // the sink is reached through an object literal, not
    // a binding, so it does not resolve.
    [commandExec, 'const o = { exec: require("child_process").exec }; function h(d) { o.exec(d); }'],
    // The `yaml` package is not mapped (its API is
    // `parse`, not `load`).
    [deserialize, 'const y = require("yaml"); function h(d) { y.load(d); }'],
    [deserialize, 'const { load } = require("yaml"); function h(d) { load(d); }'],
    // SQL has no import mapping at all.
    [sql, 'function h(d) { require("pg").query(d); }'],
    [sql, 'const { query } = require("pg"); function h(d) { query(d); }'],
    // XXE has a mapping, but the `noent: true` gate still
    // applies through a require call: without the literal
    // the call is not a finding.
    [xxe, 'function h(d) { require("libxmljs").parseXml(d); }'],
    [xxe, 'function h(d) { const x = require("libxmljs"); x.parseXml(d, { noent: false }); }'],
    // ReDoS has no import mapping at all.
    [redos, 'function h(d) { require("regexp").RegExp(d); }'],
    // Prototype pollution has a mapping, but an unknown
    // module or a relative path carries none.
    [prototypePollution, 'function h(d) { const x = require("unknown-lib"); x.merge({}, d); }'],
    [prototypePollution, 'function h(d) { const x = require("./lodash"); x.merge({}, d); }'],
    // A shadowed `require` disables the resolution (like
    // the sanitizer shadowing rule).
    [commandExec, 'function require(x) { return x; } function h(d) { require("child_process").exec(d); }'],
  ];
  for (const [detect, content] of cases) {
    assertNoFinding(run(detect, content), content);
  }
});

// ------------------------------------------------------- parser fallback

test('import resolution: exotic import forms fall back to the structural skip and the record still scans', () => {
  // A string imported name is outside the supported forms:
  // the import is skipped structurally, the sink call
  // after it still resolves by name.
  assertOneFinding(
    run(commandExec, 'import { "weird-name" as x } from "child_process"; function h(d) { child_process.exec(d); }'),
    'child_process.exec', 'tainted-arg', 'string imported name',
  );
  // Dynamic import is an expression, not a declaration:
  // skipped structurally, the rest still scans.
  assertOneFinding(
    run(commandExec, 'import("child_process").then(m => m); function h(d) { child_process.exec(d); }'),
    'child_process.exec', 'tainted-arg', 'dynamic import',
  );
});

test('import resolution: a record calling a bare `get` is skipped, not scanned (parser keyword)', () => {
  // The round-101 keyword limitation, unchanged by import
  // resolution: `get` cannot be a bare identifier, so a
  // record that calls it does not parse at all — including
  // when `get` came from an import.
  const result = run(ssrf, 'import { get } from "http"; function h(u) { get(u); }');
  assert.equal(result.findings.length, 0, 'no findings for an unparsable record');
  assert.equal(result.skipped, 1, 'record skipped');
});

test('import resolution: a record calling a bare `set` is skipped, not scanned (parser keyword, round 114)', () => {
  // The same round-101 keyword limitation, for the other
  // accessor keyword: `set` cannot be a bare identifier,
  // so a record that calls a destructured `_.set` does
  // not parse at all — the member form (`_.set(...)`)
  // parses and resolves normally, only the bare
  // destructured call is unscanable. The record is
  // skipped with a parse error, never scanned silently.
  const result = run(prototypePollution, 'const { set } = require("lodash"); function h(p) { set({}, p, 1); }');
  assert.equal(result.findings.length, 0, 'no findings for an unparsable record');
  assert.equal(result.skipped, 1, 'record skipped');
  assert.match(result.errors[0], /unexpected keyword set/);
});

// ------------------------------------------------------- inter-procedural

test('import resolution: taint flows through helpers reached via an import alias', () => {
  // Sink inside a helper, called with a tainted argument
  // through a require alias.
  const content = 'const cp = require("child_process");'
    + 'function run(cmd) { cp.exec(cmd); }'
    + 'function h(d) { run(d); }';
  const result = run(commandExec, content);
  assertOneFinding(result, 'child_process.exec', 'tainted-arg', content);
  assert.ok(
    result.findings[0].description.includes('run'),
    'chain names the cross-function flow',
  );
  // The round-95 fallback: a helper never called still
  // flags its sink with parameters-as-sources.
  const fallback = 'import { exec } from "child_process"; function run(cmd) { exec(cmd); }';
  assertOneFinding(run(commandExec, fallback), 'child_process.exec', 'aliased-call', fallback);
});
