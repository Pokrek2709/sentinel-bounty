// Tests for the tainted-pickle detector
// (src/detection/tainted-pickle.js, round 115).
// Positive cases must produce exactly one finding per
// sink call site with CWE-502 and evidence carrying the
// sink, the kind, and a non-empty notes string.
// Negative cases must produce zero findings. The
// detector runs on the Python subset AST — it never
// reuses the JavaScript taint engine.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detector = require('../src/detection/tainted-pickle.js');

const IDS = { session_id: 's1', target_id: 't1', asset_id: 'a1' };

function detect(source, extra) {
  const report = detector({ content: source, language: 'python', ...IDS, ...(extra || {}) });
  assert.equal(report.skipped, 0, `expected no skipped records, got errors: ${report.errors.join('; ')}`);
  return report.findings;
}

function detectSkipped(source) {
  const report = detector({ content: source, language: 'python', ...IDS });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
  return report;
}

test('detector: pickle.loads on input() is flagged (CWE-502)', () => {
  const findings = detect('import pickle\n\ndata = input()\nobj = pickle.loads(data)\n');
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.discovery_tool, 'tainted-pickle');
  assert.equal(finding.vulnerability_type, 'insecure deserialization');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-502');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'pickle.loads');
  assert.deepEqual(finding.evidence[0].chain, ['input', 'data']);
  assert.match(finding.evidence[0].notes, /pickle\.loads/);
  assert.equal(typeof finding.finding_id, 'string');
  assert.match(finding.finding_id, /^tainted-pickle-[0-9a-f]{16}$/);
});

test('detector: pickle.load and marshal sinks are flagged', () => {
  const load = detect('import pickle\n\nwith open("f", "rb") as f:\n    obj = pickle.load(f)\n');
  assert.equal(load.length, 0, 'a file object from open() is not a tainted source');

  const taintedLoad = detect('import pickle\n\ndef handle(f):\n    return pickle.load(f)\n');
  assert.equal(taintedLoad.length, 1);
  assert.equal(taintedLoad[0].evidence[0].sink, 'pickle.load');
  assert.equal(taintedLoad[0].evidence[0].kind, 'tainted-arg');

  const marshal = detect('import marshal\n\ndef handle(data):\n    return marshal.loads(data)\n');
  assert.equal(marshal.length, 1);
  assert.equal(marshal[0].evidence[0].sink, 'marshal.loads');

  const marshalLoad = detect('import marshal\n\ndef handle(f):\n    return marshal.load(f)\n');
  assert.equal(marshalLoad.length, 1);
  assert.equal(marshalLoad[0].evidence[0].sink, 'marshal.load');
});

test('detector: sys.argv is a source', () => {
  const findings = detect('import pickle\nimport sys\n\nobj = pickle.loads(sys.argv[1])\n');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['sys.argv']);
});

test('detector: from sys import argv binds the source', () => {
  const findings = detect('import pickle\nfrom sys import argv\n\nobj = pickle.loads(argv[1])\n');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['sys.argv']);
});

test('detector: Flask request attributes are sources', () => {
  for (const attr of ['args', 'form', 'data', 'json', 'values', 'files']) {
    const findings = detect(`import pickle\n\ndef handle():\n    data = request.${attr}["q"]\n    return pickle.loads(data)\n`);
    assert.equal(findings.length, 1, `request.${attr} should be a source`);
    assert.deepEqual(findings[0].evidence[0].chain, ['request', 'data']);
  }
});

test('detector: Flask request via flask.request and via alias', () => {
  const viaFlask = detect('import pickle\nimport flask\n\ndef handle():\n    return pickle.loads(flask.request.args["q"])\n');
  assert.equal(viaFlask.length, 1);

  const viaAlias = detect('import pickle\nfrom flask import request as req\n\ndef handle():\n    return pickle.loads(req.form["q"])\n');
  assert.equal(viaAlias.length, 1);
});

test('detector: request.get_json() is a source', () => {
  const findings = detect('import pickle\n\ndef handle():\n    payload = request.get_json()\n    return pickle.loads(payload["blob"])\n');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['request', 'payload']);
});

test('detector: bare request alone is not a source', () => {
  const findings = detect('import pickle\n\ndef handle():\n    return pickle.loads(request)\n');
  assert.equal(findings.length, 0);
});

test('detector: os.environ is NOT a source', () => {
  const findings = detect('import pickle\nimport os\n\ndef handle():\n    return pickle.loads(os.environ["BLOB"])\n');
  assert.equal(findings.length, 0, 'os.environ is operator-controlled config, not attacker input');
});

test('detector: taint flows through a variable and through a call', () => {
  const throughVar = detect('import pickle\n\ndef handle(blob):\n    data = blob\n    return pickle.loads(data)\n');
  assert.equal(throughVar.length, 1);
  assert.deepEqual(throughVar[0].evidence[0].chain, ['blob', 'data']);

  const throughCall = detect('import pickle\n\ndef handle(blob):\n    return pickle.loads(blob.strip())\n');
  assert.equal(throughCall.length, 1);
});

test('detector: taint flows through tuple unpacking', () => {
  const findings = detect('import pickle\n\ndef handle(pair):\n    first, second = pair\n    return pickle.loads(second)\n');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['pair', 'second']);
});

test('detector: taint flows through a binary expression and an f-string', () => {
  const binary = detect('import pickle\n\ndef handle(blob):\n    return pickle.loads(blob + b"==")\n');
  assert.equal(binary.length, 1);

  const fstring = detect('import pickle\n\ndef handle(blob):\n    text = f"prefix-{blob}"\n    return pickle.loads(text)\n');
  assert.equal(fstring.length, 1);
  assert.deepEqual(fstring[0].evidence[0].chain, ['blob', 'text']);
});

test('detector: inter-procedural flow through a helper and its return', () => {
  const findings = detect(
    'import pickle\n'
    + '\n'
    + 'def fetch_payload(raw):\n'
    + '    return raw\n'
    + '\n'
    + 'def handle():\n'
    + '    blob = input()\n'
    + '    payload = fetch_payload(blob)\n'
    + '    return pickle.loads(payload)\n',
  );
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence[0].chain.includes('fetch_payload'), `chain should prove the call-graph flow, got ${findings[0].evidence[0].chain}`);
});

test('detector: a helper never called is still flagged (parameters-as-sources fallback)', () => {
  const findings = detect('import pickle\n\ndef load_blob(blob):\n    return pickle.loads(blob)\n');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['blob']);
});

test('detector: a helper called only with clean arguments is still flagged (fallback)', () => {
  const findings = detect(
    'import pickle\n'
    + '\n'
    + 'def load_blob(blob):\n'
    + '    return pickle.loads(blob)\n'
    + '\n'
    + 'obj = load_blob(b"constant")\n',
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['blob']);
});

test('detector: from-import sink binding is an aliased call (any argument)', () => {
  const findings = detect('from pickle import loads\n\nobj = loads(b"constant")\n');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].kind, 'aliased-call');
  assert.equal(findings[0].evidence[0].sink, 'pickle.loads');

  const aliased = detect('from pickle import loads as ld\n\ndef handle(x):\n    return ld(x)\n');
  assert.equal(aliased.length, 1);
  assert.equal(aliased[0].evidence[0].kind, 'aliased-call');
});

test('detector: module alias and member alias resolve', () => {
  const moduleAlias = detect('import pickle as pk\n\ndef handle(blob):\n    return pk.loads(blob)\n');
  assert.equal(moduleAlias.length, 1);
  assert.equal(moduleAlias[0].evidence[0].kind, 'tainted-arg');
  assert.equal(moduleAlias[0].evidence[0].sink, 'pickle.loads');

  const memberAlias = detect('import pickle\n\nld = pickle.loads\n\ndef handle(blob):\n    return ld(blob)\n');
  assert.equal(memberAlias.length, 1);
  assert.equal(memberAlias[0].evidence[0].kind, 'aliased-call');
});

test('detector: bare loads() with no import binding is NOT a sink', () => {
  const bare = detect('def handle(data):\n    return loads(data)\n');
  assert.equal(bare.length, 0, 'a bare loads() may be json.loads — no name-based bare sink');

  const jsonLoads = detect('from json import loads\n\ndef handle(data):\n    return loads(data)\n');
  assert.equal(jsonLoads.length, 0);
});

test('detector: yaml.load without a Loader is flagged', () => {
  const findings = detect('import yaml\n\ndef handle(text):\n    return yaml.load(text)\n');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].sink, 'yaml.load');
});

test('detector: yaml.load with an unsafe Loader is flagged', () => {
  const findings = detect('import yaml\n\ndef handle(text):\n    return yaml.load(text, Loader=yaml.UnsafeLoader)\n');
  assert.equal(findings.length, 1);
});

test('detector: yaml.load with SafeLoader is clean', () => {
  const viaMember = detect('import yaml\n\ndef handle(text):\n    return yaml.load(text, Loader=yaml.SafeLoader)\n');
  assert.equal(viaMember.length, 0);

  const viaCSafe = detect('import yaml\n\ndef handle(text):\n    return yaml.load(text, Loader=yaml.CSafeLoader)\n');
  assert.equal(viaCSafe.length, 0);

  const viaImport = detect('import yaml\nfrom yaml import SafeLoader\n\ndef handle(text):\n    return yaml.load(text, Loader=SafeLoader)\n');
  assert.equal(viaImport.length, 0);
});

test('detector: yaml.safe_load and json.loads are not sinks', () => {
  const safe = detect('import yaml\n\ndef handle(text):\n    return yaml.safe_load(text)\n');
  assert.equal(safe.length, 0);

  const json = detect('import json\n\ndef handle(text):\n    return json.loads(text)\n');
  assert.equal(json.length, 0);
});

test('detector: shelve.open with a tainted filename is flagged', () => {
  const findings = detect('import shelve\n\ndef handle(name):\n    db = shelve.open(name)\n    return db\n');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence[0].sink, 'shelve.open');

  const clean = detect('import shelve\n\ndb = shelve.open("local.db")\n');
  assert.equal(clean.length, 0);
});

test('detector: sanitizers cleanse the taint', () => {
  for (const call of ['int(blob)', 'float(blob)', 'str(blob)', 'bool(blob)', 'len(blob)', 'repr(blob)']) {
    const findings = detect(`import pickle\n\ndef handle(blob):\n    return pickle.loads(${call})\n`);
    assert.equal(findings.length, 0, `${call} should cleanse`);
  }
  const decode = detect('import pickle\n\ndef handle(blob):\n    return pickle.loads(blob.decode())\n');
  assert.equal(decode.length, 0, '.decode() returns str, not bytes');
  const jsonSanitizer = detect('import pickle\nimport json\n\ndef handle(text):\n    return pickle.loads(json.loads(text))\n');
  assert.equal(jsonSanitizer.length, 0, 'json.loads output is not bytes');
});

test('detector: a constant argument is clean', () => {
  const findings = detect('import pickle\n\nobj = pickle.loads(b"constant")\n');
  assert.equal(findings.length, 0);
});

test('detector: pickle.Unpickler is out of scope (pinned)', () => {
  const findings = detect('import pickle\n\ndef handle(f):\n    return pickle.Unpickler(f).load()\n');
  assert.equal(findings.length, 0, 'Unpickler(...).load() is not modeled this round');
});

test('detector: dill is out of scope (pinned)', () => {
  const findings = detect('import dill\n\ndef handle(data):\n    return dill.loads(data)\n');
  assert.equal(findings.length, 0, 'dill is not in the sink table this round');
});

test('detector: keyword judged argument is judged', () => {
  const findings = detect('import pickle\n\ndef handle(blob):\n    return pickle.loads(data=blob)\n');
  assert.equal(findings.length, 1);

  const clean = detect('import pickle\n\ndef handle(blob):\n    return pickle.loads(data=b"constant")\n');
  assert.equal(clean.length, 0);
});

test('detector: a sink inside a branch test is seen', () => {
  const findings = detect('import pickle\n\ndef handle(blob):\n    if pickle.loads(blob):\n        return True\n    return False\n');
  assert.equal(findings.length, 1);
});

test('detector: taint survives a branch join (either branch)', () => {
  const findings = detect(
    'import pickle\n'
    + '\n'
    + 'def handle(flag, blob):\n'
    + '    data = b"clean"\n'
    + '    if flag:\n'
    + '        data = blob\n'
    + '    return pickle.loads(data)\n',
  );
  assert.equal(findings.length, 1);
});

test('detector: one finding per sink site (no duplicates)', () => {
  const findings = detect(
    'import pickle\n'
    + '\n'
    + 'def load_blob(blob):\n'
    + '    return pickle.loads(blob)\n'
    + '\n'
    + 'obj = load_blob(input())\n',
  );
  assert.equal(findings.length, 1, 'the same site found via the call graph and via the fallback is one finding');
});

test('detector: methods are not resolved through the call graph (pinned)', () => {
  const findings = detect(
    'import pickle\n'
    + '\n'
    + 'def handle(blob):\n'
    + '    return self.helper(blob)\n',
  );
  assert.equal(findings.length, 0, 'a method call is an unknown function; its return is clean without a tainted argument flowing in');
});

test('detector: non-Python language is refused', () => {
  const report = detector({ content: 'pickle.loads(x)', language: 'javascript', ...IDS });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
  assert.match(report.errors[0], /not Python/);
});

test('detector: unparseable Python is skipped, never scanned', () => {
  detectSkipped('class Foo:\n    pass\n');
  detectSkipped('import pickle\nobj = pickle.loads([x for x in y])\n');
});

test('detector: empty content and batch records', () => {
  const empty = detector({ content: '   ', language: 'python', ...IDS });
  assert.equal(empty.skipped, 1);
  assert.equal(empty.findings.length, 0);

  const batch = detector({
    tool: 'test-batch',
    results: [
      { content: 'import pickle\nobj = pickle.loads(input())\n', language: 'python', ...IDS },
      { content: 'import pickle\nobj = pickle.loads(b"clean")\n', language: 'python', ...IDS },
    ],
  });
  assert.equal(batch.skipped, 0);
  assert.equal(batch.findings.length, 1);
  assert.equal(batch.findings[0].discovery_tool, 'test-batch');
});

test('detector: finding carries no literal value or source line', () => {
  const findings = detect('import pickle\n\nobj = pickle.loads(input())\n');
  const serialized = JSON.stringify(findings[0]);
  assert.ok(!serialized.includes('input()'), 'no source line in the finding');
});
