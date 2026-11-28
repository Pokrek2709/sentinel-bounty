// Tests for the tainted-unserialize detector
// (src/detection/tainted-unserialize.js, round 116).
// Positive cases must produce exactly one finding per
// sink call site with CWE-502 and evidence carrying the
// sink, the kind, and a non-empty notes string.
// Negative cases must produce zero findings. The
// detector runs on the PHP subset AST — it never reuses
// the JavaScript taint engine or the Python analyzer.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detector = require('../src/detection/tainted-unserialize.js');

const IDS = { session_id: 's1', target_id: 't1', asset_id: 'a1' };

function detect(source, extra) {
  const report = detector({ content: source, language: 'php', ...IDS, ...(extra || {}) });
  assert.equal(report.skipped, 0, `expected no skipped records, got errors: ${report.errors.join('; ')}`);
  return report.findings;
}

function detectSkipped(source) {
  const report = detector({ content: source, language: 'php', ...IDS });
  assert.equal(report.findings.length, 0);
  assert.equal(report.skipped, 1);
  return report;
}

test('detector: unserialize of $_POST is flagged (CWE-502)', () => {
  const findings = detect('<?php $o = unserialize($_POST["data"]); ?>');
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.discovery_tool, 'tainted-unserialize');
  assert.equal(finding.vulnerability_type, 'insecure deserialization');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-502');
  assert.equal(finding.evidence[0].type, 'ast-call');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'unserialize');
  assert.deepEqual(finding.evidence[0].chain, ['_POST']);
  assert.match(finding.evidence[0].notes, /unserialize/);
  assert.equal(typeof finding.finding_id, 'string');
  assert.match(finding.finding_id, /^tainted-unserialize-[0-9a-f]{16}$/);
});

test('detector: all superglobals are sources', () => {
  for (const global of ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES']) {
    const findings = detect(`<?php $o = unserialize($${global}["d"]); ?>`);
    assert.equal(findings.length, 1, `$${global} should be a source`);
    assert.deepEqual(findings[0].evidence[0].chain, [global]);
  }
});

test('detector: $_SERVER, $_SESSION, $GLOBALS and $_ENV are NOT sources', () => {
  for (const global of ['_SERVER', '_SESSION', 'GLOBALS', '_ENV']) {
    assert.equal(detect(`<?php $o = unserialize($${global}["d"]); ?>`).length, 0,
      `$${global} must not be a source`);
  }
});

test('detector: file_get_contents php://input is a source', () => {
  const findings = detect('<?php $d = file_get_contents("php://input"); $o = unserialize($d); ?>');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['php://input', 'd']);
});

test('detector: a constant argument is clean', () => {
  assert.equal(detect('<?php $o = unserialize("a:0:{}"); ?>').length, 0);
  assert.equal(detect('<?php $d = "a:0:{}"; $o = unserialize($d); ?>').length, 0);
});

test('detector: the allowed_classes gate', () => {
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["allowed_classes" => false]); ?>').length, 0,
    'allowed_classes => false is clean');
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["allowed_classes" => []]); ?>').length, 0,
    'an empty allow-list allows no classes, so it is clean');
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["allowed_classes" => ["Foo"]]); ?>').length, 1,
    'a non-empty allow-list is still flagged');
  assert.equal(detect('<?php $o = unserialize($_POST["d"], $opts); ?>').length, 1,
    'options as a variable are flagged (no constant propagation)');
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["max_depth" => 3]); ?>').length, 1,
    'options without allowed_classes are flagged');
  assert.equal(detect('<?php $o = unserialize(data: $_POST["d"], options: ["allowed_classes" => false]); ?>').length, 0,
    'the named options: keyword gates too');
  assert.equal(detect('<?php $o = unserialize(data: $_POST["d"], options: ["allowed_classes" => ["Foo"]]); ?>').length, 1,
    'the named options: keyword with a non-empty list is flagged');
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["allowed_classes" => true]); ?>').length, 1,
    'allowed_classes => true is flagged');
});

test('detector: the judged argument is positional 0 or named data:', () => {
  assert.equal(detect('<?php $o = unserialize(data: $_POST["d"]); ?>').length, 1);
  assert.equal(detect('<?php $o = unserialize(data: "a:0:{}"); ?>').length, 0);
  assert.equal(detect('<?php $o = unserialize($_POST["d"], ["allowed_classes" => false], "extra"); ?>').length, 0,
    'the gate is judged on argument 1 even with further arguments');
});

test('detector: json_decode is not a sink; json round-trips sanitize', () => {
  assert.equal(detect('<?php $o = json_decode($_POST["d"]); ?>').length, 0);
  assert.equal(detect('<?php $o = json_decode($_POST["d"], true); ?>').length, 0);
  assert.equal(detect('<?php $o = unserialize(json_decode($_POST["d"])); ?>').length, 0,
    'json_decode output cannot be a PHP serialized object graph');
  assert.equal(detect('<?php $o = unserialize(json_encode($_POST["d"])); ?>').length, 0,
    'json_encode output is JSON syntax, not serialized PHP');
});

test('detector: sanitizers cleanse the data', () => {
  for (const cast of ['int', 'float', 'bool', 'array']) {
    assert.equal(detect(`<?php $o = unserialize((${cast}) $_POST["d"]); ?>`).length, 0,
      `(${cast}) should cleanse`);
  }
  for (const fn of ['intval', 'floatval', 'boolval']) {
    assert.equal(detect(`<?php $o = unserialize(${fn}($_POST["d"])); ?>`).length, 0,
      `${fn}() should cleanse`);
  }
  assert.equal(detect('<?php $o = unserialize((string) $_POST["d"]); ?>').length, 1,
    '(string) is NOT a sanitizer — the attacker string passes through');
  assert.equal(detect('<?php $o = unserialize(base64_decode($_POST["d"])); ?>').length, 1,
    'base64_decode does not cleanse (it only re-encodes the attacker bytes)');
});

test('detector: use function aliases are aliased-call sinks', () => {
  const aliased = detect('<?php use function unserialize as u; $o = u("clean"); ?>');
  assert.equal(aliased.length, 1, 'an aliased call is reported with ANY argument');
  assert.equal(aliased[0].evidence[0].kind, 'aliased-call');
  assert.deepEqual(aliased[0].evidence[0].chain, []);
  const aliasedTainted = detect('<?php use function unserialize as u; $o = u($_POST["d"]); ?>');
  assert.equal(aliasedTainted.length, 1);
  assert.equal(aliasedTainted[0].evidence[0].kind, 'aliased-call');
  assert.deepEqual(aliasedTainted[0].evidence[0].chain, ['_POST']);
});

test('detector: qualified and fully-qualified names', () => {
  assert.equal(detect('<?php $o = \\unserialize($_POST["d"]); ?>').length, 1,
    '\\unserialize is the global sink');
  assert.equal(detect('<?php $o = Foo\\unserialize($_POST["d"]); ?>').length, 0,
    'Foo\\unserialize is a different function, not the sink');
  assert.equal(detect('<?php use function foo\\unserialize as u; $o = u($_POST["d"]); ?>').length, 0,
    'an alias bound to a namespaced function is not the global sink');
  assert.equal(detect('<?php use function foo\\unserialize; $o = unserialize($_POST["d"]); ?>').length, 0,
    'a use import of a namespaced unserialize shadows the global fallback');
});

test('detector: a method named unserialize is not a sink', () => {
  assert.equal(detect('<?php $o = $x->unserialize($_POST["d"]); ?>').length, 0);
  assert.equal(detect('<?php $o = Foo::unserialize($_POST["d"]); ?>').length, 0);
});

test('detector: allow-list guards do NOT apply to unserialize', () => {
  assert.equal(detect('<?php $d = $_POST["d"]; if (in_array($d, $allowed, true)) { $o = unserialize($d); } ?>').length, 1,
    'checking the data against a list does not make deserializing it safe');
});

test('detector: inter-procedural taint through known functions', () => {
  const viaCall = detect('<?php function load($d) { return unserialize($d); } $x = load($_GET["d"]); ?>');
  assert.equal(viaCall.length, 1);
  assert.deepEqual(viaCall[0].evidence[0].chain, ['d']);
  assert.equal(viaCall[0].evidence[0].function, 'load');

  const fallback = detect('<?php function load($d) { return unserialize($d); } ?>');
  assert.equal(fallback.length, 1, 'an uncalled helper is still analyzed with its parameters as sources');

  const caseInsensitive = detect('<?php function LOAD($d) { return unserialize($d); } $x = load($_GET["d"]); ?>');
  assert.equal(caseInsensitive.length, 1, 'PHP function names are case-insensitive');

  const returnsTainted = detect('<?php function get($p) { return $p; } $o = unserialize(get($_POST["d"])); ?>');
  assert.equal(returnsTainted.length, 1, 'taint flows through a return value into the sink');

  const cleanReturn = detect('<?php function clean($p) { return (array) $p; } $o = unserialize(clean($_POST["d"])); ?>');
  assert.equal(cleanReturn.length, 0, 'a callee that sanitizes cleanses the return');
});

test('detector: variable function calls and call_user_func are NOT modeled', () => {
  assert.equal(detect('<?php $f = "unserialize"; $o = $f($_POST["d"]); ?>').length, 0,
    'a variable function call is not resolved (pinned, see the doc)');
  assert.equal(detect('<?php $o = call_user_func("unserialize", $_POST["d"]); ?>').length, 0,
    'call_user_func is not resolved (pinned, see the doc)');
});

test('detector: one finding per sink site', () => {
  const two = detect('<?php $a = unserialize($_GET["a"]); $b = unserialize($_GET["b"]); ?>');
  assert.equal(two.length, 2);
  const dupe = detect('<?php function load($d) { return unserialize($d); } load($_GET["a"]); load($_GET["b"]); ?>');
  assert.equal(dupe.length, 1, 'the same sink site is reported once even when reached twice');
});

test('detector: envelope — batch, language, empty and unparseable records', () => {
  const batch = detector({
    tool: 'batch-tool',
    results: [
      { content: '<?php $o = unserialize($_POST["d"]); ?>', language: 'php', ...IDS },
      { content: '<?php $o = json_decode($_POST["d"]); ?>', language: 'php', ...IDS },
    ],
  }, IDS);
  assert.equal(batch.findings.length, 1);
  assert.equal(batch.findings[0].discovery_tool, 'batch-tool');
  assert.equal(batch.skipped, 0);

  assert.throws(
    () => detector(null, IDS),
    /DETECTOR_INVALID_INPUT/,
  );

  const wrongLanguage = detector({ content: '<?php $o = unserialize($_POST["d"]); ?>', language: 'python', ...IDS }, IDS);
  assert.equal(wrongLanguage.findings.length, 0);
  assert.equal(wrongLanguage.skipped, 1);
  assert.match(wrongLanguage.errors[0], /not PHP/);

  const empty = detector({ content: '   ', language: 'php', ...IDS }, IDS);
  assert.equal(empty.skipped, 1);

  const unparseable = detectSkipped('<?php class Foo {} ?>');
  assert.match(unparseable.errors[0], /failed to parse content as PHP/);
});
