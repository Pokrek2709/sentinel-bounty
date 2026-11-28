// Tests for the tainted-include detector
// (src/detection/tainted-include.js, round 116).
// Positive cases must produce exactly one finding per
// sink call site with CWE-98 and evidence carrying the
// sink, the kind, and a non-empty notes string.
// Negative cases must produce zero findings. The
// detector runs on the PHP subset AST — it never reuses
// the JavaScript taint engine or the Python analyzer.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const detector = require('../src/detection/tainted-include.js');

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

test('detector: include of $_GET is flagged (CWE-98)', () => {
  const findings = detect('<?php include $_GET["page"]; ?>');
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.discovery_tool, 'tainted-include');
  assert.equal(finding.vulnerability_type, 'improper control of filename for include/require statement');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.cwe_id, 'CWE-98');
  assert.equal(finding.evidence[0].type, 'ast-include');
  assert.equal(finding.evidence[0].kind, 'tainted-arg');
  assert.equal(finding.evidence[0].sink, 'include');
  assert.deepEqual(finding.evidence[0].chain, ['_GET']);
  assert.match(finding.evidence[0].notes, /include/);
  assert.equal(typeof finding.finding_id, 'string');
  assert.match(finding.finding_id, /^tainted-include-[0-9a-f]{16}$/);
});

test('detector: all four include constructs are sinks', () => {
  for (const kw of ['include', 'require', 'include_once', 'require_once']) {
    const findings = detect(`<?php ${kw} $_POST["f"]; ?>`);
    assert.equal(findings.length, 1, `${kw} should be a sink`);
    assert.equal(findings[0].evidence[0].sink, kw);
    const paren = detect(`<?php ${kw}($_POST["f"]); ?>`);
    assert.equal(paren.length, 1, `${kw}(...) should be a sink`);
    assert.equal(paren[0].evidence[0].sink, kw);
  }
  const asExpr = detect('<?php $a = include $_GET["f"]; ?>');
  assert.equal(asExpr.length, 1, 'include as an expression is a sink');
});

test('detector: all superglobals are sources, bare and subscripted', () => {
  for (const global of ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES']) {
    const sub = detect(`<?php include $${global}["f"]; ?>`);
    assert.equal(sub.length, 1, `$${global}["f"] should be a source`);
    assert.deepEqual(sub[0].evidence[0].chain, [global]);
    const bare = detect(`<?php include $${global}; ?>`);
    assert.equal(bare.length, 1, `bare $${global} should be a source`);
    assert.deepEqual(bare[0].evidence[0].chain, [global]);
  }
});

test('detector: $_SERVER, $_SESSION, $GLOBALS and $_ENV are NOT sources', () => {
  for (const global of ['_SERVER', '_SESSION', 'GLOBALS', '_ENV']) {
    const findings = detect(`<?php include $${global}["f"]; ?>`);
    assert.equal(findings.length, 0, `$${global} must not be a source`);
  }
  assert.equal(detect('<?php include $_SERVER["DOCUMENT_ROOT"] . "/lib.php"; ?>').length, 0);
});

test('detector: file_get_contents php://input is a source', () => {
  const findings = detect('<?php $d = file_get_contents("php://input"); include $d; ?>');
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].evidence[0].chain, ['php://input', 'd']);
  assert.equal(detect('<?php $d = file_get_contents("/etc/passwd"); include $d; ?>').length, 0,
    'file_get_contents of a constant path is not a source');
  assert.equal(detect('<?php $d = file_get_contents($_GET["f"]); include $d; ?>').length, 1,
    'file_get_contents of a tainted path is tainted (unknown-call rule)');
});

test('detector: a constant path is clean', () => {
  assert.equal(detect('<?php include "config.php"; ?>').length, 0);
  assert.equal(detect('<?php include __DIR__ . "/lib.php"; ?>').length, 0);
  assert.equal(detect('<?php $f = "a.php"; include $f; ?>').length, 0);
});

test('detector: taint flows through assignments and expressions', () => {
  const assigned = detect('<?php $f = $_GET["f"]; include $f; ?>');
  assert.equal(assigned.length, 1);
  assert.deepEqual(assigned[0].evidence[0].chain, ['_GET', 'f']);

  const concat = detect('<?php include "pages/" . $_GET["p"] . ".php"; ?>');
  assert.equal(concat.length, 1);
  assert.deepEqual(concat[0].evidence[0].chain, ['_GET']);

  const interp = detect('<?php include "pages/{$_GET["p"]}.php"; ?>');
  assert.equal(interp.length, 1);

  const ternary = detect('<?php $f = $_GET["a"] ? $_GET["b"] : "c.php"; include $f; ?>');
  assert.equal(ternary.length, 1);

  const list = detect('<?php list($a, $b) = [$_GET["f"], "x.php"]; include $a; ?>');
  assert.equal(list.length, 1, 'list() unpacking carries taint element-wise');
  assert.equal(detect('<?php list($a, $b) = [$_GET["f"], "x.php"]; include $b; ?>').length, 0,
    'the clean element of a list unpacking stays clean');

  const aug = detect('<?php $f = "a.php"; $f .= $_GET["x"]; include $f; ?>');
  assert.equal(aug.length, 1, 'augmented assignment merges taint');
});

test('detector: sanitizers cleanse the path', () => {
  assert.equal(detect('<?php include basename($_GET["f"]); ?>').length, 0);
  for (const cast of ['int', 'float', 'bool']) {
    assert.equal(detect(`<?php include (${cast}) $_GET["f"]; ?>`).length, 0,
      `(${cast}) should cleanse`);
  }
  for (const fn of ['intval', 'floatval', 'boolval']) {
    assert.equal(detect(`<?php include ${fn}($_GET["f"]); ?>`).length, 0,
      `${fn}() should cleanse`);
  }
  assert.equal(detect('<?php include (string) $_GET["f"]; ?>').length, 1,
    '(string) is NOT a sanitizer — the attacker string passes through');
  assert.equal(detect('<?php include strtoupper($_GET["f"]); ?>').length, 1,
    'an unknown call does not cleanse');
});

test('detector: in_array strict guard cleans the consequent branch', () => {
  const guarded = detect('<?php $f = $_GET["f"]; if (in_array($f, $allowed, true)) { include $f; } ?>');
  assert.equal(guarded.length, 0);
  assert.equal(detect('<?php $f = $_GET["f"]; if (in_array($f, $allowed)) { include $f; } ?>').length, 1,
    'a non-strict in_array is not a guard');
  assert.equal(detect('<?php $f = $_GET["f"]; if (in_array($f, $allowed, true)) { echo 1; } else { include $f; } ?>').length, 1,
    'the guard does not apply to the else branch');
  assert.equal(detect('<?php $f = $_GET["f"]; if (in_array($f, $allowed, true)) { echo 1; } include $f; ?>').length, 1,
    'the guard does not survive past the if');
  assert.equal(detect('<?php $f = $_GET["f"]; $g = $_GET["g"]; if (in_array($f, $allowed, true) && in_array($g, $allowed, true)) { include $f . $g; } ?>').length, 0,
    'conjunctions guard every conjunct');
  assert.equal(detect('<?php $f = $_GET["f"]; $g = $_GET["g"]; if (in_array($f, $allowed, true)) { include $f . $g; } ?>').length, 1,
    'a concatenation is guarded only when every part is');
  assert.equal(detect('<?php $f = $_GET["f"]; if (in_array($f, $allowed, true)) { include "dir/" . $f; } ?>').length, 0,
    'a constant prefix plus a guarded variable is guarded');
});

test('detector: array_key_exists and isset guards', () => {
  assert.equal(detect('<?php $f = $_GET["f"]; if (array_key_exists($f, $allowed)) { include $f; } ?>').length, 0);
  assert.equal(detect('<?php $f = $_GET["f"]; if (isset($allowed[$f])) { include $f; } ?>').length, 0);
  assert.equal(detect('<?php $f = $_GET["f"]; if (isset($f)) { include $f; } ?>').length, 1,
    'a bare isset() only proves definedness, not membership');
  assert.equal(detect('<?php $f = $_GET["f"]; if (isset($allowed[$f])) { include $allowed[$f]; } ?>').length, 1,
    'a subscript is not a guarded expression shape (conservative — pinned, see the doc)');
});

test('detector: switch without default guards the variable in its cases', () => {
  const guarded = detect('<?php $f = $_GET["f"]; switch ($f) { case "a": include $f; break; case "b": include $f; break; } ?>');
  assert.equal(guarded.length, 0);
  const withDefault = detect('<?php $f = $_GET["f"]; switch ($f) { case "a": include $f; break; default: include $f; break; } ?>');
  assert.equal(withDefault.length, 2, 'a default case means the variable can be anything');
  assert.equal(detect('<?php $f = $_GET["f"]; switch ($f) { case "a": break; } include $f; ?>').length, 1,
    'the switch guard does not survive past the switch');
});

test('detector: the early-return guard shape is NOT modeled', () => {
  // `if (!in_array(...)) return;` guards the fall-through
  // path, which this analyzer does not model — the finding
  // is a known false positive, pinned here so a future
  // round improves it deliberately instead of silently.
  const findings = detect('<?php $f = $_GET["f"]; if (!in_array($f, $allowed, true)) { return; } include $f; ?>');
  assert.equal(findings.length, 1);
});

test('detector: inter-procedural taint through known functions', () => {
  const viaCall = detect('<?php function load($p) { include $p; } load($_GET["f"]); ?>');
  assert.equal(viaCall.length, 1);
  assert.deepEqual(viaCall[0].evidence[0].chain, ['p']);
  assert.equal(viaCall[0].evidence[0].function, 'load');

  const fallback = detect('<?php function load($p) { include $p; } ?>');
  assert.equal(fallback.length, 1, 'an uncalled helper is still analyzed with its parameters as sources');

  const cleanCall = detect('<?php function load($p) { include $p; } load("config.php"); ?>');
  assert.equal(cleanCall.length, 1, 'the fallback pass still flags the helper itself');

  const returnsTainted = detect('<?php function get($p) { return $p; } $f = get($_GET["f"]); include $f; ?>');
  assert.equal(returnsTainted.length, 1, 'taint flows through a return value');

  const caseInsensitive = detect('<?php function LOAD($p) { include $p; } load($_GET["f"]); ?>');
  assert.equal(caseInsensitive.length, 1, 'PHP function names are case-insensitive');

  const bareResolved = detect('<?php function clean($p) { return basename($p); } $f = clean($_GET["f"]); include $f; ?>');
  assert.equal(bareResolved.length, 0, 'a bare call to a known function IS resolved — the callee body sanitizes');

  const methodNotResolved = detect('<?php function clean($p) { return basename($p); } $f = $x->clean($_GET["f"]); include $f; ?>');
  assert.equal(methodNotResolved.length, 1, 'a method call is NOT resolved through the call graph — the unknown-call rule applies instead of the callee body');

  const staticNotResolved = detect('<?php function clean($p) { return basename($p); } $f = Foo::clean($_GET["f"]); include $f; ?>');
  assert.equal(staticNotResolved.length, 1, 'a static call is NOT resolved through the call graph');
});

test('detector: unset removes taint', () => {
  assert.equal(detect('<?php $f = $_GET["f"]; unset($f); include $f; ?>').length, 0);
  assert.equal(detect('<?php $f = $_GET["f"]; $g = $f; unset($f); include $g; ?>').length, 1,
    'unsetting one name does not cleanse an alias');
});

test('detector: variable function calls and call_user_func are NOT modeled', () => {
  assert.equal(detect('<?php $f = "include"; $f($_GET["p"]); ?>').length, 0,
    'a variable function call is not resolved (pinned, see the doc)');
  assert.equal(detect('<?php call_user_func("include", $_GET["p"]); ?>').length, 0,
    'call_user_func is not resolved (pinned, see the doc)');
});

test('detector: one finding per sink site; branches join by union', () => {
  const two = detect('<?php include $_GET["a"]; include $_GET["b"]; ?>');
  assert.equal(two.length, 2);
  const dupe = detect('<?php function load($p) { include $p; } load($_GET["f"]); load($_GET["g"]); ?>');
  assert.equal(dupe.length, 1, 'the same sink site is reported once even when reached twice');
  const branch = detect('<?php if ($c) { $f = $_GET["a"]; } else { $f = "clean.php"; } include $f; ?>');
  assert.equal(branch.length, 1, 'taint in either branch survives the join');
  const loop = detect('<?php foreach ($_GET as $v) { include $v; } ?>');
  assert.equal(loop.length, 1, 'a foreach target carries the iterated taint');
});

test('detector: envelope — batch, language, empty and unparseable records', () => {
  const batch = detector({
    tool: 'batch-tool',
    results: [
      { content: '<?php include $_GET["a"]; ?>', language: 'php', ...IDS },
      { content: '<?php include "clean.php"; ?>', language: 'php', ...IDS },
    ],
  }, IDS);
  assert.equal(batch.findings.length, 1);
  assert.equal(batch.findings[0].discovery_tool, 'batch-tool');
  assert.equal(batch.skipped, 0);

  assert.throws(
    () => detector(null, IDS),
    /DETECTOR_INVALID_INPUT/,
  );
  assert.throws(
    () => detector([], IDS),
    /DETECTOR_INVALID_INPUT/,
  );

  const wrongLanguage = detector({ content: '<?php include $_GET["a"]; ?>', language: 'python', ...IDS }, IDS);
  assert.equal(wrongLanguage.findings.length, 0);
  assert.equal(wrongLanguage.skipped, 1);
  assert.match(wrongLanguage.errors[0], /not PHP/);

  const empty = detector({ content: '   ', language: 'php', ...IDS }, IDS);
  assert.equal(empty.skipped, 1);

  const unparseable = detectSkipped('<?php class Foo {} ?>');
  assert.match(unparseable.errors[0], /failed to parse content as PHP/);

  const missingIds = detector({ content: '<?php include $_GET["a"]; ?>', language: 'php' }, {});
  assert.equal(missingIds.findings.length, 0);
  assert.equal(missingIds.skipped, 1, 'a finding without ids is skipped, never invented');

  const defaultedIds = detector({ content: '<?php include $_GET["a"]; ?>', language: 'php' }, IDS);
  assert.equal(defaultedIds.findings.length, 1);
  assert.equal(defaultedIds.findings[0].session_id, 's1');
});
