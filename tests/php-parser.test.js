// Tests for the PHP subset parser
// (src/detection/php-parser.js, round 116).
// Positive cases must parse into the expected AST
// shape; negative cases (constructs outside the subset)
// must fail loudly with PhpParseError, never silently
// skip or mis-parse.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const parsePhp = require('../src/detection/php-parser.js');
const { PhpParseError, tokenize } = require('../src/detection/php-parser.js');

function parses(source) {
  return parsePhp(source);
}

function fails(source, pattern) {
  assert.throws(
    () => parsePhp(source),
    (error) => error instanceof PhpParseError
      && (!pattern || pattern.test(error.message)),
    `expected PhpParseError${pattern ? ` matching ${pattern}` : ''} for: ${source}`,
  );
}

test('parser: empty program and HTML-only input parse', () => {
  assert.deepEqual(parses('<?php ?>').body, []);
  assert.deepEqual(parses('<p>no php here</p>').body, []);
  assert.deepEqual(parses('').body, []);
});

test('parser: open tags and segments', () => {
  const program = parses('<?php $a = 1; ?> <p>html</p> <?php $b = 2; ?>');
  assert.equal(program.body.length, 2);
  assert.equal(program.body[0].value.targets[0].name, 'a');
  assert.equal(program.body[1].value.targets[0].name, 'b');
  // `<?` short tags open a segment too; `<?xml` does not.
  assert.equal(parses('<? $a = 1; ?>').body.length, 1);
  assert.deepEqual(parses('<?xml version="1.0"?>').body, []);
  // A newline after `?>` is consumed with the close tag.
  assert.equal(parses("<?php $a = 1; ?>\n<?php $b = 2; ?>").body.length, 2);
});

test('parser: short echo <?= ?> is an Echo node', () => {
  const program = parses('<?= $_GET["q"] ?>');
  assert.equal(program.body.length, 1);
  assert.equal(program.body[0].type, 'Echo');
  assert.equal(program.body[0].values[0].type, 'Subscript');
  const mixed = parses('<?php $a = 1; ?> <?= $a ?> <?php $b = 2; ?>');
  assert.equal(mixed.body.length, 3);
  assert.equal(mixed.body[1].type, 'Echo');
});

test('parser: assignment forms', () => {
  const assign = parses('<?php $x = $_GET["page"]; ?>').body[0].value;
  assert.equal(assign.type, 'Assign');
  assert.equal(assign.targets[0].type, 'Variable');
  assert.equal(assign.targets[0].name, 'x');
  assert.equal(assign.value.type, 'Subscript');
  assert.equal(assign.value.value.name, '_GET');

  const chained = parses('<?php $a = $b = 1; ?>').body[0].value;
  assert.equal(chained.type, 'Assign');
  assert.equal(chained.value.type, 'Assign');

  const aug = parses('<?php $a += 1; $b ??= 2; $c .= "x"; ?>').body;
  assert.equal(aug[0].value.type, 'AugAssign');
  assert.equal(aug[0].value.op, '+=');
  assert.equal(aug[1].value.type, 'AugAssign');
  assert.equal(aug[1].value.op, '??=');

  const list = parses('<?php list($a, $b) = $arr; [$c, $d] = $arr2; ?>').body;
  assert.equal(list[0].value.targets[0].type, 'List');
  assert.equal(list[1].value.targets[0].type, 'Array');
});

test('parser: include and require are Include nodes', () => {
  for (const kw of ['include', 'require', 'include_once', 'require_once']) {
    const stmt = parses(`<?php ${kw} $x; ?>`).body[0].value;
    assert.equal(stmt.type, 'Include');
    assert.equal(stmt.kind, kw);
    const paren = parses(`<?php ${kw}($x); ?>`).body[0].value;
    assert.equal(paren.type, 'Include');
    assert.equal(paren.kind, kw);
  }
  const asExpr = parses('<?php $a = include $x; ?>').body[0].value;
  assert.equal(asExpr.type, 'Assign');
  assert.equal(asExpr.value.type, 'Include');
});

test('parser: function definitions', () => {
  const fn = parses('<?php function f(string $p, int ...$rest): ?int { return 1; } ?>').body[0];
  assert.equal(fn.type, 'FunctionDef');
  assert.equal(fn.name, 'f');
  assert.deepEqual(fn.params.map((p) => p.name), ['p', 'rest']);
  assert.equal(fn.params[1].kind, 'var_arg');
  assert.equal(fn.body[0].type, 'Return');

  const defaults = parses('<?php function g($a = 1, $b = "x", callable $c = null) {} ?>').body[0];
  assert.equal(defaults.params.length, 3);
  const byRef = parses('<?php function h(&$x, array $y) {} ?>').body[0];
  assert.equal(byRef.params.length, 2);
  const union = parses('<?php function u(int|string $x): int|float { return 0; } ?>').body[0];
  assert.equal(union.params.length, 1);
});

test('parser: control flow, braced and alternative', () => {
  const ifNode = parses('<?php if ($a) { 1; } elseif ($b) { 2; } else { 3; } ?>').body[0];
  assert.equal(ifNode.type, 'If');
  assert.equal(ifNode.orelse.length, 1);
  assert.equal(ifNode.orelse[0].type, 'If');

  const altIf = parses('<?php if ($a): 1; elseif ($b): 2; else: 3; endif; ?>').body[0];
  assert.equal(altIf.type, 'If');
  assert.equal(altIf.orelse[0].type, 'If');
  assert.equal(altIf.orelse[0].orelse.length, 1);

  const foreach = parses('<?php foreach ($arr as $k => $v) { echo $v; } ?>').body[0];
  assert.equal(foreach.type, 'Foreach');
  assert.equal(foreach.target.type, 'Pair');
  const altForeach = parses('<?php foreach ($arr as $v): echo $v; endforeach; ?>').body[0];
  assert.equal(altForeach.type, 'Foreach');

  const forNode = parses('<?php for ($i = 0; $i < 3; $i++) { echo $i; } ?>').body[0];
  assert.equal(forNode.type, 'For');
  const whileNode = parses('<?php while ($x) { $x--; } ?>').body[0];
  assert.equal(whileNode.type, 'While');
  const doWhile = parses('<?php do { $x++; } while ($x < 3); ?>').body[0];
  assert.equal(doWhile.type, 'DoWhile');

  const switchNode = parses('<?php switch ($x) { case 1: echo 1; break; default: echo 2; } ?>').body[0];
  assert.equal(switchNode.type, 'Switch');
  assert.equal(switchNode.cases.length, 2);
  assert.equal(switchNode.cases[0].test.type, 'Constant');
  assert.equal(switchNode.cases[1].test, null);
  const altSwitch = parses('<?php switch ($x): case 1: echo 1; break; default: echo 2; endswitch; ?>').body[0];
  assert.equal(altSwitch.type, 'Switch');
  assert.equal(altSwitch.cases.length, 2);

  const tryNode = parses('<?php try { foo(); } catch (Exception $e) { bar(); } finally { baz(); } ?>').body[0];
  assert.equal(tryNode.type, 'Try');
  assert.equal(tryNode.handlers.length, 1);
  assert.deepEqual(tryNode.handlers[0].types, ['Exception']);
  assert.equal(tryNode.handlers[0].name, 'e');
  assert.equal(tryNode.finalbody.length, 1);
  const bareCatch = parses('<?php try { foo(); } catch { bar(); } ?>').body[0];
  assert.equal(bareCatch.handlers[0].types.length, 0);
  const multiCatch = parses('<?php try { foo(); } catch (A | B $e) { bar(); } ?>').body[0];
  assert.deepEqual(multiCatch.handlers[0].types, ['A', 'B']);
});

test('parser: expressions', () => {
  const cmp = parses('<?php $a = $x <=> $y; $b = $x <= $y; ?>').body;
  assert.equal(cmp[0].value.value.type, 'Compare');
  assert.deepEqual(cmp[0].value.value.ops, ['<=>']);
  assert.deepEqual(cmp[1].value.value.ops, ['<=']);

  const ternary = parses('<?php $a = $b ? 1 : 2; $c = $d ?: 3; $e = $f ?? "x"; ?>').body;
  assert.equal(ternary[0].value.value.type, 'Conditional');
  assert.equal(ternary[1].value.value.type, 'Conditional');
  assert.equal(ternary[2].value.value.op, '??');

  const calls = parses('<?php $a = Foo::bar($x)->baz[$y]; $b = new Foo($x); $c = $x?->m(); ?>').body;
  assert.equal(calls[0].value.value.type, 'Subscript');
  assert.equal(calls[1].value.value.type, 'New');
  assert.equal(calls[2].value.value.type, 'Call');
  assert.equal(calls[2].value.value.func.type, 'Attribute');
  assert.equal(calls[2].value.value.func.nullsafe, true);

  const casts = parses('<?php $a = (int) $x; $b = (array) $y; $c = (string) $z; ?>').body;
  assert.equal(casts[0].value.value.type, 'Cast');
  assert.equal(casts[0].value.value.castType, 'int');

  const arrays = parses('<?php $a = [1, 2, "k" => $h, ...$i]; $b = array(1, 2); ?>').body;
  assert.equal(arrays[0].value.value.type, 'Array');
  assert.equal(arrays[0].value.value.elements.length, 4);
  assert.equal(arrays[0].value.value.elements[2].key.value, 'k');
  assert.equal(arrays[0].value.value.elements[3].spread, true);

  const named = parses('<?php foo(a: 1, b: $x, ...$y); ?>').body[0].value;
  assert.equal(named.type, 'Call');
  assert.equal(named.keywords.length, 2);
  assert.equal(named.keywords[0].arg, 'a');
  assert.equal(named.args[0].type, 'Spread');

  const fq = parses('<?php $a = \\unserialize($x); $b = Foo\\Bar($x); $c = Foo\\unserialize($x); ?>').body;
  assert.equal(fq[0].value.value.func.type, 'QualifiedName');
  assert.equal(fq[0].value.value.func.id, '\\unserialize');
  assert.equal(fq[1].value.value.func.id, 'Foo\\Bar');
  assert.equal(fq[2].value.value.func.id, 'Foo\\unserialize');

  const staticCall = parses('<?php static::foo(); $a = self::X; $b = parent::m(); ?>').body;
  assert.equal(staticCall[0].value.func.type, 'Attribute');
  assert.equal(staticCall[0].value.func.isStatic, true);
});

test('parser: string interpolation', () => {
  const str = parses('<?php $a = "pre {$x->prop} mid {$y[0]} post $v end"; ?>').body[0].value.value;
  assert.equal(str.type, 'JoinedStr');
  const exprParts = str.values.filter((p) => p.type === 'expr');
  assert.equal(exprParts.length, 3);
  assert.equal(exprParts[0].node.type, 'Attribute');
  assert.equal(exprParts[1].node.type, 'Subscript');
  assert.equal(exprParts[2].node.type, 'Variable');

  const plain = parses('<?php $a = "no vars here"; $b = \'single\'; ?>').body;
  assert.equal(plain[0].value.value.type, 'Constant');
  assert.equal(plain[1].value.value.type, 'Constant');
  assert.equal(plain[1].value.value.kind, 'string');

  const backtick = parses('<?php $a = `ls $dir`; ?>').body[0].value.value;
  assert.equal(backtick.type, 'JoinedStr');
});

test('parser: declarations and misc statements', () => {
  const ns = parses('<?php namespace Foo; use function unserialize as u; use Foo\\Bar; ?>').body;
  assert.equal(ns[0].type, 'Namespace');
  assert.equal(ns[0].name, 'Foo');
  assert.equal(ns[1].type, 'UseDecl');
  assert.equal(ns[1].kind, 'function');
  assert.equal(ns[1].names[0].name, 'unserialize');
  assert.equal(ns[1].names[0].alias, 'u');

  const grouped = parses('<?php use Foo\\{A, B}; ?>').body[0];
  assert.equal(grouped.names.length, 2);
  assert.equal(grouped.names[0].name, 'Foo\\A');
  assert.equal(grouped.names[1].name, 'Foo\\B');

  const bracedNs = parses('<?php namespace Foo { function f() { return 1; } } ?>').body[0];
  assert.equal(bracedNs.type, 'Namespace');
  assert.equal(bracedNs.body.length, 1);

  const decl = parses('<?php declare(strict_types=1); const FOO = 1, BAR = 2; ?>').body;
  assert.equal(decl[0].type, 'Declare');
  assert.equal(decl[1].type, 'Const');
  assert.equal(decl[1].names.length, 2);

  const attr = parses('<?php #[Route("/x")] function f() { return 1; } ?>').body[0];
  assert.equal(attr.type, 'FunctionDef');
  assert.equal(attr.name, 'f');

  const misc = parses('<?php global $a, $b; static $s = 1; echo 1, 2; exit; exit(1); throw new Exception("x"); ?>').body;
  assert.equal(misc[0].type, 'Global');
  assert.equal(misc[1].type, 'Static');
  assert.equal(misc[2].type, 'Echo');
  assert.equal(misc[2].values.length, 2);
  assert.equal(misc[3].type, 'Expr');
  assert.equal(misc[3].value.type, 'Exit');
  assert.equal(misc[5].type, 'Throw');

  const isset = parses('<?php if (isset($x)) { unset($y); } $z = empty($w); ?>').body;
  assert.equal(isset[0].body[0].value.func.id, 'unset');
  assert.equal(isset[1].value.value.func.id, 'empty');
});

test('parser: statements after a semicolon may be compound', () => {
  // The commonest shape in real code — the `;`-run must
  // stop at a compound statement, not swallow it.
  parses('<?php $x = 1; if ($x) { echo 1; } ?>');
  parses('<?php $x = 1; foreach ($a as $v) { echo $v; } ?>');
  parses('<?php $x = 1; switch ($x) { case 1: echo 1; break; } ?>');
  parses('<?php $x = 1; try { foo(); } catch (Exception $e) { bar(); } ?>');
  parses('<?php $x = 1; function f() { return 1; } ?>');
  parses('<?php $x = 1; while ($x) { $x--; } ?>');
  parses('<?php $a = 1; $b = 2; echo $a; if ($b) { echo $b; } foreach ([1, 2] as $v) { echo $v; } ?>');
});

test('parser: tokenizer keeps positions', () => {
  const tokens = tokenize('<?php $x = 1; ?>');
  const variable = tokens.find((t) => t.type === 'variable');
  assert.equal(variable.value, 'x');
  assert.equal(variable.line, 1);
  assert.equal(variable.column, 7);
  const open = tokens.find((t) => t.type === 'open');
  assert.equal(open.value, 'php');
});

test('parser: out-of-subset constructs fail loudly', () => {
  fails('<?php class Foo {} ?>', /class definitions are not supported/);
  fails('<?php interface I {} ?>', /interface definitions are not supported/);
  fails('<?php trait T {} ?>', /trait definitions are not supported/);
  fails('<?php enum E {} ?>', /enum definitions are not supported/);
  fails('<?php $a = function() {}; ?>', /closures are not supported/);
  fails('<?php $a = fn($x) => $x; ?>', /arrow functions/);
  fails('<?php $a = match($x) { 1 => 2 }; ?>', /match expressions are not supported/);
  fails('<?php $a = <<<EOT\nhello\nEOT; ?>', /heredoc \/ nowdoc is not supported/);
  fails('<?php function f() { yield 1; } ?>', /yield is not supported/);
  fails('<?php goto end; end: echo 1; ?>', /goto is not supported/);
  fails('<?php $$x = 1; ?>', /variable variables/);
  fails('<?php $a = $x->$y; ?>', /dynamic member access/);
  fails('<?php $a = $x->{foo}; ?>', /dynamic member access/);
  fails('<?php $a = Foo::{$x}(); ?>', /dynamic static access/);
  fails('<?php __halt_compiler(); ?>', /__halt_compiler is not supported/);
});

test('parser: malformed input fails loudly', () => {
  fails('<?php $x = ; ?>', /unexpected token/);
  fails('<?php if ($x) { echo 1; ?>', /expected '\}'/);
  fails('<?php function f( { } ?>', /a parameter name/);
  fails('<?php $a = "unterminated; ?>', /unterminated string/);
  fails('<?php /* never closed', /unterminated comment/);
  // A `?>` inside a comment closes the segment (as in
  // real PHP), so this parses — the comment is not
  // unterminated, the segment just ends.
  assert.deepEqual(parses('<?php /* unterminated ?>').body, []);
  fails('<?php switch ($x) { foo(); } ?>', /expected case or default/);
  fails('<?php try { foo(); } ?>', /at least one catch or a finally clause/);
});
