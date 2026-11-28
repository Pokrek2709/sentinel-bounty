// Tests for the Python subset parser
// (src/detection/py-parser.js, round 115).
// Valid programs must parse into the expected AST shapes;
// programs outside the subset must fail loudly with a
// PyParseError (never silently skipped, never scanned
// approximately).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const parsePython = require('../src/detection/py-parser.js');
const { PyParseError } = require('../src/detection/py-parser.js');

function parse(source) {
  return parsePython(source);
}

function parseFails(source, pattern) {
  assert.throws(
    () => parsePython(source),
    (error) => {
      assert.ok(error instanceof PyParseError, `expected PyParseError, got ${error}`);
      if (pattern) assert.match(error.message, pattern);
      return true;
    },
  );
}

test('parser: empty program and comments', () => {
  assert.deepEqual(parse('').body, []);
  assert.deepEqual(parse('# only a comment\n').body, []);
  assert.deepEqual(parse('\n\n# c\n\n').body, []);
});

test('parser: imports', () => {
  const program = parse('import pickle\nimport os, sys\nimport yaml as y\nfrom pickle import loads\nfrom pickle import loads as ld, load\nfrom flask import request as req\nfrom . import helper\nfrom ..pkg import mod\n');
  assert.equal(program.body.length, 8);
  assert.equal(program.body[0].type, 'Import');
  assert.deepEqual(program.body[0].names, [{ module: 'pickle', alias: null }]);
  assert.deepEqual(program.body[1].names, [
    { module: 'os', alias: null },
    { module: 'sys', alias: null },
  ]);
  assert.deepEqual(program.body[2].names, [{ module: 'yaml', alias: 'y' }]);
  assert.equal(program.body[3].type, 'ImportFrom');
  assert.equal(program.body[3].module, 'pickle');
  assert.equal(program.body[3].level, 0);
  assert.deepEqual(program.body[3].names, [{ name: 'loads', alias: null }]);
  assert.deepEqual(program.body[4].names, [
    { name: 'loads', alias: 'ld' },
    { name: 'load', alias: null },
  ]);
  assert.equal(program.body[5].module, 'flask');
  assert.deepEqual(program.body[5].names, [{ name: 'request', alias: 'req' }]);
  assert.equal(program.body[6].module, null);
  assert.equal(program.body[6].level, 1);
  assert.equal(program.body[7].module, 'pkg');
  assert.equal(program.body[7].level, 2);
});

test('parser: parenthesized from-import', () => {
  const program = parse('from pickle import (\n  loads,\n  load,\n)\n');
  assert.equal(program.body[0].type, 'ImportFrom');
  assert.deepEqual(program.body[0].names, [
    { name: 'loads', alias: null },
    { name: 'load', alias: null },
  ]);
});

test('parser: function definition with parameters', () => {
  const program = parse('def handle(data, flag=False, *args, **kwargs):\n    return data\n');
  const fn = program.body[0];
  assert.equal(fn.type, 'FunctionDef');
  assert.equal(fn.name, 'handle');
  assert.deepEqual(fn.params, [
    { name: 'data', kind: 'pos' },
    { name: 'flag', kind: 'pos' },
    { name: 'args', kind: 'var_arg' },
    { name: 'kwargs', kind: 'var_kw' },
  ]);
  assert.equal(fn.body[0].type, 'Return');
});

test('parser: annotated assignment and tuple unpacking', () => {
  const program = parse('x: int = 1\ny: str\n(a, b) = (1, 2)\nc = d = 3\n');
  assert.equal(program.body[0].type, 'AnnAssign');
  assert.equal(program.body[0].target.id, 'x');
  assert.equal(program.body[0].value.value, '1');
  assert.equal(program.body[1].type, 'AnnAssign');
  assert.equal(program.body[1].value, null);
  assert.equal(program.body[2].type, 'Assign');
  assert.equal(program.body[2].targets[0].type, 'Tuple');
  assert.deepEqual(program.body[2].targets[0].elts.map((e) => e.id), ['a', 'b']);
  assert.equal(program.body[3].type, 'Assign');
  assert.deepEqual(program.body[3].targets.map((t) => t.id), ['c', 'd']);
});

test('parser: augmented assignment and operators', () => {
  const program = parse('x += 1\ny **= 2\nz //= 3\n');
  assert.equal(program.body[0].type, 'AugAssign');
  assert.equal(program.body[0].op, '+=');
  assert.equal(program.body[1].op, '**=');
  assert.equal(program.body[2].op, '//=');
  const expr = parse('a = 1 + 2 * 3 ** 2 - 4 // 2 % 3\n');
  assert.equal(expr.body[0].value.type, 'BinOp');
  assert.equal(expr.body[0].value.op, '-');
});

test('parser: if / elif / else and same-line suites', () => {
  const program = parse('if a:\n    x = 1\nelif b:\n    x = 2\nelse:\n    x = 3\nif c: return 1\n');
  assert.equal(program.body[0].type, 'If');
  assert.equal(program.body[0].orelse[0].type, 'If');
  assert.equal(program.body[0].orelse[0].orelse.length, 1);
  assert.equal(program.body[1].type, 'If');
  assert.equal(program.body[1].body[0].type, 'Return');
});

test('parser: for / while with else', () => {
  const program = parse('for item in items:\n    print(item)\nelse:\n    print("done")\nwhile n > 0:\n    n -= 1\n');
  assert.equal(program.body[0].type, 'For');
  assert.equal(program.body[0].target.id, 'item');
  assert.equal(program.body[0].orelse.length, 1);
  assert.equal(program.body[1].type, 'While');
  assert.equal(program.body[1].orelse.length, 0);
});

test('parser: try / except / else / finally', () => {
  const program = parse('try:\n    risky()\nexcept ValueError as e:\n    log(e)\nexcept:\n    pass\nelse:\n    ok()\nfinally:\n    cleanup()\n');
  const node = program.body[0];
  assert.equal(node.type, 'Try');
  assert.equal(node.handlers.length, 2);
  assert.equal(node.handlers[0].name, 'e');
  assert.equal(node.handlers[0].type.type, 'Name');
  assert.equal(node.handlers[0].type.id, 'ValueError');
  assert.equal(node.handlers[1].type, null);
  assert.equal(node.orelse.length, 1);
  assert.equal(node.finalbody.length, 1);
});

test('parser: with statement', () => {
  const program = parse('with open("f", "rb") as f:\n    data = f.read()\n');
  const node = program.body[0];
  assert.equal(node.type, 'With');
  assert.equal(node.items.length, 1);
  assert.equal(node.items[0].optionalVars.id, 'f');
  assert.equal(node.body[0].type, 'Assign');
});

test('parser: calls with keywords, *args, **kwargs', () => {
  const program = parse('f(1, 2, key="v", *args, **kw)\n');
  const call = program.body[0].value;
  assert.equal(call.type, 'Call');
  assert.equal(call.args.length, 3);
  assert.equal(call.args[2].type, 'Starred');
  assert.deepEqual(call.keywords, [
    { arg: 'key', value: { type: 'Constant', value: 'v', kind: 'string', line: 1, column: 13 } },
    { arg: null, value: { type: 'Name', id: 'kw', line: 1, column: 27 } },
  ]);
});

test('parser: attribute, subscript, slices', () => {
  const program = parse('a = obj.attr\nb = data[0]\nc = data[1:3]\nd = data[::2]\ne = data[1, 2]\n');
  assert.equal(program.body[0].value.type, 'Attribute');
  assert.equal(program.body[0].value.attr, 'attr');
  assert.equal(program.body[1].value.type, 'Subscript');
  assert.equal(program.body[2].value.slice.type, 'Slice');
  assert.equal(program.body[2].value.slice.lower.value, '1');
  assert.equal(program.body[2].value.slice.upper.value, '3');
  assert.equal(program.body[3].value.slice.step.value, '2');
  assert.equal(program.body[4].value.slice.type, 'Tuple');
});

test('parser: literals, containers, conditional', () => {
  const program = parse('a = [1, 2, 3]\nb = {"k": 1, "j": 2}\nc = {1, 2}\nd = (1, 2)\ne = ()\nf = x if cond else y\ng = not a and b or c\n');
  assert.equal(program.body[0].value.type, 'List');
  assert.equal(program.body[1].value.type, 'Dict');
  assert.equal(program.body[1].value.keys.length, 2);
  assert.equal(program.body[2].value.type, 'Set');
  assert.equal(program.body[3].value.type, 'Tuple');
  assert.equal(program.body[4].value.type, 'Tuple');
  assert.equal(program.body[4].value.elts.length, 0);
  assert.equal(program.body[5].value.type, 'IfExp');
  assert.equal(program.body[6].value.type, 'BoolOp');
});

test('parser: f-strings', () => {
  const program = parse('a = f"hello {name}, {x + 1!r:>10} and {{braces}}"\n');
  const node = program.body[0].value;
  assert.equal(node.type, 'JoinedStr');
  assert.equal(node.values.length, 5);
  assert.equal(node.values[0].type, 'literal');
  assert.equal(node.values[0].value, 'hello ');
  assert.equal(node.values[1].type, 'expr');
  assert.equal(node.values[1].node.id, 'name');
  assert.equal(node.values[2].type, 'literal');
  assert.equal(node.values[2].value, ', ');
  assert.equal(node.values[3].type, 'expr');
  assert.equal(node.values[3].node.type, 'BinOp');
  assert.equal(node.values[4].type, 'literal');
  assert.match(node.values[4].value, /braces/);
});

test('parser: f-string with debug specifier and nested quotes', () => {
  const program = parse('a = f"{d[\'k\']}"\nb = f"{value=}"\n');
  assert.equal(program.body[0].value.type, 'JoinedStr');
  assert.equal(program.body[0].value.values[0].node.type, 'Subscript');
  assert.equal(program.body[1].value.values[0].node.id, 'value');
});

test('parser: string prefixes and adjacent concatenation', () => {
  const program = parse('a = r"raw\\n"\nb = b"bytes"\nc = "one" "two"\n');
  assert.equal(program.body[0].value.kind, 'string');
  assert.equal(program.body[0].value.value, 'raw\\n');
  assert.equal(program.body[1].value.kind, 'string');
});

test('parser: indentation, blank lines, comments, semicolons', () => {
  const program = parse(
    'def f():\n'
    + '\n'
    + '    # a comment\n'
    + '    if x:\n'
    + '        a = 1; b = 2\n'
    + '    return a\n',
  );
  const fn = program.body[0];
  assert.equal(fn.body[0].type, 'If');
  assert.equal(fn.body[0].body.length, 2);
  assert.equal(fn.body[0].body[0].targets[0].id, 'a');
  assert.equal(fn.body[0].body[1].targets[0].id, 'b');
  assert.equal(fn.body[1].type, 'Return');
});

test('parser: implicit continuation inside brackets', () => {
  const program = parse('result = func(\n    first,\n    second,\n)\nitems = [\n    1,\n    2,\n]\n');
  assert.equal(program.body[0].value.type, 'Call');
  assert.equal(program.body[0].value.args.length, 2);
  assert.equal(program.body[1].value.type, 'List');
  assert.equal(program.body[1].value.elts.length, 2);
});

test('parser: explicit backslash continuation', () => {
  const program = parse('total = first + \\\n    second\n');
  assert.equal(program.body[0].value.type, 'BinOp');
  assert.equal(program.body[0].value.op, '+');
});

test('parser: raise, assert, del, global, return values', () => {
  const program = parse('def f():\n    global counter\n    assert x > 0, "bad"\n    del cache["k"]\n    raise ValueError("no") from cause\n    return 1, 2\n');
  const body = program.body[0].body;
  assert.equal(body[0].type, 'Global');
  assert.deepEqual(body[0].names, ['counter']);
  assert.equal(body[1].type, 'Assert');
  assert.equal(body[2].type, 'Delete');
  assert.equal(body[3].type, 'Raise');
  assert.equal(body[3].cause.id, 'cause');
  assert.equal(body[4].value.type, 'Tuple');
});

test('parser: nested function definitions', () => {
  const program = parse('def outer():\n    def inner(x):\n        return x + 1\n    return inner(2)\n');
  assert.equal(program.body[0].body[0].type, 'FunctionDef');
  assert.equal(program.body[0].body[0].name, 'inner');
});

test('parser: numbers', () => {
  const program = parse('a = 0x1F\nb = 0o17\nc = 0b101\nd = 1_000_000\ne = 3.14\nf = 1e10\ng = 2j\n');
  assert.equal(program.body[0].value.value, '0x1F');
  assert.equal(program.body[4].value.value, '3.14');
  assert.equal(program.body[6].value.value, '2j');
});

test('parser: chained comparisons and not-in / is-not', () => {
  const program = parse('a = 1 < x < 10\nb = y is not None\nc = k not in keys\n');
  assert.equal(program.body[0].value.type, 'Compare');
  assert.deepEqual(program.body[0].value.ops, ['<', '<']);
  assert.deepEqual(program.body[1].value.ops, ['is not']);
  assert.deepEqual(program.body[2].value.ops, ['not in']);
});

test('parser: class definitions fail loudly', () => {
  parseFails('class Foo:\n    pass\n', /class definitions are not supported/);
});

test('parser: decorators fail loudly', () => {
  parseFails('@app.route("/")\ndef f():\n    pass\n', /decorators are not supported/);
});

test('parser: lambda fails loudly', () => {
  parseFails('f = lambda x: x + 1\n', /lambda expressions are not supported/);
});

test('parser: comprehensions fail loudly', () => {
  parseFails('xs = [x * 2 for x in items]\n', /comprehensions are not supported/);
  parseFails('d = {k: v for k, v in items}\n', /comprehensions are not supported/);
  parseFails('s = {x for x in items}\n', /comprehensions are not supported/);
});

test('parser: generator expressions fail loudly', () => {
  parseFails('total = sum(x for x in items)\n', /generator expressions are not supported/);
});

test('parser: async / await / yield fail loudly', () => {
  parseFails('async def f():\n    await g()\n', /async \/ await are not supported/);
  parseFails('def gen():\n    yield 1\n', /yield is not supported/);
});

test('parser: walrus operator fails loudly', () => {
  parseFails('if (n := len(items)) > 0:\n    print(n)\n', /:=/);
});

test('parser: bad indentation fails loudly', () => {
  parseFails('def f():\n    x = 1\n  y = 2\n', /unindent does not match/);
});

test('parser: unterminated string fails loudly', () => {
  parseFails('x = "never closed\n', /unterminated string literal/);
});

test('parser: matrix multiplication fails loudly', () => {
  parseFails('c = a @ b\n', /expected a newline/);
});

test('parser: unbalanced brackets fail loudly', () => {
  parseFails('x = f(1, 2\n', /expected/);
});

test('parser: non-string source fails loudly', () => {
  assert.throws(() => parsePython(42), /source must be a string/);
  assert.throws(() => parsePython(null), /source must be a string/);
});
