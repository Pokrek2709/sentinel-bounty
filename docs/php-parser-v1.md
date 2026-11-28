# PHP Subset Parser v1 (Round 116)

A hand-written PHP subset parser (`src/detection/php-parser.js`):
tokenizer + recursive-descent parser producing an AST with 1-based
line/column positions. Stdlib-only, synchronous, deterministic, and it
never executes the code it parses.

## Why hand-written

The fourth language needs structure (tags, function definitions,
include constructs, superglobals, taint flow through assignments and
calls) that a regex cannot see, and the skill installs and verifies
offline, so an npm parser is out of scope this round. The model is
`src/detection/py-parser.js` (round 115): the same tokenizer +
recursive-descent shape, the same error discipline, the same test
posture (valid code parses, unsupported syntax fails loudly). PHP's
difference from Python is its segment structure: the source is HTML
with `<?php` / `<?=` / `<?` segments (HTML between segments is
skipped, `?>` ends a segment even inside a comment, and the newline
immediately after `?>` belongs to the close tag), and `<?xml` is not
an open tag.

No PHP parser was evaluated for adoption this round — the subset
grammar is small and the first PHP classes (tainted include /
unserialize) need only it. A full PHP grammar (e.g. a vendored
parser) remains the documented upgrade path if the PHP detector set
grows beyond what the subset covers. That is a future decision, not
a blocker for this round.

## Grammar covered

- Segments: `<?php` / `<?=` / `<?` open tags, `?>` close tags, HTML
  between segments skipped. `<?=` is a short-echo segment (an Echo
  node). `<?xml` is not an open tag.
- Function definitions: `function name(params) { ... }` with
  defaults (parsed, not analyzed), type annotations (parsed and
  discarded, including nullable / union / intersection types),
  variadic `...$rest`, by-reference `&$x`, return types (parsed and
  discarded), and return-by-reference `function &name(...)`.
  Nested function definitions parse and are registered in the
  detector's function table. Visibility / `readonly` modifiers in
  parameters (constructor promotion) are accepted and ignored.
- Statements: assignment (simple, chained `a = b = c`, `list()` and
  short-list `[$a, $b] = ...` targets, augmented `+=` / `-=` / `.=` /
  `??=` and the rest), `if` / `elseif` / `else` (braced and
  alternative `:` / `endif` forms), `foreach` (key / value targets,
  `list()` targets), `for` / `while` / `do-while` (braced and
  alternative forms), `switch` (braced and alternative `:` /
  `endswitch` forms, fall-through cases, `default`), `try` /
  `catch` (multiple / union exception types, bare `catch`, catch
  without a variable) / `finally`, `return` / `break` / `continue`
  (with or without a value), `throw`, `echo` (comma-separated
  values), `print`, `exit` / `die` (with or without a value, with
  or without parentheses), `isset` / `empty` / `unset` (parsed as
  calls), `global` / `static` (declarations; `static $x = 1;` binds
  like an assignment for taint purposes), `const` declarations,
  `namespace` (semicolon and braced forms — a declaration only, no
  scoping effect), `use` (class imports, `use function` imports
  with `as` aliases, grouped `use Foo\{A, B};` — the `use function`
  bindings are recorded and resolved by the taint analyzer),
  `declare(...)` (statement and braced / alternative `enddeclare`
  forms), `#[...]` attributes (skipped, balanced brackets), and
  `;`-separated simple statements on one line (a `;`-run stops at
  a compound statement — `$x = 1; if (...) {...}` parses).
- Expressions: literals (numbers, single / double-quoted strings,
  backtick strings, `true` / `false` / `null`), interpolated
  double-quoted / backtick strings (`$var`, `${var}`, `{$expr}`
  with `->prop` / `[...]` chains — fragments are re-tokenized like
  the Python parser's f-strings, positions approximate; a quote
  inside an interpolation, `"{$_GET["p"]}"`, does not terminate
  the outer string), array literals `[]` / `array()` (with keys,
  spread, trailing commas), casts (`(int)` / `(float)` / `(bool)` /
  `(array)` / `(string)` / `(object)` / `(unset)` / `(binary)`),
  `new`, `clone`, `instanceof`, ternary (including the short `?:`
  form and right-associative nesting), `??`, named arguments
  (`name: value`, PHP 8), spread (`...$args`), `include` /
  `require` / `include_once` / `require_once` (as a statement and
  as an expression, with or without parentheses), method calls
  (`->`, nullsafe `?->`), static calls (`::`, including `self::` /
  `parent::` / `static::` and `::$prop`), subscripts, calls with
  positional / named / spread arguments, binary / unary / boolean
  / comparison (including `<=>`) / concatenation (`.`) / bitwise /
  shift operators, prefix / postfix `++` / `--`, and error
  suppression `@`. Keywords are case-insensitive, as in PHP.

## Fails loudly (never silently skipped)

- Class / interface / trait / enum definitions.
- Closures (`function() {...}`) and `fn` arrow functions.
- `match` expressions.
- Heredoc / nowdoc (`<<<`).
- `yield`, `goto`, `__halt_compiler`.
- Variable variables (`$$x`), `${expr}` (complex variable
  variables), dynamic member access (`->$x`, `->{...}`,
  `::{...}`).
- A `try` with neither `catch` nor `finally`; a `switch`
  with a statement that is not `case` / `default`; an
  unterminated string, comment, or attribute group.
- Malformed input (a missing `;`, `}`, or `)`, an invalid
  assignment target) fails with a named `PhpParseError`
  carrying a 1-based line and column.

## Documented deviations from PHP

- Nested ternary is accepted as right-associative. PHP 8
  rejects an unparenthesized nested ternary
  (`$a ? 1 : $b ? 2 : 3` is a parse error in PHP 8); the
  subset parser accepts it, because the taint of the
  expression does not depend on the rejection.
- `$$` inside an interpolated string is approximated as a
  literal `$` followed by a variable (the tokenizer
  rejects `$$` outside strings; inside a string the
  fragment parser sees `$` + `$var`).
- Interpolation fragment positions are approximate (the
  string token's line). Findings never carry a source line,
  so this affects nothing the operator sees.
- A reserved word is accepted as a named-argument name
  (`foo(default: 1)` parses). PHP rejects some reserved
  words there; accepting them cannot change a taint
  verdict.
- `?:` lexes as `?` + `:` (the short ternary), not as a
  single token — that is PHP's own lexing.
- A `use function` binding that shadows the global
  fallback (`use function foo\unserialize;` then
  `unserialize($x)`) resolves to the namespaced function,
  per PHP semantics; the taint analyzer treats a bare
  `unserialize` with no binding as the global sink.

## Examples

```php
<?php
// Tainted include: $_GET flows to include.
$page = $_GET["page"];
include "pages/" . $page . ".php";

// Guarded: strict in_array in the consequent branch.
if (in_array($page, $allowed, true)) {
    include $page;
}

// Tainted unserialize with the options gate.
$data = $_POST["data"];
$obj = unserialize($data, ["allowed_classes" => false]);
?>
<p>html between segments is skipped</p>
<?= $page ?>
```

## Tests

`tests/php-parser.test.js` — positive cases (every construct
above, including alternative syntax, interpolation with
nested quotes, and `;`-separated statements followed by
compound statements) and negative cases (every loud failure
above, plus malformed input). Run with `npm test`.
