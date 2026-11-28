# Python Subset Parser v1 (Round 115)

A hand-written Python subset parser (`src/detection/py-parser.js`):
tokenizer + recursive-descent parser producing an AST with 1-based
line/column positions. Stdlib-only, synchronous, deterministic, and it
never executes the code it parses.

## Why hand-written

The third language needs structure (imports, function definitions,
taint flow through assignments and calls) that a regex cannot see,
and the skill installs and verifies offline, so an npm parser is out
of scope this round. The model is `src/detection/sol-parser.js`
(round 108): the same tokenizer + recursive-descent shape, the same
error discipline, the same test posture (valid code parses,
unsupported syntax fails loudly). Python's difference from Solidity
is indentation: the tokenizer emits INDENT / DEDENT / NEWLINE tokens
(the classic CPython approach), with implicit line continuation
inside `()`, `[]`, `{}` and explicit `\` continuation (a backslash
continuation suppresses the next line's indent processing, so a
continued line never opens a block).

No Python parser was evaluated for adoption this round — the subset
grammar is small and the first Python class (tainted pickle) needs
only it. A full Python grammar (e.g. a vendored parser) remains the
documented upgrade path if the Python detector set grows beyond what
the subset covers. That is a future decision, not a blocker for this
round.

## Grammar covered

- Modules: `import a`, `import a.b as c`, `from x import y`,
  `from x import y as z`, `from x import (a, b)` (parenthesized,
  trailing comma allowed), relative imports (`from . import x`,
  `from ..pkg import mod` — the level is recorded, the module is
  NOT resolved across files).
- Function definitions: `def name(params): suite` with positional
  parameters, defaults, annotations (parsed, not analyzed),
  `*args`, `**kwargs`, bare `*` (keyword-only marker) and `/`
  (positional-only marker). Nested function definitions parse and
  are registered in the detector's function table.
- Statements: assignment (simple, chained `a = b = c`, tuple
  unpacking `a, b = ...`, starred targets, annotated assignment
  `x: int = 1` with or without a value), augmented assignment
  (`+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`, `<<=`, `>>=`, `&=`,
  `|=`, `^=`), `if` / `elif` / `else`, `for` / `while` (both with
  `else`), `try` / `except` (with optional type and `as name`) /
  `else` / `finally`, `with` (multiple items, `as` targets),
  `return` (with or without a value, including tuple returns),
  `break` / `continue` / `pass`, `raise` (with optional `from`),
  `assert` (with optional message), `del`, `global` / `nonlocal`.
  Suites are indented blocks or same-line simple statements
  (`if x: return 1`); simple statements may be `;`-separated on
  one line.
- Expressions: literals (numbers: hex / octal / binary, decimal
  with `_` separators, fractions, exponents, imaginary `j`;
  strings with `r` / `b` / `f` / `u` prefixes and triple-quoted
  multi-line strings; `True` / `False` / `None`), adjacent-string
  concatenation (`"a" "b"` is one string), f-strings (literal and
  expression parts; `{{` / `}}` escapes; `!r` / `!s` / `!a`
  conversions, `:format-spec`, and `=` debug specifiers are
  stripped before the interpolation is parsed), names, attribute
  access, subscript / slice (`x[a]`, `x[a:b]`, `x[::2]`,
  multi-dimensional `x[a, b]`), calls (positional, keyword,
  `*args`, `**kwargs`), list / dict / set / tuple displays,
  binary / unary / boolean / comparison (including chained
  comparisons, `is` / `is not`, `in` / `not in`) / conditional
  (`a if cond else b`) expressions.

## What fails loudly

- Class definitions, decorators (`@...`), lambdas, comprehensions
  (list / dict / set), generator expressions, `async` / `await`,
  `yield`, the walrus operator (`:=`), matrix multiplication (`@`).
- Bad indentation (`unindent does not match any outer indentation
  level`), unterminated strings, unbalanced brackets.
- An assignment whose left-hand side is not a valid target
  (`x + y = 1`, a call as a target).
- An f-string with an unmatched `{`, a single `}`, or an empty
  interpolation.

Any of these raises `PyParseError` with line and column; the
detector counts the record in `skipped` and never falls back to
scanning text with a regex. A partial or wrong answer presented
as a parse is worse than no answer.

## Safety properties

- Comments (`#`) are stripped by the tokenizer and string contents
  are single tokens, so sink text inside a comment or a string
  never becomes a call node.
- Positions are 1-based line/column, taken from the first token of
  each node. F-string interpolation fragments are tokenized
  separately and re-based to the f-string token's position, so
  their positions are approximate (the f-string's line, the
  fragment's column) — findings never carry a source line, so
  this affects nothing the operator sees.
- Blank and comment-only lines emit no tokens and never change
  the indent level. A tab moves to the next multiple of 8
  columns for indentation, as in CPython.

## What the parser does not model (detector-level limits)

The parser is only the front end. The tainted-pickle detector's
own limits — methods not resolved through the call graph,
`pickle.Unpickler` and `dill` out of scope, `os.environ` not a
source, no constant propagation for literal keys — are documented
in `docs/detection-tainted-pickle-v1.md`, not here.

## Next step

Round 116: the PHP subset parser + tainted include/unserialize —
the fourth language on the same pattern.
