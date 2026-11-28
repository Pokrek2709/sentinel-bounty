# Solidity Subset Parser v1 (Round 108)

A hand-written Solidity subset parser (`src/detection/sol-parser.js`):
tokenizer + recursive-descent parser producing an AST with 1-based
line/column positions. Stdlib-only, synchronous, deterministic, and it
never executes the code it parses.

## Why hand-written

The second language needs structure (contracts, state variables,
functions, external calls, state writes in order) that a regex cannot
see, and the skill installs and verifies offline, so an npm parser is
out of scope this round. `@solidity-parser/parser` was evaluated (MIT,
the community-standard Solidity grammar) and NOT adopted: it would
need a vendoring story that does not exist yet, and the prototype's
first Solidity class does not need a full grammar. It remains the
documented upgrade path if the detector set grows beyond what the
subset grammar covers. That is a future decision (round 119's
Acorn-vendoring decision covers the same question for JavaScript), not
a blocker for this round.

The model is `src/detection/js-parser.js` (round 95): the same
tokenizer + recursive-descent shape, the same error discipline, the
same test posture (valid code parses, unsupported syntax fails loudly).

## Grammar covered

- Programs: `pragma`, `import`, `using` (skipped structurally — no
  analyzable code), `contract` / `library` / `interface`, free
  functions, `struct` / `enum` (bodies skipped), `event` / `error` /
  user-defined value types (skipped to `;`).
- Contracts: inheritance lists (`is A, B("arg")` — base constructor
  arguments skipped), state variables (including `mapping`, visibility,
  mutability, initializers), functions, `constructor` / `receive` /
  `fallback`, modifiers (name + arguments recorded; bodies parsed).
- Function headers: visibility, mutability, `virtual` / `override`,
  modifiers in any order, `returns (...)`. Interface functions without
  bodies are accepted (`body: null`).
- Statements: blocks, variable declarations (including tuple
  declarations `(uint a, uint b) = ...` with empty slots),
  assignments (simple and compound), `if` / `else`, `for` / `while` /
  `do-while`, `return` / `break` / `continue`, `emit`, `unchecked {}`
  blocks, `delete`.
- Expressions: literals (numbers with `_` separators, fractions,
  exponents, and units — `1 ether`, `30 days`; strings; booleans),
  member / index / call (including call options `{value: ...}` —
  critical for `.call{value:}("")`), `new`, type conversions
  (`address(x)`, `payable(x)`, `type(X)`), unary / binary / ternary,
  `msg.sender` / `msg.value` / `block.timestamp` / `tx.origin`.

## What fails loudly

Anything outside the subset fails with a `SolParseError` carrying
line and column — the caller counts that record in `skipped`, it never
falls back to scanning text with a regex. Pinned by tests:

- Inline assembly (`assembly { ... }`).
- `try` / `catch`.
- Struct-constructor arguments (`Foo({a: 1})`).
- Unbalanced braces, unterminated strings and block comments,
  unexpected characters.

## Safety properties

- Comments (line, block, and NatSpec `///` / `/** */`) are stripped
  by the tokenizer and string contents are single tokens, so sink
  text inside a comment or a string never becomes a call node.
- Positions are 1-based line/column, taken from the first token of
  each node.
- A reserved word can never be a type name: without that guard
  `delete x;` would parse as a variable declaration of type `delete`
  named `x`. The guard makes the declaration attempt fail and fall
  back to expression parsing, where `delete` is a unary operator.
- A `for`-init declaration does not consume its `;` — the `;` is the
  separator between init and test.

## Known limitations

- Base contracts from another file are not resolved (see the
  reentrancy doc — the detector still analyzes the contract with its
  own variables).
- `using ... for ...` directives are skipped structurally; a library
  function bound with `using for` is not inlined.
- Free functions at file scope are parsed but not analyzed by the
  reentrancy detector (which analyzes contract functions).
- No `abi.encode*` / `abi.decode` special-casing: they parse as
  ordinary calls, which is all the current detector needs.
