# Detection: Solidity Weak Randomness v1 (Round 110)

Detector `solidity-weak-randomness` — the twenty-first real
detector and the SIXTH Solidity detector. It flags
block-derived entropy used as randomness: `block.timestamp`,
`block.number`, `blockhash(...)`, `block.difficulty` /
`block.prevrandao`, `block.coinbase` feeding a hash, a
modulo, or a seed variable. One finding per
entropy-source site, with the context named in the
evidence.

## CWE choice: CWE-338, not CWE-337

Predictable randomness maps to **CWE-338 (Use of
Cryptographically Weak PRNG)**. Block data is public
before the transaction executes and, for
`block.timestamp` and `block.coinbase`, partly chosen by
the block producer — the "PRNG" itself (hash or modulo
of block data) is weak and predictable. CWE-337
(Predictable Seed in PRNG) is the closest sibling: it
covers a predictable seed fed into an otherwise sound
generator. Here the block data IS the generator — the
hash / modulo of block data is the whole "PRNG" — so
CWE-338 is the right mapping. This detector reports
`cwe_id: CWE-338`, severity `medium`,
`vulnerability_type: weak randomness`.

## Why block data is not randomness

- `block.timestamp`: public in advance, and the block
  producer can shift it within a small window.
- `block.number`: fully predictable.
- `blockhash(...)`: public once the block exists, and
  only the last 256 blocks are even available.
- `block.difficulty` / `block.prevrandao`: `prevrandao`
  is the post-merge randomness beacon, but it is known
  to the block proposer in advance — it is NOT secure
  randomness either.
- `block.coinbase`: chosen by the block producer.

Any "random" value derived from these sources can be
computed in advance by an attacker (or, as a
miner/validator, influenced), who then only submits the
transaction when it wins.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-weak-randomness-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `renderExpression` in `sol-guards.js` (round 110) — the
  shared evidence renderer.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-weak-randomness --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as weak randomness

A block-entropy source is flagged ONLY when it sits in a
randomness context — one of three:

- **(a) Inside a hash call** — `keccak256(...)`,
  `sha256(...)`, `sha3(...)` (the classic
  `uint(keccak256(abi.encodePacked(block.timestamp,
  msg.sender))) % n`). The source may be nested inside
  `abi.encodePacked` or any other call inside the hash
  arguments; the context flag propagates through.
- **(b) As an operand of `%`** — the classic "random in
  range" (`block.timestamp % 100`,
  `uint(blockhash(block.number - 1)) % 100`). The source
  may be nested inside the operand's subtree
  (`(block.timestamp + x) % 100`).
- **(c) As a seed initializer** — the initializer of a
  variable, or the right side of an assignment, whose
  target name matches `/seed|random|rand|entropy/i`
  (`uint256 seed = block.timestamp;`). The name match is
  case-insensitive.

When more than one context applies (a hash inside a
modulo, a seed that is a hash), the evidence names the
first in priority order hash, then modulo, then seed —
`kind` is `block-entropy-hash`, `block-entropy-modulo`,
or `block-entropy-seed`. A `blockhash(...)` call's
arguments are NOT scanned for further sources: the
argument is a block SELECTOR (`blockhash(block.number -
1)`), not entropy — the blockhash result is the
randomness, the number inside it is not. That keeps one
`blockhash` site to one finding.

## What is NOT a finding

Block data is legitimate in most code, and the context
restriction is the whole point of this detector:

- **Deadline checks** — `require(block.timestamp >=
  start)` — a comparison, not randomness.
- **Deadline arithmetic** — `uint256 deadline =
  block.timestamp + 1 days` — `+`, not `%`, and the
  target name is not seed-like.
- **Logging** — `emit Tick(block.timestamp)`.
- **A hash of user input only** —
  `keccak256(abi.encodePacked(msg.sender, nonce))` —
  has no block source.
- **`block.gaslimit`** — not in the source list, never a
  finding (it is a block property, not an entropy source
  this detector models).

## Deliberate exclusions, pinned by tests

- **A seed variable used later is not traced.**
  `uint256 seed = block.timestamp;` is flagged by rule
  (c), but a later `keccak256(seed)` is not traced back
  to the seed — that needs data flow, not one expression.
  A documented limitation.
- **Modifier bodies are not scanned** — randomness does
  not live in modifiers (unlike authorization checks,
  which do — see the tx.origin detector).
- **A finding is a candidate for manual review**: the
  detector cannot tell whether the "random" value guards
  anything with value at stake. A lottery built on
  `block.timestamp % 100` is a real finding; a
  cosmetic random pick with nothing at stake is the same
  pattern and the reviewer dismisses it.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately.
