# Detection: Solidity tx.origin v1 (Round 110)

Detector `solidity-tx-origin` — the twentieth real detector and
the FIFTH Solidity detector. It flags `tx.origin` used in an
authorization comparison — `require(tx.origin == owner)`,
`if (tx.origin == ...)`, or the same shape inside a modifier
body. One finding per comparison site.

## CWE choice: CWE-862, not CWE-477

Authorization through the wrong principal maps to
**CWE-862 (Missing Authorization)**. The intended
authorization — "only the immediate caller may do this" —
is missing, because the check validates the transaction
originator instead of the caller: from the contract's
perspective the direct caller is never checked at all.
CWE-477 (Use of Obsolete Function) is the wrong family
entirely: `tx.origin` is not an obsolete or deprecated
function, it is a live global that is legitimate for other
uses (logging, for example). CWE-863 (Incorrect
Authorization) is the closest sibling — the check exists
but checks the wrong thing — and the repo's convention
(round 109) uses CWE-862 for authorization failures, so
this detector reports `cwe_id: CWE-862`, severity `high`,
`vulnerability_type: broken access control`, and documents
the CWE-863 reading here rather than hiding it.

## Why tx.origin is the wrong check

`tx.origin` is the externally-owned account that started
the whole transaction; `msg.sender` is the immediate
caller. Any contract in the middle can be tricked into
calling the victim on the originator's behalf — the
classic phishing shape: the owner makes one
innocent-looking call to an attacker contract, the
attacker contract calls the victim, and the victim's
`tx.origin` check passes because the originator is still
the owner. The check must be against `msg.sender`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-tx-origin-<sha256 16 hex>`).
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
sentinel detect --detector solidity-tx-origin --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as a tx.origin comparison

A `==` / `!=` BinaryExpression whose left or right subtree
contains a `tx.origin` member expression (object identifier
`tx`, property `origin`). Either side, either operator:
`require(tx.origin == owner)`, `require(owner ==
tx.origin)`, `if (tx.origin != owner) revert(...)`.
Function bodies AND modifier bodies are scanned — a
modifier is where an authorization check usually lives,
and the parser keeps ModifierDefinition nodes on the
contract since this round (see `docs/solidity-parser-v1.md`)
precisely so this scan is possible.

A nested comparison inside an already-flagged one
(`(tx.origin == owner) == true`) is flagged once, on the
outermost comparison — the walk carries an
"inside a flagged comparison" flag down the tree so the
inner comparison stays silent.

## What is NOT a finding

- **`tx.origin` as a plain value** — assigned
  (`address a = tx.origin;`), logged
  (`emit Log(tx.origin)`), or passed as a call argument
  (`foo(tx.origin)`): it is not an authorization
  comparison. Pinned by tests.
- **`msg.sender` comparisons**: the correct check, never
  flagged.

## Deliberate exclusions, pinned by tests

- **`require(tx.origin != address(0))` IS flagged.**
  It is a comparison using tx.origin, and the detector
  cannot tell a null-check from an authorization check.
  That is a false positive by design: the reviewer
  dismisses it when the comparison guards nothing
  sensitive. The alternative — exempting `!= address(0)`
  — would also exempt `require(tx.origin != attacker)`,
  which IS an authorization check, so the detector flags
  both and lets the human judge.
- **A function guarded ONLY by tx.origin is flagged twice,
  on purpose**: once by `solidity-access-control` (round
  109 does not count tx.origin as a guard, so the function
  has no valid guard) and once here (the guard it has
  checks the wrong principal). The two findings are
  complementary, not duplicates.
- **Cross-function authorization is not modeled**
  (round 112): a function that relies on a caller that
  checked tx.origin is not traced back to that caller.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately.
