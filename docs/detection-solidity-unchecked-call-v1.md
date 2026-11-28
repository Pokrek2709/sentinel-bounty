# Detection: Solidity Unchecked Call v1 (Round 112)

Detector `solidity-unchecked-call` — the twenty-fourth
real detector and the NINTH Solidity detector. It flags
a low-level external call (`.call`, `.delegatecall`,
`.staticcall`, `.send`) whose return value is NEVER
checked in the same function or modifier body. One
finding per unchecked call site.

## CWE choice: CWE-252, not CWE-841 or CWE-252's neighbours

A discarded return value maps to **CWE-252 (Unchecked
Return Value)**. The call itself is issued and may or
may not have failed — the contract never looks. The
failure mode is silent: ETH or a call sent nowhere,
state updated as if the call succeeded, no revert, no
event. CWE-841 (Improper Enforcement of Behavioral
Workflow) is the reentrancy sibling — it is about
ordering (call before state update), not about whether
the call's result was read at all. CWE-252's
neighbours — CWE-253 (Incorrect Check of Function
Return Value), CWE-754 (Improper Check for Unusual or
Exceptional Conditions) — are the siblings for when
the value IS checked but wrongly (the wrong branch,
the wrong boolean, a check that can never fail). Here
nothing is checked at all, so the finding reports
`cwe_id: CWE-252`, severity `high`,
`vulnerability_type: unchecked return value`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-unchecked-call-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `walkExpression` and `renderExpression` in
  `sol-guards.js` — the shared expression walker and the
  evidence renderer, so the Solidity detectors read calls
  the same way.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-unchecked-call --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as a low-level call

A call site is in scope only when it is one of four
low-level forms, on any receiver:

- `x.call{...}(...)` — the plain low-level call.
- `x.delegatecall(...)` — runs the callee's code in
  this contract's storage context.
- `x.staticcall(...)` — the read-only low-level call.
- `x.send(...)` — returns `false` on failure instead
  of reverting, so an unchecked `.send` is exactly
  the silent-failure shape CWE-252 describes.

`.transfer(...)` is deliberately NOT a sink: it reverts
when it fails, so there is nothing to check — a bare
`.transfer` cannot silently fail, and flagging it
would be a false positive. Pinned by a test.

## What counts as a check

A call site is checked — and produces no finding —
when ANY ONE of these holds, in the same function or
modifier body:

- **Direct check**: the call sits inside a check
  position — the argument of `require(...)` /
  `assert(...)`, the test of an `if` / `while` /
  `do-while` / `for`, or a `return` statement.
- **Assigned then checked**: the call's result is
  bound to a variable (plain assignment, declaration,
  or a tuple declaration — which binds only its FIRST
  NAMED element, because `.call` returns
  `(bool, bytes)` and only the bool says whether it
  worked) and that variable is MENTIONED in a check
  position anywhere later in the same body.

A variable used elsewhere — emitted in an event,
returned from a helper, fed into a ternary — is NOT
a check. A check of the tuple's second element
(`bytes memory ret`) does not check the call: the
bytes can be non-empty from a call that failed.
Both are pinned by tests.

## What is NOT a finding

- **A checked call** (direct or assigned-then-checked,
  as above) — even when the check is a bare `if (ok)
  {}` that does nothing on failure. Presence of a
  check counts, not its quality; the reviewer judges
  whether the check actually reverts.
- **`.transfer(...)`**: reverts on failure, nothing
  to check. Pinned by a test.
- **An unchecked ERC20 `transfer(...)`** (or
  `transferFrom`, `approve`): a real class — a token
  transfer that returns `false` instead of reverting
  — but a separate class with its own return-value
  semantics, not a low-level call. Out of scope,
  pinned by a test, not mixed into this detector.
- **A call in another function**: a result returned to
  a caller is a check in the caller only if the
  caller checks it — this detector checks one body
  at a time and never follows the value across
  functions.
- **A low-level call inside a comment or a string
  literal**: the parser never sees it as a call.
  Pinned by tests.

## False-positive profile

The detector cannot prove the call can actually
fail for reachable inputs. A call to a trusted,
known-good address that cannot fail in practice
still flags — the pattern is identical to the
unchecked one. The reviewer checks whether the
callee can fail and whether the unchecked path
matters; when it cannot fail, the finding is a
false positive by design. A finding here is a
candidate for manual review, the same posture as
every detector in this repo.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately. Cross-function analysis is out of scope —
the check must live in the same body as the call, and a
value returned to a caller is not followed. A tuple
declaration binds only its first named element, matching
the `(bool, bytes)` return of `.call`; a tuple whose
first element is unnamed binds nothing.
