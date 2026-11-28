# Detection: Solidity Access Control v1 (Round 109)

Detector `solidity-access-control` — the seventeenth real detector and
the SECOND Solidity detector. It flags an external/public function
that performs a sensitive operation with no access control at all: no
onlyOwner/role modifier, no `require(msg.sender == ...)` check, no
if-revert guard on `msg.sender`. One finding per function, on the
earliest sensitive operation in source order.

## CWE choice: CWE-862, not CWE-284

Missing access control maps to **CWE-862 (Missing Authorization)**.
The flaw is the complete absence of an authorization check before a
sensitive operation — the function never asks who is calling.
CWE-284 (Improper Access Control) is the broader parent: it covers a
check that exists but is wrong or incomplete. A function whose only
guard is `require(tx.origin == owner)` is a CWE-284 shape (a check
exists and is the wrong one) — that is round 110 territory, not this
detector. This detector reports `cwe_id: CWE-862`, severity `high`,
`vulnerability_type: broken access control`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-access-control-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `sol-guards.js` — the guard rule (`hasAccessControl`) and the
  effective state variables (`effectiveStateVars`), shared with the
  unprotected-initializer detector (round 109) so the two detectors
  cannot drift apart on what counts as a guard.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-access-control --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as a sensitive operation

- A write to a state variable: an assignment (simple or compound),
  an update (`x++`), or `delete`, whose target's root identifier is
  a state variable of this contract or of one of its bases declared
  in the same file (transitive, cycle-guarded). A local variable or
  a parameter with the same name shadows the state variable inside
  its scope. A base from another file is not resolved — the detector
  still analyzes the contract with its own variables, and a miss on
  an inherited write is a documented limitation, not a silent wrong
  answer about what it did see.
- An external fund-moving call: `.call`, `.transfer`, or `.send` on
  ANY receiver (`token.transfer(...)` is an external call too).
- A `selfdestruct` call.
- A `.delegatecall` — arbitrary code in this contract's context (the
  SWC-112 shape). The call itself moves no funds, but an unprotected
  delegatecall is the canonical "unprotected sensitive function".

A function is flagged only when it is externally callable: `external`
or `public` visibility (the parser records `visibility` on
FunctionDefinition nodes since round 109; a function with no
visibility qualifier is internal by the language default, so its
visibility is null and it is not flagged). Constructors, `receive`,
and `fallback` are not analyzed; interface functions without bodies
are skipped.

## What counts as a guard

One rule, shared with the unprotected-initializer detector
(`src/detection/sol-guards.js`, `hasAccessControl`):

- A modifier from the allow-list: `onlyOwner`, `onlyAdmin`,
  `onlyRole`, `onlyGovernance`, `onlyMinter`, `onlyPauser`,
  `onlyOperator`, `onlyManager`, `onlyAuthorized`, `onlyWhitelisted`,
  `onlySelf`, `authorized`, `requiresAuth`. An explicit allow-list,
  not a prefix rule: `only*` would also match `onlyAfter` /
  `onlyDuring` (time locks, not authorization).
- `require(msg.sender == <x>)` (or `<x> == msg.sender`) anywhere in
  the body.
- `require(<role-call>(..., msg.sender))` — `hasRole`, `hasRoleOr`,
  `isAdmin`, `isAuthorized`, `isWhitelisted` (a member call such as
  `accessControl.hasRole(...)` counts).
- `if (msg.sender != <x>) revert(...)` (or the revert in the else
  branch). The `==` form (`if (msg.sender == owner) revert(...)`)
  reverts on the authorized party itself, so it is NOT a guard.

Deliberately NOT guards (pinned by tests):

- `require(tx.origin == ...)` — tx.origin is the wrong check (round
  110 territory); a function guarded only by tx.origin is still
  flagged.
- `assert(msg.sender == ...)` — assert is for invariants, not
  authorization.
- `nonReentrant` — a reentrancy guard, not access control.
- `whenNotPaused` — a circuit breaker, not access control.
- `onlyInitializing` — a lifecycle modifier, not an authorization
  check.

The guard check is syntactic and position-blind: a guard anywhere in
the function counts, even after the sensitive operation (no
control-flow analysis — a guard placed after the write is a known
limitation, pinned by a test, not a false negative the detector
claims to catch).

## Examples

Flagged (unprotected ownership write):

```solidity
function setOwner(address next) external {
    owner = next;   // anyone can take ownership
}
```

Flagged (unprotected withdrawal — the call is the earliest operation):

```solidity
function withdraw(uint256 amount) external {
    (bool ok, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}
```

Clean (modifier):

```solidity
function setOwner(address next) external onlyOwner {
    owner = next;
}
```

Clean (require):

```solidity
function setOwner(address next) external {
    require(msg.sender == owner, "not owner");
    owner = next;
}
```

## False-positive profile — read this before trusting a finding

The detector cannot tell intent. A public function that is MEANT to
be public — `deposit()`, `vote()`, `claim()` — writes state with no
access control and is flagged. That is by design: the brief defines
"sensitive" as state-write / fund-move / ownership change, and the
detector reports every externally callable function matching it. A
finding here is a candidate for manual review — the reviewer
dismisses the ones that are public by design. The same posture as
every detector in this repo: a precise, evidence-backed signal, not a
verdict.

Evidence carries the function, the contract, the operation
(`state-write` / `fund-call` / `selfdestruct` / `delegatecall` with
the variable or the rendered sink), and a `notes` string — call
arguments are elided as `(...)` in the rendered callee, so no literal
value ever lands in a finding.

## Not modeled (pinned by tests)

- Cross-function access control (a guard in a caller that calls an
  unguarded sensitive function) — round 112 territory.
- `this.` calls (an external call to the contract itself through its
  own external interface).
- Whether a guard is sufficient — a `require` on the wrong address
  still counts; the detector is a candidate generator, and the human
  reviewer judges sufficiency.
- Intent: a function that is public by design is still flagged (see
  the false-positive profile above).
