# Detection: Solidity Reentrancy v1 (Round 108)

Detector `solidity-reentrancy` — the sixteenth real detector and the
FIRST Solidity detector. It flags a function that performs an external
call and then writes state afterwards: the classic
checks-effects-interactions violation (SWC-107).

## CWE choice: CWE-841, not CWE-362

Reentrancy maps to **CWE-841 (Improper Enforcement of Behavioral
Workflow)**. The vulnerability is a state-machine ordering violation:
an untrusted call happens before the state transition that should
have closed the workflow (the balance update that would make a second
withdrawal fail). CWE-362 (Concurrent Execution using Shared Resource
with Improper Synchronization, i.e. race condition) is the broader
parent — reentrancy IS a race in the loose sense (two executions
interleaving over shared state) — but CWE-362 is about concurrent
threads / processes sharing a resource, and it says nothing about the
ordering contract that was violated. CWE-841 names exactly what went
wrong: the workflow's steps ran in the wrong order. SWC-107
(Reentrancy) maps to CWE-841 in the SWC registry, and the detector
reports `cwe_id: CWE-841`, severity `high`.

## Architecture: a separate path, not the JavaScript taint engine

The JavaScript taint engine (`src/detection/taint-engine.js`) is
JavaScript-specific — its identifiers, member expressions, call
shapes, and source model are all JavaScript. Reusing it for Solidity
would mean lying about what the engine models. So this detector is a
separate analysis over the Solidity subset AST
(`src/detection/sol-parser.js`, see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper (`solidity-reentrancy-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-reentrancy --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## Sinks

`.call`, `.transfer`, `.send` on ANY receiver. In Solidity the member
name is distinctive — `token.transfer(...)` is an external call to
another contract too, and it is flagged. `.delegatecall` /
`.staticcall` are NOT sinks this round (a delegatecall class of its
own; pinned by a test).

## State writes

An assignment (simple or compound), an update (`x++`), or `delete`
whose target's root identifier is a state variable of this contract
or of one of its bases declared in the same file (transitive,
cycle-guarded). A local variable or a parameter with the same name
shadows the state variable inside its scope. A base from another file
is not resolved — the detector still analyzes the contract with its
own variables, and a miss on an inherited write is a documented
limitation, not a silent wrong answer about what it did see.

## Analysis model: segment-based, branch-sensitive

Statements are walked in source order, collecting events per segment:
an external call (sink) or a state write. A finding is a call
followed by a write in the SAME segment — one finding per call site
(the call and the FIRST state write after it; a write pairs with the
nearest preceding call, so two call sites with a write each are two
findings).

- A branch (`if`) evaluates its test first, then walks the consequent
  and the alternate as separate segments seeded with the events before
  the branch — events inside a branch never leak out of it (the write
  may or may not happen).
- A loop body is seeded with the events before the loop and the test;
  a `for` update is analyzed as a segment seeded with the body
  events.
- `return` / `revert(...)` / `break` / `continue` end a segment: dead
  code after them is not analyzed (a return after a call is the
  correct pattern).
- A function with the `nonReentrant` modifier is not flagged. A
  constructor is not analyzed (it cannot be re-entered while it is
  still constructing). Interface functions without bodies are skipped.
- An assignment whose value IS the call (`balances[x] =
  addr.call{value: 1}("")`) writes the state variable AFTER the call
  returns, so it IS a call-then-write and it is flagged.

Evidence carries the call, the write, and a `notes` string
(`external call <sink> at line <n> precedes state write to <var> at
line <n> in function <fn>`) — the `reentrancy` entry in
`knowledge/evidence-checklists.json` requires `evidence_notes`, so
the field is mandatory, not decorative. Call arguments are elided as
`(...)` in the rendered callee, so no literal value ever lands in a
finding.

## Examples

Flagged (classic withdraw):

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "call failed");
    balances[msg.sender] -= amount;   // write AFTER the call
}
```

Clean (checks-effects-interactions):

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount;   // effects first
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "call failed");
}
```

Clean (guard):

```solidity
function withdraw(uint256 amount) external nonReentrant {
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;
}
```

## Not modeled (pinned by tests)

- Cross-function reentrancy (a call in one function, the write in
  another) — round 112 territory.
- Storage-reference aliasing (`uint storage b = balances; b[x] = 0;`
  writes through an alias the detector does not track).
- Cross-iteration writes inside one loop body (a write before the
  call in the same body, reached again on the next iteration).
- `this.` calls (an external call to the contract itself through its
  own external interface).

A finding here is a candidate for manual review — the same posture as
every detector in this repo: a precise, evidence-backed signal, not a
verdict.
