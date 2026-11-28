# Detection: Solidity Cross-Function Reentrancy v1 (Round 112)

Detector `solidity-cross-function-reentrancy` — the
twenty-fifth real detector and the TENTH Solidity
detector. It flags a function A (external / public)
that performs an external call and then READS a state
variable, while a DIFFERENT external / public function
B of the same contract WRITES that variable. One
finding per (call site, variable, writing function)
triple.

## CWE choice: CWE-841, the same as single-function reentrancy

The single-function reentrancy detector (round 108)
already maps call-then-write to **CWE-841 (Improper
Enforcement of Behavioral Workflow)**. The
cross-function shape is the same vulnerability one
level out: the ordering assumption is not "state is
updated before the call returns" but "no other
function runs between the call and the read" — and
during the external call the callee CAN re-enter
through B, changing the variable A is about to read.
The workflow the contract enforces is broken by the
interleaving, not by the call itself. The finding
reports `cwe_id: CWE-841`, severity `high`,
`vulnerability_type: cross-function reentrancy`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-cross-function-reentrancy-<sha256 16 hex>`).
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
sentinel detect --detector solidity-cross-function-reentrancy --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as the pattern

Three pieces must all be present, in one contract
(including same-file base contracts, whose state
variables and functions are visible to the derived
contract — pinned by a test):

1. **A sink in A**: A calls `.call`, `.transfer`,
   or `.send` on an address, or `msg.sender.call`
   / `address(this).call`. `delegatecall` is NOT
   a sink — it runs foreign code in THIS contract's
   storage, which is a different class (pinned by
   a test). `this.f()` is NOT a sink — the parser
   models it as an external call to this contract,
   but the detector does not follow it into the
   callee (pinned by a test).
2. **A post-call READ in A**: A reads a state
   variable at a source position AFTER the sink's
   position, and NOT inside the sink call's own
   subtree (a read inside the call's arguments, e.g.
   the `value:` option, happens before the call
   returns and is not a post-call read — pinned by
   a test). A read inside a branch after the call
   counts: the analysis is position-based, not
   segment-based, so a read in an `if` that may or
   may not run is still counted (over-approximation,
   stated honestly here).
3. **A WRITE in B**: a different external / public
   function B of the same contract writes the same
   variable — plain assignment, compound assignment,
   or `++` / `--`.

One finding per (sink, variable, B) triple: two
functions writing the same variable are two
findings; two reads of the same variable after one
sink are one finding.

## What counts as a guard

The pair (A, B) is suppressed — and produces no
finding — ONLY when BOTH functions carry the
`nonReentrant` modifier. One guard alone is not
enough: a guarded A still lets the callee re-enter
through an unguarded B, and a guarded B still lets
the callee re-enter through an unguarded A (the
guard lives on the function entered, not on the
contract). This was analyzed, not assumed — the
suppression rule is `A guarded AND B guarded`, and
both one-sided cases are pinned by tests as
findings. A mutex implemented as a state variable
(`locked = true; ...; locked = false;`) is NOT
recognized as a guard — the detector cannot prove
the flag is checked on entry — so a hand-rolled
mutex pair still flags; the reviewer judges it.

## What is NOT a finding

- **Both functions guarded** (`nonReentrant` on A
  AND on B): the shared guard blocks the
  interleaving. Pinned by a test.
- **A writing the variable after the call**: that is
  single-function reentrancy (round 108) territory —
  this detector only reads after the call. A function
  that only writes after the call produces no finding
  here, pinned by a test.
- **A read before the call only**: the interleaving
  cannot change what was already read. Pinned by a
  test.
- **B is internal / private, a constructor, or a
  modifier**: only external / public functions can be
  re-entered from outside, so only they are B
  candidates. All three are pinned by tests.
- **A is internal / private**: an internal function
  cannot be entered directly from outside. Pinned by
  a test.
- **B writes a different variable**: the shared state
  is the variable read after the call, nothing else.
  Pinned by a test.
- **A local or parameter shadowing the state
  variable**: the read is of the local, not the state
  variable — the analysis tracks declaration scopes
  and function parameters. Both are pinned by tests.
- **`this.` calls and `delegatecall`**: not sinks, as
  above. Pinned by tests.

## False-positive profile

The detector cannot prove the callee actually
re-enters through B, nor that B is reachable by the
attacker at all. A call to a trusted contract that
never calls back still flags — the pattern is
identical to the exploitable one. The reviewer
checks whether the callee can call back into B and
whether the read after the call matters; when it
cannot, the finding is a false positive by design.
The position-based read rule adds a second source
of noise: a read inside a branch that cannot run
after the call still counts. A finding here is a
candidate for manual review, the same posture as
every detector in this repo.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately. Cross-contract analysis is out of scope:
inheritance across files is not resolved, a base contract
in another file is missed, not misreported; storage-reference
aliasing is not modeled (a variable assigned to a storage
reference and written through it is missed); a hand-rolled
mutex via a state variable is not recognized as a guard.
The read rule is position-based, not segment-based —
unlike the round-108 detector, it does not track which
branch a read sits in.
