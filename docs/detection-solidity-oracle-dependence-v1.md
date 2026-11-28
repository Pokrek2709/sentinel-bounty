# Detection: Solidity Oracle Dependence v1 (Round 111)

Detector `solidity-oracle-dependence` — the twenty-second real
detector and the SEVENTH Solidity detector. It flags a price
taken from ONE on-chain source and used in a critical
arithmetic computation with no TWAP, median, or staleness
check in the same function. One finding per critically-used
price-call site.

## CWE choice: CWE-829, not CWE-20

Trusting a single manipulable price maps to **CWE-829
(Inclusion of Functionality from Untrusted Control
Sphere)**. The price is data from an untrusted control
sphere — a DEX pool anyone can trade against, or a
single Chainlink feed whose rounds anyone can watch go
stale — included in the contract's trusted computation
(a mint, a borrow, a liquidation, a payout). CWE-20
(Improper Input Validation) is the generic "the input
was not checked" bucket: it says nothing about trusting
the source, and the price here is not "input" in the
validation sense — it is a read from infrastructure the
contract chose to trust. This detector reports
`cwe_id: CWE-829`, severity `high`,
`vulnerability_type: oracle price dependence`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-oracle-dependence-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `walkExpression`, `renderExpression`, and `callName` in
  `sol-guards.js` — the shared expression walker, the
  evidence renderer, and the callee-name helper, so the
  round-110 and round-111 detectors read calls the same way.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-oracle-dependence --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as a single-source price

A call whose callee name is one of:

- `getReserves` — a Uniswap V2 pair's reserves, from which
  the spot price is computed (`reserve1 * 1e18 / reserve0`).
- `getAmountsOut` / `getAmountsIn` — a Uniswap V2 router
  spot quote.
- `latestAnswer` / `latestRoundData` — a Chainlink feed read.
  A feed is a single source too until its staleness is
  checked: reading `latestAnswer()` and computing with it
  is the same shape as reading a pool's reserves.

A bare `price()` / `spotPrice()` call is deliberately NOT a
source: the name is too ambiguous (it could be a view over
a TWAP, a stored admin-set price, or a spot read), and
flagging it would be a guess. Pinned by a test.

## What counts as critical use

The price call's result must reach arithmetic in the same
function — either directly (the call sits inside a `*` `/`
`+` `-` `%` expression) or through a variable it was
assigned to (a plain declaration, a tuple declaration, or
a plain assignment — the parser puts a plain
declaration's initial value on the declarator, not on the
statement, so both shapes are read). The tracking is
name-based, not data flow: a variable reassigned to a
non-price value later in the function still counts as
price-bearing. That is a documented limitation, not a
silent wrong answer about what the detector did see.

## What counts as protection

A function is protected — and produces no finding even
when it uses a single-source price in arithmetic — when
ANY of these is present in the same function:

- A TWAP / median / average call: `consult`, `observe`,
  `getTWAP`, `getAveragePrice`, `getPriceCumulative`,
  `getCumulativePrice`, `median`, `getMedian`.
- A staleness check: a comparison (`<` `>` `<=` `>=`
  `==` `!=`), or a `require` argument, whose subtree
  mentions `updatedAt`, `answeredInRound`, or a
  `stale*` identifier (`isStale`, `stalePrice`).

Protection is presence, not sufficiency: a TWAP call
whose result is ignored still suppresses the finding,
and a staleness check on the wrong round still counts.
The detector cannot prove the protection actually
guards the price — the reviewer judges that, the same
way the access-control detectors cannot prove a guard
is sufficient.

## What is NOT a finding

- **Price used only for display** (an `emit` of the
  reserves, or a return of the raw values): the price
  gates nothing and computes nothing.
- **Comparison-only use** (`require(out >= minOut)`):
  the price gates a threshold, it is not computed
  with. Whether a threshold check is itself safe is a
  different question (a manipulated price can still
  pass a loose threshold), out of this round's scope.
  Pinned by a test.
- **A protected function** (TWAP / median / staleness
  check present, as above) — even when the single-source
  call is still in the function.
- **Cross-function protection**: a TWAP checked in
  another function does not protect this one. Round
  112 territory.
- **Modifier bodies**: only function bodies are scanned
  (price computation does not live in modifiers).

## False-positive profile

The detector cannot prove the pool can be moved, or
the feed can go stale, for reachable inputs. A pool
with deep liquidity, a feed checked in a base contract
in the same file but another function, or a price that
is only ever read after an off-chain sanity check all
still flag — the pattern is identical to the vulnerable
one. The reviewer checks whether the source can
actually be moved for reachable inputs; when it
cannot, the finding is a false positive by design. A
finding here is a candidate for manual review, the
same posture as every detector in this repo.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately. Cross-function and cross-contract analysis
is out of scope — the pattern is local to one function.
