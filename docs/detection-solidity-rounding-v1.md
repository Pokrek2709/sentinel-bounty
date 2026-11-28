# Detection: Solidity Rounding v1 (Round 110)

Detector `solidity-rounding` — the nineteenth real detector and
the FOURTH Solidity detector. It flags integer division
BEFORE multiplication (`x / y * z`, `amount / total *
price`): the division truncates toward zero before the
multiplication runs, so the result is systematically
smaller than the exact value. One finding per
multiplication site.

## CWE choice: CWE-682, not CWE-190 / CWE-191

Incorrect calculation maps to **CWE-682 (Incorrect
Calculation)**. The arithmetic itself is wrong — a
truncation the author did not intend, in the wrong
order. CWE-191 (Integer Underflow) is wrap-around below
zero, and CWE-190 (Integer Overflow) is wrap-around
above the maximum: neither describes a division that
throws away a remainder. This detector reports
`cwe_id: CWE-682`, severity `medium`,
`vulnerability_type: integer precision loss`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-rounding-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `walkExpression` and `renderExpression` in `sol-guards.js`
  (round 110) — the shared expression walker and the
  evidence renderer, so the three round-110 detectors
  render expressions the same way.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-rounding --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as divide-before-multiply

A `*` BinaryExpression whose left or right operand is DIRECTLY a
`/` BinaryExpression. Solidity parses left-associatively, so
`x / y * z` is `(x / y) * z` — the `*` node's left child is the
`/` node — and `(a / b) * c` is the same AST (the parser has no
paren node), so both are flagged the same way. `z * (x / y)` is
flagged too: the division is the `*` node's right operand.

The evidence names both sides: `division` is the rendered
division (`amount / total`), `multiplication` is the rendered
multiplication (`(amount / total) * price` — nested binary
children are parenthesized so the evidence reads
unambiguously).

## What is NOT a finding

- **Multiply first, divide last** (`x * y / z`, which parses as
  `(x * y) / z`): the division is the LAST operation, so the
  truncation happens once, at the end, and is the intended
  rounding. This is the fix the remediation prescribes, so it
  must stay silent.
- **Bare division** (`x / y` with no following multiplication):
  the truncation is the whole result, not a loss before a
  later operation.
- **Division and multiplication in separate statements**
  (`uint q = x / y; ... z = q * w;`): tracking that needs
  data flow, not one expression. A documented limitation,
  pinned by a test.
- **Division inside a call argument of a multiplied value**
  (`foo(a / b) * c`): the `/` is not a direct operand of the
  `*`. Pinned by a test.
- **Division before exponentiation** (`(x / y) ** 2`):
  precision loss of a different shape, out of this round's
  scope. Pinned by a test.
- **Modifier bodies**: only function bodies are scanned
  (constructors included — arithmetic there matters too).

## False-positive profile

The detector cannot prove divisibility statically. A division
that always divides evenly — a constant denominator that
always divides the numerator — is still flagged, because
the pattern is identical to the lossy one. The reviewer
checks whether the division can actually truncate for
reachable inputs; when it cannot, the finding is a false
positive by design. A finding here is a candidate for
manual review, the same posture as every detector in this
repo.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately. Cross-function and cross-contract analysis
is out of scope — the pattern is local to one expression.
