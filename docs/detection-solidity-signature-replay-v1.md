# Detection: Solidity Signature Replay v1 (Round 111)

Detector `solidity-signature-replay` — the twenty-third
real detector and the EIGHTH Solidity detector. It flags
an authorization built on `ecrecover` whose signed
message carries NO replay protection — no nonce, no
deadline / expiry, no EIP-712 domain separator. One
finding per compared ecrecover site, in function and
modifier bodies.

## CWE choice: CWE-294, not CWE-347

A captured signature resubmitted maps to **CWE-294
(Authentication Bypass by Capture-replay)**. The
authentication itself is bypassed by reuse: the
signature is genuine, the signer really signed that
message, and the attacker never forges anything — they
replay what they saw. CWE-347 (Improper Verification
of Cryptographic Signature) is the sibling for when
the signature is NOT verified properly — the recovered
address never compared, a malleable `s` accepted, a
`v` outside 27 / 28. Here the signature IS verified
correctly (`ecrecover` recovers the signer and the
result IS compared); what is missing is the message's
uniqueness, not the verification. A call that never
verifies the signer at all is CWE-347 territory, not
this detector's. This detector reports
`cwe_id: CWE-294`, severity `high`,
`vulnerability_type: signature replay`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-signature-replay-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `walkExpression` and `renderExpression` in
  `sol-guards.js` — the shared expression walker and the
  evidence renderer, so the round-110 and round-111
  detectors read calls the same way.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-signature-replay --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## What counts as an authorization

An `ecrecover(...)` call is in scope only when its result
is COMPARED — directly (the call sits inside a `==` /
`!=` comparison) or through a variable it was assigned
to (`address signer = ecrecover(...); require(signer ==
owner);`). The comparison is what makes the recovered
address gate something. The brief's own boundary is
stated here honestly: an ecrecover whose result is only
compared with the owner is STILL a finding when the
message can be reused — the comparison does not make
the message safe, it makes the replay matter. An
ecrecover whose result is never compared (returned,
logged, discarded) authorizes nothing, so it is out of
this detector's scope — pinned by a test — and belongs
to the CWE-347 question, not the replay question.

Authorization checks live in modifiers too
(`modifier onlySigner(...) { require(ecrecover(...) ==
msg.sender); _; }`), and the parser keeps
ModifierDefinition nodes on the contract since round
110 for exactly that scan, so modifier bodies are
scanned alongside function bodies. A finding in a
modifier names it as a modifier in the evidence, not
as a function.

## What counts as replay protection

A body is protected — and produces no finding even
when it compares an ecrecover result — when ANY ONE
of these is present in the same body:

- A `nonce*` identifier: a consumed nonce
  (`nonces[signer]++`, `nonces[to]` in the hashed
  message, `useNonce`, `_useNonce`).
- A `deadline` / `expir*` / `validUntil` identifier:
  an expiry check (`require(block.timestamp <=
  deadline)`).
- An EIP-712 binding: a `DOMAIN_SEPARATOR`
  identifier, or a typed-data helper call
  (`_hashTypedDataV4`, `hashTypedData`,
  `toTypedDataHash`).

ANY ONE counts. The safe pattern is all three together
(the OpenZeppelin ECDSA shape: EIP-712 typed data +
consumed nonce + deadline), but a consumed nonce alone
already prevents replay entirely — flagging it would be
a false positive an experienced reviewer would reject.
Protection is presence, not sufficiency: a deadline
with no nonce still allows replay inside the window,
and the detector cannot tell — the reviewer judges
whether the protection actually binds the signature.
That limitation is stated here, not hidden in the
code.

## What is NOT a finding

- **A protected body** (nonce, deadline, or EIP-712
  present, as above) — even when the ecrecover call
  is otherwise identical to a flagged one.
- **An uncompared ecrecover** (result returned, logged,
  or discarded): it authorizes nothing, so the replay
  question does not arise. Pinned by a test.
- **Cross-function protection**: a nonce consumed in
  another function does not protect this one. Round
  112 territory.
- **Library wrappers**: `ECDSA.recover(...)` /
  `SignatureChecker.isValidSignatureNow(...)` are not
  bare `ecrecover` calls, so they are not scanned.
  Whether the wrapper's message is protected is a
  different detector's question.
- **Signature malleability** (an `s` above the curve
  order, a `v` outside 27 / 28): CWE-347 territory,
  out of this round's scope.

## False-positive profile

The detector cannot prove the signature can be
captured for reachable inputs. A signature that is
only ever submitted by its signer through a private
channel, or a message whose action is harmless to
repeat, still flags — the pattern is identical to
the replayable one. The reviewer checks whether the
signature can actually be seen and resubmitted; when
it cannot, the finding is a false positive by design.
A finding here is a candidate for manual review, the
same posture as every detector in this repo.

## Limits carried over from the parser

The Solidity subset parser (round 108, §12) parses the
contracts this detector needs; anything outside the subset
(assembly, try/catch, struct-constructor arguments) fails
the parse loudly and the record is skipped, never scanned
approximately. Cross-function and cross-contract analysis
is out of scope — the pattern is local to one body, and
a base contract in another file is not resolved (a
`permit` flow whose nonce lives in a base in another
file is missed, not misreported).
