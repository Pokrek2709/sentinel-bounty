# Detection: Solidity Unprotected Initializer v1 (Round 109)

Detector `solidity-unprotected-initializer` — the eighteenth real
detector and the THIRD Solidity detector. It flags an external/public
`initialize()` function that carries neither the `initializer` (or
`reinitializer`) modifier nor any access control — the
unprotected-initializer shape (SWC-112's initialization half): anyone
can call it and re-initialize the contract, typically taking
ownership. One finding per `initialize()` function.

## CWE choice: CWE-862, not CWE-284

An unprotected initializer maps to **CWE-862 (Missing
Authorization)**. The flaw is the absence of an authorization check
on the initialization entry point — the function never asks who is
calling, and nothing stops a second call. CWE-284 (Improper Access
Control) is the broader parent: it covers a check that exists but is
wrong or incomplete. This detector reports `cwe_id: CWE-862`,
severity `high`, `vulnerability_type: broken access control`.

## Architecture: a separate path, not the JavaScript taint engine

Same posture as the reentrancy detector (round 108): the JavaScript
taint engine is JavaScript-specific, so this detector is a separate
analysis over the Solidity subset AST (`src/detection/sol-parser.js`,
see `docs/solidity-parser-v1.md`).

What IS shared with the taint detectors (all language-neutral):

- `findingIdFor` — the finding-id helper
  (`solidity-unprotected-initializer-<sha256 16 hex>`).
- `MAX_CONTENT_CHARS` (1,000,000) and `MAX_FINDINGS_PER_RECORD` (100).
- `normalizeRawFinding` — every finding is normalized to
  `schemas/finding.schema.json` the same way.
- `sol-guards.js` — the guard rule (`hasAccessControl`), shared with
  the access-control detector (round 109) so the two detectors cannot
  drift apart on what counts as a guard.

Even the envelope is its own function following
`createTaintDetector`'s pattern (batch / single, content cap, finding
cap, ids from the record, parse error → `skipped`), because that
factory's `scanRecord` parses JavaScript and runs `TaintAnalyzer`.
This detector's `scanRecord` parses Solidity instead, and it rejects
a record whose `language` is present but not `solidity` / `sol`.

Run it with:

```
sentinel detect --detector solidity-unprotected-initializer --input <record.json>
```

The record's `content` is the Solidity source. A record that fails
to parse is counted in `skipped` with a parse-error message — never
scanned approximately.

## Rule: both protections missing

A function named `initialize` is flagged only when BOTH are missing:

- no `initializer` / `reinitializer` modifier, AND
- no access control (the guard rule shared with the access-control
  detector — see `docs/detection-solidity-access-control-v1.md` for
  the full list: onlyOwner/role modifiers, `require(msg.sender ==
  ...)` or a role call mentioning `msg.sender`, `if (msg.sender !=
  ...) revert(...)`).

Either protection alone is enough to stay silent:

- `initialize()` with `onlyOwner` but no `initializer` modifier is
  NOT flagged: the owner re-initializing is a lesser issue, and the
  modifier is the primary guard against re-initialization.
- `initialize()` with the `initializer` modifier but no access
  control is NOT flagged either — the modifier itself is the
  protection (it makes the second call revert).

A function is flagged only when it is externally callable: `external`
or `public` visibility (the parser records `visibility` on
FunctionDefinition nodes since round 109; a function with no
visibility qualifier is internal by the language default). Interface
functions without bodies are skipped. A function NOT named
`initialize` is never flagged by this detector — a `setup()` that
writes state with no guard is the access-control detector's job.

## Examples

Flagged (anyone can re-initialize and take ownership):

```solidity
function initialize(address next) external {
    owner = next;
    totalSupply = 1000;
}
```

Clean (initializer modifier):

```solidity
function initialize(address next) external initializer {
    owner = next;
}
```

Clean (access control, no modifier):

```solidity
function initialize(address next) external onlyOwner {
    owner = next;
}
```

## Not modeled (pinned by tests)

- Whether the contract is actually upgradeable — the detector does
  not verify inheritance from `Initializable` / `UUPSUpgradeable` or
  the absence of a constructor. A function named `initialize` on a
  non-upgradeable contract is still flagged when it is unprotected:
  the name signals initialization semantics, and an unprotected
  function that (re)initializes state is a missing-authorization
  finding either way.
- `onlyInitializing` on `initialize()` itself is not counted as
  protection (it is a lifecycle modifier for functions called DURING
  initialization, and treating it as a guard here would hide a
  genuinely unprotected entry point behind an unusual pattern).
- Constructors on upgradeable contracts (a constructor that sets
  state in an upgradeable contract is a different class — the
  constructor runs once at deployment, not through the proxy).
- Cross-file bases (pin round 108): an `initialize()` inherited from
  a base in another file is not analyzed.
- Intent: a deliberately re-runnable initializer is a false positive
  by design, and the detector cannot tell intent.

A finding here is a candidate for manual review — the same posture as
every detector in this repo: a precise, evidence-backed signal, not a
verdict. Evidence carries the function, the contract, the modifiers
present, and a `notes` string.
