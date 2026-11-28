# Changelog — sentinel-bounty

All notable changes to this project are documented here. Entries are drawn
from the capability reports in `~/workspace/sentinel-bounty/`
(`capability-report-*.md`). Phase percentages are the reports' own
first-implementation estimates, not test counts. Releases are cut on the
v0.x tag line (see `docs/release-process-v1.md`).

## [Unreleased]

### Round 116: PHP subset parser and tainted-include/unserialize detectors (2026-11-29)

- Second language round after the JavaScript set closed
  in round 114. The fourth language on the project: a
  hand-written stdlib-only PHP subset parser
  (`src/detection/php-parser.js`, `docs/php-parser-v1.md`)
  — tokenizer + recursive-descent parser over `<?php` /
  `<?=` / `<?` segments (HTML between segments skipped,
  `?>` ends a segment even inside a comment, the newline
  after `?>` belongs to the close tag, `<?xml` is not an
  open tag), covering function definitions (defaults,
  types, variadic `...$rest`, by-reference `&$x`, return
  types parsed and discarded, nested defs), assignment
  (chained, `list()` and short-list targets, augmented,
  `??=`), `if` / `elseif` / `else`, `foreach` / `for` /
  `while` / `do-while`, `switch`, `try` / `catch` /
  `finally` — braced AND alternative (`:` / `endif` /
  `endforeach` / `endfor` / `endwhile` / `endswitch`)
  suites — `return` / `break` / `continue` / `throw`,
  `echo` / `print` / `exit` / `die`, `isset` / `empty` /
  `unset`, `global` / `static` / `const`, `namespace` /
  `use` / `declare`, `#[...]` attributes, and expressions
  (interpolated strings with nested quotes, array
  literals `[]` / `array()`, casts, `new`, `clone`,
  `instanceof`, ternary including the short form, `??`,
  named arguments, spread, `include` / `require` as
  statements and expressions, `->` / `?->` / `::` calls,
  concatenation). Fails loudly on class / interface /
  trait / enum definitions, closures, `fn` arrow
  functions, `match`, heredoc / nowdoc, `yield`, `goto`,
  variable variables, dynamic member access, and
  `__halt_compiler`. A shared config-driven PHP taint
  analyzer (`src/detection/php-taint.js`) sits between
  the parser and the two detectors, modeled on the
  Python analyzer, not on the JavaScript taint engine.
  No external PHP parser adopted (stdlib-only).
- `tainted-include` (thirtieth real detector, FIRST PHP
  detector, CWE-98 Improper Control of Filename for
  Include/Require Statement in PHP Program, severity
  high): tainted data reaching `include` / `require` /
  `include_once` / `require_once` (statement and
  expression forms; kind always `tainted-arg` — a
  language construct cannot be aliased). Sources:
  function parameters (round-95 fallback), the
  superglobals `$_GET` / `$_POST` / `$_REQUEST` /
  `$_COOKIE` / `$_FILES` (bare and subscripted), and
  `file_get_contents('php://input')`. `$_SERVER` /
  `$_SESSION` / `$GLOBALS` / `$_ENV` are NOT sources.
  Sanitizers: `basename()`, `(int)` / `(float)` /
  `(bool)` casts, `intval` / `floatval` / `boolval`.
  Guards: strict `in_array($x, $allowed, true)`
  (strict `true` REQUIRED), `array_key_exists($x,
  $allowed)`, `isset($allowed[$x])` in an enclosing
  `if`, plus a `switch ($var)` with NO `default` case;
  guards intersect on branch join and a judged
  expression is guarded iff all its variable leaves
  are guarded. The early-return guard shape and a
  Subscript as a guarded expression are NOT modeled
  (pinned by tests). One finding per sink site,
  confidence `potential`, never carrying a literal
  value or source line.
- `tainted-unserialize` (thirty-first real detector,
  SECOND PHP detector, CWE-502 Deserialization of
  Untrusted Data, severity high): tainted data reaching
  `unserialize($data)` (judged argument positional 0
  or named `data:`). Sources are the same superglobal
  / `php://input` / parameter sources as the include
  detector. `unserialize($data, ['allowed_classes' =>
  false])` — positional argument 1 or named
  `options:` — is CLEAN, and an empty allow-list is
  likewise clean; a non-empty allow-list is still
  flagged (listed classes can carry gadgets); options
  passed as a variable are flagged (no constant
  propagation). Sanitizers: `(int)` / `(float)` /
  `(bool)` / `(array)` casts, `intval` / `floatval` /
  `boolval`, `json_decode` / `json_encode`. A bare
  `unserialize` always resolves to the global sink (the
  PHP fallback); `\unserialize` is a sink; a qualified
  `Foo\unserialize` is NOT a sink; a call reached
  through a `use function` alias reports kind
  `aliased-call` with any argument. `json_decode` is
  NOT a sink, and allow-list guards do NOT apply to
  this detector. One finding per sink site, confidence
  `potential`, never carrying a literal value or source
  line.
- The detectors are wired into `src/detection/detector.js`,
  `bin/sentinel.js` (usage line and description),
  `SKILL.md` (both copies, byte-identical), and
  `docs/README.md`; the scope document gains addendum
  §20. Total detectors now 31 (5 regex + 13
  parser-based JavaScript + 10 Solidity + 1 Python +
  2 PHP).

### Round 115: Python subset parser and tainted-pickle detector (2026-11-29)

- First language round after the JavaScript set closed in
  round 114. The third language on the project: a
  hand-written stdlib-only Python subset parser
  (`src/detection/py-parser.js`, `docs/python-parser-v1.md`)
  — tokenizer + recursive-descent parser with INDENT /
  DEDENT / NEWLINE tokens (the classic CPython approach),
  implicit continuation inside `()`, `[]`, `{}` and
  explicit `\` continuation (which suppresses the next
  line's indent processing), covering imports (including
  parenthesized from-imports and relative imports, level
  recorded, never resolved across files), function
  definitions (defaults, annotations, `*args`, `**kwargs`,
  bare `*` and `/` markers, nested defs), assignment
  (chained, tuple unpacking, starred targets, annotated,
  augmented), `if` / `elif` / `else`, `for` / `while`
  (with `else`), `try` / `except` / `else` / `finally`,
  `with`, `return` / `break` / `continue` / `pass` /
  `raise` / `assert` / `del` / `global` / `nonlocal`, and
  expressions (literals, f-strings with conversions /
  format specs / debug specifiers, attribute / subscript /
  slice, calls, list / dict / set / tuple displays,
  binary / unary / boolean / comparison / conditional).
  Fails loudly on class definitions, decorators, lambdas,
  comprehensions, generator expressions, `async` /
  `await`, `yield`, the walrus operator, and matrix
  multiplication. No external Python parser adopted
  (stdlib-only).
- `tainted-pickle` (twenty-ninth real detector, FIRST
  Python detector, CWE-502 Deserialization of Untrusted
  Data, severity high): runs a separate taint analysis
  over the Python subset AST — NOT the JavaScript taint
  engine, which is JavaScript-specific — flagging
  tainted data reaching `pickle.load` / `loads`,
  `marshal.load` / `loads`, `yaml.load` (without a safe
  Loader), or `shelve.open`. Sources: function
  parameters (round-95 fallback: a helper never called,
  or called only with clean arguments, is still analyzed
  with its parameters as sources), `input()`,
  `sys.argv`, Flask `request` attributes (`args` /
  `form` / `data` / `json` / `values` / `files` /
  `cookies` / `get_json()` / `get_data()`). `os.environ`
  is NOT a source. Sanitizers: `int` / `float` / `str` /
  `bool` / `len` / `hash` / `repr` / `json.loads` /
  `json.load` / `int.from_bytes` and `.decode()` /
  `.hex()`. Taint flows inter-procedurally through known
  functions and their return values (memoized per
  tainted-parameter mask, recursion cut, call-graph
  depth capped at 8); import resolution applies
  (module aliases, from-import bindings, assignment
  aliases collected flow-insensitively at module
  level); a sink reached through a name binding reports
  kind `aliased-call` with any argument, a direct
  member call reports kind `tainted-arg` only when its
  judged argument is tainted. A bare `loads(...)` with
  no import binding is NOT a sink. `yaml.load` with
  `Loader=yaml.SafeLoader` / `CSafeLoader` is clean.
  `pickle.Unpickler(...).load()` and `dill` are out of
  scope; methods are not resolved through the call
  graph; object-attribute taint is not modeled. One
  finding per sink site, confidence `potential`, never
  carrying a literal value or source line.
- The detector is wired into `src/detection/detector.js`,
  `bin/sentinel.js` (usage line and description),
  `SKILL.md` (both copies, byte-identical), and
  `docs/README.md`; the scope document gains addendum
  §19. Total detectors now 29 (5 regex + 13
  parser-based JavaScript + 10 Solidity + 1 Python).

### Round 111: Solidity oracle-dependence and signature-replay detectors (2026-11-29)

- Two Solidity detectors on the same subset parser (round
  110's §14 "next step"), each with its own CWE — the
  Solidity detectors keep diverging in CWE, because the
  flaws are different kinds:
  - `solidity-oracle-dependence` (twenty-second real
    detector, seventh Solidity detector): a single-source
    price (`getReserves`, `getAmountsOut` /
    `getAmountsIn`, `latestAnswer` / `latestRoundData`)
    used in arithmetic with no TWAP, median, or staleness
    check in the same function (CWE-829 Inclusion of
    Functionality from Untrusted Control Sphere, severity
    high — not CWE-20, which is too generic to say
    anything about trusting the source), one finding per
    price-call site. A TWAP / median call or a staleness
    check on `updatedAt` in the same function is clean; a
    price used only for display, only returned, or only
    in a comparison is clean.
  - `solidity-signature-replay` (twenty-third real
    detector, eighth Solidity detector): a compared
    `ecrecover` authorization whose signed message
    carries no nonce, no deadline, and no EIP-712 domain
    separator (CWE-294 Authentication Bypass by
    Capture-replay, severity high — not CWE-347, because
    the signature IS verified correctly and what is
    missing is the message's uniqueness), one finding per
    ecrecover site, in function and modifier bodies. ANY
    ONE of a nonce, a deadline, or an EIP-712 binding in
    the same body is clean; an uncompared ecrecover is
    out of scope.
- Shared this round, not duplicated: the name-based
  assignment tracking both detectors use — and the parser
  fact it exposed (a plain declaration's initial value
  lives on the declarator, a tuple declaration's at
  statement level; both shapes are read now). The first
  test run caught the plain-declaration shape being
  missed; the fix is pinned by the two "through a
  variable" tests.

### Round 112: Solidity unchecked-external-calls and cross-function-reentrancy detectors (2026-11-29)

- Two Solidity detectors on the same subset parser (round
  111's §15 "next step"), the last two Solidity classes
  on the map before the round returns to JavaScript
  (round 113: XXE + ReDoS). No parser growth — no new
  node types, no new fields:
  - `solidity-unchecked-call` (twenty-fourth real
    detector, ninth Solidity detector): a low-level call
    (`.call` / `.delegatecall` / `.staticcall` /
    `.send`) whose return value is never checked in the
    same function or modifier body (CWE-252 Unchecked
    Return Value, severity high — not CWE-841, because
    nothing is checked at all rather than ordered
    wrongly), one finding per unchecked call site. A
    check is direct (require / assert / if / while /
    do-while / for-test / return) or assigned-then-checked
    (name-based, anywhere later in the same body). A
    tuple declaration binds only its first NAMED element
    (the bool of `.call`'s `(bool, bytes)` return), so
    checking only the bytes does not check the call.
    `.transfer` is not a sink (it reverts on failure);
    an unchecked ERC20 `transfer` is a separate class,
    pinned out of scope.
  - `solidity-cross-function-reentrancy` (twenty-fifth
    real detector, tenth Solidity detector): the first
    detector that analyzes ACROSS functions — function A
    (external / public) performs an external call
    (`.call` / `.transfer` / `.send`) and then READS a
    state variable, while a different external / public
    function B of the same contract WRITES it (CWE-841
    Improper Enforcement of Behavioral Workflow,
    severity high — the same CWE as single-function
    reentrancy, because the ordering assumption is broken
    by the interleaving), one finding per (call site,
    variable, writing function) triple. The read rule is
    position-based (a read after the sink, not inside
    its subtree), so a read inside a branch after the
    call counts. The guard rule is `A guarded AND B
    guarded` — one `nonReentrant` alone is not enough,
    analyzed not assumed, both one-sided cases pinned
    as findings. Same-file base contracts count. A write
    after the call in the same function is single-function
    reentrancy territory, not this detector's;
    `delegatecall` and `this.` calls are not sinks;
    locals and parameters shadowing a state variable are
    not reads of it.
- Shared this round, not duplicated: nothing new — both
  detectors reuse `walkExpression` / `renderExpression`
  in `sol-guards.js` and the §15 tuple-declaration
  reading (plain vs statement-level initial value).
  All 53 new tests passed on the first run.
- Tests: 1679 total (1674 pass, 0 fail, 5 skip) — 53 new
  tests (`tests/solidity-unchecked-call.test.js`,
  `tests/solidity-cross-function-reentrancy.test.js`);
  verify-install 11/11.

### Round 113: tainted-XXE and ReDoS detectors on the shared taint engine (2026-11-29)

- Two JavaScript detectors on the shared taint engine (round
  112's §16 "next step"), the return to JavaScript after the
  Solidity set closed in round 112 — the first JavaScript
  classes since round 107:
  - `tainted-xxe` (twenty-sixth real detector, eleventh
    parser-based detector): a tainted XML string reaching
    an XML parser that resolves entities (CWE-611 Improper
    Limitation of XML External Entity Reference, severity
    high), one finding per sink call site. Sinks:
    `libxmljs.parseXml` / `libxmljs.parseXmlString` (gated
    on a `noent: true` options literal — the library
    default does not substitute entities), xmldom
    `parseFromString`, xml2js `parseString` /
    `parseStringPromise`, sax `parser.write`. Only the
    first argument (the XML string) is judged. `JSON.parse`
    is not a sink; a bare `parseXml` is not a sink; a
    three-part call is not resolved. xmldom / xml2js
    findings need version-specific verification (they
    expand internal entities by default; external-entity
    fetching depends on the version).
  - `tainted-redos` (twenty-seventh real detector, twelfth
    parser-based detector): a tainted regex pattern
    reaching regex construction or use (CWE-1333 Regular
    Expression Denial of Service, severity medium —
    availability only), one finding per sink call site.
    Sinks: bare `RegExp` (`RegExp(tainted)` and `new
    RegExp(tainted)`), and the method sinks `match` /
    `search` / `replace` / `split` (first argument
    judged). `match` / `search` coerce a string argument
    to a RegExp; `replace` / `split` match a string
    literally, so only a tainted RegExp object is a vector
    there (pinned, `potential`). `regex.test` / `regex.exec`
    are not sinks (the danger lives in the receiver
    pattern); `matchAll` is out of scope. There is NO
    regex-complexity analysis — a tainted pattern is
    flagged because the attacker controls it, not because
    it is proven catastrophic; a clean pattern is never
    flagged, however catastrophic it looks.
- Shared engine, extended twice (the second round to extend
  it, after round 104): a config-driven `dangerousOptions`
  gate on a sink entry (the finding fires only when the
  named argument is an object literal carrying one of the
  named properties with a strictly equal literal value —
  used only by the libxmljs pair), and `new` expressions
  sink-checked like calls (`new RegExp(tainted)` flags
  exactly like `RegExp(tainted)`). Both extensions are
  additive: detectors that declare neither behave exactly
  as before. The subset parser's `new` target grammar is
  fixed too: `new RegExp(d)` used to mis-parse as `new
  (RegExp(d))` with empty arguments (`parsePostfix` now
  takes `allowCalls`; the `new` case parses its callee
  with calls disallowed).
- Tests: 1765 total (1760 pass, 0 fail, 5 skip) — 86 new
  tests (`tests/tainted-xxe.test.js`,
  `tests/tainted-redos.test.js`, battery entries in
  `tests/inter-procedural-taint.test.js`, libxmljs cases
  in `tests/import-resolution.test.js`);
  verify-install 11/11.

### Round 114: tainted-prototype-pollution detector on the shared taint engine (2026-11-29)

- One JavaScript detector on the shared taint engine (round
  113's §17 "next step"), the last JavaScript class on the
  approved map before the language rounds (Python, PHP):
  - `tainted-prototype-pollution` (twenty-eighth real
    detector, thirteenth parser-based detector): an
    attacker-controlled object or key reaching an unsafe
    property-writing sink (CWE-1321 Improperly Controlled
    Modification of Object Prototype Attributes, severity
    high), one finding per sink site. Sinks:
    `Object.assign` (every source from index 1),
    `_.merge` / `_.defaultsDeep` (every source from index
    1), `_.set` (the path, index 1), `$.extend` (every
    source from index 2), `merge` / `merge.all`
    (deepmerge), dynamic-key assignment (`obj[key] =
    value`, kind `tainted-key-assign`), dangerous-key-
    chain assignment (kind `dangerous-key-assign`:
    `__proto__` anywhere, a consecutive `constructor` →
    `prototype` pair, or the root `Object.prototype` — a
    lone leaf `constructor` / `prototype` is clean), and
    tainted object spread (`{ ...tainted }`, kind
    `tainted-spread`, conservative: a spread copies
    `__proto__` as an own property, it does not change
    the new object's prototype). A static safe key, a
    null-prototype target (`Object.create(null)`, not
    for `$.extend`), a same-function key filter, and
    `Object.freeze` on the prototype are clean.
    Import resolution applies (lodash → `_`, jquery →
    `$`, deepmerge → bare sink `merge`). Not modeled:
    key-path splitting and loop assignment, a key filter
    in a helper function, a literal dangerous key stored
    in a variable, deep-merge depth, a bare destructured
    `set` call (parser keyword — the record is skipped,
    like `get` since round 101).
- Shared engine, extended four times (the third round to
  extend it, after rounds 104 and 113): a per-sink
  `argIndexFrom` (judge every argument from that index
  onward — multi-source merge sinks), a per-detector
  `flagAssignmentKeys` (tainted computed-key assignment
  and dangerous-key-chain assignment as new finding
  kinds), a per-detector `flagTaintedSpread` (tainted
  object spread as a new finding kind), and a per-sink
  `nullProtoTargetSafe` with null-prototype binding
  tracking (target tracking through identifiers, copies,
  and branch joins). `renderMember` now renders a
  computed key that is itself a member expression
  (`o[d.key]`) instead of collapsing to the fallback.
  All extensions are additive: detectors that declare
  none of them behave exactly as before.
- Engine change — alias check runs before the bare-sink
  check, overturning the round-105 collision rule: a
  destructured alias whose name collides with a bare
  sink name (`const { merge } = _`, `const { request }
  = http`) is now judged as the ALIAS, not as the bare
  sink. The old rule misattributed the sink and
  suppressed the alias finding for clean arguments;
  the prototype-pollution detector made the overturn
  necessary (its lodash shape must resolve to
  `_.merge`). The SSRF colliding case now reports sink
  `http.request`, kind `aliased-call`, with any
  argument; the pinned tests and the three docs that
  stated the old rule were updated in the same round.
- Tests: 1815 total (1810 pass, 0 fail, 5 skip) — 50 new
  tests (`tests/tainted-prototype-pollution.test.js`
  (27), battery entry in
  `tests/inter-procedural-taint.test.js` (22), the
  bare-`set` keyword pin and lodash/jquery/deepmerge
  cases in `tests/import-resolution.test.js`, the
  colliding-alias updates in `tests/tainted-ssrf.test.js`
  and `tests/import-resolution.test.js`);
  verify-install 11/11.

### Round 110: Solidity rounding, tx.origin and weak-randomness detectors (2026-11-29)

- Three Solidity detectors on the same subset parser (round
  109's §13 "next step") — the first round where the
  Solidity detectors diverge in CWE, because the flaws are
  different kinds:
  - `solidity-rounding` (nineteenth real detector, fourth
    Solidity detector): a `*` whose operand is directly a
    `/` — division before multiplication, the division
    truncates before the multiplication runs (CWE-682
    Incorrect Calculation, severity medium), one finding
    per multiplication site. Multiply-first-divide-last
    (`x * y / z`) and bare division are clean.
  - `solidity-tx-origin` (twentieth real detector, fifth
    Solidity detector): a `==` / `!=` comparison whose
    subtree contains `tx.origin`, in a function or modifier
    body (CWE-862 — the check validates the transaction
    originator, not the immediate caller — not CWE-477,
    because tx.origin is not an obsolete function; CWE-863
    is the closest sibling and is documented as
    considered), one finding per comparison site,
    outermost only. This closes the pin round 109 left
    behind: a function guarded only by tx.origin is
    flagged by both detectors — complementary, not
    duplicate.
  - `solidity-weak-randomness` (twenty-first real detector,
    sixth Solidity detector): block entropy
    (`block.timestamp`, `block.number`, `blockhash(...)`,
    `block.difficulty` / `block.prevrandao`,
    `block.coinbase`) inside a hash call (`keccak256` /
    `sha256` / `sha3`), as a modulo operand, or as a
    seed-named initializer (CWE-338 Use of
    Cryptographically Weak PRNG, severity medium; CWE-337
    is the closest sibling and is documented as
    considered), one finding per entropy-source site.
    Block data in a deadline check, deadline arithmetic,
    or a log is clean — the context restriction is the
    whole point.
- Shared this round, not duplicated: `renderExpression`
  in `src/detection/sol-guards.js` (new) — the evidence
  renderer all three detectors use (nested binary
  children parenthesized, call arguments elided as
  `(...)`, so a literal inside an argument never lands in
  a finding).
- The parser grows one small additive piece:
  ContractDefinition nodes now keep their `modifiers`
  (ModifierDefinition nodes with name, params, and body).
  Before this round modifiers were parsed and discarded —
  a contract whose only tx.origin check sat in a modifier
  was invisible to every detector.
- Pinned exclusions (tested): rounding — division and
  multiplication in separate statements (needs data flow),
  division inside a call argument of a multiplied value,
  division before exponentiation, modifier bodies;
  tx.origin — tx.origin as a plain value (assigned,
  logged, passed as an argument) is clean, while
  `require(tx.origin != address(0))` IS flagged (a
  null-check the detector cannot tell from an
  authorization check, false positive by design);
  weak randomness — a seed variable used later is not
  traced (no data flow), `block.gaslimit` is not a
  source, modifier bodies are not scanned, a `blockhash`
  call's arguments are not scanned for further sources
  (the argument is a block selector, not entropy).
- Tests: 1593 total (1588 pass, 0 fail, 5 skip) — 66 new
  tests (`tests/solidity-rounding.test.js`,
  `tests/solidity-tx-origin.test.js`,
  `tests/solidity-weak-randomness.test.js`,
  `tests/sol-parser.test.js`,
  `tests/sol-guards.test.js`); verify-install 11/11.
- Docs: three new docs
  (`docs/detection-solidity-rounding-v1.md`,
  `docs/detection-solidity-tx-origin-v1.md`,
  `docs/detection-solidity-weak-randomness-v1.md`); §14
  addendum in `docs/parser-taint-scope-v1.md`;
  `docs/solidity-parser-v1.md` (modifiers),
  `SKILL.md` (both copies, byte-identical) and
  `docs/README.md` updated. Phase movement: F5 stays
  100% (three more Solidity classes on the same parser;
  the remaining Solidity limits are per-detector scope,
  not a phase gap).

### Round 109: Solidity access-control and unprotected-initializer detectors (2026-11-29)

- Two Solidity access-control detectors on the same subset
  parser (round 108's §12 "next step"), both CWE-862
  (Missing Authorization — the absence of a check, not a
  wrong one; CWE-284 is the broader parent and stays out
  of scope until a detector judges a check that exists),
  severity high, one finding per function, confidence
  `potential`:
  - `solidity-access-control` (seventeenth real detector,
    second Solidity detector): an external/public function
    that performs a sensitive operation — a state write, a
    fund-moving call (`.call` / `.transfer` / `.send` on
    any receiver), a `selfdestruct`, or a `.delegatecall`
    — with no access control at all, flagged on the
    earliest operation in source order. A function that is
    public by design (deposit, vote, claim) is still
    flagged — the detector cannot tell intent, and the
    finding is a candidate for manual review.
  - `solidity-unprotected-initializer` (eighteenth real
    detector, third Solidity detector): an external/public
    `initialize()` with neither the `initializer` /
    `reinitializer` modifier nor any access control.
    Either protection alone is enough to stay silent.
- The guard rule is shared, not duplicated
  (`src/detection/sol-guards.js`, new): `hasAccessControl`
  — an allow-list of access-control modifiers
  (`onlyOwner`, `onlyRole`, ...), `require(msg.sender ==
  ...)` or a role call (`hasRole` / `isAdmin` /
  `isAuthorized` / `isWhitelisted`) mentioning
  `msg.sender`, `if (msg.sender != ...) revert(...)` —
  plus `effectiveStateVars` (own + same-file bases,
  transitive, cycle-guarded). The reentrancy detector
  keeps its own copies (it predates this module); it was
  not refactored. Both detectors are separate analyses
  over the Solidity AST, NOT reuses of the JavaScript
  taint engine; their envelopes are their own functions
  following `createTaintDetector`'s pattern, sharing only
  the language-neutral pieces (`findingIdFor`, the caps,
  `normalizeRawFinding`).
- The parser grows two small additive pieces:
  FunctionDefinition nodes now record `visibility`
  (`external` / `public` / `internal` / `private`, null
  when unqualified — internal by the language default),
  and `revert` statements now parse (`revert
  NotOwner();`, `revert("reason");`, `revert();`) as
  RevertStatement nodes — the if-revert guard the
  detectors recognize is now actually parseable (before
  this round `revert` was a reserved word with no
  statement form, so the guard could never fire through
  the parser).
- Pinned exclusions (tested): `require(tx.origin == ...)`
  is NOT a guard (round 110 territory); `assert`,
  `nonReentrant`, `whenNotPaused`, and `onlyInitializing`
  are NOT guards; a guard placed after the sensitive
  operation still counts (no control-flow / reachability
  proof); cross-function access control and `this.` calls
  are not modeled; a base from another file is not
  resolved; the initializer detector does not verify the
  contract is actually upgradeable.
- Tests: 1527 total (1522 pass, 0 fail, 5 skip) — 65 new
  tests (`tests/sol-parser.test.js`,
  `tests/sol-guards.test.js`,
  `tests/solidity-access-control.test.js`,
  `tests/solidity-unprotected-initializer.test.js`);
  verify-install 11/11.
- Docs: two new docs
  (`docs/detection-solidity-access-control-v1.md`,
  `docs/detection-solidity-unprotected-initializer-v1.md`);
  §13 addendum in `docs/parser-taint-scope-v1.md`;
  `docs/solidity-parser-v1.md` (visibility + revert),
  `SKILL.md` (both copies, byte-identical) and
  `docs/README.md` updated. Phase movement: F5 stays
  100% (two more Solidity classes on the same parser;
  the remaining Solidity limits are per-detector scope,
  not a phase gap).

### Round 108: Solidity subset parser + reentrancy detector (2026-11-29)

- The second language lands: a hand-written stdlib-only
  Solidity subset parser (`src/detection/sol-parser.js`,
  tokenizer + recursive-descent, modeled on the
  JavaScript subset parser) covering contracts (with
  inheritance lists), state variables (including
  `mapping`), functions (constructor / receive /
  fallback), modifiers, and the statements and
  expressions reentrancy detection needs (including
  call options `{value: ...}`, tuple declarations, and
  `msg.sender` / `msg.value` / `block.timestamp` /
  `tx.origin`). Unsupported syntax (inline assembly,
  try/catch, struct-constructor arguments) fails with a
  named `SolParseError`, never silently skipped.
  `@solidity-parser/parser` was evaluated (MIT,
  community-standard grammar) and NOT adopted — no
  vendoring story exists yet; it remains the documented
  upgrade path if the detector set outgrows the subset
  grammar.
- First Solidity detector: `solidity-reentrancy`
  (CWE-841, SWC-107, severity high — the
  behavioral-workflow CWE, not the broader
  race-condition CWE-362), a separate segment-based
  analysis over the Solidity AST, NOT a reuse of the
  JavaScript taint engine (which is JavaScript-specific).
  It flags a function that performs an external call
  (`.call` / `.transfer` / `.send` on any receiver)
  and then writes state, one finding per call site,
  branch-sensitive (branch events never leak out of the
  branch; return / revert / break / continue end a
  segment), with local/parameter shadowing and same-file
  inherited state variables. `nonReentrant` guards,
  constructors, and write-before-call
  (checks-effects-interactions) are clean. Its envelope
  is its own function following `createTaintDetector`'s
  pattern (that factory's `scanRecord` parses
  JavaScript); shared code is limited to the
  language-neutral pieces (`findingIdFor`, the caps,
  `normalizeRawFinding`). A record whose `language` is
  present but not Solidity is refused; an unparseable
  record is counted in `skipped`.
- Pinned exclusions (tested): `delegatecall` /
  `staticcall` are not sinks this round; cross-function
  reentrancy, storage-reference aliasing, cross-iteration
  writes, and `this.` calls are not modeled; base
  contracts from another file are not resolved.
- Tests: 1462 total (1457 pass, 0 fail, 5 skip) —
  41 new tests (`tests/sol-parser.test.js`,
  `tests/solidity-reentrancy.test.js`); verify-install
  11/11.
- Docs: two new docs
  (`docs/solidity-parser-v1.md`,
  `docs/detection-solidity-reentrancy-v1.md`); §12
  addendum in `docs/parser-taint-scope-v1.md`;
  `SKILL.md` (both copies, byte-identical) and
  `docs/README.md` updated. Phase movement: F5 ~99% →
  100% — the last F5 gap (the second-language parser)
  is closed; the remaining Solidity limits are
  per-detector scope, not a phase gap.

### Round 107: tainted-LDAP, XPath and open-redirect detectors on the shared taint engine (2026-11-29)

- Three parser-based detectors on the shared taint engine
  (`src/detection/taint-engine.js`), all thin wrappers
  with no engine change (round 104's config tables
  already cover them): `tainted-ldap` (CWE-90,
  severity high — LDAP search sink `client.search`,
  judging its SECOND argument, the filter / options,
  because ldapjs takes `(base, options, callback)` and
  the filter lives in `options`, either as a string or
  as an object whose properties' taint joins; a tainted
  search base is not judged — DN injection is a
  different shape); `tainted-xpath` (CWE-643, severity
  high — XPath evaluation sinks `xpath.select` /
  `select1` / `evaluate` and `document.evaluate`,
  first argument, the expression, judged; a tainted
  context node is not judged); `tainted-open-redirect`
  (CWE-601, severity high — HTTP redirect sinks
  `res.redirect` / `response.redirect` /
  `reply.redirect` / `ctx.redirect`, first argument,
  the URL, judged; a tainted URL in second position of
  the two-argument form is not judged). Each reports a
  sink call only when the judged argument is tainted or
  the call is reached through an alias, and a direct
  sink call with a clean judged argument is not
  reported (the regex detector already flags it).
- Import tables (round 106 mechanism): LDAP `ldapjs` /
  `ldapts` → root `client`; XPath `xpath` → root
  `xpath`; open redirect carries no table — `res` /
  `response` / `reply` / `ctx` are request-handler
  parameters, not modules.
- Pinned exclusions (tested): LDAP — a tainted base DN,
  a single-argument call, `client.bind` / `add` /
  `modify` / `del`, a bare `search(...)`, a three-part
  call, an unknown module, a relative path; XPath — a
  tainted context node, a bare `select(...)` /
  `evaluate(...)`, `document.querySelector` (CSS, not
  XPath), `xpath.parse` (parses, does not evaluate), a
  three-part call; open redirect — a tainted URL in
  second position of `res.redirect(status, url)`, a
  bare `redirect(...)`, `res.render` (a view name), a
  `window.location` assignment, a three-part call. LDAP
  filter escaping (RFC 4515) and URL allow-list checks
  are NOT modeled as sanitizers.
- Tests: 1421 total (1416 pass, 0 fail, 5 skip) —
  58 new tests across three detector test files
  (`tests/tainted-ldap.test.js`, `tests/tainted-xpath.test.js`,
  `tests/tainted-open-redirect.test.js`), plus 66 new
  parameterized cases in the inter-procedural battery
  (three new detectors × 22 templates, now covering all
  ten parser-based detectors) and import-resolution
  cases for the new tables; verify-install 11/11.
- Docs: three new detector docs
  (`docs/detection-tainted-ldap-v1.md`,
  `docs/detection-tainted-xpath-v1.md`,
  `docs/detection-tainted-open-redirect-v1.md`); §11
  addendum in `docs/parser-taint-scope-v1.md`;
  `SKILL.md` (both copies), `docs/README.md`, and
  `docs/import-resolution-v1.md` updated. No phase
  movement (F5 ~99%, remaining gap is the
  second-language parser, round 108).

### Round 106: import resolution (require/ESM) on the shared taint engine (2026-11-29)

- A sink reached through an import now resolves to its
  canonical sink, for all seven parser-based detectors
  at once, with no detector's finding rules changed
  (sources, sanitizers, and the judged argument are
  exactly as before). Four spellings resolve: a direct
  require member (`require('child_process').exec(d)`),
  a namespace alias (`const cp =
  require('child_process'); cp.exec(d)`), a
  destructured require (`const { exec } =
  require('child_process'); exec(d)`), and the ESM
  equivalents (`import { exec } from 'child_process'`,
  `import cp from 'child_process'`, `import * as cp
  from 'child_process'`). Direct calls are judged like
  any direct sink call (finding only when the judged
  argument is tainted); aliased calls follow the alias
  rule (reported with any argument). Import bindings
  are hoisted like function declarations; assignment
  binds the module too (`let cp; cp =
  require('child_process')`); an identifier re-alias
  propagates the module binding; a bare-root identity
  (`const cp = child_process`, `const mydb = db`) binds
  as that root.
- Per-detector import tables (`moduleRoots` /
  `moduleBareSinks`, pinned by tests): command
  execution `child_process` / `node:child_process`;
  path traversal `fs` / `node:fs`; SSRF `http` /
  `node:http`, `https` / `node:https`, `axios`, plus
  bare sinks `request` → `request` and `node-fetch` →
  `fetch`; SSTI `ejs`, `pug`, `nunjucks`,
  `handlebars`; deserialize `js-yaml` → `yaml` only
  (the `yaml` package is NOT mapped — its API is
  `parse`, not `load`). SQL and XSS carry no table:
  SQL sink roots are receiver variable names, not
  modules, and XSS sinks are DOM globals.
- The round-105 bare-sink collision quirk is
  reconciled, not changed: a destructured name
  colliding with a bare sink (`request`) is judged as
  the bare sink, because the direct-sink check runs
  first — whether the source is a bare identifier or
  a require call.
- Parser (`src/detection/js-parser.js`): import
  declarations now parse with bindings tracked
  (side-effect, default, namespace, and named imports
  with `as` aliases, string-literal module
  specifier); anything outside that set falls back to
  the pre-round-106 structural skip, so a record with
  an exotic import still scans. Dynamic import
  (`import('mod')`) is skipped structurally. The
  round-101 keyword limitation is unchanged: a bare
  identifier named `get` does not parse, so a record
  calling `get(...)` is skipped, not scanned.
- Pinned exclusions (tested): dynamic require, a
  concatenated module name, an unknown module, a
  relative path, re-export (named and star), a
  module-object assignment (`module.exports =
  require(...)`), object-property indirection (the
  deep-alias pin — identifier re-aliasing propagates,
  property indirection does not), and a shadowed
  `require`.
- Pin changes: the round-100/103/104/105 pins that
  said these import spellings were unresolved are
  retired — the affected cases moved to
  `tests/import-resolution.test.js` as positives, with
  the move recorded in the detector test files and
  the detector docs. SQL's `require('pg').query` and
  deserialize's `require('yaml').load` stay pinned as
  non-sinks.
- Tests: 1297 total (1292 pass, 0 fail, 5 skip) —
  9 new tests in `tests/import-resolution.test.js`;
  verify-install 11/11.
- Docs: new `docs/import-resolution-v1.md`; §10
  addendum in `docs/parser-taint-scope-v1.md`;
  `SKILL.md`, `docs/README.md`, and the detector docs
  updated. No phase movement (F5 ~99%, remaining gap
  is the second-language parser, round 108).

### Round 105: three AST detectors — tainted-SSTI, path-traversal, SSRF (2026-11-28)

- Three parser-based detectors on the shared taint engine
  (`src/detection/taint-engine.js`), all thin wrappers
  with no new sink shape (round 104's config tables
  already cover them): `tainted-ssti` (CWE-1336,
  severity high — template-engine sinks `ejs.render` /
  `compile`, `pug.compile` / `render`,
  `nunjucks.renderString`, `handlebars.compile`,
  first argument judged; CWE-1336 is the
  template-engine-specific CWE, not the broader CWE-94;
  a constant template with a tainted data object is not
  flagged), `tainted-path-traversal` (CWE-22, severity
  high — `fs` path sinks `readFile` / `readFileSync` /
  `writeFile` / `writeFileSync` / `createReadStream` /
  `createWriteStream` / `readdir` / `readdirSync` /
  `unlink` / `unlinkSync`, first argument judged;
  `path.join` does not sanitize; path containment
  checks are not modeled as sanitizers), and
  `tainted-ssrf` (CWE-918, severity high —
  outbound-request sinks `fetch`, `request`, `http.get` /
  `request`, `https.get` / `request`, `axios.get` / `post`
  / `put` / `delete` / `request`, first argument judged;
  the bare names `fetch` and `request` ARE sinks —
  distinctive globals, unlike `query` or `render`; an
  options object as the first argument is judged as a
  whole). Each reports a sink call only when its judged
  argument is tainted (`tainted-arg`, chain proves the
  flow, inter-procedural since round 101) or when the
  call is reached through an alias (`aliased-call`).
- One small additive engine fix (`aliasSinkOf` in
  `src/detection/taint-engine.js`): a bare-name sink
  bound to a new name (`const f = fetch`,
  `const f = unserialize`) now resolves as an alias of
  that sink — before this fix only member-expression
  aliases resolved. The fix only affects identifiers
  that ARE bare-name sinks; the pre-existing AST
  detectors are unchanged (their test files pass
  unmodified). Deliberate exclusions, pinned by tests:
  SSTI `renderFile` / `nunjucks.render` / `res.render` /
  bare `render` / three-part calls / tainted data
  object; traversal `existsSync` / `mkdir` /
  `res.sendFile` / `fs.promises.*` / bare `readFile` /
  tainted second argument; SSRF `window.fetch` /
  `XMLHttpRequest.open` / `WebSocket` / three-part
  calls / tainted second argument / a destructured
  alias colliding with a bare sink name. A bare
  identifier literally named `get` does not parse
  (round-101 keyword limitation) — a record calling
  `get(...)` is skipped, not silently scanned.
- Tests: 19 new tests each in `tests/tainted-ssti.test.js`
  and `tests/tainted-path-traversal.test.js`, 20 in
  `tests/tainted-ssrf.test.js` (all sink spellings, taint
  flows, aliases, safe patterns, envelope, resolution
  limits); the round-101 inter-procedural battery now
  parameterizes over all seven parser-based detectors
  (+66 tests). Full suite green; no behavior change to
  the four existing AST detectors.

### Round 104: fourth AST detector — tainted-xss (2026-11-28)

- Fourth parser-based detector (`tainted-xss`, CWE-79,
  severity high): tracks taint from function parameters and
  `process.argv` to HTML sinks on the shared taint engine
  (`src/detection/taint-engine.js`). XSS sinks are not all
  calls, so this round is the first to EXTEND the engine
  for a new sink shape (round 103 needed no engine
  change): assignment sinks (`innerHTML`, `outerHTML` —
  judged on the assigned value, any receiver, including
  `+=` and computed properties), method sinks
  (`insertAdjacentHTML` — matched by method name alone,
  whatever the receiver), and a per-sink judged-argument
  index (`argIndex`, default 0: `insertAdjacentHTML`
  judges its second argument, the HTML, because its first
  is the position constant). All three are config tables
  in the engine; the three earlier AST detectors define
  neither new table and behave exactly as before — the
  round-100 "first argument only" pin is generalized to
  "one judged argument per sink", not dropped.
- Sinks (JavaScript): `document.write` / `document.writeln`
  (fixed-root calls, first argument judged), `insertAdjacentHTML`
  (second argument judged), `innerHTML` / `outerHTML`
  assignments. A sink is reported only when the judged
  value is tainted (`tainted-arg`, chain proves the flow,
  inter-procedural since round 101), when the assigned
  value is tainted (`tainted-assign`, new evidence type
  `ast-assign` carrying the target and property), or when
  the call is reached through an alias (`aliased-call`:
  `const w = document.write`, `const { write } = document`,
  `const f = el.insertAdjacentHTML`). Deliberate
  exclusions, pinned by tests: `textContent` / `innerText`
  are safe by construction; jQuery `.html()` is not a sink
  (no jQuery modeling); a three-part call
  (`window.document.write(...)`) is not resolved; a
  destructured method sink is not resolved; `Object.assign`
  into `innerHTML` is not a sink; `document.write`'s second
  and later arguments are not judged.
- Tests: 21 new tests in `tests/tainted-xss.test.js` (all
  sink shapes, taint flows, aliases, safe patterns,
  envelope, resolution limits); the round-101
  inter-procedural battery now parameterizes over all four
  parser-based detectors (tainted-xss joins the three
  earlier ones). Full suite green; no behavior change to
  the three existing AST detectors.

### Round 103: third AST detector — tainted-sql (2026-11-28)

- Third parser-based detector (`tainted-sql`, CWE-89,
  severity high): tracks taint from function parameters and
  `process.argv` to SQL query sinks on the shared taint
  engine (`src/detection/taint-engine.js`) — the first
  detector built on the engine without touching it: the new
  module is a thin wrapper over `createTaintDetector(config)`
  with only its sink table and finding metadata. No engine
  change was needed.
- Sinks (JavaScript, the common driver call-site shapes):
  `db`, `pool`, `connection`, `client`, `conn`, each with
  `query` and `execute` (10 sinks). A sink call is reported
  only when its first argument is tainted (`tainted-arg`,
  chain proves the flow, inter-procedural since round 101)
  or when it is reached through an alias (`aliased-call`:
  `const q = db.query`, `const { query } = db`). A
  parameterized query — constant SQL with placeholders plus
  a parameter array — is not flagged: only the first
  argument is judged, so the safe pattern falls out of the
  same rule. Deliberate exclusions, pinned by tests: a bare
  `query(...)` is not a sink (too generic), a three-part
  call (`app.db.query(...)`) is not resolved, `prepare` is
  not a sink in this round, and a tainted second argument
  (the parameter vector) is not judged.
- Tests: 19 new tests in `tests/tainted-sql.test.js` (all
  ten sink spellings, taint flows, aliases, parameterized
  queries, sanitizer, envelope, resolution limits); the
  round-101 inter-procedural battery now parameterizes over
  all three parser-based detectors (tainted-sql joins
  tainted-deserialize and tainted-command-execution), so
  the shared-engine coverage grows with the detector set.
  Full suite green; no behavior change to the two existing
  AST detectors.

### Round 102: park Meta integration items — local-only F0/F1 completion criteria (2026-11-28)

- Meta integration items parked, not deleted (user decision 28 Nov
  2026): the "Expected future integration evidence" section of
  `SKILL.md` (official manifest format + installation location,
  official-integration invocation, supported permission model,
  approved local-lab test) moves verbatim to the new
  `docs/meta-integration-deferred-v1.md`, with persona indexing
  as a fifth parked item and a restoration rule. `SKILL.md` (both
  copies, byte-identical) now carries a "Phase completion (local
  scope)" section instead.
- F0/F1 completion criteria rewritten to local scope only: F0 is
  complete when the skill is distributed versioned via GitHub
  plus custom-skill install with `verify-install` green; F1 is
  complete when it is invocable through the supported local paths
  (the `sentinel` CLI and the custom-skill shell invocation) with
  the local permission model documented. The same criteria are
  applied to the knock-on phases (F2: check-env reports local
  capabilities accurately; F3: scope/policy cover local
  registration and enforcement; F8: release process and CI guards
  in place and green).
- Phase movement (criteria change, no behavior change): F0 ~60% →
  100%, F1 ~80% → 100%, F2 ~99% → 100%, F3 ~99% → 100%,
  F8 ~99% → 100% — each phase's only remaining items were the
  parked Meta items. F4 (~90%, first real fetch), F5 (~99%,
  second language parser), F6 (~95%), F7 (~99%, HackerOne/
  Bugcrowd templates unverified against the live platforms'
  forms) are unchanged. The 1.0 release gate now rests on a
  first real fetch only (`docs/release-process-v1.md`).
- Reconciliation of every Meta reference in the repo (see the
  inventory in `docs/meta-integration-deferred-v1.md`): six docs
  rewritten (SKILL.md, release-process, operator-sessions,
  scope-explain, scope-list-default-path, controlled-wrapper);
  dated addenda over preserved records (implementation-status,
  check-env-audit); the docs index lists the new doc. Historical
  records (CHANGELOG, capability evidence, PRD/SAD) and factual
  status statements (README, adapt-to-agent) are retained as
  written and listed in the inventory with reasons.
- Incidental fix found while editing: `docs/release-process-v1.md`
  still said `verify-install` is "10/10 since round 98" — the
  eleventh check landed in round 99; now "11/11 since round 99".
  No detector, policy, kill-switch, invocation-path, or release
  behavior changed in this round.

### Round 101: inter-procedural taint + sanitizer modeling on a shared engine (2026-11-28)

- Shared taint engine extracted (`src/detection/taint-engine.js`):
  the round-95/100 per-detector analyzer copies are gone;
  `tainted-deserialize` and `tainted-command-execution`
  are thin wrappers over `createTaintDetector(config)` with
  their sink tables and finding metadata. All 35 pre-existing
  parser-detector tests pass on the shared engine unchanged
  (no behavior change from the refactor).
- Inter-procedural taint (call graph): taint flows from a
  call site into a callee, through return values, IIFEs, and
  function aliases; a helper never called (or called only
  with clean arguments) is still analyzed once with its
  parameters as sources (the round-95 fallback). The evidence
  chain proves the cross-function flow (e.g. `parameter 'req'
  of function 'handle' -> req.body -> parameter 'd' of
  function 'parse'`). Termination guards: a recursion set
  (direct and mutual recursion fall back to the unknown-call
  convention), a depth cap of 8 nested call-site analyses
  (deeper helpers are still flagged via the fallback), and
  per-function memoization (tainted / clean / fallback).
  Methods are not resolved through the graph, there is no
  `this` modeling and no import resolution, and when several
  flows reach one sink site the first chain wins
  (deterministic, pinned by a test). Documented in
  `docs/inter-procedural-taint-v1.md`.
- Sanitizer modeling (explicit allow-list in the engine):
  `Number`, `parseInt`, `parseFloat`, `Boolean`,
  `Number.parseInt`, `Number.parseFloat` cleanse taint
  (their return values cannot carry a string payload);
  encoding and content-preserving calls
  (`encodeURIComponent`, `encodeURI`, `String`,
  `JSON.stringify`, string methods) do NOT cleanse, and a
  user binding shadowing a sanitizer name disables it.
  An unknown `validate()` is still not modeled. Documented
  in `docs/sanitizer-modeling-v1.md`, with each allow-list
  entry and each exclusion pinned by a test.
- 45 new tests in `tests/inter-procedural-taint.test.js`
  (parameterized over both detectors, plus one shared-engine
  test): cross-function and multi-hop flows with exact chains,
  hoisting, fallback pins, recursion and depth-cap termination,
  IIFE / arrow-var / alias resolution, return-taint identity /
  constant / global-source, sanitizer positives, negatives,
  shadowing, wrapper-through-sanitizer, and nested sinks
  inside sanitizer arguments.
- Docs: two new docs (`docs/inter-procedural-taint-v1.md`,
  `docs/sanitizer-modeling-v1.md`); dated §6 addendum in
  `docs/parser-taint-scope-v1.md` (the §5 items are done);
  the two detector docs updated (inter-procedural behavior,
  sanitizer allow-list) and one correction carried in both:
  earlier versions wrongly said unknown-call return values
  were clean — the engine has always returned tainted for
  an unknown call with a tainted argument. `SKILL.md`
  (sixth/seventh detector paragraphs + See-list) updated
  and copied byte-identical to
  `skills/sentinel-bounty/SKILL.md`.
- Limits that stand: JavaScript only; no import resolution
  (round-100 pins: `require('child_process').exec`,
  `const cp = child_process`); only the first argument is
  judged (tainted argument vectors still not covered);
  methods not resolved through the call graph; no
  reachability proof. No phase moves beyond F5: the
  inter-procedural engine is the second AST capability
  the F5 100% target needs (a second language parser is
  still open). No Meta items touched; no F6/policy change;
  no new release tag.

### Round 100: second AST detector — tainted-command-execution (2026-11-28)

- Second parser-based detector (`tainted-command-execution`,
  seventh real detector): reuses the taint engine proven by
  `tainted-deserialize` (round 95) — the same hand-written
  stdlib-only subset parser (`src/detection/js-parser.js`)
  and the same analyzer design, parameterized by this
  detector's sink table — on command-execution sinks
  (`child_process.exec`, `execSync`, `spawn`, `spawnSync`,
  `execFile`, `execFileSync`; the JS-relevant subset of
  `dangerous-call`'s command-exec pattern). A sink call is
  reported only when its first argument is tainted (from a
  function parameter or `process.argv`) or the call is
  reached through an alias (`const e = child_process.exec`,
  `const { exec } = child_process`); a direct sink call
  with a clean argument is not reported (the regex detector
  already flags it), and a finding never carries a literal
  value or a source line. Registered in
  `src/detection/detector.js` (`getDetector`) and in the
  `sentinel detect` help text and comment block; the
  round-99 CLI-help-vs-registry test covers the new id.
  Documented limits (same as round 95, plus one new):
  JavaScript only, intra-procedural only, no sanitizer
  modeling, no import resolution
  (`require('child_process').exec` and `const cp =
  child_process` are not resolved), and only the first
  argument is judged — a tainted argument vector (second
  argument of `spawn` / `execFile`) is not covered in this
  round. `child_process.fork` is not a sink. The analyzer
  stays a per-detector copy (the repo's self-contained
  detector pattern); a shared-engine refactor is future
  work, listed in the new detector doc
  (`docs/detection-tainted-command-execution-v1.md`). 17 new
  tests in `tests/tainted-command-execution.test.js`. No
  phase moves beyond F5: the second AST class was the
  named next step toward F5 100%, which still needs
  inter-procedural taint, sanitizer modeling, and a second
  language.

### Round 99: CI hardening + regression (2026-11-28)

- CI hardening for the lessons of the four-red-run saga (rounds
  91–92): the Windows simulation preload is committed as
  `scripts/fake-win32.cjs` (rounds 91–98 used a `/tmp` copy the VM
  wipes on every restart), and a new `.github/workflows/ci-guards.yml`
  runs the suite, the simulation through the committed preload,
  `verify-install`, and the changelog rule on every push and pull
  request; `windows-test.yml` is unchanged. A new pre-push gate
  (`scripts/pre-push-check.cjs`, `npm run pre-push`) runs the same
  four steps locally, and its changelog rule requires every
  code-touching commit to carry its CHANGELOG.md entry in the same
  commit (round 94's entry missed its commit and landed as
  follow-up `683169c`); it is opt-in, never installed as a hook.
  `verify-install` grows from 10 checks to 11 with `ci-guards`
  (workflow/preload/script consistency, PASS-vacuous when no guard
  files are present). A new log archiver
  (`scripts/fetch-windows-logs.cjs`) downloads one Windows CI run's
  logs into `logs_<check_suite_id>-<shortsha>/`, rate-limit aware.
  Regression tests pin the paid-for lessons: simulation
  effectiveness (`process.platform` really reads `win32`), the
  workflow's shape, the changelog rule against scratch git repos,
  the archiver against a stub API, the ci-guards check, and CLI-help
  vs detector-registry completeness (round 95's missing fifth-detector
  sentence). No phase moves: this round hardens CI, regression, and
  procedure, not a capability.

## [0.2.0] — 2026-11-28

The second tagged release. It covers rounds 91–98; round 92 made no code
change (Windows log verification only) and has no entry.

### Round 98: F0/F1 release packaging + local operator sessions (2026-11-28)

- Release packaging: the CHANGELOG is restructured into release
  sections — `## [0.2.0]` (rounds 91–98, this entry), `## [0.1.0]`
  (rounds 34–90, the first tagged release on `c4c9060`), and the
  pre-release baseline (rounds 1–32, retitled from the `[1.0.0]`
  label that predated the tag line and was never a tagged release;
  head commit `f42c61b` verified present in history after the
  clone was deepened). Entries moved verbatim; `package.json`
  `version` aligns to the release line (`1.0.0` → `0.2.0`) and
  the new `docs/release-process-v1.md` records how a release is
  cut, the numbering rules (MINOR for capability, PATCH for
  fixes, MAJOR stays 0 until the Meta items and a first real
  fetch are done), and why the other `1.0.0` numbers in the repo
  (tool-config schema, check-env report format, `POLICY_VERSION`)
  are not release versions. Tag `v0.2.0` (annotated) on the
  round-98 commit.
- `verify-install` is strengthened from 7 checks to 10:
  `cli-syntax` (the entrypoint must parse as JavaScript —
  `node --check`, never executed, writes nothing; absence is
  `cli-reachable`'s failure, not this check's),
  `skill-copies-identical` (both SKILL.md copies byte-identical;
  a single-copy install passes vacuously), and
  `operator-sessions` (the new session store must parse and be
  valid). The stale "seventh check" wording in SKILL.md, the
  docs index, and the repo README now names the ten checks.
- Local operator sessions (`src/policy/operator-sessions.js`,
  new `sentinel session start/heartbeat/list/status/revoke/rotate`,
  21 tests): a bounded token (48-hex, returned once, stored only
  as its SHA-256 hash), a heartbeat proving liveness, a lease
  (default 30 minutes, max 2 hours — a lapsed lease cannot be
  revived), a TTL (default 8 hours, max 24 hours, never extended
  by heartbeat or rotation), and revocation (final, idempotent).
  Start and rotate are refused while the kill switch is armed;
  revoke, heartbeat, list, and status work while armed.
  `sentinel fetch --session-token <token>` binds a fetch to a
  live session, validated after the fetch context resolves and
  before the approval step, so a dead session never burns a
  one-time approval token; the binding is audited as
  `PUBLIC_FETCH_SESSION_BOUND` (metadata only). A fetch without
  `--session-token` behaves exactly as before. No Meta service is
  involved — a session is local liveness, not platform identity.
  See `docs/operator-sessions-v1.md`.
- What remains, recorded as ceilings rather than chased: F0's
  official manifest/registry and F1's official API, quotas, and
  native identity all need Meta (final stage); F4's first real
  fetch needs the user's word, a registered target, and a
  verified authorization reference.

### Round 97: Close F2/F3/F7/F8 tails — edge tests, one matcher fix, stale docs (2026-11-28)

- F2 (environment checker): five untested branches found by
  inspection and pinned by tests, no production change — the Node
  floor constant now has a drift-guard test against `package.json`
  `engines` (the round-41 claim that the mirror was "covered by a
  test" was true of the floor behavior, not of the mirror itself);
  `detectMuseEnvironment`'s `MUSE_` marker branch;
  `checkFirstAvailableCommand`'s all-fail branches (all-ENOENT →
  `unavailable`, mixed → `not_verified`); the `NOT_FOUND` code in
  `checkCommand`; and the `checkStorage` failure path (probe
  directory through a file → `unavailable`). 5 new tests
  (`tests/environment-checker.test.js`).
- F7 (reporting): the hyphen gap in `resolveEvidenceClass`
  (`src/analysis/validator.js`) is fixed — the matcher now treats
  hyphens as spaces on both sides, so `sql-injection` resolves to
  `sql injection` instead of staying its own class, and the same
  fix applies to the per-class evidence checklist (same function).
  One existing test expectation was updated deliberately
  (`tests/report-stats.test.js`: `sql-injection` now resolves),
  with new hyphen cases in the stats and evidence-checklist
  tests. `docs/reporting-v1.md` no longer says "markdown and JSON
  only" (six formats exist) and `docs/report-stats-v1.md` records
  the gap as closed.
- F3 (scope manager) and F8 (testing & release): docs only. The
  open items in `docs/scope-explain-v1.md` and the "does not do"
  list in `docs/scope-manage-v1.md` were stale since rounds 53–54
  (scope add/remove/list and `default_excluded_paths` all exist)
  and now record themselves as closed.
  `docs/github-prototype-readiness.md` no longer claims no CLI
  command resolves hosts or sends HTTP requests (the gated
  `sentinel fetch` from rounds 93–94 does both, under
  registration + preview + explicit approval), and
  `docs/implementation-status.md` carries a dated 2026-11-28
  addendum over the preserved 2026-11-21 snapshot (public-target
  support exists, gated; Windows CI is green).
- What remains, recorded as ceilings rather than chased: F2's Muse
  attestation and skill-invocation verification and F3's
  Meta-side ceiling (official manifest, quotas, native identity);
  F7's HackerOne/Bugcrowd templates, still not verified against
  the live platforms' forms; F8's official Muse skill release.
  No behavior change to any CLI command surface; both SKILL.md
  copies unchanged.

### Round 96: F6 policy hardening (2026-11-28)

- Enforcement gap, found by this round and fixed: the
  conservative semantic dedup pass (`semanticDedupeFindings`,
  round 48) had no production caller — `sentinel report`
  rendered duplicate findings, and a report with two
  identical findings failed its own `report validate` with
  `REPORT_VALIDATE_DUPLICATE_FINDING_ID`. `enforceReportPolicies`
  (`src/analysis/policies.js`) is now the single enforcement
  entry point for report generation from raw findings:
  false-positive exclusion first, then the conservative
  semantic dedup pass, in `sentinel report` (`bin/sentinel.js`
  `runReport`). `generateReport` itself is untouched, so
  report transformations keep whatever a stored report
  already carries.
- Order is load-bearing and pinned by tests: exclusion first
  means a valid finding can never absorb a false_positive's
  evidence by merging, and a false_positive can never survive
  inside a merged valid finding. Dedup never merges across
  rule verdicts, even with `--include-false-positives` — two
  findings with different rule verdicts carry different
  triage states, and merging them would let input order pick
  the surviving verdict. The four merge conditions are
  unchanged (the pass itself is untouched); the verdict
  partition is composition, not a fifth condition. The
  semantic pass runs directly, not after the exact-key
  dedup — exact-first would silently drop findings the
  conservative rule refuses to merge.
- Second gap, found by the AST end-to-end test and fixed:
  the evidence-entry canonicalization only recognized the
  classic `{request, response, notes}` shape, so findings
  whose evidence carries other fields — the round-95 AST
  detector's `{type, sink, kind, line, column, call, taint}`
  entries — could never satisfy rule (d), and the policy
  silently did not apply to a whole detector class. The
  canonicalization now falls back to the full entry (sorted
  keys, `full:` prefix) when none of the three classic
  subfields is present, counting only when the entry carries
  at least one non-empty string leaf. Classic entries are
  unchanged. The fallback also fixes the evidence union in
  `mergeFindingGroup`, which collapsed distinct AST entries
  onto one key. `merged_from` is now an id set (two members
  sharing one deterministic id list it once).
- Policy versioning (`docs/policy-versioning-v1.md`):
  `POLICY_VERSION = '1.0.0'` tracks the decision set
  (MAJOR = a decision changed, needs a user decision;
  MINOR/PATCH = enforcement or doc changes, no bump), and
  `sentinel policy [--json]` prints the active version and
  the five decisions (read-only). The stderr notes on
  report generation carry the version, so a run's
  enforcement is auditable from its own output. No flag,
  environment variable, or config file can change a
  decision — a code search finds only the constants, their
  tests, and their docs.
- End-to-end proof: `sentinel detect --detector
  tainted-deserialize` over a batch of two identical
  records yields two findings (detect stays raw by design),
  and `sentinel report` merges them into one finding whose
  report passes `report validate`. AI-verdict disagreement
  is proven at the CLI level both ways with the class
  verifier fixture: a rule-valid finding with an AI
  false_positive is kept with the advisory verdict
  recorded, and a rule-false_positive finding with an AI
  valid is still excluded. 16 new tests
  (`tests/policies-f6-enforcement.test.js`).

### Round 95: F5 parser/taint scoping + first AST-based detector (2026-11-28)

- The regex detector set is now extended by a parser: new
  `docs/parser-taint-scope-v1.md` scopes what regex cannot
  do and why (code vs prose, aliased calls, taint,
  cross-function flow), the approach (hand-written
  stdlib-only JavaScript subset parser — tokenizer +
  recursive descent — plus intra-procedural taint), and
  the deliberate limits (JavaScript only,
  intra-procedural, no sanitizer modeling, no import
  resolution, subset grammar that fails loudly instead of
  scanning approximately).
- Dependency decision (documented, not a blocker): Acorn
  was evaluated and NOT adopted this round — the skill
  installs and verifies offline, every module is
  stdlib-only, and the prototype's single class does not
  need a full grammar. Vendored Acorn remains the upgrade
  path if the grammar outgrows the subset or a second
  language is added.
- Sixth real detector `tainted-deserialize` (new
  `src/detection/js-parser.js`,
  `src/detection/tainted-deserialize.js`, 18 tests):
  unsafe deserialization sinks in JavaScript (yaml.load,
  YAML.load, yaml.loadAll, unserialize) reported only
  when the regex detector cannot see them — a direct call
  with a tainted first argument (function parameters and
  `process.argv` are sources; taint flows through
  assignments, members, templates, binary/conditional,
  arrays/objects; branch joins are OR) or an aliased call
  (`const l = yaml.load`, `const { load } = yaml`,
  `yaml['load']`) with any first argument. A direct call
  with a clean argument is not reported (the regex
  detector already flags it); sink text in a comment or
  a string is never a finding; parse failures skip the
  record with a positioned error and never fall back to
  regex. Findings carry only the sink name, position,
  and a taint chain of identifier names — never a literal
  value or source line. Registered in
  `src/detection/detector.js` and the `sentinel detect`
  CLI help; SKILL.md (both copies) updated. The CLI
  comment block also gains the insecure-transport
  sentence round 90 had omitted.
- `docs/detection-policy-v1.md` updated: the parser
  decision the policy left open is now made (round 95);
  the AI-verifier model choice and the public-target
  execution authorization remain open.

### Round 94: Public-fetch activation drill — E2E chain, refusal matrix, kill-switch drill (2026-11-28)

- The round-93 invocation path is drilled end to end with stub
  transport/resolver only (new
  `tests/public-fetch-activation-drill.test.js`, 8 tests):
  register → preview → mint → fetch, audit trail in order
  (`PUBLIC_TARGET_ADDED` → `PUBLIC_FETCH_APPROVAL_MINTED` →
  `PUBLIC_HTTP_REQUEST_ALLOWED` → `PUBLIC_HTTP_RESPONSE`), no
  token/body/reference in the audit log. The refusal matrix is
  replayed as a sequence: every gate refuses before any
  network, and a refusal decided before the token is read does
  not spend it — the same token still fetches afterwards.
  A refusal decided after the token is consumed (DNS failure;
  the adapter's kill-switch re-check) burns it.
- Kill-switch drill at every point in the chain, with the
  persistent kill switch in a real temp state directory:
  trigger before fetch refuses (`KILL_SWITCH_ACTIVE`, zero
  requests, zero DNS) and the token is NOT spent; minting is
  refused while armed; add/remove are refused while armed
  (`target list` still works); reset restores service and a
  token minted before the trigger, never spent, still within
  its TTL, still fetches after reset (documented semantics:
  the switch blocks use while armed, it does not revoke
  approvals). A trip between token consume and adapter run is
  refused by the adapter's own re-check (token burned, zero
  requests, worker registration never reached). A trigger
  mid-flight aborts a hanging request in ~160–220 ms with
  `PROCESS_FAILED` + `cancellation: 'KILL_SWITCH_ACTIVE'` —
  both via direct worker cancel and via the cross-instance
  poller. The CLI drill (register → mint → trigger →
  refusals → reset → CLI-minted token fetches at module level
  with stubs) proves the CLI-produced stores interoperate
  with the fetch path.
- Fix found by the drill: the adapter's in-flight abort detail
  (`cancellation: 'KILL_SWITCH_ACTIVE'`) was dropped by
  `runPublicFetch`, so a kill-switch abort looked like a bare
  `PROCESS_FAILED`; it is now propagated when present
  (additive only; the refusal reason stays the contract).
- Operator runbook: new
  `docs/public-fetch-activation-drill-v1.md` (activation chain
  table, what each refusal spends, kill-switch drill table,
  pre-trigger-token semantics), listed in `docs/README.md` and
  anchored in both SKILL.md copies.
- No real-target execution in this round: all fetch tests use
  stub transport/resolver; no CLI spawn test presents a valid
  token. Phase 4 moves to ~90%; what keeps F4 from 100% is a
  first real fetch against a real registered target, which
  needs the user's word, a registered target with a verified
  authorization reference, and the five activation
  requirements.

### Round 93: Public-fetch invocation path — `sentinel target` + `sentinel fetch` (2026-11-28)

- The user approved ("Boleh", 28 Nov ~02:01 WIB) the two-step
  invocation design proposed by the parent: register once, then
  invoke per request with explicit human approval. This round
  builds the CLI + activation verification + tests for it.
- `sentinel target add <host> --scope <path> --purpose <purpose>
  --auth-ref <reference>` registers a public target in the new
  `<state-dir>/public-targets.json` store (one host, one
  path-prefix scope, one purpose, one authorization reference;
  exact host only, no wildcards). A separate store was required
  because the scope schema cannot express a path-prefix
  allowlist (`allowed_urls` is validated but never enforced in
  scope evaluation). `target list` (read-only, never prints the
  reference) and `target remove` are added for symmetry with
  `scope`; add/remove are refused while the kill switch is
  armed; a conflicting re-add is refused
  (`PUBLIC_TARGET_ALREADY_REGISTERED`), an identical re-add is
  an idempotent no-op.
- `sentinel fetch --url <url>` is the ONLY command that invokes
  the public HTTP adapter: unregistered host refused outright,
  kill-switch and scope-prefix checks, preview (GET only, no
  headers/body/credentials, 5 s timeout, 1 MiB body cap), then
  explicit human approval — interactive YA confirmation
  (terminal only, no `--yes` flag) or a one-time token from
  `fetch --mint-approval` (5-minute TTL, bound to the exact
  URL/target/fingerprint, single-use, consumed before the
  adapter runs so a DNS failure still burns it; the store holds
  only the SHA-256 hash). The adapter then runs its own gate
  and never follows a redirect. The response body goes to the
  operator's stdout only, never to the audit log.
- The adapter result gained `contentLength` and `redirected`
  (both already recorded in the audit event; additive only).
  Lock files in the two new stores ensure the state directory
  first (a missing directory used to surface as a bogus
  `*_STORE_LOCKED`).
- No real-target execution in this round: all fetch tests use
  stub transport/resolver; no CLI spawn test presents a valid
  token. Phase 4 moves up (invocation path complete); the
  remaining F4 work is the end-to-end activation drill (roadmap
  round 94).

### Round 91: Windows run for c4c9060 diagnosed by name from the user-supplied log, test fixed (2026-11-28)

- The user supplied the Windows run log
  (`logs_124580440327.zip`, check suite 124580440327):
  run 46049522263 for head `c4c9060` (round 90), completed
  2026-11-27T18:27:37Z, conclusion `failure` — 905 tests,
  888 pass, 1 fail, 16 skipped. The single failing test is
  named in the log: `tests/environment-checker.test.js:71`
  ("checkTool without a runner still probes the real command
  (default runner)") — `docker --version` spawns but exits
  non-zero on the windows-2025-vs2026 runner, so the real
  probe reports `not_verified`, which the test's whitelist
  (`verified`/`unavailable`) did not accept.
- Fix (test-only, no production change): the whitelist now
  accepts `not_verified` as a legitimate real-probe outcome;
  the regression detector for the round-83 bug is the reason
  guard (`commandRunner is not a function`), which is
  unchanged. A new test pins the production behavior the
  failure relied on: a command that runs but exits non-zero
  is `not_verified`, never `unavailable` (which means "not
  found on PATH"). The log is preserved at
  `~/workspace/sentinel-bounty/windows-ci-logs/logs_124580440327-c4c9060/`.
  Whether the same test caused the three earlier red runs
  (`933e0e7`, `98f09cb`, `31df812`) is an unproven
  hypothesis — their logs were never supplied — and the
  confirmation is the next green Windows run, not this
  round's claim.

## [0.1.0] — 2026-11-28

The first tagged release, on the round-90 commit (`c4c9060`). It covers
rounds 34–90. Rounds 1–32 are narrated in the pre-release baseline below.

### Round 90: user decisions executed — asset_url scrub, F6 policies, fifth detector, public HTTP adapter groundwork, first release tag (2026-11-28)

- User decision 28 Nov 2026 ~01:03 WIB ("Semua yang di
  daftar"): the operator approved the whole pending-decision
  list at once. This round executes items 1–3 and 5 in full,
  item 4 (tagging) at the end, and records items 6–7 as still
  blocked/pending.
- `asset_url` is now scrubbed by `report anonymize`: the host
  maps to a deterministic `anon-<sha256(salt + ':' +
  host).slice(0, 12)>` value, scheme/port/path/query/fragment
  preserved, userinfo stripped, and a non-URL value passes
  through unchanged. The pinned test that asserted
  "asset_url is NOT scrubbed" is replaced by four tests
  (host mapping, userinfo strip, fallback non-URL, salt
  mapping). See `docs/report-anonymize-v1.md`.
- Phase 6 policies v1 (`src/analysis/policies.js`,
  `docs/policies-f6-v1.md`): semantic dedup is
  `conservative`, rule-verdict false positives are
  `exclude-from-reports` (opt back in with
  `--include-false-positives` on `--finding`/`--findings`;
  when every finding is excluded the report fails with
  `REPORT_ALL_FINDINGS_FALSE_POSITIVE` and a stderr note),
  AI verdicts are advisory-only and never override the rule
  verdict (`AI_VERDICT_OVERRIDE=false`), detection is NOT
  auto-run and detectors are NOT async. The false-positive
  exclusion is the only policy that changes runtime behavior;
  the rest pins behavior that already existed.
- F5's fifth real detector: `insecure-transport`
  (`src/detection/insecure-transport.js`, registered as the
  built-in `--detector insecure-transport`). It scans the
  `content` string of an operator-supplied local input record
  for cleartext HTTP URLs (carrying only `http://<host>`,
  never path/query/userinfo; loopback never matches) and
  disabled TLS verification, one finding per distinct call
  site, never executing the code it scans. The detection
  policy (`docs/detection-policy-v1.md`) declares the
  detector set complete for the synchronous regex approach:
  SQL/template/LDAP/XPath need a parser, path traversal /
  SSRF / open redirect / XXE / ReDoS need taint, and key
  management / certificate validation / password-storage are
  outside call-site reach; auto-run is NO and async is NO.
- Public HTTP adapter groundwork
  (`src/http/public-http-adapter.js`,
  `docs/public-http-adapter-v1.md`): a GET-only adapter for
  public targets mirroring the local adapter, with a
  public-hostname rule, an authorization-reference match
  against the registered target
  (`TargetRegistry.getAuthorizationReference`), and a
  post-approval DNS resolution that refuses non-public
  addresses (SSRF guard, including 169.254.169.254). Tests
  use a stub transport and a stub resolver only; no CLI
  command invokes the adapter yet and nothing runs against
  a real target — the activation requirements stand.
- Windows run verdict for the round-89 commit `31df812`
  (round 90, part 6): run 46042520416 completed
  2026-11-27T17:59:36Z with conclusion `failure` — job `test`
  failed at step `Run npm test` (~34 s; setup, checkout,
  setup-node all success). The failing test name is not
  retrievable (log download 403), so no fix was attempted;
  this is the third unexplained red run, and the flake
  hypothesis is weakening.
- First release tag `v0.1.0` (annotated) on the round-90
  commit: pre-1.0 because the Meta integration items and the
  public-adapter invocation path are still outstanding and
  three Windows runs are red and unexplained.

### Second real detector: dangerous-call over local text (round 87, 2026-11-27)

- Windows run verdict for the round-86 commit `4c10a44`
  (round 87, part 1): run 45984432990 completed
  2026-11-27T10:43:01Z with conclusion `success` — job `test`
  success, every step success including `Run npm test`. This is
  the third green Windows run in the project's history (after
  run 45881977604 for `d2d1991` and run 45884755893 for
  `82d68d4`) and the first green run for the round-86 commit
  itself, so the round-86 detector change causes no Windows
  regression. The red `933e0e7` run stays unexplained (the
  failing test name is still unknown, log download 403) and no
  fix was attempted; it is now sandwiched between three green
  runs on the same suite.
- F5's second real detector: `dangerous-call`
  (`src/detection/dangerous-call.js`, registered as the
  built-in `--detector dangerous-call` alongside `stub` and
  `secret-scan`; CLI help and `runDetect` comment updated).
  It scans the `content` string of an operator-supplied local
  input record for six risky code-sink patterns (eval, the
  Function constructor, command execution, innerHTML
  assignment, document.write, unsafe deserialization) and
  reports one finding per distinct call site (pattern, line,
  column, match) in four classes — code injection (CWE-94,
  high), OS command injection (CWE-78, high), cross-site
  scripting (CWE-79, medium), insecure deserialization
  (CWE-502, high) — confidence `potential`, never executing
  the code it scans. No network, no scanner, no target; the
  detector only ever sees text the operator hands it. Safety
  properties, all tested: a finding carries only the matched
  call text (never the whole source line, which could hold
  adjacent sensitive data); `finding_id` is deterministic
  (`dangerous-call-` + SHA-256 of pattern + line + column +
  match, first 16 hex); one finding per call site with the
  first occurrence line and column; at most 100 findings per
  record with the truncation recorded in `errors`, never
  silent; content over 1,000,000 characters is skipped; a
  record without usable content is counted in `skipped`,
  never thrown; batch records follow the stub convention
  (batch `tool` forced as `discovery_tool`). The detect →
  validate → dedupe → report pipeline is proven end to end by
  test (XSS and deserialization findings validate as
  `needs_evidence` — their checklists require a `response_log`
  / `evidence_notes` — and the JSON report carries the
  per-finding evidence checklist; code injection and OS
  command injection have no dedicated checklist class and
  resolve to the generic checklist). 15 new tests
  (`tests/dangerous-call.test.js`); see
  `docs/detection-dangerous-call-v1.md`. SKILL.md's detector
  paragraph now names `dangerous-call` as the second real
  detector (both copies, still 150 lines, `cmp` passes); the
  open decisions (which further detectors, auto-run, async)
  are unchanged.

### Third real detector: insecure-crypto over local text (round 88, 2026-11-27)

- Windows run verdict for the round-87 commit `e2d164b`
  could NOT be checked this round: the unauthenticated GitHub
  API returns 403 "API rate limit exceeded" for the shared
  egress IP (104.29.197.140) — no run list, no jobs, no
  verdict, and no fix was guessed from the absence. No token
  was used (none is available to this round) and no run log
  was downloaded. The check is deferred to the next round,
  when the rate-limit window may have reset; the red `933e0e7`
  run stays unexplained as before.
- F5's third real detector: `insecure-crypto`
  (`src/detection/insecure-crypto.js`, registered as the
  built-in `--detector insecure-crypto` alongside `stub`,
  `secret-scan`, and `dangerous-call`; CLI help and
  `runDetect` comment updated). It scans the `content` string
  of an operator-supplied local input record for six
  weak-cryptography call-site patterns (MD5/SHA-1 hash calls,
  ECB cipher mode, DES/3DES/RC4/ARC4 cipher instantiation,
  Node's deprecated `crypto.createCipher()` /
  `createDecipher()`, `Math.random()` / `random.random()`)
  and reports one finding per distinct call site in the
  `cryptographic failure` class (CWE-327, CWE-338 for the weak
  PRNG; DES/RC4 high, the rest medium — each medium pattern is
  only exploitable in a sensitive context the detector cannot
  prove), confidence `potential`, never executing the code it
  scans. No network, no scanner, no target; the detector only
  ever sees text the operator hands it. Safety properties, all
  tested: a finding carries only the matched call text (never
  the whole source line, which could hold adjacent sensitive
  data); `finding_id` is deterministic (`insecure-crypto-` +
  SHA-256 of pattern + line + column + match, first 16 hex);
  one finding per call site with the first occurrence line and
  column; at most 100 findings per record with the truncation
  recorded in `errors`, never silent; content over 1,000,000
  characters is skipped; a record without usable content is
  counted in `skipped`, never thrown; batch records follow the
  stub convention (batch `tool` forced as `discovery_tool`).
  A DES cipher in ECB mode is two distinct weaknesses and
  yields two findings, one per pattern (tested explicitly).
  The detect → validate → dedupe → report pipeline is proven
  end to end by test (findings validate as `valid` under the
  generic checklist — `cryptographic failure` has no dedicated
  checklist class and resolves to the generic fallback, the
  same situation as round 87's code-injection classes — and
  the JSON report carries the per-finding evidence checklist).
  16 new tests (`tests/insecure-crypto.test.js`); see
  `docs/detection-insecure-crypto-v1.md`. SKILL.md's detector
  paragraph now names `insecure-crypto` as the third real
  detector (both copies, still 150 lines, `cmp` passes); the
  open decisions (which further detectors, auto-run, async)
  are unchanged.

### Fourth real detector: hardcoded-credential over local text (round 89, 2026-11-28)

- Windows run verdicts, checked first this round (the
  round-88 API rate limit had reset): run 46034607189 for the
  round-87 commit `e2d164b` completed 2026-11-27T16:33:24Z
  with conclusion `success` — job `test` success, every step
  success including `Run npm test`. This is the fourth green
  Windows run in the project's history and the first green
  run for the round-87 commit itself, so the round-87
  detector change causes no Windows regression. The
  round-88 commit `98f09cb` is RED: run 46039065088 completed
  2026-11-27T17:07:30Z with conclusion `failure` — job `test`
  failed at step `Run npm test` (setup, checkout, setup-node
  all success). The failing test name is not retrievable
  from the lab without repo-admin log access (log download
  returns 403), so no fix was attempted — a blind fix is not
  a fix. A bounded local investigation found no
  Windows-hostile construct in the round-88 change (no
  `os.EOL` / `path.sep` / `process.platform` use in the new
  detector or its tests; the win32 simulation passes
  833/0/16; the new CLI test follows the same temp-dir
  pattern as the round-87 CLI test, which passed on Windows
  in run 46034607189) — so the red run stays unexplained,
  not resolved: it may be a flake in a timing-sensitive
  pre-existing test or a genuine Windows-only issue
  invisible without the log. The red `933e0e7` run is now
  joined by a second unexplained red run on the same suite.
- F5's fourth real detector: `hardcoded-credential`
  (`src/detection/hardcoded-credential.js`, registered as the
  built-in `--detector hardcoded-credential` alongside `stub`,
  `secret-scan`, `dangerous-call`, and `insecure-crypto`; CLI
  help and `runDetect` comment updated). It scans the
  `content` string of an operator-supplied local input record
  for credential-named variables assigned a quoted string
  literal (password / passwd / pwd, API key names,
  secret/token names — `=`, `:=`, or `:` operators) and
  reports one finding per distinct assignment site in one
  class — use of hard-coded credentials (CWE-798, high) —
  confidence `potential`, never executing the code it scans.
  No network, no scanner, no target; the detector only ever
  sees text the operator hands it. Safety properties, all
  tested: a finding NEVER carries the literal value — the
  matched assignment is rebuilt as `<name><operator> "****"`
  (fixed four asterisks, no length information) before any
  finding is built, so no layer can leak it, and the
  finding_id hashes the masked match, not the secret;
  `finding_id` is deterministic
  (`hardcoded-credential-` + SHA-256 of pattern + line +
  column + masked match, first 16 hex); one finding per
  assignment site; at most 100 findings per record with the
  truncation recorded in `errors`, never silent; content
  over 1,000,000 characters is skipped; a record without
  usable content is counted in `skipped`, never thrown;
  batch records follow the stub convention (batch `tool`
  forced as `discovery_tool`). The detect → validate →
  dedupe → report pipeline is proven end to end by test
  (findings validate as `valid` under the generic checklist
  — the class has no dedicated checklist — and the JSON and
  Markdown reports were both tested to contain no assigned
  literal). 15 new tests
  (`tests/hardcoded-credential.test.js`); see
  `docs/detection-hardcoded-credential-v1.md`. SKILL.md's
  detector paragraph now names `hardcoded-credential` as the
  fourth real detector (both copies, still 150 lines, `cmp`
  passes); the open decisions (which further detectors,
  auto-run, async) are unchanged.

### First real detector: secret-scan over local text (round 86, 2026-11-27)

- Windows run verdict for the round-85 commit `82d68d4`
  (round 86, part 1): run 45884755893 completed
  2026-11-26T19:36:10Z with conclusion `success` — job `test`
  success, every step success including `Run npm test`. This is
  the second green Windows run in the project's history (after
  run 45881977604 for `d2d1991`) and the first green run for
  the round-85 commit itself, so the round-85 ENOENT change
  causes no Windows regression. The red `933e0e7` run is now
  sandwiched between two green runs on the same suite, which
  strengthens the flake hypothesis — but the failing test name
  is still unknown (log download 403), so the red run stays
  unexplained, not resolved, and no fix was attempted. A green
  run proves no regression, not that the new ENOENT branches
  fired: they only fire on Windows when a state path goes
  through a file, which the suite does not exercise.
- F5's first real detector: `secret-scan`
  (`src/detection/secret-scan.js`, registered as the built-in
  `--detector secret-scan` alongside `stub`; CLI help and
  `runDetect` comment updated). It scans the `content` string
  of an operator-supplied local input record for five strict
  fixed-format credential patterns (AWS access key ID, GitHub
  classic and fine-grained tokens, Slack tokens, private-key
  PEM headers) and reports one finding per distinct secret in
  the `information disclosure` class (`severity: high`,
  `cwe_id: CWE-200`, confidence `potential` — it never checks
  whether a credential is live, because it never contacts any
  service). No network, no scanner, no target; the detector
  only ever sees text the operator hands it. Safety properties,
  all tested: a finding never contains the full matched secret
  (proof of concept and evidence carry first 4 + `****` +
  last 4; the PEM header is not secret material and is carried
  verbatim); `finding_id` is deterministic
  (`secret-scan-` + SHA-256 of pattern + value, first 16 hex);
  one finding per distinct (pattern, value) with the first
  occurrence line; at most 100 findings per record with the
  truncation recorded in `errors`, never silent; content over
  1,000,000 characters is skipped; a record without usable
  content is counted in `skipped`, never thrown; batch records
  follow the stub convention (batch `tool` forced as
  `discovery_tool`). The detect → validate → dedupe → report
  pipeline is proven end to end by test (findings validate as
  `needs_evidence` — the checklist also requires a
  `response_log` — and the JSON report carries the
  `information disclosure` evidence checklist). 16 new tests
  (`tests/secret-scan.test.js`); see
  `docs/detection-secret-scan-v1.md`. SKILL.md's detector
  paragraph now names `secret-scan` as the first real detector
  (both copies, still 150 lines, `cmp` passes); the open
  decisions (which further detectors, auto-run, async) are
  unchanged.
- Phase movement: F5 ~20% → ~35% (the interface plus the
  first working detector, CLI wiring, docs, and tests; more
  detectors and the auto-run/async decisions remain). All
  other phases unchanged.

### ENOENT-through-a-file: same taxonomy for every state reader (round 85, 2026-11-27)

- Round 83 fixed the ENOENT-through-a-file case at one call site
  (token-digest read). This round applies the same fix everywhere
  a state read treats ENOENT as "missing": on Windows a path
  through a file is reported as ENOENT, not ENOTDIR, so a
  broken path was previously misread as "no state yet". New
  module `src/policy/storage-errors.js` (round 85) now holds
  `classifyStateReadError()` (token-digest + kill-switch reads),
  `classifyTokenFileError()` (rotate/revoke-token), and the
  shared probe `hasNonDirectoryAncestor()` — walk ancestors
  with `lstat`; a file ancestor means the path is invalid, a
  missing ancestor is ignored, `EACCES`/`EPERM`/`ELOOP` abort
  the walk and return `false` (fail-closed: keep the original
  error). The probe is a property of the path, not of the
  error: the same ENOENT can mean "genuinely missing" on one
  machine and "invalid path" on another.
- Wired to every reader that assumed ENOENT means missing:
  `PersistentKillSwitch` (load + snapshotLockless),
  `collectAudit` (operator status), `auditStatePermissions`
  (throws `STATE_PERMISSION_PATH_INVALID`), the install
  verifier (CLI entrypoint, kill-switch, audit log, scope
  config checks — a file parent now fails the check instead
  of passing it as "nothing there yet"), `state-backup`
  (`BACKUP_STATE_INVALID` / `BACKUP_CORRUPT`) and
  `state-export` (`STATE_EXPORT_STATE_INVALID` instead of
  silently returning the empty default state), and the CLI
  itself (`bin/sentinel.js`): `auditHealthWithStateReserve`
  now reports `KILL_SWITCH_STATE_PATH_INVALID` instead of
  falling through as "no state file yet", and the
  token-rotation lock / metadata / removal paths report
  `RESET_TOKEN_ROTATION_PATH_INVALID`. Existing codes are
  reused; no new error code was invented. `verify-install`
  still passes 7/7.
- One regression test added (`tests/storage-errors.test.js`):
  synthetic Windows-style ENOENTs plus `ENOENT` with a real
  file ancestor. The new ENOENT branches are only reachable
  on Windows through real filesystem calls (on Linux a path
  through a file yields ENOTDIR, which the existing branches
  already map), so the Linux suite proves they do not change
  genuinely-missing behavior, not that they fire — the
  Windows run is the proof for that, same as round 83.
  Linux suite: 802 tests (801 + 1), 798 pass, 0 fail, 4
  skipped (win32-only); win32 simulation 786 pass, 0 fail,
  16 skipped. The audit-log EACCES probe test now also copies
  `storage-errors.js` into its scratch skill tree.
- Windows run verdict for the round-84 commit `933e0e7`
  (round 85, part 1): run 45882467549 completed
  2026-11-26T23:31:34Z with conclusion `failure` — job `test`
  failed, step `Run npm test` exit 1 after ~48 s. The failing
  test name is not visible through the API (log download 403),
  so no fix was attempted and none was guessed; the local
  suite is green 3x on the same commit, so this is either a
  Windows-only failure or a flake. The second consecutive
  green run was NOT recorded — there is no second green run.
  The evidence needed is the failing test name from the run
  log (user's admin access, when awake). No phase movement:
  audit found no other decision-free lab-local polish gap
  (see the round-85 capability report for the full audit).

### First green Windows run: the round-83 fixes are confirmed (round 84, 2026-11-27)

- The first `windows-test` run after round 83 (run 45881977604,
  head `d2d1991`, 2026-11-26T19:13:08Z) completed with
  conclusion `success` — job `test` success, every step success
  including `Run npm test` (~39 s). This is the first green
  Windows run in the project's history; the workflow had failed
  on every run since round 28 (53/53 before round 81, then the
  runs for `bcc3037` and `0897b2e`).
- The ten run-54 fixes from round 83 are therefore confirmed on
  a real Windows runner, not just by local simulation: (1)
  `redact()` no longer runs `new URL()` on Windows paths;
  (2) drill polite-cancel via IPC `cancel` on win32; (3)
  digest-read ENOENT walks ancestors and reports
  `RESET_TOKEN_FILE_PATH_INVALID` when a parent is a file;
  (4) the pending-promise scanner normalizes paths to
  forward slashes; (5) `checkTool` has a default command
  runner, so `sentinel status` now reports the real tool
  count. The `tests/windows-platform.test.js` win32-only
  tests, skipped on POSIX, are verified by this run itself.
- Safe status changes with this run: the "implemented but not
  proven to pass on Windows" caveat from rounds 81–83 is
  retired for these fixes. It is not a phase move — no new
  capability was built and no blocked decision was taken in
  this round (docs-only, +2 files). The remaining blockers
  are unchanged: `asset_url` scrub, F5 real detectors, F6
  policies, release tagging, and the local-lab rule.
- Linux suite stays green alongside: 801 tests, 797 pass,
  0 fail, 4 skipped (win32-only), `verify-install` 7/7.

### Fix the 10 Windows run-54 failures by name (round 83, 2026-11-27)

- The user uploaded the run-54 log archive, so all ten failing test
  names are known for the first time. Each is a genuine
  Windows-vs-Linux difference, none of them the POSIX mode bits
  round 81 fixed: (1) audit-log `redact()` ran `new URL()` on every
  string, and a Windows path `C:\...` parses as URL scheme `c`,
  whose `toString()` lowercases the drive letter — URL parsing is
  now gated on `scheme://`, credentials in real URLs are still
  stripped; (2-5) the drill's polite cancel was SIGTERM, which
  Windows cannot deliver to a handler (TerminateProcess kills
  outright), so the stubborn worker died on the polite step and the
  escalation check failed — the polite step is now an IPC `cancel`
  message on win32, SIGTERM unchanged on POSIX, SIGKILL escalation
  unchanged on both; (6-7) a path through a file yields ENOENT on
  Windows, not ENOTDIR, so rotate/revoke degraded to
  "unauthorized" — an ENOENT digest read now walks the ancestors
  and reports `RESET_TOKEN_FILE_PATH_INVALID` when a parent is a
  file; (8-9) the pending-promise scanner compared
  `path.relative` output (backslashes on Windows) against the
  forward-slash allowlist — relative paths are now normalized to
  forward slashes; (10) `sentinel status` always reported 0 tools
  available because `probeTools` called `checkTool` with no command
  runner and `checkTool` had no default — the runner now defaults
  to the real one (masked on Linux, where no documented tools are
  installed; exposed on Windows, where docker is installed).
- Linux mode assertions stay strict (0600/0700); no new platform
  skip was added. Safe status until a Windows run passes: the fix
  is implemented but not proven to pass on Windows.

### Windows run 54 verdict: round-81 fix not proven green (round 82, 2026-11-27)

- The first `windows-test` run after round 81 (run 54, head
  `bcc3037`, 2026-11-26T18:38:39Z) completed with conclusion
  `failure` — the `Run npm test` step failed with exit code 1
  after a near-full-duration run, the same shape as the 53
  runs before it. The POSIX-mode diagnosis from round 81
  therefore did not turn the run green. Safe status until a
  Windows run passes: the fix is implemented but not proven
  to pass on Windows.
- The failing test name is still not visible from the lab:
  the jobs API names only the failed step (`Run npm test`),
  and the check-run carries no output and a single
  annotation ("Process completed with exit code 1"). The run
  log download still needs admin access, and no fix was
  guessed from the verdict alone — per the user's rule for
  this round, an unreadable failing test name means stop,
  not speculate.
- Checked locally and cleared as a cause of the branching
  logic: a one-off platform simulation (a `--require`
  preload that reports `process.platform === 'win32'` so
  the suite's win32 branches and skips engage) ran the
  full suite green — 780 pass, 0 fail, 16 skipped. That is
  NOT proof the real Windows run passes: the simulation
  cannot reproduce OS-level Windows behavior (real `chmod`
  no-ops, real `0666`/`0777` mode bits, real path
  separators in the OS, real symlink privileges), so it
  only proves the branching logic, not the run.
- No code changed in this round and no test was loosened:
  the Linux `0600`/`0700` assertions stay strict, and no
  new platform skip or exception was added. What changed
  is the record only: this entry and a status paragraph
  in `docs/state-permissions-v1.md`. The next step is
  named, not taken: the failing test name is readable
  only from the Windows run log, which needs the user's
  admin access.

### Windows CI failure investigated and fixed (round 81, 2026-11-27)

- The `windows-test` workflow failed on all 53 runs since round
  28, always in the `npm test` step. The cause: the suite
  asserted POSIX permission bits (`stat().mode & 0o777 ===
  0o600` for files, `0o700` for directories) in ~20 places,
  and the whole round-45 permission layer encodes them
  end to end. On Windows those bits do not exist — Node
  reports every file as `0666` and every directory as `0777`,
  and `fs.chmod` is a no-op except for the read-only bit —
  so the assertions could never pass there. No other certain
  cause was found: POSIX shell commands, `mount`/`umount`,
  and the nobody probes were already skipped or
  platform-aware on `win32`, and no test concatenates paths
  with `'/'`.
- `src/policy/state-permissions.js` now knows the platform
  boundary in one place: `posixModesApply()` (`platform !==
  'win32'`). The audit skips mode checks on Windows
  (`posixModes: false` in the result) but still refuses
  symlinks and special files; repair therefore never reports
  a tightening it did not perform; `verify-install` passes
  the state-permissions check for a normal Windows state
  directory (its PASS message says POSIX modes do not apply
  there). The privacy guarantee on Windows is the OS ACL,
  which Node cannot observe — documented in
  `docs/state-permissions-v1.md`, not hidden.
- Tests assert modes through the new
  `tests/helpers/private-mode.js` (exact bits on POSIX;
  existence + entry kind on Windows). The mode-behavior
  tests in `tests/state-permissions.test.js` are skipped on
  Windows; `tests/windows-platform.test.js` pins the Windows
  behavior (skipped on POSIX — verified by the Windows CI
  run itself). Symlink-creation sites in four test files now
  skip instead of failing when the platform refuses to create
  a symlink (the `backup-restore.test.js` precedent). A new
  `.gitattributes` pins LF endings on checkout (defense
  against CRLF; the docs tests trim lines, so this is
  hardening, not a proven cause). SKILL.md gains one
  sentence noting the Windows exception to the permission
  standard.
- Honest limit: the exact failing test names on Windows were
  never readable from the lab (log download needs admin
  access), and there is no local Windows machine — the fix
  rests on documented Node behavior plus the 53/53 failure
  record, not on a reproduced Windows run. If the Windows
  run still fails after this round, the log will name the
  next cause.

### Report generated_at fallback unified (round 80, 2026-11-26)

- `generateReport`'s own `generated_at` fallback (newest finding
  `created_at` when `options.generatedAt` is absent) now calls
  the shared `pickGeneratedAt` helper with an empty reports
  array (`pickGeneratedAt([], findings)`) instead of its own
  lexical `.sort()` over `created_at`. The round-73 claim that
  the two orderings were "equivalent for valid ISO strings"
  was wrong on probe: a lexical sort and a `Date.parse` sort
  disagree on mixed timezone offsets (`2026-01-01T23:00:00-02:00`
  is 2026-01-02T01:00:00Z but sorts lexically before
  `2026-01-02T00:30:00Z`), non-padded dates (`2026-1-1`
  sorts lexically after `2026-01-02T00:00:00Z`), and two
  representations of the same instant (lexical order picks by
  string shape; `Date.parse` ties sort stably, so input order
  wins). `validateFinding` never checks `created_at`'s format
  (it is not a required field), so such values genuinely
  reach the fallback. The new behavior is the chronological
  one in all three cases; for same-format ISO inputs the
  output is byte-identical (sha256 goldens pinned on the
  pre-refactor code). This closes the last polish item from
  round 73's F5; the only remaining open item from the
  report rounds is the `asset_url` scrub decision, which
  needs the user.

### Report stats error findings (round 79, 2026-11-26)

- `sentinel report stats` now excludes findings with verdict
  `error` from every breakdown: their declared severity,
  CVSS score, class, and asset are not trusted, so they
  contribute to no severity bucket, no CVSS distribution, no
  class count, and no top-asset count. They are still counted
  in `total` and in the verdict counts, and are named by a new
  `error_findings` line in text (`Error findings: N (not
  counted in severity, CVSS, class, or top assets)`) and key
  in `--json` — present only when greater than zero, so
  generator-produced output stays byte-identical. Interaction
  with round 77's `invalid_severity`: the two are independent,
  not a partition — `invalid_severity` counts
  invalid/missing-severity findings regardless of verdict,
  `error_findings` counts verdict-`error` findings regardless
  of severity validity; every invalid-severity finding is
  `error`, so `invalid_severity` is always a subset of
  `error_findings`. The severity buckets sum to `total` minus
  `error_findings`. This closes the last breakdown-pollution
  item from round 74's F5. One consequence: the `unknown`
  class is unreachable through stats (any finding that would
  map to it is an `error` finding); `classOf` still returns
  `unknown` for direct callers. The summary line is unchanged
  (the generator's wording counts declared valid severity,
  error findings included) — on a hand-edited file it can name
  more criticals than the Severity line shows, and the Error
  findings line explains why. Two pre-existing tests were
  updated for the deliberate behavior change (the
  band-mismatch test, which used to pin the declared severity
  being counted, and the blank-type/missing-asset test, whose
  fixtures are `error` findings); generator-produced goldens
  (FIVE, empty, FIVE+FP, md/json) are unchanged.

### Report stats class resolution (round 78, 2026-11-26)

- `sentinel report stats` now resolves each finding's class
  through the validator's evidence-class resolution
  (`resolveEvidenceClass` over
  `knowledge/evidence-checklists.json`, 15 classes): aliases
  and prefixed spellings of one class merge into its
  canonical id — `SQLi` and `Blind SQL Injection` count as
  `sql injection`, `auth bypass via JWT` counts as
  `authentication bypass` by file-order precedence — while a
  spelling no class matches falls back to the normalized raw
  string and a missing or blank type still counts as
  `unknown`. The resolution needs no evidence (it matches the
  type string alone). This closes the raw-string limitation
  from round 74's F5. No existing golden moved
  (generator-produced fixtures spell their classes in full,
  which already equals the canonical id); the generator's
  md/json goldens are unchanged. One documented gap: the
  matcher does not normalize hyphens, so `sql-injection`
  matches neither `sql injection` nor `sqli` and stays its
  own class.

### Report stats reconciliation (round 77, 2026-11-26)

- `sentinel report stats` now reconciles the executive
  summary's number with `total` on hand-edited files: the
  summary counts only findings with a valid severity, while
  `total` counts every finding, so the two could diverge
  with no explanation (round 74 F5). The gap is now named
  `invalid_severity` (findings with an invalid or missing
  severity — also in the `error` verdict bucket) and carried
  in both renderers, but only when greater than zero: the
  text Total line reads `Total: N findings (M counted in
  summary, K invalid severity)`, and `--json` gains the
  `invalid_severity` key after `total`. Generator-produced
  output is byte-identical (no key, no parenthetical when
  the gap is zero). No other command changed; the
  generator's md/json goldens are unchanged.

### Docs cross-reference audit (round 76, 2026-11-26)

- Docs-only round: audited every documentation cross-reference
  and fixed the drift found — 7 doc links missing from the
  SKILL.md report-paragraph See-list (`reporting-v1`,
  `report-templates-v1`, `report-filter-v1`, `report-stats-v1`,
  `report-helpers-export-v1`, `report-generated-at-helper-v1`,
  `cvss-vector-v1`), 2 from the detect-paragraph See
  (`detection-stub-v1`, `validation-v1`), 2 from the
  scope-paragraph See (`scope-manager-v1`,
  `scope-explain-v1`), 5 from the foundation paragraph
  (`request-governor-v1`, `approval-gate-v1`,
  `controlled-wrapper-v1`, `kill-switch-v1`,
  `persistent-kill-switch-v1`), and 10 usage lines missing
  from the SKILL.md command code block (`drill`,
  `verify-install`, `report-diff`, and the 7 `report`
  subcommands) plus the stale `sentinel report` lines, which
  lacked `[--allow-mixed-targets] [--verifier stub|<path>]`.
  The code block now lists exactly the 32 CLI help usage
  lines. No command behavior or output changed. New guard
  test `tests/docs-crossref.test.js` (8 tests) pins the
  cross-references: docs index completeness, README-to-index
  link, report docs in SKILL.md, report subcommands in
  SKILL.md, code block vs CLI help, resolvable doc
  references, real flags in docs usage spans, and a
  SKILL.md-anchor-or-allowlist rule for every doc (14 docs
  deliberately unanchored, with reasons). Full audit in
  `docs/report-docs-audit-v1.md`.

### Report render command (round 75, 2026-11-26)

- New command `sentinel report render <report.json>
  --format markdown|json|html|csv|summary|jsonl [--out <file>]`:
  re-renders an existing JSON report file into another format
  through the generator's own render path, so the output is
  byte-identical to what the generator would have produced for
  the same finding set (same report_id derivation, same
  grouping, same counts). The source report's `generated_at`
  is carried through via the shared `pickGeneratedAt` helper
  (round 73) — never re-stamped; JSON output with no
  timestamp anywhere fails with
  `REPORT_RENDER_NO_GENERATED_AT`. A platform-template source
  is refused (`REPORT_RENDER_TEMPLATE_REFUSED`); a
  mixed-target source renders only when it declares
  `mixed_targets` (a hand-edited second target without the
  declaration is refused with
  `REPORT_MIXED_TARGETS_REFUSED`); transformation metadata
  blocks (`split`/`filter`/`anonymization`) are not carried
  through. The rendered report goes to stdout (pipeable) or
  `--out` (mode 0600), the one-line summary (`rendered N
  findings as <format> from <report-id>`) to stderr; read-only
  on the input. 26 new tests, including byte-identical
  re-renders in all six formats, the generated_at
  carry-through and fallback, template refusal,
  mixed-target render + refusal, and the CLI contract
  (stdout/stderr, --out mode 0600, input untouched, symlink
  refused).

### Report stats command (round 74, 2026-11-26)

- New command `sentinel report stats <report.json> [--json]`:
  a compact triage summary of one JSON report — total, counts
  by severity (generator's exported `countBySeverity`), counts
  by rule verdict from round 67's `validateOneFinding` (valid /
  false_positive / needs_evidence, plus an `error` bucket for
  findings failing the strict check), counts by class (the
  finding's `vulnerability_type`, normalized trim + lowercase,
  missing or blank counts as `unknown`), the CVSS distribution
  (scored vs unscored, min / max / mean over scored only, mean
  rounded to 2 decimals), the top 5 assets by finding count
  (count desc, ties by `asset_id`), and the generator's
  executive summary line. Exit 0 whenever the file parses —
  stats is a summary view, not a verdict, so even an
  all-false-positive report or a report full of `error`
  findings exits 0; shape failures carry `REPORT_DIFF_*`
  codes (the round-64 shared reader); read-only, no writing.
  22 new tests, including hand-computed goldens for a 5-finding
  set (text + JSON) and a 6-finding set with the false-positive
  fixture, the top-5 cap with tie-breaking, the empty report,
  determinism across input orders, and the md/json goldens
  unchanged.

### Shared `pickGeneratedAt` helper (round 73, 2026-11-26)

- Pure refactor, no new command and no output change:
  `pickGeneratedAt(reports, findings)` is now exported from
  `src/report/generator.js` (newest valid `generated_at` among
  the source reports, else newest finding `created_at`, else
  null, never the wall clock), and all four call sites —
  filter, split, merge (both inputs), anonymize — call it
  instead of their own copies, each keeping its own named
  error on null (`REPORT_FILTER/SPLIT/MERGE/ANONYMIZE_NO_GENERATED_AT`).
  Corrects round 72: the duplication was a quadruple, not a
  triple — `anonymize.js` carried a fourth copy the round-72
  audit missed. 9 golden sha256 pins prove the four commands'
  byte output is unchanged; 7 direct contract tests cover the
  helper. `generateReport`'s own fallback and
  `deriveExpectedReportId` deliberately left independent.

### Shared report-summary helpers exported (round 72, 2026-11-26)

- Pure refactor, no new command and no output change:
  `executiveSummary` is now exported from
  `src/report/generator.js` (alongside the already-exported
  `countBySeverity`), and the empty report built by
  `sentinel report filter` calls the helpers instead of
  hand-replicating the summary wording and the zero-counts
  object (round 71 F5). A byte-identical golden pins the
  empty report's bytes, and an anti-divergence test asserts
  the empty report's summary/counts equal
  `executiveSummary(countBySeverity([]), programName)` /
  `countBySeverity([])`, so a future generator wording change
  propagates automatically. Audit of the other report
  commands: JSONL and summary already reuse the exported
  helpers; `deriveExpectedReportId` is deliberately left an
  independent re-implementation (validate must check the
  generator, not call it); the `pickGeneratedAt` triple in
  filter/split/merge is found and deferred to a future round
  (the three copies differ in semantics and error codes).

### Report filter command (round 71, 2026-11-26)

- `sentinel report filter <report.json> [--severity
  <level>] [--verdict <rule-verdict>] [--out
  <filtered.json>]` keeps a threshold subset of one JSON
  report as one valid round-31 JSON report — `--severity`
  keeps findings at or above that level (matched
  case-insensitively), `--verdict` keeps findings whose
  RULE verdict from round 67's `validateOneFinding` (valid
  / false_positive / needs_evidence) equals the given
  value, NOT the stored `validation_status` workflow state
  (which would keep everything or nothing on
  generator-produced reports); at least one predicate is
  required (`REPORT_FILTER_NO_PREDICATE`), both AND
  together. The output is rendered by `generateReport`
  itself with its own recomputed report id (the generator's
  own derivation for the kept subset) and a `filter`
  metadata block (`from_report_id`, plus only the predicates
  given), and each output passes `report validate` cleanly
  with `report_id_matches: true`. An empty result is a
  valid empty report (total 0), not an error — built
  following `renderJson`'s shape since `generateReport`
  refuses an empty finding set for JSON. The filtered JSON
  goes to stdout (pipeable) or `--out` (mode 0600) with the
  one-line summary (`filtered K of N findings (severity >=
  high, verdict valid)`) on stderr. The input file is never
  modified. Docs, SKILL.md (both copies, `cmp` verified),
  and README updated.

### Report split command (round 70, 2026-11-26)

- `sentinel report split <report.json> --by
  severity|verdict --out-dir <dir> [--force]` splits one
  JSON report into one valid round-31 JSON report per
  non-empty group — one file per severity (critical / high
  / medium / low / informational) or per rule verdict
  (valid / false_positive / needs_evidence, from round
  67's `validateOneFinding`, NOT the stored
  `validation_status` workflow state, which carries
  detected / needs_review / validated / false_positive /
  duplicate / rejected and would put every
  generator-produced finding in one "validated" group).
  Each file is named `<report-id>-<group>.json` with its
  own recomputed report id (the generator's own
  derivation for that subset) and a `split` metadata
  block (`from_report_id`, `group_by`, `group`), and each
  passes `report validate` cleanly. Empty groups are not
  written. `--out-dir` is created mode 0700, refused when
  non-empty unless `--force` (which only overwrites the
  files this split writes), and refused inside the skill
  directory or the state directory. stdout lists only the
  written paths, one per line; the per-group summary
  lines go to stderr. The input file is never modified.
  Docs, SKILL.md (both copies, `cmp` verified), and
  README updated.

### Report anonymize command (round 69, 2026-11-26)

- `sentinel report anonymize <report.json>
  [--out <anon.json>] [--salt <hex>]` strips internal
  identifiers from a JSON report so it can be shared:
  `target_id`, `session_id`, and every finding's `asset_id`
  map to deterministic `anon-<sha256(salt + ':' +
  original).slice(0, 12)>` values (default salt is the
  fixed public constant `sentinel-report-anonymize-v1`; a
  provided salt must be hex, 8–64 chars, and is never
  printed anywhere — not in the output, the summary line,
  or an error message), and internal hostnames/IPs in
  `description` and evidence `notes` are scrubbed (IPv4
  dotted quads -> `anon-ip`, hostnames ending
  `.local`/`.internal` -> `anon-host`, nothing else).
  Severity, CVSS, verdict, checklist, `ai_verdict`,
  `finding_id`s, and finding order are preserved; the
  output is re-rendered by `generateReport` itself, so the
  `report_id` is unchanged by design (it derives from
  `program_name` + finding ids, which anonymization
  preserves) and the output passes `report validate`
  cleanly with `report_id_matches: true`; it carries
  `anonymized: true` plus an `anonymization` metadata
  block (`salt_source`, `patterns`, never the salt). The
  anonymized JSON goes to stdout (pipeable) or `--out`
  (mode 0600), with the one-line summary (`anonymized N
  findings (I identifiers replaced, S text
  substitutions)`) on stderr. This is de-identification
  for sharing, NOT cryptographic redaction — anyone
  holding the original report and the salt can reverse
  the mapping — and `asset_url`, `request`/`response`
  logs, `title`, `impact`, `remediation`,
  `steps_to_reproduce`, `proof_of_concept`, and
  `references` are NOT scrubbed (the `asset_url` gap is a
  known limitation, pinned by a test). Docs, SKILL.md
  (both copies, `cmp` verified), and README updated.

### Report merge command (round 68, 2026-11-26)

- `sentinel report merge <a-report.json> <b-report.json>
  [--out <merged.json>]` combines two JSON reports into one
  valid round-31 JSON report: identical findings (after
  canonicalization — keys sorted recursively, `merged_from`
  sorted as an id set) kept once, disjoint findings unioned, a
  same-id finding with different content fails with
  `REPORT_MERGE_CONFLICTING_FINDING` naming the id and the
  first differing field, both inputs must agree on
  `program_name` (`REPORT_MERGE_PROGRAM_MISMATCH`), differing
  targets merge as `target_ids` + `mixed_targets: true` (the
  round-49 convention; the merge itself is the opt-in), and
  every finding is checked with round 67's strict-check path
  (`REPORT_MERGE_INVALID_FINDING`). The merged report is
  rendered by `generateReport` itself (its report id is the
  generator's own derivation; a test pins the merged output
  byte-identical to a direct render of the same set);
  `generated_at` is the newer input value, else the newest
  finding `created_at`, else `REPORT_MERGE_NO_GENERATED_AT`.
  The merged JSON goes to stdout (pipeable) or `--out` (mode
  0600); the one-line summary (`merged N findings from A + B
  (X shared, 0 conflicts)`) goes to stderr. Docs, SKILL.md
  (both copies, `cmp` verified), and README updated.

### Report validation command (round 67, 2026-11-26)

- `sentinel report validate <report.json> [--json]` checks a JSON
  report file before the operator trusts it: shape (non-empty
  `report_id`, `findings` array, bounded at 10,000, duplicate
  `finding_id`s refused, symlinked input refused), per-finding
  strict generator check (required fields, severity band, CVSS
  vector/score agreement — a failure is an `error`) plus the
  rule-based verdict (`valid` / `false_positive` /
  `needs_evidence`, counted but never failing), and the report-id
  recomputation (SHA-256 of program + sorted finding ids, the
  same derivation as the generator; a mismatch is a warning, not
  a failure — the file may come from an older generator
  version). Exit 0 when the file parses and every finding
  validates; exit 1 only on structural errors and band
  mismatches. Text and JSON output are deterministic
  (per-finding entries sorted by `finding_id`); validate is
  read-only (a test proves the input file byte-identical
  afterwards). Docs, SKILL.md (both copies, `cmp` verified),
  and README updated.

### Streaming JSONL report export (round 66, 2026-11-26)

- `sentinel report --format jsonl` renders one JSON object per
  line: a summary line first (`type: "report-summary"`,
  `report_id`, `total`, `counts_by_severity`,
  `counts_by_verdict` over `validation_status`, `target_id`,
  `session_id`, plus `target_ids` + `mixed_targets` for opt-in
  multi-target reports), then one finding per line in the same
  grouped order as the flat JSON `findings` array, each line the
  same shape as the JSON format's finding entries (finding object
  plus `evidence_checklist`, plus advisory `ai_verdict` when a
  verifier ran). Deterministic across input orders; no
  `--generated-at` needed (output identical with and without it);
  an empty set renders the summary line only (total 0), not an
  error. Template + jsonl refused like the other text formats;
  `--json` refused as an unknown option (jsonl is its own
  format); mixed-target rules unchanged. Counts are reused from
  the shared helpers (`countBySeverity`,
  `countByVerdict`), never re-implemented. Docs, SKILL.md (both
  copies, `cmp` verified), and README updated. Two deliberate
  test-expectation changes: the unknown-format error now lists six
  formats, so the round-55 and round-61 assertions were updated
  to the new message.

### Three more evidence checklists (round 65, 2026-11-26)

- Per-class evidence checklists grow from twelve classes to fifteen
  (`knowledge/evidence-checklists.json`, no code change):
  clickjacking (`response_log` — the framing response showing the
  page rendered inside a foreign frame with no X-Frame-Options or
  CSP frame-ancestors), open redirect (`request_log` +
  `response_log` — the redirect parameter and the Location header
  returned), and JSON Web Token weakness (`evidence_notes` — the
  forged or unsigned token and the response accepting it; the
  finding schema has no dedicated token field, the same limitation
  as reentrancy's trace). CVSS scores for the three new full
  fixtures are hand-computed from the FIRST 3.1 formula and
  cross-checked against the repo scorer (clickjacking 5.4 medium,
  open redirect 6.1 medium, JWT 9.8 critical). Matching is
  unchanged (first match in file order wins); the three new
  classes sit last, so every earlier class wins a tie — `auth
  bypass via JWT` stays authentication bypass, `Open Redirect via
  XSS` stays XSS, `Clickjacking via CSRF` stays CSRF, `JWT in SQL
  Injection` stays SQL injection. The round-31 `potential-full`
  fixture is an open redirect finding and now resolves to that
  class; the generic-fallback tests retarget a clone at `Missing
  Authentication` instead. Docs, SKILL.md (both copies, `cmp`
  verified), and README updated.

### Report diff between two runs (round 64, 2026-11-26)

- `sentinel report-diff <old-report.json> <new-report.json>
  [--format markdown|json] [--out <diff.md>]` compares two JSON
  reports from two runs: added / removed / changed findings,
  matched by `finding_id`, compared on severity / `cvss_score` /
  verdict (`validation_status`) / `asset_id` only. `merged_from`
  is provenance, not substance, so a `merged_from`-only
  difference is unchanged. Inputs are read bounded (10 MiB,
  depth 100) with a symlink refusal; shape errors are named
  (`REPORT_DIFF_INVALID_REPORT`, `REPORT_DIFF_INVALID_FINDING`,
  `REPORT_DIFF_DUPLICATE_FINDING_ID`,
  `REPORT_DIFF_SYMLINK_REFUSED`,
  `REPORT_DIFF_TOO_MANY_FINDINGS`) and fail before any output is
  produced. Added / removed entries are compact summaries, not
  full findings; the diff's own `report_id` is a hash of the two
  source report ids plus the sorted id lists, so the same pair of
  report sets renders byte-identically in both formats. An empty
  diff renders the counts line plus "No differences." The diff
  does not re-validate findings and never runs a verifier;
  `--template` is refused.

### Operator status overview (round 63, 2026-11-26)

- `sentinel status [--state-dir <path>] [--skill-dir <path>]
  [--json]` gives one strictly read-only overview of the whole
  operator state: kill-switch state (active/inactive, live-worker
  count, trigger when active, reset-token file presence — never
  the value), audit chain counts (total/verified/legacy/broken,
  anchor hash, first/last timestamps, prune-anchor count, first
  break reason), scope target counts, retention policy,
  verify-install pass/fail counts, and tool availability counts.
  Every read is lockless and creates nothing: the kill-switch is
  read with `snapshotLockless()` (no lock file, no mkdir, no lease
  pruning — stricter than `kill-switch status`, which takes the
  lock), the audit log is read with plain `readFile` and its chain
  replayed with the round-43/56 rules, and the scope store,
  retention policy, verify-install, and tool probes are all reads
  or local version-command spawns. A test proves it: state file
  contents AND mtimes, and the state directory's own mtime, are
  identical before and after a status run (module level and via
  the real CLI). Failure semantics: a corrupt/unreadable
  kill-switch state, audit-log storage failure, or damaged scope
  store fails the whole command (exit 1, JSON with the component
  named); audit content breaks and a damaged retention policy are
  reported inside their sections and the command still exits 0; a
  missing state directory is the empty view, not an error. The
  status object carries no wall-clock timestamp, so the same state
  renders byte-identically. New module
  `src/policy/operator-status.js` (15 tests: golden text + JSON,
  lockless-vs-locked chain cross-check, read-only proof, armed,
  empty, corrupt kill-switch/scope, corrupt audit content,
  damaged retention, token presence, direct-command count match,
  CLI text/JSON/unknown-option, CLI read-only proof) plus a guard
  test: the installed-copy root `SKILL.md` must be byte-identical
  to the canonical copy when present (skipped in a fresh clone,
  which has no root copy). That guard caught a real drift: the
  root copy had missed the round-62 retention command line and
  paragraph — re-copied in this round.

### Audit-log retention policy (round 62, 2026-11-26)

- `sentinel audit retention [--max-archives <n>] [--max-records
  <n>] [--show]` manages the operator's retention limits in
  `<state-dir>/audit-retention.json` (mode 0600, symlinks refused,
  schema v1; both limits optional, integers >= 1). Limits are
  enforced lazily at rotation: archives beyond `max_archives` are
  deleted and the oldest lines of the rotated-in active log are
  truncated to `max_records`. Every prune is RECORDED, not silent —
  an `AUDIT_LOG_PRUNED` anchor record (count, first/last
  timestamps, hash of the last pruned record, limits in force) is
  written to the new active log together with the incoming record
  in one atomic write, chained from the old tail, so
  `audit verify` still reports `verified: true` after a prune and
  `audit export` shows the anchor as a verified record. Setting a
  limit is refused while the kill-switch is armed
  (`AUDIT_RETENTION_REFUSED_KILL_SWITCH_ACTIVE`) and writes an
  `AUDIT_RETENTION_SET` audit record. A corrupt policy file fails
  loudly on `--show`/set but never blocks audit appends (rotation
  reads it leniently). With `max_records = 1` the retained set
  bottoms out at anchor + incoming (2 records). New module
  `src/audit/audit-retention.js`; `AuditLog.append` gains the
  rotation-branch plan/enforce steps. Two bugs of this round's own
  caught by its tests before commit: the anchor was first prepended
  to the in-memory active log and lost when rotation renamed the
  on-disk file (fixed by writing anchor + incoming record to the
  new active log in one write), and the anchor was first stamped
  with the clock, making `recordedAt` non-monotonic along the chain
  (fixed by sharing the incoming record's timestamp). The round-39
  EACCES nobody probe now also copies `audit-retention.js`,
  `safe-write.js`, and `input-limits.js` into its scratch layout,
  and the `audit bogus` error message is back to
  `Unknown audit action: bogus` (a round-62 wording change broke
  the existing test's expectation).

### Compact summary report format (round 61, 2026-11-26)

- `sentinel report --format summary` renders a validated finding
  set as a one-page plain-text executive summary — report id,
  target/session, severity and verdict counts, highest severity,
  the top 10 findings (severity then finding_id, with a "+N more"
  line), the advisory AI-verdict count, and a pointer to the full
  report. Plain text by design (pasteable into chat/email/tickets);
  no `--generated-at` needed, like CSV. An empty finding set
  renders the zero-count summary with "No findings." instead of
  erroring. A platform template with summary output is refused
  (`Template "<name>" renders Markdown only; summary output uses
  the generic template.`); the report command has no `--json`
  flag, so a stray `--json` is refused as `Unknown option:
  --json`. The verdict counts are over the findings'
  `validation_status` values, not the validator's rule verdict
  enum (documented in `docs/report-summary-v1.md`). New renderer
  `src/report/summary.js`; `src/report/generator.js` dispatches
  to it (required lazily to avoid a require cycle over
  `SEVERITY_ORDER`). Markdown/JSON/HTML/CSV output byte-identical
  (golden hashes re-pinned).

### Bugcrowd report template (round 60, 2026-11-26)

- `sentinel report --template bugcrowd` renders one validated
  finding into Bugcrowd's section layout (Description, Steps to
  Reproduce, Impact, Recommended Fix, Supporting Material),
  mirroring round 59's HackerOne pattern. No code change was
  needed: the template is data only, a new JSON file in
  `knowledge/report-templates/`, loaded and shape-validated by
  the existing `src/report/templates.js` (only the CLI help text
  names the new template). A finding without `proof_of_concept`
  fails with a named error (required for "Steps to Reproduce");
  JSON output adds `"template": "bugcrowd"`. Honest limit: the
  section order and names follow Bugcrowd's standard report
  structure as commonly documented and were derived offline —
  the layout has NOT been verified against the live platform's
  submission form, so check it before sending a real submission
  (documented in `docs/report-templates-v1.md` and the
  template's own description). Immunefi/Code4rena/HackerOne
  outputs are byte-identical (golden hashes unmoved). Suite
  493 → 496 tests.

### HackerOne report template (round 59, 2026-11-26)

- `sentinel report --template hackerone` renders one validated
  finding into HackerOne's section layout (Vulnerability
  Description, Steps to Reproduce, Impact, Recommended Fix,
  Supporting Material), mirroring round 35's Immunefi/Code4rena
  pattern. No code change was needed: the template is data only,
  a new JSON file in `knowledge/report-templates/`, loaded and
  shape-validated by the existing `src/report/templates.js`.
  A finding without `proof_of_concept` fails with a named error
  (required for "Steps to Reproduce"); JSON output adds
  `"template": "hackerone"`. Honest limit: the section order and
  names follow HackerOne's standard report structure as commonly
  documented and were derived offline — the layout has NOT been
  verified against the live platform's submission form, so check
  it before sending a real submission (documented in
  `docs/report-templates-v1.md` and the template's own
  description). Immunefi/Code4rena outputs are byte-identical
  (golden hashes unmoved). Suite 490 → 493 tests.

### Portable state export (round 58, 2026-11-26)

- `sentinel state export [--state-dir <path>] [--out <file>]`
  produces one portable JSON envelope of the whole operator
  state — kill-switch state + scope targets + audit summary —
  with a SHA-256 `contentHash` over the canonical `contents`
  only (the timestamp is excluded, so the same state always
  yields the same hash). The kill-switch state is exported as
  stored (`{ version, active, trigger, workers }`); the state
  file carries no token value or reset-token digest, and a test
  asserts by construction that no exported key matches
  `token|secret|password|api-key`. The audit summary carries
  counts and timestamps from round 56's per-record verification,
  not the full log (which already has its own export). Missing
  state/store/log export as the empty state; a corrupt state
  file fails with `STATE_EXPORT_STATE_INVALID`, a symlinked
  state file or output with `STATE_EXPORT_SYMLINK_REFUSED`, and
  a damaged scope store fails the whole export rather than
  dropping a target. A broken audit chain still exports with
  exit 0 (`chainVerified: false`). EXPORT ONLY — no `state
  import` exists; importing foreign state is an open user
  decision. 14 new tests in `tests/state-export.test.js`, suite
  476 → 490.

### Four more per-class evidence checklists (round 57, 2026-11-26)

- `knowledge/evidence-checklists.json` now defines twelve
  vulnerability classes (was eight): XXE (`xml external entity`,
  aliases `xml external entity` / `xxe`, extra required
  `request_log` + `response_log`), insecure deserialization
  (aliases `insecure deserialization` / `deserialization`, extra
  required `evidence_notes`), path traversal (aliases `path
  traversal` / `directory traversal` / `traversal`, extra required
  `request_log` + `response_log`), and business logic flaw
  (aliases `business logic flaw` / `business logic` / `logic
  flaw` / `business-logic`, extra required `evidence_notes`).
  Each follows the round-40 pattern exactly (required items +
  recommended items + `match` aliases + a `why`); no validator
  code changed — the new classes are a knowledge-file edit, four
  fixtures, and tests. File order is precedence, so a type
  containing both an old alias and a new alias still resolves to
  the old class (proven: `SQL Injection via path traversal` stays
  SQL injection, `SSRF via XML` stays SSRF). 4 new tests in
  `tests/evidence-checklists.test.js`, suite 472 → 476.

### Verifiable audit export (round 56, 2026-11-26)

- `sentinel audit export [--state-dir <path>] [--out <file>]
  [--format json|jsonl]` dumps the whole retained audit trail —
  active log plus rotated archives, oldest first — with each
  record's hash-chain status attached (`verified` / `legacy` /
  `broken`, with the `AUDIT_CHAIN_*` reason for broken records)
  and a summary with per-status counts (`totalRecords`,
  `verifiedRecords`, `legacyRecords`, `brokenRecords`,
  `anchorHash`, `firstRecordedAt`, `lastRecordedAt`). The
  top-level `verified` boolean is true exactly when no record is
  broken. JSON renders one object
  `{ exportVersion: 1, verified, summary, records }`; JSONL renders
  one compact line per record plus a final summary line marked
  `{ "type": "audit-export-summary", … }` (record lines carry no
  `type` field). A broken chain is NOT a refusal — the export exits
  0 and shows exactly which records verify and which do not —
  unlike `audit verify`, which exits 4 on a broken chain. The
  export carries no timestamp, so the same log always renders
  byte-identically. `--out` writes mode `0600` and refuses a
  symlinked output path; an unknown `--format` fails before the log
  is touched. The per-record walk continues past breaks (a modified
  record flags only itself; its successor still verifies, checked
  against the modified record's stored hash). A garbage line becomes
  an error entry with its file and line and a `null` record, never
  silently dropped. The same honest limits as the chain itself
  apply (prefix/last-record deletion undetectable, full rewrite
  outside the mechanism), documented in
  `docs/audit-export-v1.md`. `verifyChain()` is unchanged (the
  entry-collection loop is now shared). 13 new tests in
  `tests/audit-export.test.js`, suite 459 → 472.

### Flat CSV report export (round 55, 2026-11-26)

- `sentinel report --format csv` renders the same validated,
  grouped findings as a flat export: one row per finding plus a
  header row, in the same grouped order as the flat JSON
  `findings` array (targets ascending, then asset groups
  ascending, findings inside a group by severity then
  `finding_id`). Columns, in fixed order: `finding_id`,
  `target_id`, `asset_id`, `severity`, `cvss_base_score`,
  `cvss_temporal_score`, `cvss_environmental_score`, `verdict`
  (the finding's `validation_status`), `evidence_checklist`
  (`present/total` plus missing items joined with `; `, or
  `(complete)`), `merged_from` (joined with `; `, empty for a
  singleton), `ai_verdict` (the advisory line, empty without a
  verifier). Scores are plain numbers; a missing score is an empty
  cell. No `generated_at` is needed, so CSV output never requires
  `--generated-at`.
- Every field is RFC 4180 escaped (`escapeCsvField` in
  `src/report/generator.js`): a field containing a double quote, a
  comma, or a line break is wrapped in double quotes with inner
  quotes doubled. Hostile values (`<script>`, `=cmd`, `+cmd`,
  `@cmd`) render verbatim as inert text — the file itself never
  executes anything — and the generator deliberately does not
  alter values to defuse them. Formula injection is a
  spreadsheet-consumer risk, documented in
  `docs/report-csv-v1.md`: open exports with data-import (cells
  as text) or in a text editor, never double-click a CSV whose
  findings may carry attacker-controlled strings.
- An empty finding set renders the header row only (exit 0);
  every other format still requires at least one finding. A
  platform template with `--format csv` is refused with the same
  named error as HTML (`Template "<name>" renders Markdown only;
  CSV output uses the generic template.`), for empty and
  non-empty sets alike. Mixed-target input without
  `--allow-mixed-targets` is refused with
  `REPORT_MIXED_TARGETS_REFUSED`; with the flag, rows render for
  all targets in ascending target order. Markdown and JSON output
  are unchanged: the round-43 golden hashes are re-pinned in
  `tests/report-csv.test.js` (15 new tests, suite 444 → 459).

### Scope list and overridable default excluded paths (round 54, 2026-11-26)

- `sentinel scope list [--state-dir <path>] [--store <file>] [--url
  <url>] [--json]` lists every target in the persistent store
  (`<state-dir>/scope-targets.json`), sorted by `target_id`, each with
  its validation status and a summary of the normalized target. Without
  `--url` there is no decision to report (`decision: null` in JSON,
  `—` in text) — a scope decision is a property of a (target, URL)
  pair, and inventing a probe URL would fabricate data; with `--url`,
  each valid target is evaluated with the same
  `evaluateTargetRequest` that `check-scope` uses. One invalid entry
  is reported as `valid: false` with its validation error instead of
  hiding the rest of the list; a damaged store *shape* still fails
  loudly (`SCOPE_STORE_CORRUPT` /
  `SCOPE_STORE_UNSUPPORTED_SCHEMA`), a symlinked store is refused
  (`SCOPE_STORE_SYMLINK_REFUSED`), and an invalid `--url` fails with
  `SCOPE_LIST_INVALID_URL`. JSON output is deterministic (same store
  twice, or written in the opposite order, lists byte-identically).
  The command is read-only, needs no kill-switch guard, and works
  while the switch is armed. An empty store prints `No scope targets
  in <store>.` and exits 0.
- A target file may now declare `default_excluded_paths` — a list
  that replaces the built-in default excluded paths
  (`DEFAULT_EXCLUDED_PATHS`: `/logout`, `/signout`, `/delete`,
  `/reset-password`, `/unsubscribe`) for that target only; an empty
  list means no default exclusions. Absent the field, the built-ins
  stand. An invalid value (non-array, or an entry that is not an
  absolute path) fails `normalizeTarget` loudly with no silent
  fallback; `scope add` of such a target fails with
  `SCOPE_TARGET_INVALID` and writes nothing. The decision object is
  unchanged; the `--explain` trail now cites the right source for a
  default-list denial (built-in vs. `target file:
  <file> (default_excluded_paths)`) and the suggestion names the
  override instead of the round-52 "cannot be un-excluded" wording
  (one round-52 test expectation was updated for the intentional
  policy change). `policies/scope-policy.md` section 4 records the
  override. Open items from round 53 are now both closed; what
  remains for Phase 3 is the Meta-side ceiling, not reachable by
  rounds.

### Scope target management (round 53, 2026-11-26)

- `sentinel scope add <target.json> [--state-dir <path>]` and
  `sentinel scope remove <target-id> [--state-dir <path>]` manage the
  persistent store `<state-dir>/scope-targets.json` (`{schema_version:
  1, targets: [...]}`; the store lives in the state directory, not
  the skill directory, so it survives reinstalls). Entries are the raw
  target objects as supplied and are re-validated with
  `normalizeTarget` on every load, so a damaged entry fails loudly
  instead of silently changing scope. The parent directory is created
  private (`0700`), the file is written `0600` with planted symlinks
  refused, and mutations run under an exclusive lock file
  (`scope-targets.json.lock`, 5 s timeout, 60 s stale reaper).
  Successful mutations write an audit record (`SCOPE_TARGET_ADDED` /
  `SCOPE_TARGET_REMOVED`); a mutation whose audit append fails exits
  4. Adding an already-present `target_id` is an idempotent no-op
  (exit 0, `added: false, alreadyPresent: true`, no rewrite, no audit
  record). Both commands refuse while the kill-switch is armed
  (`SCOPE_CHANGE_REFUSED_KILL_SWITCH_ACTIVE`, exit 1, JSON result).
  `sentinel check-scope --store <scope-targets.json> --target-id <id>
  --url <url> [--explain] [--json]` resolves a stored target and
  evaluates it with the unchanged decision logic (`--store` and
  `--target` are mutually exclusive). Named errors:
  `SCOPE_TARGET_INVALID`, `SCOPE_TARGET_NOT_FOUND`,
  `SCOPE_STORE_CORRUPT`, `SCOPE_STORE_UNSUPPORTED_SCHEMA`,
  `SCOPE_STORE_SYMLINK_REFUSED`, `SCOPE_STORE_LOCKED`. The decision
  logic is unchanged and the plain `--target` path is byte-identical.
  Open items: no `scope list` yet; the built-in default excluded
  paths still cannot be overridden from the target file.

### Scope-decision explainability (round 52, 2026-11-26)

- `sentinel check-scope --target <target.json> --url <url> [--explain]
  [--json]` explains a scope decision: the ordered rule trail (which rule
  matched, from which policy source), the deciding rule, and a one-line
  suggestion for what would change the outcome. `--explain` prints a
  human-readable trail; `--explain --json` carries the same trail as
  structured data under `explanation` (rules with `evaluated` / `matched`
  / `outcome` / `source` / `detail` / `note`, `decidingRule`,
  `suggestion`, `source.targetFile`). Plain (non-explain) output is
  byte-identical to before this round. The six rules are evaluated in a
  fixed order (`TARGET_REGISTERED`, `URL_VALID`, `EXCLUDED_DOMAIN`,
  `ALLOWED_DOMAIN`, `EXCLUDED_PATH`, `IN_SCOPE`); the first rule whose
  condition holds decides and the rest are honestly marked
  `not evaluated`. Excluded-path matches cite the target file
  (`excluded_paths`) or the built-in default
  (`DEFAULT_EXCLUDED_PATHS`; `policies/scope-policy.md` section 4) —
  built-in defaults cannot be un-excluded from the target file, and the
  suggestion says so. The decision logic itself is unchanged:
  `explain().decision` is asserted identical to `evaluate()` across the
  full URL matrix. A corrupt or missing `--target` file fails before any
  trail is produced (`Invalid JSON in <path>` / `Cannot read <path>`,
  exit 1). Programmatic use: `TargetRegistry.explain(targetId, url, {
  targetFile })`, `evaluateTargetRequestWithTrail(target, url, source)`,
  `renderScopeExplanationText(explanation)`.

### Pluggable detector interface (round 51, 2026-11-26)

- The detector contract is defined (`src/detection/detector.js`):
  a SYNCHRONOUS function `detector(input, defaults) -> {
  findings, skipped, errors }` where `input` is a raw
  detector-input record (the shape `normalizeRawFinding()`
  accepts) or a batch record `{ tool, results: [...] }`, and the
  envelope carries normalized finding records (each re-normalized
  on validation, so a non-conformant finding is refused, not
  repaired), a non-negative integer `skipped` count, and an
  `errors` array of strings. A detector must not make network
  requests, write outside its return value, or invent data; a
  Promise return is refused (`DETECTOR_INVALID_RESULT`). The
  built-in stub detector is the reference implementation (it
  normalizes its input and nothing else; batch `tool` forced as
  `discovery_tool`; bad records counted in `skipped`). The shared
  batch normalizer `runDetectorOnRecords` is now used by both the
  stub detector and `runStubDetector` (round 31, behavior
  unchanged — verified by test). `loadDetector` loads a custom
  module only from inside the skill directory (same safety rules
  as the round-50 verifier loader: no symlinks, realpath inside
  the real skill root, export a function or an object with a
  `detect` function), with named refusals
  (`DETECTOR_NOT_FOUND`, `DETECTOR_SYMLINK_REFUSED`,
  `DETECTOR_PATH_OUTSIDE_SKILL`, `DETECTOR_INVALID_MODULE`,
  `DETECTOR_LOAD_FAILED`). `runDetector` runs against a defensive
  copy and records a throwing or invalid detector as an error
  envelope, never a crash. `sentinel detect [--detector
  stub|<path>] --input <record.json> [--session-id <id>]
  [--target-id <id>] [--asset-id <id>] [--out <findings.json>]`
  prints the findings as JSON (or writes them mode `0600`,
  symlink-refusing); a bad detector path fails cleanly with no
  output file. The output findings are directly consumable by the
  validator (detect → validate → dedupe → report proven end to
  end by test). NO real detector is built; which detectors to
  build, whether detection should ever run automatically, and
  whether detectors may be asynchronous remain open user
  decisions.

### Pluggable AI-verdict interface, advisory only (round 50, 2026-11-26)

- The verifier contract is defined (`src/analysis/ai-verdict.js`):
  a SYNCHRONOUS function `verifier(finding) -> { verdict,
  confidence, reasons }` with verdict one of `valid` /
  `false_positive` / `needs_evidence`, confidence a finite number
  in `[0, 1]`, and reasons an array of strings; the verifier
  receives a defensive copy of the finding and cannot mutate it. A
  verifier that returns a Promise is refused as an invalid result
  (the validator and generator are synchronous and deterministic).
  The built-in stub verifier is the default: it always returns
  `needs_evidence` with confidence 0 and the reason "no AI model
  configured", and never claims a finding valid or false_positive.
  `loadVerifier` loads a custom module only from inside the skill
  directory (absolute paths must resolve inside the skill root;
  relative paths resolve under it; the file must not be a symlink
  and its realpath must stay inside the real skill root; the export
  must be a function or an object with a `verify` function), with
  named refusals (`AI_VERDICT_NOT_FOUND`,
  `AI_VERDICT_SYMLINK_REFUSED`, `AI_VERDICT_PATH_OUTSIDE_SKILL`,
  `AI_VERDICT_INVALID_MODULE`, `AI_VERDICT_LOAD_FAILED`).
  `validateFinding(finding, { verifier })` computes the rule
  verdict first, unchanged, then records `aiVerdict` +
  `aiVerdictSource` — the rule verdict NEVER changes because of
  the AI verdict (tested both directions). `sentinel report
  --verifier stub|<path>` attaches `ai_verdict` +
  `ai_verdict_source` to every finding and renders it distinctly,
  labelled advisory, in Markdown, HTML, and JSON; platform
  templates do not render it in Markdown (fixed sections) but
  their JSON form still carries it. A verifier that throws or
  returns an invalid result is recorded as a `needs_evidence`
  error, never a crash. When no verifier is configured, no
  `ai_verdict` is attached and the report is byte-identical to the
  pre-round-50 output (the round-44 golden hashes still pass). NO
  model is plugged in; choosing the model, and whether the AI
  verdict should ever override the rule verdict, remain open user
  decisions.

### Mixed-target reports with explicit opt-in (round 49, 2026-11-26)

- A report covering more than one distinct `target_id` is now
  refused by default (`REPORT_MIXED_TARGETS_REFUSED`, naming the
  target count and every target, and pointing at the opt-in flag) —
  the pre-round-49 generator rendered mixed input silently and put
  only the first finding's `target_id` into JSON `target_id`,
  dropping the rest (verified by probe before the change). With
  `--allow-mixed-targets` (generator option `allowMixedTargets`)
  the report groups by target first, then by asset within each
  target (reusing `groupFindingsByAsset`), in deterministic order
  (target ascending, asset ascending, severity, finding id), with
  the finding number global across targets, and states the full
  target list in its header in all three formats (Markdown sentence
  + `## Target:` sections with `### Asset:` subsections; HTML
  paragraph + `<h2>Target:` / `<h3>Asset:`; JSON `target_ids`
  sorted array + `mixed_targets: true` + `target_id` per group,
  while top-level `target_id` holds the first target in sorted
  order, as `schemas/report.schema.json` still requires it).
  Platform templates render one finding per report, so they can
  never be mixed-target; the mixed-target check runs before the
  template branch. Single-target output is byte-identical to
  before (the round-44 golden hashes still pass). No automatic
  splitting into one report per target; whether mixed-target
  reports should ever be the default remains a user decision.

### Conservative semantic dedup v1 (round 48, 2026-11-26)

- Second dedup pass after the exact-key dedup (`semanticDedupeFindings`
  in `src/analysis/validator.js`, run over the exact pass's
  representatives): two findings merge ONLY when all four hold — same
  normalized `vulnerability_type`, same `asset_id` (exact), same CVSS
  base vector AND same severity (or, when neither carries a vector,
  the same severity band), and at least one shared evidence entry
  (same entry value; an empty `{}` entry never counts). The
  same-severity requirement in the vector branch is a deliberate
  tightening beyond the brief's minimum (identical base vectors
  imply identical computed scores, so a pair that differs there is
  mislabelled input). The merged finding keeps the union of
  evidence, steps, and references, the highest effective base score
  (with a shared vector, the score the vector computes — never a
  declared score that would disagree with it), and `merged_from`,
  the list of all member ids including the representative's (also
  declared as an optional property in `schemas/finding.schema.json`).
  Grouping is greedy on the representative, not transitive-closure.
  The generator renders `merged_from` in Markdown, JSON, and HTML;
  singletons render exactly as before (the golden hashes in
  `tests/report-html.test.js` still pass unchanged). Fuzzy text
  similarity and same type + asset without shared evidence are
  deliberately out of scope — looser matching is an open policy
  question for the user. Suite 341 → 356 tests. See
  `docs/semantic-dedup-v1.md`.

### Pending-promise audit (round 47, 2026-11-26)

- Audited every unawaited async call in `src/` and `bin/` (all
  `async` functions enumerated, every call site checked for
  `await` / `return` / `.catch()` / both-handled `.then()`; also
  `fs` promises, `new Promise(async ...)` executors, async timer
  callbacks, and async event handlers). Four real risks fixed:
  (1) the HTTP adapter's `cleanup()` called the async
  `unregister()` fire-and-forget — `get()` could resolve before
  the worker record was removed, and a write rejection became an
  unhandled rejection; `finishRun` now awaits cleanup and never
  rejects (a cleanup failure resolves with the real result plus
  `unregisterFailed: true`); (2) the controlled wrapper's
  timeout callback let a throwing `terminate()` hang the run
  forever and escape unhandled — the run now always settles by
  `timeoutMs`, reporting `terminationFailed: true`, and the kill
  poller's catch-path `terminate()` is guarded the same way;
  (3) the adapter poller's `catch { await cancel(); }` is
  guarded with a nested `try/catch`; (4) lock close/unlink
  ordering: a throwing `close()` used to skip the lock removal
  (stale lock for up to 60 s) — new shared helper
  `src/policy/lock-file.js` `closeAndRemoveLock` removes the
  lock file even when `close()` throws, used by the audit log
  and the CLI token-rotation lock. A regression guard runs on
  every `npm test` (`tests/pending-promise-guard.test.js` +
  `tests/pending-promise-allowlist.json`): it flags bare
  `unregister()`, unallowlisted `.then(` and async timers, bare
  `finishRun(`, and `new Promise(async`. The guard caught two
  adapter `finishRun` sites the manual audit had missed before
  the commit. Full audit, benign-site list, and guard limits in
  `docs/pending-promise-audit-v1.md`.

### Test hygiene and Python-not-required (round 46, 2026-11-26)

- Test temp dirs are now owned by a shared helper,
  `tests/helpers/temp-dir.js` (`makeTempDir(t, prefix)` registers
  removal with `t.after()`, which runs even when the test fails):
  90 async `fs.mkdtemp` sites across 12 test files migrated, plus
  the `tempDir`/`tempStateDir` helpers in the CLI-security and
  drill tests and the round-45 local helper (now the shared one).
  The 8 sync `mkdtempSync` sites were left alone — they already
  clean up in `try...finally`. The migration exposed one real
  bug: the drill test called the async `unregister()` without
  awaiting it, so its state write raced the new removal
  (`ENOTEMPTY`); the test now awaits it. A new
  `tests/temp-dir-helper.test.js` proves cleanup after a passing
  test and after a failing test (the child `node --test` run
  needs `NODE_TEST_CONTEXT`/`NODE_TEST_WORKER_ID` scrubbed from
  its env, or the runner refuses the recursive run). Before this
  round `/tmp` held 1,698 leaked test dirs (123M); a full green
  suite now leaves zero new ones, and the accumulated debris was
  removed (`/tmp` 39M after). Suite 327 → 330 tests.
- Python is not a requirement: no component invokes a Python
  interpreter (no `.py` files, nothing spawns `python`, README
  lists only Node.js 18+). The `check-env` Python probe and the
  `python_based_tools` disabled-feature entry are removed;
  `checkFirstAvailableCommand` stays as a tested utility for
  future first-available probes. `docs/check-env-audit-v1.md`
  and README.md record the decision, closing the last
  round-41 gap that was fixable without Meta. See the round-46
  capability report.

### State-file permissions audit and repair (round 45, 2026-11-26)

- New permission standard for the state directory (files `0600`,
  directories `0700`, no symlinks), enforced and verified in
  `src/policy/state-permissions.js`: `sentinel verify-install`
  gained a seventh check (`state-permissions`, reporting each
  violation by path with actual vs expected mode), and
  `sentinel verify-install --fix` tightens loose modes inside the
  state dir only, refusing symlinks (`STATE_PERMISSION_SYMLINK_REFUSED`).
  Writers now guarantee the state directory itself is `0700` even
  when it already exists (`ensurePrivateDir` — `mkdir({ recursive,
  mode })` alone never chmods an existing directory, which is how
  the live state dir stayed `2770`). The live install's audit
  found exactly three violations (state dir `2770`, two legacy
  `0660` files from Nov 18) and `--fix` repaired all three; the
  install now passes 7/7. A chmod that fails with `EACCES`/`EPERM`
  inside `ensurePrivateDir` is swallowed so the caller's next
  operation surfaces the properly classified permission error —
  throwing the raw `EPERM` regressed the round-27 EACCES probes
  (fixed here, and the probes now mirror the repo layout to load
  the new dependency). Fresh writes stay `0600`/`0700` under
  umask `022` (tested). Suite 316 → 327 tests. See
  `docs/state-permissions-v1.md`.

### Standalone HTML report export (round 44, 2026-11-26)

- `sentinel report --format html` renders the same validated,
  grouped findings as Markdown/JSON into one self-contained HTML
  file: inline CSS only, no JavaScript, no external resources (no
  CDN links, images, fonts, `@import`, `url()`, or any `href`/`src`
  attribute). It carries report ID, severity summary, executive
  summary, per-asset sections in the round-42 grouping order, CVSS
  base/temporal/environmental scores, and the per-class evidence
  checklist with `[x]`/`[ ]` marks; it is deterministic
  (byte-identical across runs and input orders). Finding content is
  untrusted, so every interpolated value is HTML-escaped
  (`escapeHtml`, exported from `src/report/generator.js`);
  references and asset URLs render as inert text, never as links.
  The hostile-content test pins the honest subtlety: `onerror`,
  `onload`, `src=`, and `javascript:` still appear in the file as
  escaped text inside `&lt;...&gt;` — the check is tag-based (every
  tag must be one the generator emits, no tag may carry
  `href`/`src`), not string-absence. Platform templates stay
  Markdown-only: `--format html` with `--template immunefi|code4rena`
  fails cleanly. Markdown/JSON output is unchanged (golden SHA-256
  hashes pinned in `tests/report-html.test.js`). Suite 305 → 316
  tests. See `docs/report-html-v1.md`.

### Audit-log hash chain and `audit verify` (round 43, 2026-11-26)

- Every audit record now carries a SHA-256 hash chained to the
  previous record (format v1: `chainVersion`, `prevHash`, `hash`;
  hash over the canonical JSON of the record's fields in documented
  order, genesis prevHash is 64 zeroes; a worked example with a
  hand-verifiable hash is in `docs/audit-integrity-v1.md`).
  `sentinel audit verify` replays the chain over the active log plus
  rotated archives (oldest first) and reports the first broken link
  with its file and line (exit 4 when broken): modification
  (`AUDIT_CHAIN_HASH_MISMATCH`), reordering or middle deletion
  (`AUDIT_CHAIN_PREV_MISMATCH`), a legacy record after chained ones
  (`AUDIT_CHAIN_LEGACY_AFTER_CHAINED`), an unparseable line
  (`AUDIT_CHAIN_UNPARSEABLE`). Pre-chain records verify as a legacy
  prefix and are never rewritten. Honest limits, pinned by tests:
  deleting a leading prefix or the last record is undetectable, and a
  full rewrite with recomputed hashes is outside the mechanism
  (tamper-evidence, not tamper-prevention). The writer never refuses
  to append because the chain is broken, so a tampered log cannot
  destroy the ability to record the incident that follows;
  `healthCheck()` stays structural-only and remains the gate before
  reset. A chained record is ~310 bytes (was ~130), so the round-37
  rotation tests were re-tuned to the new size (limits 700/1,000
  bytes); rotation behavior is unchanged. Suite 295 → 305 tests.
  See `docs/audit-integrity-v1.md`.

### Report grouping by asset (round 42, 2026-11-26)

- `sentinel report` now groups findings by `asset_id` in both output
  formats (generic template only): groups ordered by asset_id
  ascending (plain string order, never locale-dependent), findings
  inside a group by severity (critical first) then finding_id, with a
  global finding number across groups. The order is a pure function
  of the finding set, so the same findings in any input order produce
  byte-identical output (tested). Markdown gains a per-asset section
  (`## Asset: <id> — N finding(s) (critical: …, …)`); JSON gains a
  `groups` array (per-group counts and findings, each carrying its
  evidence checklist) alongside the flat `findings` array, which
  follows the same grouped order (documented in
  `schemas/report.schema.json`). A missing/empty/non-string asset_id
  maps to the `"unassigned"` group (defensive: the generator rejects
  such findings first, since asset_id is a required schema field).
  Grouping never changes a verdict — validation and deduplication
  happen before it. Platform-template JSON keeps its previous flat
  shape (no `groups` key); grouping across different targets
  (split, tag, or refuse) remains an open policy decision. One test
  expectation was corrected during the round (MIX-003 is low, CVSS
  2.0 — not high as first assumed; the code was already correct).
  Suite 284 → 295 tests. See `docs/report-grouping-v1.md`.

### check-env completion audit (round 41, 2026-11-26)

- `sentinel check-env` now enforces the documented Node.js 18 minimum
  (`runtime` reports `not_verified` below the floor, with the floor
  named; the constant mirrors `package.json` engines), loads its tool
  list from `config/environment-tools.json` at runtime (new
  `toolConfiguration` capability reports the source; a missing,
  unreadable, or malformed config falls back to the built-in
  definitions and says so; a config tool with no checker definition is
  reported `not_verified`, never silently skipped; a drift-guard test
  asserts the built-in definitions match the config list), reports
  each tool's purpose and — when unavailable — an install hint (plus
  the docker-CLI-is-not-a-daemon caveat), and probes the kill-switch
  state machinery in an isolated temporary directory
  (`processTermination` verified; end-to-end cancellation is proven by
  `sentinel drill`). The stale `processTermination` text (`Controlled
  cancellation has not been implemented…`) is gone. Considered and
  excluded: git/npm (install-time only), a Python minimum version
  (none documented), and `implementation-status.md` (a dated 21 Nov
  snapshot, left untouched). Remaining: check-env reports but does not
  gate (exit 0 even on failures; `verify-install` is the gate), and
  the probe verifies the machinery, not a kill. See
  `docs/check-env-audit-v1.md`. Suite 275 → 284 tests. This round also
  repairs the CHANGELOG gap below (round 39 was missing).

### Per-class evidence checklists (round 40, 2026-11-26)

- `knowledge/evidence-checklists.json` defines eight vulnerability
  classes (XSS, SQLi, SSRF, broken access control, authentication
  bypass, CSRF, reentrancy, information disclosure), each with
  required and recommended evidence items; the validator resolves a
  finding's free-form `vulnerability_type` to a class by
  trim+lowercase equals-or-contains matching (so `Stored
  Cross-Site Scripting` and `xss` both resolve to XSS) and enforces
  the class's required items — e.g. XSS/SQLi/broken access control/
  authentication bypass/information disclosure additionally require
  a `response_log`, SSRF requires `request_log` AND `response_log`,
  CSRF requires `request_log`, reentrancy requires `evidence_notes`.
  Unknown types fall back to the generic seven-item checklist. A
  missing class-required item is a `needs_evidence` reason named
  `missing <item> (required for <class id>)`; an evidence-derived
  item is only checked when the evidence array itself is present, so
  a missing array reports only `missing evidence`. The generator
  renders the checklist per finding (Markdown `### Evidence
  Checklist` section; JSON `evidence_checklist` object); platform
  templates keep their fixed sections in Markdown. The checklist
  spec loader throws on a malformed spec and the validator falls
  back to generic on load failure, keeping its never-throws
  contract. Regression fixed in this round: the validator's CVSS
  ratings were a top-level require, which crashed the operator-CLI
  `bin/`+`src/`-only copy run as `nobody` once the generator
  required the validator — the ratings are now loaded lazily on
  first use. Checklists verify PRESENCE, not truth.

### Incident-response drill (round 39, 2026-11-26)

- `sentinel drill [--state-dir <path>] [--recover]`
  (`src/policy/incident-drill.js`): kill-switch end-to-end against
  fake lab workers — two phases (cooperative worker cancelled via
  SIGTERM; stubborn SIGTERM-ignoring worker escalated to SIGKILL
  after a 1,000 ms grace), then audit verification and reset. Drill
  state is scoped to the drill directory and never touches real
  state; the drill refuses while the real kill switch is armed or
  real workers are registered, and only ever cancels workers it
  started itself; `--recover` recovers an interrupted run (PID
  liveness check, `DRILL_RECOVERED` audit record). Three bugs were
  caught by the drill's own tests during the round and fixed: a
  readiness race (SIGTERM before the handler was installed), an
  `exitCode`-only aliveness check (signal-killed reads null), a
  `DRILL_START` record written before pre-checks (refusals posed as
  abandoned runs), and an unawaited `unregister()` racing `reset()`
  (suite flake under load). CLI drill 30/30 PASS standalone; suite
  254 → 261 tests. Phase 8 ~80% → ~82%. The drill proves the
  machinery against a local sleep loop; it does not prove
  cancellation of a real tool or a networked worker. See
  `docs/drill-v1.md`.

### CVSS 3.1 temporal + environmental metrics (round 38, 2026-11-26)

- `src/analysis/cvss.js` parses and scores the full CVSS 3.1 vector:
  temporal metrics E/RL/RC (`Roundup(BaseScore x E x RL x RC)`) and
  environmental metrics CR/IR/AR/MAV/MAC/MPR/MUI/MS/MC/MI/MA
  (ModifiedISCBase capped at 0.915, scope-changed/unchanged
  modified-impact formulas, double Roundup before the temporal
  multipliers). Modified metrics fall back to their base metric on X
  (MS to S, requirements to 1.00). Values live in
  `knowledge/cvss/cvss-calc.json` (`temporal`/`environmental`
  tables); the module holds only the formulas. `resolveCvss()`
  returns `temporalScore`/`environmentalScore` plus named
  `temporalError`/`environmentalError` mismatches, and the validator
  and report generator enforce the same strict rule as for the base
  score; the generator fills in and renders derived temporal/
  environmental scores (generic and Immunefi/Code4rena templates).
  Severity is still checked against the BASE score only. Scores are
  computed only for metric groups the vector carries (absent = null,
  never fabricated from all-X). New optional schema fields
  `cvss_temporal_score` / `cvss_environmental_score`. Expected
  scores are hand-derived from the FIRST specification's formulas
  and cross-checked with an independent computation — no network
  oracle was reachable, so they are NOT copied from the FIRST
  calculator; re-checking them against it is the first verification
  for a future networked run. See
  `docs/cvss-temporal-environmental-v1.md`. Suite 225 → 254 tests.

### State backup/restore and audit-log rotation proof (round 37, 2026-11-26)

- `sentinel backup --out <file>` / `sentinel restore --from <file>`
  (`src/policy/state-backup.js`, `--state-dir` supported): backup
  captures only `kill-switch.json` in a schema-version 1 envelope
  carrying a SHA-256 integrity hash; the audit log is deliberately
  excluded (append-only evidence — restoring an old copy would erase
  intervening events). Restore verifies hash and schema version before
  writing anything and refuses with a named error and no partial write
  on corrupt input, hash mismatch, or unsupported schema. The
  armed-with-leased-workers rule is REFUSE
  (`BACKUP_ARMED_WITH_LEASED_WORKERS`): an armed state holding a live
  lease is not restored, so no phantom workers can block a later reset;
  an armed state with no live leases restores normally and stays armed.
  Backup/restore never follow symlinks for output or input, and restore
  refuses while a fresh state lock is held. See
  `docs/backup-restore-v1.md`. Audit rotation itself was NOT rebuilt
  (8 MiB / retain 3 already existed): this round proves it with tests
  (trigger at limit, no records lost across rotation, archives bounded
  at retention) and completes it — `healthCheck()` now validates the
  rotated archives and reports a corrupt one as
  `AUDIT_LOG_ARCHIVE_CORRUPT` instead of silently dropping it, and
  `readAllEvents()` returns active plus archives, oldest first, while
  `readEvents()` stays active-log-only by design.

### CVSS 3.1 base-vector parsing and scoring (round 36, 2026-11-26)

- `src/analysis/cvss.js` parses a CVSS 3.1 base vector and computes the
  base score per the FIRST specification (scope-changed formula and
  Roundup included), with severity bands from the shared
  `knowledge/cvss/cvss-calc.json` table — no second band table. The
  validator and the report generator share `resolveCvss()`: a malformed
  vector fails by name, a vector disagreeing with a declared score
  fails by name, and a vector-only finding derives its score (and is
  checked/rendered with it) instead of going unscored. Four lab
  fixtures carried declared scores contradicting their own vectors
  (STUB-001 8.2 vs 6.1, potential-full 6.5 vs 5.4, duplicate-a/b 5.3
  vs 5.4); the declared scores were corrected to the computed values
  and the affected test expectations updated. See
  `docs/cvss-vector-v1.md`. Temporal/environmental metrics are out of
  scope; the stub normalizer still derives severity from the declared
  score only (documented limitation).

### Report templates for Immunefi and Code4rena (round 35, 2026-11-26)

- `sentinel report --template immunefi|code4rena` renders one validated
  finding into a platform's section layout (one finding per report;
  `--findings` with a template fails cleanly). Templates are data, not
  code: JSON files in `knowledge/report-templates/`, loaded and
  shape-validated at runtime by `src/report/templates.js`; adding a
  platform is a new data file. A required section with no source data
  fails with a named field (a finding without `proof_of_concept` cannot
  be rendered in either template); an optional section with no data is
  omitted. `--format json --template <name>` keeps the generic JSON
  shape and adds a `"template"` field. Cantina submissions use the
  Code4rena template (same section set; see
  `docs/report-templates-v1.md` for the caveat). Deterministic:
  same input, byte-identical output, Markdown and JSON.

### Security self-review of the CLI (round 34, 2026-11-26)

- Report/check-env output writes now refuse a planted symlink at the
  exact output path (`src/policy/safe-write.js`: lstat pre-check plus
  `O_NOFOLLOW` on POSIX), so attacker-influenced report content can
  never be redirected to the link target. The check-env storage marker
  write uses the same guard.
- Finding/target input files are bounded (`src/policy/input-limits.js`):
  10 MiB per file, 10,000 findings per `--findings` array, 100 nesting
  levels (checked iteratively, never recursively).
- `countBySeverity` ignores severities outside the schema bands, so a
  hostile severity can never reach a bucket or inflate the total.
- Probed and found NOT vulnerable (regression tests added):
  prototype pollution via parsed JSON, argument injection (spawn is
  `shell: false` with fixed allowlisted args), malicious kill-switch
  state and audit-log lines (fail closed, hostile entries dropped).

## Pre-release baseline — rounds 1–32 (2026-11-26)

Round 98 note: this section was headed `## [1.0.0]` before the
release-tag line existed. The `1.0.0` label was never a tagged release —
the first tagged release is v0.1.0 (round 90) — and the section is
retitled here without rewriting its content. Head commit `f42c61b`.


First consolidated release of the lab-local Sentinel Bounty skill, as
installed at `~/workspace/custom-skills/sentinel-bounty/`. Development ran
autonomously in 32 rounds under the standing limits: **local lab only, no
network scanner, no public targets**. Head commit `f42c61b`
(`test(phases-5-7): commit pipeline integration test, expand fixtures,
harden validator`).

### Kill switch / token lifecycle

- Persistent cross-process kill switch with process-group (PGID) kill of
  the lab process tree; kill state survives restarts and is stored in
  versioned JSON state files (mode 0600, atomic temp-write + rename).
- Bound single-use approval gate: approvals are recorded in state but are
  not authorization by themselves — execution still requires a runtime
  approval card (`permissions.preapprove` has no generic Sentinel binding).
- Token-gated operator CLI (`sentinel`): hash-file token gate, operator
  audit, race stress tested. Tokens are expiring and auditable: rotation
  is serialized, expiry metadata normalized to ISO (`validUntil`), reset
  repair documented, and revocation is crash-recoverable
  (`REVOKE_PENDING` + idempotent retry, scoped by token key; 100-cycle
  revoke run green). Corrupt token files now fail closed with
  `RESET_TOKEN_FILE_CORRUPT`.
- Audit log is append-only JSONL; audit health is classified on storage
  failures (including disk-full / ENOSPC recovery), and audit fails
  closed. Secrets are never written to state files — Secure Vault only.

### Scope & policy

- Default-deny scope manager with allowlist/exclusion rules and path
  blocking; target registry refuses IP literals and non-localhost hosts.
- Request governor: token-bucket rate limit, request budget, and 429/503
  backoff. Localhost-only HTTP GET adapter (`LOCALHOST_ONLY` enforcement,
  audited); every non-localhost attempt is blocked with zero transport
  calls. No scanner tools are installed or invoked anywhere.
- Environment checker probes runtime, filesystem, and persistence, and
  detects `python3` before `python`. Network is `not_tested`; external
  tools (docker, subfinder, dnsx, httpx, katana) are all `unavailable`
  in the lab.

### Detection stub (phase 5 — partial)

- Lab-local detection scaffolding only: `src/detection/` normalizes raw
  scanner-shaped fixture output into the finding schema (strict, no
  invented data; `impact`/`remediation` required, severity derived from
  `cvss_score` with inclusive lower-bound bands ≥9.0 / ≥7.0 / ≥4.0 / >0 /
  0). The stub detector never aborts on one bad result — it counts it in
  `skipped` with the error recorded. No real detector and no scanner
  integration exist; phase 5 needs a user scope decision before it can
  move past scaffolding.

### Validation (phase 6 — partial)

- Rule-based finding validator: verdicts `valid` / `false_positive` /
  `needs_evidence` / `needs_manual_review`, with a documented precedence
  order (missing field → analyst `false_positive` → manual review →
  severity/CVSS mismatch + missing evidence → confidence rules). It never
  throws on malformed input. Unknown severities and invalid `cvss_score`
  values (non-finite, out of [0, 10]) are rejected as `needs_evidence`,
  never `valid`.
- Root-cause dedup by `vulnerability_type|asset_id|normalized-first-step`
  (exact-key only — no semantic similarity). Fixed 7-item evidence
  checklist, always fully listed. No AI-model verdict, no semantic dedup,
  no live verification.

### Reporting (phase 7 — partial)

- Deterministic report generator (`sentinel report`): Markdown + JSON
  from validated findings, with strict severity/completeness rules
  (a report that must fail never leaves a half-written file). Two CLI
  runs with a fixed `generated_at` are byte-identical (same SHA-256).
- End-to-end pipeline (stub → validator → dedupe → report) is covered
  by a committed integration test, including a mixed fixture exercising
  dedup, verdicts, skipped findings, and a `valid` confirmed finding.
  No PDF output, no multi-session aggregation, no mixed-target grouping,
  no false-positive policy yet.

### Adaptation / uninstall

- Agent adaptation protocol (`docs/adapt-to-agent.md`): maps the skill
  contract to another agent platform and records the result. It is a
  documentation answer to the missing official manifest, not a
  substitute for one — the skill cannot be made "official" by rounds.
- Uninstall-restore protocol (`docs/uninstall-restore.md`): verified on
  a scratch copy only (kill-switch trigger → reset → revoke → removal →
  dead-CLI check), with the real install and real state untouched.
  Literal-name skill discovery works; persona-based discovery does not.

### Testing

- `npm test`: **148/148 PASS, 0 fail on Linux** (Node v24), verified on
  both the repo clone and the installed copy after reinstall. Suite grew
  from 13 tests (18 Nov) to 148 (26 Nov), including lock-error
  classification matrices (EEXIST + live lock stays `STATE_LOCKED`;
  permission failures classified separately), disk-full, and token
  lifecycle stress tests.
- Phase completion (per the round-32 report): phase 0 ~50%, phase 1
  ~65%, phase 2 ~95%, phase 3 ~92%, phase 4 ~25% (local lab adapter
  only), phase 5 ~15%, phase 6 ~30%, phase 7 ~45%, phase 8 ~70%.

## Known issues

- **Windows CI native run: GREEN on the round-87 commit, RED on the round-88 and round-89 commits.**
  GitHub Actions `windows-latest` passed `npm test` four times —
  run 45881977604, head `d2d1991`, 2026-11-26T19:13:08Z,
  conclusion `success`, the first green Windows run in the
  project's history (round 84) — run 45884755893, head
  `82d68d4`, 2026-11-26T19:36:10Z, conclusion `success` (round
  86) — run 45984432990, head `4c10a44`,
  2026-11-27T10:43:01Z, conclusion `success` (round 87), the
  first green run for the round-86 commit itself — and run
  46034607189, head `e2d164b`, 2026-11-27T16:33:24Z,
  conclusion `success` (round 89), the first green run for
  the round-87 commit itself. Four runs are RED; the fourth
  is diagnosed by name, the first three still unexplained.
  Between the first two green runs, run 45882467549 for head
  `933e0e7` (round 84's docs-only commit) completed
  2026-11-26T23:31:34Z with conclusion `failure`: job `test`
  failed, step `Run npm test` exit 1 after ~48 s (setup,
  checkout, setup-node all success). And run 46039065088 for
  head `98f09cb` (round 88's detector commit) completed
  2026-11-27T17:07:30Z with conclusion `failure`: job `test`
  failed at step `Run npm test` (setup, checkout, setup-node
  all success). And run 46042520416 for head `31df812`
  (round 89's detector commit) completed 2026-11-27T17:59:36Z
  with conclusion `failure`: job `test` failed at step
  `Run npm test` (~34 s; setup, checkout, setup-node all
  success). The failing test name is not retrievable from
  the lab without repo-admin log access (log download returns
  403), so no fix was attempted for any of the three red runs
  — a blind fix is not a fix. A bounded local investigation
  in round 89 found no Windows-hostile construct in the
  round-88 change, so the second and third red runs stay
  unexplained, not resolved; they may be a flake in a
  timing-sensitive pre-existing test or a genuine
  Windows-only issue invisible without the log. The
  evidence that decides either red run is the failing test
  name from the run log, which needs the user's admin access.
  The ten run-54 failures were fixed by name in round 83 after
  the user uploaded the run log; the same path applies here
  when the user is awake.
  The fourth red run, run 46049522263 for head `c4c9060`
  (round 90's commit), completed 2026-11-27T18:27:37Z with
  conclusion `failure` (905 tests, 888 pass, 1 fail, 16
  skipped) — and this one IS diagnosed: the user supplied
  its log (`logs_124580440327.zip`, check suite
  124580440327), which names the single failing test,
  `tests/environment-checker.test.js:71` — `docker
  --version` spawns but exits non-zero on the
  windows-2025-vs2026 runner, so the real probe reports
  `not_verified`, which the test's whitelist did not accept.
  Round 91 fixes the test by name (the whitelist now accepts
  `not_verified` as a legitimate probe outcome; the
  regression detector is the reason guard). Whether the same
  test caused the first three red runs is an unproven
  hypothesis — the test file is unchanged since `d2d1991`
  and the failure is a runner-environment issue, not a
  round-88/89/90 code issue, but without their logs it
  cannot be confirmed; the confirmation is the next green
  Windows run.
- **Phases 0–1 cannot reach 100% by rounds.** They need Meta: an
  official manifest, quotas, native identity, and persona indexing.
  There is no public Muse skill registry — distribution is this GitHub
  repo plus custom-skill install.
- **Phase 4 and public adapters are blocked** by the local-lab-only
  constraint until the user lifts it.
- A 25 Nov reinstall attempt shipped a commit with six unresolved merge
  conflicts (`826d9587`); the user fixed them upstream and the
  continuation commit (`1056e20c`) passed 60/60. The broken commit is
  history, not the current tree.
