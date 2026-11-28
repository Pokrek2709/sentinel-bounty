# Tainted Include Detector v1 (Round 116)

The FIRST PHP detector (`tainted-include`, CWE-98 Improper Control
of Filename for Include/Require Statement in PHP Program — "PHP
Remote File Inclusion", severity high). It parses the `content`
string of a local input record as PHP (hand-written stdlib-only
subset parser, `src/detection/php-parser.js` — never a regex, never
executed) and tracks taint to include / require sinks, reporting a
sink only when its judged path is tainted and not guarded — never
carrying a literal value or a source line into a finding; every
finding is confidence `potential` because the detector cannot prove
the call is reachable or attacker-controlled.

The taint analysis is the shared PHP analyzer
(`src/detection/php-taint.js`), configured here with this detector's
sink predicate, sanitizers, and guards. The analyzer runs on the PHP
subset AST, NOT on the JavaScript taint engine (which is
JavaScript-specific) and NOT on the Python analyzer (whose sources
and sinks are Python-specific). See `docs/php-parser-v1.md` for the
parser scope.

## Sinks

`include`, `require`, `include_once`, `require_once` — as a
statement (`include $path`) and as an expression (`include($path)`,
`$x = include $path`). The judged value is the included path. The
kind is always `tainted-arg`: an include construct cannot be
aliased (`use function` cannot import a language construct), so
there is no `aliased-call` form for this detector. A direct sink
with a clean judged value is NOT reported. One finding per distinct
sink site per record.

## Sources

- Every function parameter (the round-95 fallback: a helper never
  called, or called only with clean arguments, is still analyzed
  with parameters as sources).
- The superglobals `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` /
  `$_FILES` — bare AND subscripted (the array itself is attacker
  input: `include $_GET;` is a finding).
- `file_get_contents('php://input')` with the literal argument
  (special case); `file_get_contents($tainted)` via the unknown-call
  rule.
- `$_SERVER`, `$_SESSION`, `$GLOBALS` and `$_ENV` are NOT sources
  (operator-controlled configuration / session state, not attacker
  input) — pinned by tests.

## Taint flow

Taint flows through assignments (including `list()` and short-list
unpacking, element-wise when the value is an array literal of the
same length), augmented assignment, foreach targets, attribute /
subscript access, binary / boolean / comparison / conditional /
coalesce expressions, casts that do not cleanse, containers,
interpolated-string parts, and unknown function calls (a call is
tainted when its receiver or any argument is tainted). Branches join
by union (a name tainted in either branch stays tainted); a loop
body is analyzed once and joined the same way. Taint flows
inter-procedurally through known functions and their return values
(memoized per tainted-parameter mask, recursion cut, call-graph
depth capped at 8 — the JavaScript engine's rules), and a helper
never called is still analyzed with its parameters as sources.
Function names are matched by bare name, case-insensitively. Methods
(`$this->m()`, `Foo::m()`) are NOT resolved through the call graph.

## Sanitizers

- `basename($path)` — strips the directory, so the included file is
  confined to one directory. Documented caveat: a same-directory
  file chosen by the attacker is still includable; `basename` is a
  scope reduction, not a proof of safety.
- `(int)` / `(float)` / `(bool)` casts and `intval` / `floatval` /
  `boolval` — the path becomes a number, which cannot name an
  attacker file.
- A `(string)` cast is NOT a sanitizer — the attacker string passes
  through unchanged. An unknown call does not cleanse.

Sanitizer calls resolve through the `use function` bindings, so an
alias cleanses too.

## Guards

An allow-list guard on the path, in an enclosing `if` test, guards
the variable in the consequent branch:

- `in_array($x, $allowed, true)` — strict `true` REQUIRED. A
  non-strict call proves nothing about the type and is not a guard.
- `array_key_exists($x, $allowed)`.
- `isset($allowed[$x])` — the subscript form. A bare `isset($x)`
  only proves definedness and is not a guard.

`&&` / `and` conjunctions contribute the guards of every conjunct
(the consequent runs only when all of them hold); `||` / `or`,
negation, and any other shape contribute none. A `switch ($var)`
with NO `default` case guards the variable inside its cases (if it
matched nothing, no case body ran).

Guards intersect on branch join: a guard survives only if all
joined branches — including the pre-branch state — have it, so a
guard added by one branch never leaks past the construct. A judged
expression is guarded iff all its variable leaves are guarded: a
Variable, a `.` concatenation of guarded parts, an interpolated
string of guarded parts; a Constant counts as guarded. Any other
shape (a Subscript, a Cast, a Call that is not a modeled sanitizer)
is NOT guarded — a conservative choice. In particular,
`include $allowed[$x]` after `isset($allowed[$x])` is still
flagged: the analyzer does not track array contents, so it cannot
prove the element came from the allow-list. That false positive is
pinned by a test so a future round improves it deliberately.

The early-return guard shape (`if (!in_array(...)) return;`) is NOT
modeled: the guard applies to the fall-through path, which this
analyzer does not model. Only the consequent-branch shape is
modeled. That known false positive is pinned by a test.

## What is NOT modeled (pinned by tests)

- Variable function calls (`$f($x)`), `call_user_func` /
  `Closure::fromCallable`.
- Object-attribute taint (`$obj->field = $tainted` then read).
- `include` / `require` cross-file resolution (other files are
  never loaded).
- The early-return guard shape (above).
- A Subscript as a guarded expression (above).
- Methods / static calls through the call graph.
- `$_SERVER` / `$_SESSION` / `$GLOBALS` / `$_ENV` as sources.
- A `(string)` cast as a sanitizer.

## Evidence

Evidence type `ast-include`, carrying the sink (the construct
name), the kind (`tainted-arg`), the 1-based line and column of the
include, the function name, the taint chain of identifier names,
and a notes string. Never a literal value or a source line.

## Examples

```php
<?php
// Flagged: $_GET flows to include.
include $_GET["page"];

// Clean: constant path.
include "config.php";

// Clean: basename strips the directory.
include basename($_GET["file"]);

// Clean: strict in_array guards the consequent branch.
$page = $_GET["page"];
if (in_array($page, $allowed, true)) {
    include $page;
}

// Flagged: non-strict in_array is not a guard.
if (in_array($page, $allowed)) {
    include $page;
}

// Flagged: the guard does not apply to the else branch.
if (in_array($page, $allowed, true)) {
    echo "ok";
} else {
    include $page;
}
?>
```

## Tests

`tests/tainted-include.test.js` — positive cases (all four
constructs, statement and expression forms, all superglobals bare
and subscripted, `php://input`, taint through assignments /
concatenation / interpolation / ternary / list unpacking /
augmented assignment, inter-procedural flow, `unset`), negative
cases (constant paths, sanitizers, all three guard forms, the
switch-no-default guard, non-sources, variable function calls,
`call_user_func`), and the envelope (batch, language, empty and
unparseable records). Run with `npm test`.
