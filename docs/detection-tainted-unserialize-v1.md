# Tainted Unserialize Detector v1 (Round 116)

The SECOND PHP detector (`tainted-unserialize`, CWE-502
Deserialization of Untrusted Data, severity high). It parses the
`content` string of a local input record as PHP (hand-written
stdlib-only subset parser, `src/detection/php-parser.js` — never a
regex, never executed) and tracks taint to the `unserialize()`
deserialization sink, reporting a sink call only when its judged
data is tainted or the call is reached through a `use function`
alias — never carrying a literal value or a source line into a
finding; every finding is confidence `potential` because the
detector cannot prove the call is reachable or attacker-controlled.

The taint analysis is the shared PHP analyzer
(`src/detection/php-taint.js`), configured here with this detector's
sink predicate, sanitizers, and options gate. The analyzer runs on
the PHP subset AST, NOT on the JavaScript taint engine (which is
JavaScript-specific) and NOT on the Python analyzer (whose sources
and sinks are Python-specific). See `docs/php-parser-v1.md` for the
parser scope.

## Sinks

`unserialize($data)` — the judged argument is positional argument
0, or the named keyword `data:` when no positional argument is
given (the same judged-argument rule the Python pickle detector
applies). A bare `unserialize` always resolves to the global sink
(the PHP fallback for unqualified function names); `\unserialize`
is a sink; a qualified `Foo\unserialize` is NOT a sink; a call
reached through a `use function` alias (`use function unserialize
as u;`) is a sink of kind `aliased-call`, reported with ANY
argument. A method named `unserialize` (`$x->unserialize(...)`,
`Foo::unserialize(...)`) is NOT a sink. `json_decode` is NOT a
sink (a data-only format).

## Sources

- Every function parameter (the round-95 fallback: a helper never
  called, or called only with clean arguments, is still analyzed
  with parameters as sources).
- The superglobals `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` /
  `$_FILES` — bare AND subscripted (the array itself is attacker
  input).
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

## The allowed_classes gate

`unserialize($data, ['allowed_classes' => false])` — positional
argument 1 or the named keyword `options:` — is CLEAN: with no
classes allowed, no attacker class can be instantiated. An empty
allow-list (`['allowed_classes' => []]`) is likewise clean (it
allows no classes at all). A non-empty allow-list is still flagged:
the listed classes can carry `__wakeup` / `__unserialize` gadgets,
so an allow-list is a scope reduction, not a proof of safety.
Options passed as a variable are flagged (no constant propagation);
no options argument at all is flagged; options without an
`allowed_classes` key are flagged. This mirrors the `yaml.load`
SafeLoader gate of the Python pickle detector.

## Sanitizers

- `(int)` / `(float)` / `(bool)` / `(array)` casts and `intval` /
  `floatval` / `boolval` — the data becomes a scalar or a plain
  array, which cannot be a serialized object graph.
- `json_decode` / `json_encode` — the output is JSON syntax, which
  cannot be a valid PHP serialized object graph.
- A `(string)` cast is NOT a sanitizer — the attacker string passes
  through unchanged. `base64_decode` does not cleanse (it only
  re-encodes the attacker bytes). An unknown call does not cleanse.

Sanitizer calls resolve through the `use function` bindings, so an
alias cleanses too.

## Guards do not apply

Allow-list guards do NOT apply to this detector: checking the data
against a list (`in_array($d, $allowed, true)`) does not make
deserializing it safe — the data itself is still serialized
attacker bytes. The include detector's guard model is not reused
here, by design.

## What is NOT modeled (pinned by tests)

- Variable function calls (`$f($x)`), `call_user_func` /
  `Closure::fromCallable`.
- Object-attribute taint (`$obj->field = $tainted` then read).
- Methods / static calls through the call graph.
- `$_SERVER` / `$_SESSION` / `$GLOBALS` / `$_ENV` as sources.
- A `(string)` cast as a sanitizer.
- Options passed as a variable (no constant propagation).
- A `use function` binding that shadows the global fallback
  (`use function foo\unserialize;` then `unserialize($x)` is
  not the global sink — per PHP semantics).

## Evidence

Evidence type `ast-call`, carrying the sink (`unserialize`), the
kind (`tainted-arg` or `aliased-call`), the 1-based line and column
of the call, the function name, the taint chain of identifier
names, and a notes string. Never a literal value or a source line.

## Examples

```php
<?php
// Flagged: $_POST flows to unserialize.
$obj = unserialize($_POST["data"]);

// Clean: allowed_classes => false forbids every class.
$obj = unserialize($_POST["data"], ["allowed_classes" => false]);

// Flagged: a non-empty allow-list is still flagged.
$obj = unserialize($_POST["data"], ["allowed_classes" => ["Foo"]]);

// Flagged: an alias is reported with ANY argument.
use function unserialize as u;
$obj = u("clean");

// Clean: json_decode is not a sink, and its output cannot
// be a serialized object graph.
$obj = unserialize(json_decode($_POST["data"]));
?>
```

## Tests

`tests/tainted-unserialize.test.js` — positive cases (all
superglobals, `php://input`, taint through assignments and return
values, inter-procedural flow, the named `data:` argument, aliases
with clean and tainted arguments), negative cases (constant
arguments, the `allowed_classes` gate in all its forms, sanitizers,
`json_decode` as a non-sink and as a sanitizer, qualified names,
method calls, non-sources, variable function calls,
`call_user_func`, guards not applying), and the envelope (batch,
language, empty and unparseable records). Run with `npm test`.
