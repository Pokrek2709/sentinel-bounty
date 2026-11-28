# Tainted Pickle Detector v1 (Round 115)

The twenty-ninth real detector and the FIRST Python detector:
`tainted-pickle` runs a separate taint analysis over the Python
subset AST (`src/detection/py-parser.js`, `docs/python-parser-v1.md`),
NOT the JavaScript taint engine — which is JavaScript-specific.
One finding per sink call site, severity high, CWE-502
(Deserialization of Untrusted Data).

## Sinks

| Sink | Judged argument |
| --- | --- |
| `pickle.load` | argument 0 (the file object), or keyword `file` |
| `pickle.loads` | argument 0 (the bytes), or keyword `data` |
| `marshal.load` | argument 0, or keyword `file` |
| `marshal.loads` | argument 0, or keyword `data` |
| `yaml.load` | argument 0, or keyword `stream` (see the Loader gate) |
| `shelve.open` | argument 0 (the filename), or keyword `filename` |

`shelve.open` is a sink because shelve unpickles values on read —
a tainted filename opens an attacker-chosen database whose values
are deserialized. `yaml.safe_load` / `safe_load_all` and
`json.loads` / `json.load` are NOT sinks.

## Sources

- Every function parameter (the round-95 fallback: a helper never
  called, or called only with clean arguments, is still analyzed
  with its parameters as sources, so a sink reachable from a
  parameter is flagged with confidence `potential` and no claim
  of reachability).
- `input()` calls.
- `sys.argv` — any member / subscript of it (`sys.argv[1]`), and
  a bare `argv` bound by `from sys import argv`.
- Flask `request.args` / `form` / `data` / `json` / `values` /
  `files` / `cookies` / `get_json()` / `get_data()` — also via
  `flask.request.*` and via a `from flask import request as
  <alias>` binding. A bare `request` alone is NOT a source (the
  request object is not bytes; `pickle.loads(request)` would fail
  at runtime).
- `os.environ` is NOT a source: it is operator-controlled
  configuration, not attacker input. Pinned by a test.

## Taint flow

Taint flows through assignments (including tuple unpacking,
element-wise when the value is a Tuple of the same length),
augmented assignment, for-loop targets, with-targets, attribute /
subscript access, binary / boolean / comparison / conditional
expressions, containers, f-string interpolations, and unknown
function calls (a call is tainted when its receiver or any
argument is tainted). Branches join by union (a name tainted in
either branch stays tainted); a loop body is analyzed once and
joined the same way. A taint chain of identifier names proves
the flow in the evidence (`input -> data -> blob`).

Inter-procedural flow follows the JavaScript engine's round-101
rules, adapted to Python: a call to a known module-level (or
nested) function propagates taint into the callee's parameters
and through its return value, with the chain proving the flow.
Analyses are memoized per (function, tainted-parameter mask),
recursion is cut by an in-progress set (a recursive call does
not propagate taint — a documented false negative, not a loop),
and the call-graph depth is capped at 8. Methods
(`self.helper(...)`) are NOT resolved through the call graph —
the same limit the JavaScript engine carries. A user-defined
function named `input` is not distinguished from the builtin
(a documented approximation).

## Import resolution

Module aliases (`import pickle as pk`), from-import bindings
(`from pickle import loads`, `from pickle import loads as ld`),
and assignment aliases (`p = pickle`, `ld = pickle.loads`,
collected at module level in source order before any analysis)
all resolve to the canonical sink. A sink reached through a
name binding reports kind `aliased-call` with ANY argument —
the same rule the JavaScript engine applies to aliased sinks,
because the binding proves the call IS the sink. A direct
member call (`pickle.loads(x)`) reports kind `tainted-arg` only
when its judged argument is tainted. A bare `loads(...)` with no
import binding is NOT a sink: `json.loads` is the commonest
`loads`, so a name-based bare sink would misattribute it
(unlike JavaScript's bare `unserialize`, which is
distinctive). Module-level alias bindings are collected
flow-insensitively (a may-alias: a name rebound in a branch
keeps its sink binding).

## The yaml.load Loader gate

`yaml.load` with `Loader=yaml.SafeLoader` or
`Loader=yaml.CSafeLoader` (or the bare names when bound by a
from-import) is clean. Any other Loader — including
`yaml.FullLoader` and `yaml.UnsafeLoader` — or no Loader at
all is flagged. Note the version caveat: modern PyYAML (>= 5.4)
raises `TypeError` for `yaml.load(data)` without a Loader, so
the call would crash rather than deserialize — the finding is
about the unsafe pattern, not about a proven runtime exploit.

## Sanitizers

The allow-list (mirroring the JavaScript engine's): `int`,
`float`, `str`, `bool`, `len`, `hash`, `repr`, `json.loads`,
`json.load`, `int.from_bytes`, and the methods `.decode()` /
`.hex()` (bytes -> str, so the result cannot be unpickled as
attacker bytes). Resolved through the import bindings, so
`import json as j; j.loads(x)` cleanses too. Encoding and
content-preserving calls do not cleanse.

## What is NOT modeled (pinned by tests)

- `pickle.Unpickler(f).load()` — the method form of the
  Unpickler class is out of scope this round.
- `dill.load` / `dill.loads` — not in the sink table.
- Object-attribute taint (`obj.field = tainted` then
  `pickle.loads(obj.field)`): a write to an attribute does
  not taint a later read of it.
- A key filter or validation living in a helper function;
  only the modeled sanitizers cleanse.
- Constant propagation: a literal dangerous value stored in
  a variable is tracked by name, not by value.
- Class definitions: the parser fails loudly on `class`, so
  a record containing one is skipped, never scanned
  approximately. Methods are therefore never analyzed at all.

## Evidence

A finding carries only the sink name, position, kind
(`tainted-arg` / `aliased-call`), the function name, and a
taint chain of identifier names — never a literal value or a
source line. Confidence is `potential`: the detector cannot
prove the call is reachable or the input is really
attacker-controlled.

## Next step

Round 116: the PHP subset parser + tainted include/unserialize —
the fourth language on the same pattern.
