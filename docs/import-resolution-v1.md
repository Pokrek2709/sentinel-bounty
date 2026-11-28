# Import resolution v1 (round 106)

A sink reached through an import resolves to its canonical
sink. Before this round the engine matched sink calls only
by their spelled name (`child_process.exec`,
`yaml.load`, `db.query`): a sink reached as
`require('child_process').exec(...)`, through a module
alias (`const cp = require('child_process'); cp.exec(...)`),
through destructuring (`const { exec } =
require('child_process')`), or through an ESM import
(`import { exec } from 'child_process'`) was invisible.
Round 106 closes that gap on the shared taint engine
(`src/detection/taint-engine.js`), for every parser-based
detector at once. No detector's finding rules change —
sources, sanitizers, and the judged argument are exactly
as before; only the spelling of the sink call is now
resolved.

## What resolves

Four spellings, all to the same canonical sink:

| Spelling | Example | Finding kind |
|---|---|---|
| Direct require member | `require('child_process').exec(d)` | `tainted-arg` (direct call) |
| Namespace alias | `const cp = require('child_process'); cp.exec(d)` | `tainted-arg` (direct call) |
| Destructured require | `const { exec } = require('child_process'); exec(d)` | `aliased-call` |
| ESM import | `import { exec } from 'child_process'; exec(d)` | `aliased-call` |
| ESM default / namespace | `import cp from 'child_process'; cp.exec(d)` | `tainted-arg` (direct call) |

Direct calls (the first, second, and fifth rows) are judged
like any direct sink call: a finding only when the judged
argument is tainted. Aliased calls (the third and fourth
rows) follow the existing alias rule: reported with any
argument, because the regex detector cannot see them at
all. A sanitizer still cleanses the judged argument of a
direct call (`require('child_process').exec(Number(d))` is
not a finding); an aliased call on a sanitized value is
reported, exactly as a non-import alias is.

Import bindings are hoisted like function declarations:
a sink call textually before its import still resolves,
because real JavaScript hoists imports. Assignment binds
the module too (`let cp; cp = require('child_process')`).
An identifier re-alias propagates the module binding
(`const cp2 = cp`) — one hop per bind, transitively, the
same rule function and sink aliases have followed since
rounds 95/101.

## The import tables (per detector)

Each detector carries two optional config tables
(`moduleRoots`, `moduleBareSinks`); detectors without
them resolve nothing through imports. The tables are
pinned by tests (`tests/import-resolution.test.js` asserts
the exact allow-lists).

| Detector | `moduleRoots` (module → sink root) | `moduleBareSinks` (module → bare sink) |
|---|---|---|
| tainted-command-execution | `child_process`, `node:child_process` → `child_process` | — |
| tainted-path-traversal | `fs`, `node:fs` → `fs` | — |
| tainted-ssrf | `http`, `node:http` → `http`; `https`, `node:https` → `https`; `axios` → `axios` | `request` → `request`; `node-fetch` → `fetch` |
| tainted-ssti | `ejs` → `ejs`; `pug` → `pug`; `nunjucks` → `nunjucks`; `handlebars` → `handlebars` | — |
| tainted-deserialize | `js-yaml` → `yaml` | — |
| tainted-ldap (round 107) | `ldapjs`, `ldapts` → `client` | — |
| tainted-xpath (round 107) | `xpath` → `xpath` | — |
| tainted-sql | — (none) | — (none) |
| tainted-xss | — (none) | — (none) |
| tainted-open-redirect (round 107) | — (none) | — (none) |

Why SQL and XSS have no table: SQL sink roots are
receiver variable names (`db`, `pool`, `connection`,
`client`, `conn`), not modules — `db.query` already
matches by name whatever `db` came from, and no driver
module exposes `.query` on the module object itself
(`require('pg').query` is not a sink). XSS sinks are DOM
globals (`document.write`, `innerHTML`), not module
members. Open redirect (round 107) has no table for the
same reason as SQL: `res` / `response` / `reply` / `ctx`
are request-handler parameters, not modules.

Why only `js-yaml` maps to `yaml`: its API really is
`yaml.load` / `loadAll`. The `yaml` package is NOT
mapped — its API is `parse`, not `load`, so mapping it
would manufacture findings for calls that cannot be
`yaml.load` at runtime.

A bare-root identity also resolves: an identifier that
IS a sink root binds as that root (`const cp =
child_process; cp.exec(...)`, `const mydb = db;
mydb.query(...)`). This is the same name-based treatment
the sink tables already apply to the bare root call.

## The bare-sink collision rule (round-105 quirk, reconciled)

A destructured name that collides with a bare sink is
judged as the bare sink, not as the alias, because the
direct-sink check runs first — whether the destructuring
source is a bare identifier or a require call:

- `const { request } = http; request(u)` with tainted `u`
  → finding for sink `request`, kind `tainted-arg`.
- `const { request } = require('http');
  request("https://example.com")` with a clean argument
  → no finding (a direct call needs a tainted judged
  argument), even though the alias binding exists.
- `const { request } = http; request("https://example.com")`
  behaves identically (the round-105 pin, unchanged).

The collision only matters where a bare sink and a member
sink share a name (`request` in SSRF). Non-colliding
names resolve as aliases (`const { get } = require('http')`
cannot be tested as a call — see below).

## What stays unresolved (pinned by tests)

- **Dynamic require** — `require(m)`, `require('child_' +
  'process')`: the module name is not a string literal.
- **Relative paths** — `require('./lib')`,
  `require('../lib')`: resolving them is cross-file
  analysis, which is not on the map (round 108 adds a
  second-language parser, not cross-file resolution).
- **Unknown modules** — `require('unknown-lib')`,
  `require('pg')` for SQL, `require('yaml')` for
  deserialize: not in the detector's import tables.
- **Re-export** — `export { exec } from
  'child_process'`, `export * from 'child_process'`: a
  re-export binds nothing locally.
- **Module-object assignment** — `module.exports =
  require('child_process')`: the sink is reached through
  an object property, not a binding.
- **Object-property indirection** — `const o = { exec:
  require('child_process').exec }; o.exec(d)`: the sink
  is reached through an object literal, not a binding.
  This is the deep-alias pin: identifier re-aliasing
  propagates, property indirection does not.
- **A shadowed `require`** — a user binding named
  `require` disables the resolution, like the sanitizer
  shadowing rule.

## Parser support and fallback

The subset parser (`src/detection/js-parser.js`) now
parses import declarations with bindings tracked
(round 106): side-effect imports, default imports,
namespace imports, named imports (with `as` aliases),
and default-plus-named / default-plus-namespace
combinations — all with a string-literal module
specifier. Anything outside that set falls back to the
pre-round-106 structural skip, so a record with an
exotic import still scans instead of failing the parse:
a string imported name (`import { "weird" as x } from
'mod'`) and dynamic import (`import('mod')`) are skipped
structurally, and the rest of the record is analyzed
normally. Import local names that are subset keywords
(`get`, `from`, `as`) cannot bind and also fall back to
the skip.

The round-101 keyword limitation is unchanged: a bare
identifier literally named `get` does not parse, so a
record calling `get(...)` directly is skipped, not
silently scanned — including when `get` came from an
import (`import { get } from 'http'`).

## Evidence

A finding from an import-resolved call is identical in
shape to any other finding of its detector: the sink is
the canonical name (`child_process.exec`), the evidence
`call` is the source spelling (`require('child_process').exec`
or `cp.exec`), the taint chain names identifiers only.
No literal value or source line is ever carried — the
module name in the `call` text is code structure, not
data.
