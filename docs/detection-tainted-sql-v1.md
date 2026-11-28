# tainted-sql detector v1 — eighth real detector, third parser-based (round 103)

`sentinel detect --detector tainted-sql` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to SQL query
sinks, reporting one finding per distinct sink call site.
It is the eighth real detector (after
`tainted-command-execution`, round 100) and the third
parser-based one: it reuses the shared taint engine
(`src/detection/taint-engine.js`, extracted in round 101)
without touching it — the first detector built on the
engine as a thin wrapper only. See
`docs/parser-taint-scope-v1.md` §7 for the scoping (SQL
was the next named AST class after tainted command
execution).

## Input contract

- The detector takes a raw detector-input record — the shape
  `normalizeRawFinding()` accepts — or a batch
  `{ tool, results: [...] }`. It parses only the record's
  `content` string: text the operator already holds (for
  example source code or a code excerpt captured in the lab)
  and hands to the CLI. It never reads a file itself, never
  makes a request, and never executes the code it scans.
- `source` (optional, non-empty string) labels where the text
  came from and is carried into the description and proof of
  concept.
- `language` (optional) must be JavaScript (`javascript`,
  `js`, `node`, case-insensitive) when present; any other
  value counts the record in `skipped`. When absent, the
  content is attempted as JavaScript.
- `session_id` / `target_id` / `asset_id` come from the
  record, else from `defaults` (the CLI `--session-id` /
  `--target-id` / `--asset-id` options); a record missing an
  id after defaults is counted in `skipped`, never invented.
- A record without a non-empty string `content` is counted in
  `skipped` with its error recorded, never thrown; a bad
  record never aborts a batch. A non-object input throws
  `DETECTOR_INVALID_INPUT`, exactly like the stub detector.
- Batch records follow the stub convention: the batch `tool`,
  when present, is forced as `discovery_tool` on every
  finding; otherwise the finding carries
  `discovery_tool: 'tainted-sql'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript — the common driver call-site shapes;
all CWE-89, severity high):

| sink | notes |
|---|---|
| `db.query`, `db.execute` | generic receiver |
| `pool.query`, `pool.execute` | node-postgres pool / mysql pool |
| `connection.query`, `connection.execute` | mysql/mysql2 connection |
| `client.query`, `client.execute` | node-postgres client |
| `conn.query`, `conn.execute` | generic short receiver |

Only these two-part member calls are sinks. A bare
`query(...)` is deliberately NOT a sink — the name is too
generic and would false-positive on non-SQL `query`
calls. A three-part call (`app.db.query(...)`) is not
resolved either. `prepare` is NOT a sink in this round (a
prepared statement is created, not executed; judging it
is future work). ORM/query-builder shapes (knex, Prisma,
Sequelize) and other languages' SQL APIs stay
regex-covered by `dangerous-call` — this parser is
JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink call is reported

A sink call is reported ONLY when it carries information
the regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`db.query(...)`, `pool.execute(...)`) whose first argument is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const q = db.query`, `const { query } = db`, `db['query']`) with any first argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean argument is NOT reported:
the regex detector already flags that call site, and the
AST detector adds nothing. A sink call with zero arguments
cannot execute attacker data and is not reported. Only the
FIRST argument is judged (the SQL string): a tainted
second argument (the parameter vector) is NOT covered in
this round (see limitations).

A PARAMETERIZED query is not a finding: `db.query('SELECT
* FROM users WHERE id = $1', [userId])` carries a constant
SQL string as its first argument, so it is clean even when
the bound parameters are tainted. That is the intended
safe pattern, and it falls out of the first-argument rule
— no special case is needed. The same holds for a SQL
string held in a constant variable
(`const sql = 'SELECT ... $1'; db.query(sql, [id])`).

Taint propagates through: assignment and declaration,
member access on a tainted base, binary / logical /
conditional expressions, template interpolations, array /
object literals, `await`, unary `-` / `+` / `~`. `!`,
`typeof`, `void`, `delete` cleanse (they produce a boolean
or nothing, not the data). Return values of known
functions are computed: an identity wrapper propagates
taint, a constant-returning wrapper does not, a wrapper
returning a global source propagates it. Return values of
unknown calls are tainted when any argument is tainted
(an over-approximation, chain extended with
`callee(...)`). A sanitizer call (`Number`, `parseInt`,
`parseFloat`, `Boolean`, `Number.parseInt`,
`Number.parseFloat`) returns clean — see
`docs/sanitizer-modeling-v1.md`. Branch joins are OR:
tainted on any path stays tainted.

## What the parser sees that a regex cannot — and what it cannot

- A sink call in a comment or a string literal is NOT a
  call: the tokenizer strips comments and treats string
  contents as single tokens, so prose never becomes a
  finding. This is the sharpest difference from the regex
  detector, which matches call text wherever it appears.
- An aliased call IS a call: `const q = db.query;
  q(x)` and `const { query } = pool; query(x)`
  resolve the alias to its sink. Reassigning the alias to a
  non-sink value clears it (`let q = db.query;
  q = 5; q(x)` is not a finding).
- A wrapper function IS analyzed through the call
  graph (round 101): `function run(q) {
  return db.query(q); }` called as
  `run(userInput)` flags the sink with the
  cross-function chain (`parameter 'req' of function
  'handle' → req.body → parameter 'q' of function
  'run'`), and the fallback still flags the sink when
  the wrapper is never called or called only with
  clean arguments — then with the parameter chain only,
  and without claiming the wrapper is reachable from a
  tainted call. See `docs/inter-procedural-taint-v1.md`.

## Known limitations (documented, not hidden)

- **JavaScript only.** A second language needs a second
  parser.
- **Inter-procedural (round 101).** Taint flows from a
  call site into a callee, through return values, IIFEs,
  and function aliases, on the shared engine
  (`src/detection/taint-engine.js`); the chain proves
  the flow. A sink inside a helper never called, or
  called only with clean arguments, is still flagged
  via the parameters-as-sources fallback. Remaining
  limits: methods are not resolved through the call
  graph (analyzed with parameters-as-sources when
  their class is walked), no `this` modeling, and
  when several flows reach one sink site the first
  chain wins (see `docs/inter-procedural-taint-v1.md`).
- **Sanitizer modeling (round 101).** `Number`,
  `parseInt`, `parseFloat`, `Boolean`,
  `Number.parseInt`, `Number.parseFloat` cleanse
  taint — their return values cannot carry a string
  payload. Encoding and content-preserving calls
  (`encodeURIComponent`, `encodeURI`, `String`,
  `JSON.stringify`, string methods) do NOT cleanse;
  a user binding shadowing a sanitizer name disables
  it. An unknown `validate()` is still not modeled,
  so code that validates before querying can still
  be flagged; the finding is confidence `potential`
  for exactly this reason — the operator triages it,
  and the validator's `false_positive` verdict exists
  for exactly that. See `docs/sanitizer-modeling-v1.md`.
- **Import resolution (round 106).** An object alias of a
  root (`const mydb = db; mydb.query(...)`) now resolves
  to `db.query`. `require('pg').query(...)` is still NOT
  a sink: `pg` is not a known module for this detector —
  its sink roots are receiver variable names, not modules.
  Destructuring of a name already in scope
  (`const { query } = db`) was already resolved. See
  `docs/import-resolution-v1.md`.
- **First argument only.** A tainted second argument
  (the parameter vector) is not judged in this round;
  only the SQL string (first argument) is. By
  convention the second argument holds bound
  parameters, not SQL text — which is exactly why
  parameterized queries are safe — but a driver call
  that builds SQL in a second argument would be
  missed; that is future work, not a silent gap.
- **Receiver allow-list, not a pattern.** Only the ten
  listed two-part calls are sinks. A driver or wrapper
  with another receiver name (`knex.raw`, `orm.query`,
  `app.db.query`) is not covered in this round; the
  list is the tested surface, and extending it is a
  one-line sink-table change plus tests — not an
  engine change.
- **Subset grammar.** Class fields, decorators, and other
  constructs outside the subset (see
  `docs/parser-taint-scope-v1.md` §2.2) fail the parse and
  skip the record rather than being scanned
  approximately. Block scoping is not modeled: bindings
  are function-scoped.
- **No reachability proof.** A sink inside dead code is
  still flagged — the detector parses structure, not
  reachability. Every finding is confidence `potential`
  because the detector cannot prove the call is reachable
  or attacker-controlled; exploitability must be verified
  out of band before reporting.

## Future work (not this round)

- Judging the argument vector (second-argument taint)
  as a tainted-arg variant.
- `prepare` as a sink class (prepared-statement creation
  with a tainted SQL string).
- Extending the receiver allow-list (other drivers /
  wrappers) with tests per receiver.
- A fourth AST class on the same engine (tainted XSS is
  the next named candidate in
  `docs/parser-taint-scope-v1.md`).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-sql-` + the first 16 hex chars of SHA-256
  (`tainted-sql:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink call site per record; at
  most 100 findings per record (further matches are
  dropped and the drop is recorded in `errors`, so a
  truncated scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
