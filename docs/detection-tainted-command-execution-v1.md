# tainted-command-execution detector v1 — seventh real detector, second parser-based (round 100)

`sentinel detect --detector tainted-command-execution` parses the
`content` string of an operator-supplied local input record
as JavaScript and tracks taint from sources to command-execution
sinks, reporting one finding per distinct sink call site. It is
the seventh real detector (after `tainted-deserialize`, round 95)
and the second parser-based one: it reuses the taint engine
proven by `tainted-deserialize` — the same hand-written
stdlib-only subset parser (`src/detection/js-parser.js`) and
the same analyzer design, parameterized by this detector's
sink table. The engine itself was not refactored into a
shared module in this round: each detector stays a
self-contained module (the repo's established pattern), and a
shared-engine refactor is listed as future work below. See
`docs/parser-taint-scope-v1.md` §5 for the scoping (the
second AST class was named there: tainted command execution
is the natural next one — the sink list exists in
`dangerous-call`).

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
  `discovery_tool: 'tainted-command-execution'`.
- Content that does not parse under the subset grammar is
  counted in `skipped` with a parse error (reason + line +
  column). The detector NEVER falls back to scanning text
  with a regex — a partial or wrong answer presented as a
  parse is worse than no answer.

## Sinks and sources

Sinks (JavaScript, Node's `child_process` — the JS-relevant
subset of `dangerous-call`'s command-exec pattern; all
CWE-78, severity high):

| sink | notes |
|---|---|
| `child_process.exec` | runs a shell command string |
| `child_process.execSync` | synchronous `exec` |
| `child_process.spawn` | spawns a program (command = first argument) |
| `child_process.spawnSync` | synchronous `spawn` |
| `child_process.execFile` | executes a file (file = first argument) |
| `child_process.execFileSync` | synchronous `execFile` |

`child_process.fork` is NOT a sink (it spawns a Node module,
not a shell command). Python's `os.system` / `os.popen` /
`subprocess.*`, C's `system()` / `popen()`, and bare
`exec()` stay regex-covered by `dangerous-call` — this
parser is JavaScript-only.

Sources: every function parameter (untrusted input by
definition) and member access rooted at `process.argv`.

## When a sink call is reported

A sink call is reported ONLY when it carries information
the regex detector cannot:

| kind | rule | evidence |
|---|---|---|
| `tainted-arg` | direct sink call (`child_process.exec(...)`, `child_process.spawn(...)`) whose first argument is tainted | the taint chain (source + identifier-name steps) |
| `aliased-call` | sink call reached through an alias (`const e = child_process.exec`, `const { exec } = child_process`, `child_process['exec']`) with any first argument | the alias binding (`name` → `boundTo`) |

A direct sink call with a clean argument is NOT reported:
the regex detector already flags that call site, and the
AST detector adds nothing. A sink call with zero arguments
cannot execute attacker data and is not reported. Only the
FIRST argument is judged (the command): a tainted argument
vector — the second argument of `spawn` / `execFile` — is
NOT covered in this round (see limitations).

Taint propagates through: assignment and declaration,
member access on a tainted base, binary / logical /
conditional expressions, template interpolations, array /
object literals, `await`, unary `-` / `+` / `~`. `!`,
`typeof`, `void`, `delete` cleanse (they produce a boolean
or nothing, not the data). Return values of unknown calls
are clean (an under-approximation — it trades missed
findings for fewer false positives). Branch joins are OR:
tainted on any path stays tainted.

## What the parser sees that a regex cannot — and what it cannot

- A sink call in a comment or a string literal is NOT a
  call: the tokenizer strips comments and treats string
  contents as single tokens, so prose never becomes a
  finding. This is the sharpest difference from the regex
  detector, which matches call text wherever it appears.
- An aliased call IS a call: `const e = child_process.exec;
  e(x)` and `const { exec } = child_process; exec(x)`
  resolve the alias to its sink. Reassigning the alias to a
  non-sink value clears it (`let e = child_process.exec;
  e = 5; e(x)` is not a finding).
- A wrapper function IS analyzed: `function run(c) {
  return child_process.exec(c); }` flags the sink because
  `c` is a parameter (a source by rule) — the detector does
  not need to see the call site `run(userInput)` to flag
  it, and it does not claim the wrapper is reachable
  from one.

## Known limitations (documented, not hidden)

- **JavaScript only.** A second language needs a second
  parser.
- **Intra-procedural only.** Taint does not flow from a
  call site into a callee, and a sink inside a helper is
  flagged only because the helper's parameter is a source
  by rule — not because the call graph was analyzed.
- **No sanitizer modeling.** A `validate()` or allow-list
  call does not cleanse taint; code that validates before
  executing can still be flagged. The finding is
  confidence `potential` for exactly this reason — the
  operator triages it, and the validator's
  `false_positive` verdict exists for exactly that.
- **No import resolution.** A sink reached as
  `require('child_process').exec(...)` is not resolved to
  `child_process.exec`, and an object alias of the root
  (`const cp = child_process; cp.exec(...)`) is not
  resolved either. Destructuring of a name already in scope
  (`const { exec } = child_process`) IS resolved — that is
  not an import.
- **First argument only.** A tainted argument vector (the
  second argument of `spawn` / `spawnSync` / `execFile` /
  `execFileSync`) is not judged in this round; only the
  command (first argument) is. Argument injection through
  a tainted vector is future work, not a silent gap.
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

- A shared taint-engine module (`tainted-deserialize` and
  this detector currently carry per-detector copies of the
  analyzer, parameterized by their sink tables) — a
  refactor, not a capability change.
- Judging the argument vector of `spawn` / `execFile`
  (second-argument taint) as a tainted-arg variant.
- A third AST class on the same engine (tainted SQL is the
  next named candidate in `docs/parser-taint-scope-v1.md`).

## Safety properties (tested, not assumed)

- A finding carries only the sink name, position, and a
  taint chain of identifier names — never a literal value,
  never a source line, never an argument's text.
- `finding_id` is deterministic:
  `tainted-command-execution-` + the first 16 hex chars of
  SHA-256
  (`tainted-command-execution:<sink>:<line>:<column>:<kind>`).
- One finding per distinct sink call site per record; at
  most 100 findings per record (further matches are
  dropped and the drop is recorded in `errors`, so a
  truncated scan is visible, never silent).
- Content over 1,000,000 characters is skipped, not
  scanned; the CLI already bounds the input file to
  10 MiB, this bound keeps the scan itself bounded.
