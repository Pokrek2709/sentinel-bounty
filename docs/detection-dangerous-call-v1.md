# dangerous-call detector v1 — second real detector (round 87)

`sentinel detect --detector dangerous-call` scans the `content`
string of an operator-supplied local input record for risky
code-sink calls and reports one finding per distinct call site.
It is the second real detector (after `secret-scan`, round 86)
and the first detector that covers a class other than
information disclosure: code injection, OS command injection,
cross-site scripting, and insecure deserialization.

## Input contract

- The detector takes a raw detector-input record — the shape
  `normalizeRawFinding()` accepts — or a batch
  `{ tool, results: [...] }`. It scans only the record's
  `content` string: text the operator already holds (for
  example source code or a code excerpt captured in the lab)
  and hands to the CLI. It never reads a file itself, never
  makes a request, and never executes the code it scans.
- `source` (optional, non-empty string) labels where the text
  came from and is carried into the description and evidence.
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
  `discovery_tool: 'dangerous-call'`.

## Pattern table

All patterns are call-site syntax, word-boundary anchored, and
matched per line with a global regex. Severity is per pattern:
code-execution and deserialization sinks are high; the XSS
sinks are medium (an `innerHTML` assignment or
`document.write()` is only exploitable with attacker-controlled
data, which this detector cannot prove).

| pattern id | matches | class | severity | CWE |
|---|---|---|---|---|
| `eval-call` | `eval(` | code injection | high | CWE-94 |
| `function-constructor` | `new Function(` | code injection | high | CWE-94 |
| `command-exec` | `exec(`, `execSync(`, `spawn(`, `spawnSync(`, `execFile(`, `execFileSync(`, `system(`, `popen(`, `os.system(`, `os.popen(`, `os.exec*(` , `os.spawn*(` , `subprocess.call(`, `subprocess.run(`, `subprocess.Popen(`, `subprocess.check_output(`, `subprocess.check_call(` | os command injection | high | CWE-78 |
| `inner-html-assign` | `.innerHTML =`, `.innerHTML +=` | cross-site scripting | medium | CWE-79 |
| `document-write` | `document.write(`, `document.writeln(` | cross-site scripting | medium | CWE-79 |
| `unsafe-deserialize` | `pickle.load(`, `pickle.loads(`, `marshal.load(`, `marshal.loads(`, `shelve.open(`, `yaml.load(`, `unserialize(` | insecure deserialization | high | CWE-502 |

The regexes are case-sensitive by design (`EXEC(` does not
match — that is SQL, not a code sink), and the word boundary
keeps lookalikes out: `myeval(`, `evaluate(`, `execution(`,
`os.systemx(`, `pickle.loadss(`, `yaml.safe_load(`, a bare
`innerHTML` read, `document.writeText(`, and a bare
`child_process.execFileSync` reference (no call paren) do not
match. A match in a comment or a string literal still matches
— the detector has no parser and cannot tell code from prose,
so a match is a lead, never a verdict.

## Finding shape

- One finding per distinct (pattern, line, column, match):
  the same call text on the same line at a different column is
  a different finding (a different call site); the same call
  on a different line is a different finding. Identity is per
  call site, not per call text — unlike `secret-scan`, where
  the secret value IS the identity.
- `finding_id` is deterministic: `dangerous-call-` + the
  first 16 hex chars of SHA-256
  (`dangerous-call:<pattern>:<line>:<column>:<match>`).
- `title`: `Dangerous <label> in supplied text`.
- `vulnerability_type` / `severity` / `cwe_id`: per the
  pattern table. `confidence` is always `potential`.
- `proof_of_concept`: `Matched <pattern> at line <n>,
  column <c>: <match>` — the matched call text only, never
  the whole source line (the line could hold adjacent
  sensitive data; the call itself is the evidence).
- `evidence`: one item, `{ type: 'pattern-match', pattern,
  line, column, match, source? }`.
- `steps_to_reproduce`: run the detect command, observe the
  finding, verify out of band whether the call is reachable
  with attacker-controlled input.
- At most 100 findings per record (`MAX_FINDINGS_PER_RECORD`);
  further matches are dropped and the drop is recorded in
  `errors`, never silent. Content over 1,000,000 characters
  (`MAX_CONTENT_CHARS`) is skipped, not scanned.

## What it does not prove

- **Reachability and taint.** A match proves the call text is
  present in the supplied text; it does not prove the call is
  reachable, or that attacker-controlled data reaches it.
  Every finding is `potential` until the operator verifies
  out of band. Findings validate as `needs_evidence` for the
  classes whose checklists require more (XSS needs a
  `response_log`; insecure deserialization needs
  `evidence_notes`); the code-injection classes resolve to
  the generic checklist, whose required items the finding
  already carries.
- **No parser.** Comments, string literals, and documentation
  examples match exactly like real code. Triage stays the
  operator's job, and the validator's `false_positive`
  verdict is the mechanism.
- **No data flow.** `eval()` on a constant string is not
  exploitable, and this detector cannot tell it from
  `eval(userInput)`. The distinction is the operator's
  verification step, not the detector's.

## Pipeline

`detect --detector dangerous-call` → `validateFinding` →
`dedupeFindings` → `generateReport`, the same pipeline
`secret-scan` proved in round 86. The JSON report carries the
per-finding evidence checklist: `cross-site scripting` and
`insecure deserialization` resolve to their classes; `code
injection` and `os command injection` have no dedicated
checklist class and resolve to the generic checklist (the
validator's fallback, not this module's choice).

## Limits

- Six patterns, three new evidence classes beyond
  information disclosure. SQL string-concatenation
  injection, template injection, and LDAP/XPath injection
  are NOT covered — their call sites are too fuzzy for
  strict regexes and belong to a parser-based detector, not
  this one.
- No auto-run, no async: the detector is synchronous and
  runs only when the operator invokes `sentinel detect`.
  Whether detection should ever run automatically, and
  whether detectors may be asynchronous, remain open user
  decisions.
