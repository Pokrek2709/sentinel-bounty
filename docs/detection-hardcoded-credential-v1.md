# hardcoded-credential detector v1 — fourth real detector (round 89)

`sentinel detect --detector hardcoded-credential` scans the
`content` string of an operator-supplied local input record for
credential-named variables assigned a quoted string literal and
reports one finding per distinct assignment site. It is the
fourth real detector (after `secret-scan`, round 86,
`dangerous-call`, round 87, and `insecure-crypto`, round 88)
and the first detector that works on the assignment context
rather than a value format or a call site: a variable called
`password` assigned `"hunter2"` is a hard-coded credential
(CWE-798) even though the literal itself matches no known
token format.

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
  `discovery_tool: 'hardcoded-credential'`.

## Pattern table

All patterns are assignment syntax, matched per line with a
global case-insensitive regex: a credential name, an operator
(`=`, `:=`, or `:`), and a non-empty quoted literal
(single or double quotes, at most 200 characters). Severity
is uniform high: every pattern names a directly usable
credential.

| pattern id | matches | class | severity | CWE |
|---|---|---|---|---|
| `hardcoded-password` | `password` / `passwd` / `pwd` assigned a quoted literal (`password = "..."`, `const password = '...'`, `user_password = "..."`, `userPassword = "..."`, `{"password": "..."}`, `password := "..."`) | use of hard-coded credentials | high | CWE-798 |
| `hardcoded-api-key` | `api_key` / `apikey` / `api-key` / `access_key` / `accesskey` / `secret_key` / `secretKey` assigned a quoted literal | use of hard-coded credentials | high | CWE-798 |
| `hardcoded-secret` | `client_secret` / `clientSecret` / `secret` / `access_token` / `accessToken` / `auth_token` / `authToken` / `token` assigned a quoted literal | use of hard-coded credentials | high | CWE-798 |

The name must begin a fresh identifier segment — at the
start of a word, after a `_`/`-` separator, or at a
camelCase hump — and must not continue into a longer
identifier. That keeps lookalikes out: `password == "..."`
and `password === "..."` (comparisons, not assignments),
`password != "..."`, `password = ""` (empty literal),
`password = process.env.PASSWORD` (an env read, not a
literal), `password = getPassword()` (a function call),
`password = 123` / `null` (not a string literal),
`passwordHash` / `password_hash` (a hash, not the password),
`password2` / `password_confirmation` (suffixed variants —
out of scope by design), `secretKey` as a bare identifier
(it IS matched, as `hardcoded-api-key` — a key name, not
the secret itself), `secretary`, `tokenize(`, `api_keys`,
bare `pass` (excluded — it collides with `bypass`), and
`myToken = getToken()` (no literal) do not match.

Out of scope by design, all documented as limits, not
oversights: unquoted values (`password=abc123`, `.env`
style — the bare-value surface overlaps with config
placeholders and with `secret-scan`'s format matching);
backtick template literals (interpolation makes the literal
only part of the value); suffixed name variants
(`password2`, `password_confirmation`); bare `pass` (see
above). A match in a comment or a string literal still
matches — the detector has no parser and cannot tell code
from prose, so a match is a lead, never a verdict.

## Finding shape

- One finding per distinct (pattern, line, column, masked
  match): the same assignment on the same line at a
  different column is a different finding (a different
  assignment site); the same assignment on a different line
  is a different finding. Identity is per assignment site,
  not per literal value — unlike `secret-scan`, where the
  secret value IS the identity, and unlike
  `dangerous-call` / `insecure-crypto`, where the matched
  call text is the identity: here the matched literal is a
  secret, so it cannot be part of the identity. Two
  different literals at the same site are the same finding
  (they cannot occur twice in one scan).
- `finding_id` is deterministic: `hardcoded-credential-` +
  the first 16 hex chars of SHA-256
  (`hardcoded-credential:<pattern>:<line>:<column>:<masked
  match>`).
- `title`: `Hard-coded <label> in supplied text`.
- `vulnerability_type` / `severity` / `cwe_id`: per the
  pattern table. `confidence` is always `potential`.
- `proof_of_concept`: `Matched <pattern> at line <n>,
  column <c>: <name><operator> "****"` — the masked
  assignment only, never the literal value, never the whole
  source line (the line could hold adjacent sensitive data;
  the assignment is the evidence).
- `evidence`: one item, `{ type: 'pattern-match', pattern,
  line, column, match, source? }`, where `match` is the
  masked assignment (`password = "****"`).
- `steps_to_reproduce`: run the detect command, observe the
  finding, verify out of band whether the credential is
  live, used anywhere, or a placeholder. The description
  states the masking explicitly, so an operator reading the
  finding knows the value was withheld by design, not lost.
- At most 100 findings per record (`MAX_FINDINGS_PER_RECORD`);
  further matches are dropped and the drop is recorded in
  `errors`, never silent. Content over 1,000,000 characters
  (`MAX_CONTENT_CHARS`) is skipped, not scanned.

## What it does not prove

- **Liveness and use.** A match proves the assignment text
  is present in the supplied text; it does not prove the
  credential is live, used anywhere, or not a placeholder
  or test value. Every finding is `potential` until the
  operator verifies out of band. Findings validate as
  `valid` under the generic checklist (its required items —
  proof of concept, evidence, steps to reproduce — are all
  carried), which is a statement about the finding's
  completeness, not about exploitability.
- **No parser.** Comments, string literals, and
  documentation examples match exactly like real code.
  Triage stays the operator's job, and the validator's
  `false_positive` verdict is the mechanism.
- **No data flow.** A hardcoded password that is never
  read and one that gates production access look identical
  to this detector. The distinction is the operator's
  verification step, not the detector's.

## Pipeline

`detect --detector hardcoded-credential` → `validateFinding`
→ `dedupeFindings` → `generateReport`, the same pipeline
`secret-scan` proved in round 86. The JSON report carries
the per-finding evidence checklist: `use of hard-coded
credentials` has no dedicated checklist class and resolves
to the generic checklist (the validator's fallback, not
this module's choice) — the same situation as round 87's
code-injection classes and round 88's cryptographic
failure. No literal value survives into any rendered
format: the JSON and Markdown reports were both tested to
contain no assigned literal.

## Limits

- Three patterns, one new evidence class beyond the six
  the first three detectors cover. What is NOT covered:
  unquoted values, backtick literals, suffixed name
  variants, and bare `pass` (see the pattern table); key
  management beyond the assignment itself (key length, key
  reuse, rotation state — the assignment does not carry
  them); and any credential whose weakness needs a parser
  or data flow (for example a credential assembled from
  parts, or one read from a vault at runtime — the
  detector cannot tell a live credential from a placeholder).
- No auto-run, no async: the detector is synchronous and
  runs only when the operator invokes `sentinel detect`.
  Whether detection should ever run automatically, and
  whether detectors may be asynchronous, remain open user
  decisions.
