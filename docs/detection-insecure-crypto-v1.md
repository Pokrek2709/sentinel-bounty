# insecure-crypto detector v1 — third real detector (round 88)

`sentinel detect --detector insecure-crypto` scans the `content`
string of an operator-supplied local input record for
weak-cryptography call sites and reports one finding per distinct
call site. It is the third real detector (after `secret-scan`,
round 86, and `dangerous-call`, round 87) and the first detector
that covers a cryptographic class: cryptographic failure
(CWE-327/CWE-338).

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
  `discovery_tool: 'insecure-crypto'`.

## Pattern table

All patterns are call-site or cipher-selection syntax,
word-boundary anchored, and matched per line with a global
regex. Severity is per pattern: DES/RC4 are high (the
primitives themselves are practically broken); the weak
hashes, ECB mode, the deprecated cipher API, and the weak
PRNG are medium (each is only exploitable in a sensitive
context the detector cannot prove).

| pattern id | matches | class | severity | CWE |
|---|---|---|---|---|
| `weak-hash-md5` | `hashlib.md5(`, `hashlib.new('md5', ...)`, `createHash('md5')`, `MessageDigest.getInstance("MD5")`, bare `md5(` | cryptographic failure | medium | CWE-327 |
| `weak-hash-sha1` | `hashlib.sha1(`, `hashlib.new('sha1', ...)`, `createHash('sha1')`, `MessageDigest.getInstance("SHA-1")`, bare `sha1(` | cryptographic failure | medium | CWE-327 |
| `ecb-mode` | `AES/ECB/...`, `DES/ECB/...`, `DESede/ECB/...`, `createCipheriv('...ecb...')` | cryptographic failure | medium | CWE-327 |
| `weak-cipher-des-rc4` | `Cipher.getInstance("DES...")`, `getInstance("DESede...")`, `getInstance("3DES...")`, `getInstance("RC4...")`, `getInstance("ARC4...")`, `createCipheriv('des...')`, `createCipheriv('des-ede...')`, `createCipheriv('des3...')`, `createCipheriv('rc4...')`, `createCipheriv('arc4...')`, `ARC4.new(` | cryptographic failure | high | CWE-327 |
| `deprecated-cipher` | `crypto.createCipher(`, `crypto.createDecipher(` | cryptographic failure | medium | CWE-327 |
| `insecure-random` | `Math.random(`, `random.random(` | cryptographic failure | medium | CWE-338 |

The regexes are case-sensitive by design for the hash names
(`MD5(` and `SHA1(` do not match — the bare call is the
lowercase library spelling; the uppercase forms appear only
inside the quoted `getInstance`/`createHash` strings, which
are matched as full call shapes), and the ECB/DES/RC4
patterns are case-insensitive because cipher names appear in
both cases across Java and Node spellings. The word boundary
keeps lookalikes out: `md5sum(`, `md5Hex(`, `getMd5(`,
`sha1sum(`, `sha256(`, `createHash('sha256')`, `Math.randomInt(`,
`random.randint(`, `random.choice(`, `secrets.token_hex(`,
`crypto.randomBytes(`, and a bare `random(` do not match — the
last three are the safe generators, and their non-matching is
itself tested. A match in a comment or a string literal still
matches — the detector has no parser and cannot tell code
from prose, so a match is a lead, never a verdict.

One deliberate overlap: a DES cipher selected in ECB mode
(`Cipher.getInstance("DES/ECB/...")`) is two distinct
weaknesses and yields two findings, one per pattern — the
same rule round 87 set (different patterns on one line are
distinct findings). It is tested explicitly so the behavior
is a decision, not an accident.

## Finding shape

- One finding per distinct (pattern, line, column, match):
  the same call text on the same line at a different column is
  a different finding (a different call site); the same call
  on a different line is a different finding. Identity is per
  call site, not per call text — unlike `secret-scan`, where
  the secret value IS the identity.
- `finding_id` is deterministic: `insecure-crypto-` + the
  first 16 hex chars of SHA-256
  (`insecure-crypto:<pattern>:<line>:<column>:<match>`).
- `title`: `Weak <label> in supplied text`.
- `vulnerability_type` / `severity` / `cwe_id`: per the
  pattern table. `confidence` is always `potential`.
- `proof_of_concept`: `Matched <pattern> at line <n>,
  column <c>: <match>` — the matched call text only, never
  the whole source line (the line could hold adjacent
  sensitive data; the call itself is the evidence).
- `evidence`: one item, `{ type: 'pattern-match', pattern,
  line, column, match, source? }`.
- `steps_to_reproduce`: run the detect command, observe the
  finding, verify out of band whether the call guards
  something sensitive. The `insecure-random` finding adds
  the note that the call is only a weakness when its output
  feeds a secret, a token, or a session id.
- At most 100 findings per record (`MAX_FINDINGS_PER_RECORD`);
  further matches are dropped and the drop is recorded in
  `errors`, never silent. Content over 1,000,000 characters
  (`MAX_CONTENT_CHARS`) is skipped, not scanned.

## What it does not prove

- **Sensitivity and context.** A match proves the weak-crypto
  call text is present in the supplied text; it does not prove
  the call guards anything sensitive — MD5/SHA-1 are fine for
  non-security checksums, `Math.random()` is fine for a UI
  shuffle, and ECB/DES/RC4 are only weaknesses where the data
  matters. Every finding is `potential` until the operator
  verifies out of band. Findings validate as `valid` under
  the generic checklist (its required items — proof of
  concept, evidence, steps to reproduce — are all carried),
  which is a statement about the finding's completeness, not
  about exploitability.
- **No parser.** Comments, string literals, and documentation
  examples match exactly like real code. Triage stays the
  operator's job, and the validator's `false_positive`
  verdict is the mechanism.
- **No data flow.** `Math.random()` feeding a session token
  and `Math.random()` shuffling a playlist look identical to
  this detector. The distinction is the operator's
  verification step, not the detector's.

## Pipeline

`detect --detector insecure-crypto` → `validateFinding` →
`dedupeFindings` → `generateReport`, the same pipeline
`secret-scan` proved in round 86. The JSON report carries the
per-finding evidence checklist: `cryptographic failure` has
no dedicated checklist class and resolves to the generic
checklist (the validator's fallback, not this module's
choice) — the same situation as round 87's code-injection
classes.

## Limits

- Six patterns, one new evidence class beyond the five the
  first two detectors cover. What is NOT covered: key
  management (hardcoded keys, key length, key reuse — the
  call site does not carry the key), certificate validation,
  password-storage policy (the detector sees the hash call,
  not the iteration count or salt), and any crypto whose
  weakness needs a parser or data flow (for example a custom
  cipher, or a hash used only in a non-security path — the
  detector cannot tell the two apart).
- No auto-run, no async: the detector is synchronous and
  runs only when the operator invokes `sentinel detect`.
  Whether detection should ever run automatically, and
  whether detectors may be asynchronous, remain open user
  decisions.
