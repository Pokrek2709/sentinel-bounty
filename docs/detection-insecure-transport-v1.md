# Detection: insecure-transport (round 90, Phase 5)

`insecure-transport` (`src/detection/insecure-transport.js`)
is the fifth real detector. It scans the `content` string
of an operator-supplied local input record for
insecure-transport call sites — cleartext HTTP URLs and
disabled TLS verification — and reports one finding per
distinct call site, never executing the code it scans.

## Input contract

Same as the other detectors: a raw detector-input record
with a non-empty string `content` (or a batch
`{ tool, results: [...] }`), `session_id` / `target_id` /
`asset_id` from the record else from `defaults`, never
invented. Content over 1,000,000 characters is skipped;
at most 100 findings per record (further matches dropped
and the drop recorded in `errors`).

## Pattern table

| Pattern | Matches | Class / severity / CWE |
| --- | --- | --- |
| `cleartext-http` | `http://` + non-loopback host | cleartext transmission / medium / CWE-319 |
| `tls-verify-disabled` | `rejectUnauthorized: false` / `= false`; `verify = False` / `: False`; `check_hostname = False` / `: False`; `ssl._create_unverified_context(`; `verify_mode = CERT_NONE` | improper certificate validation / high / CWE-295 |

Severity is per pattern, not uniform: disabling TLS
verification is high (the control itself is switched off
— any data on the connection is exposed to a
machine-in-the-middle); cleartext HTTP is medium (only
exploitable when sensitive data traverses the connection,
which this detector cannot prove).

## The match that reaches the finding

For a cleartext URL the finding carries ONLY
`http://<host>` — never the path, the query, or the
userinfo. A URL can hide credentials
(`http://user:pass@host/`) and tokens in its query, so
the match is rebuilt as scheme + host before any finding
is built (the regex captures the host after an optional
userinfo segment, which is discarded). A loopback host
(`localhost`, `127.0.0.0/8`, `::1`) never matches at all:
loopback traffic does not traverse a network. A trailing
dot on the host is trimmed (`example.com.` → `example.com`).

For TLS verification the finding carries the matched
configuration text itself (for example
`rejectUnauthorized: false`); it names no secret.

## What it does not prove

- Sensitivity and context: a match proves the
  insecure-transport text is present, not that sensitive
  data traverses the connection. `http://` is fine for
  public documentation links; `verify=False` is fine for
  a local mock. Every finding is `potential` until the
  operator verifies out of band.
- No parser: comments, strings, and documentation
  examples match like real code.
- No data flow: `verify=False` on a test mock and
  `verify=False` on a production payment client look
  identical to this detector.
- No reachability: the URL may point nowhere; the
  detector never fetches it.

Lookalikes that must NOT match (all tested in
`tests/insecure-transport.test.js`): `https://` URLs,
`http://localhost`, `http://127.0.0.1`, `http://[::1]/`,
a bare `http://` with no host, `verify=True`,
`rejectUnauthorized: true`, `CERT_REQUIRED`,
`check_hostname = True`, `verify_mode = CERT_REQUIRED`,
a `CERT_NONE` comparison (`mode == CERT_NONE` — a
comparison is not a setting), and a bare `verify`
variable with no `False` assignment.

## Pipeline

`getDetector('insecure-transport')` returns the detector
with source `'insecure-transport'`; the CLI help line
reads `[--detector stub|secret-scan|dangerous-call|
insecure-crypto|hardcoded-credential|insecure-transport|
<path>]`. The module is also loadable by path under the
existing loader safety rules. Findings validate as
`valid` under the generic checklist (neither class has a
dedicated evidence-checklist class — that mapping is the
validator's fallback, not this module's choice).

## Judgment calls (round 90)

- Per-pattern severity (high for the verification
  switch, medium for cleartext) instead of a uniform
  level — the same split the round-87/88 detectors use.
- Identity per call site (pattern, line, column, match),
  the same rule as rounds 87–89.
- The host-only match for URLs (never path/query/
  userinfo) — forced by the fact that a URL can carry
  credentials; the same discipline as
  hardcoded-credential's masking, applied to a different
  secret carrier.
- The loopback exclusion (`localhost`, `127/8`, `::1`)
  — loopback traffic is not exposure, and matching it
  would drown the operator in local-dev noise.
- The 100-findings-per-record cap and the 1,000,000
  character content bound are the same engineering bounds
  as rounds 86–89 (named constants
  `MAX_FINDINGS_PER_RECORD`, `MAX_CONTENT_CHARS`), not
  user decisions.
- The detector set is complete for the synchronous
  regex approach (see `docs/detection-policy-v1.md`):
  the remaining vulnerability classes need a parser or
  taint analysis, not another regex.
