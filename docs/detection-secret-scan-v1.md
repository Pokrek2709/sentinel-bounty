# First real detector: secret-scan (round 86, Phase 5)

> **The first detector that performs detection.** Everything
> before round 86 was interface and stub: the round-31 stub
> normalizes input and nothing else, and the round-51 interface
> defines the contract a real detector must satisfy.
> `secret-scan` is the first module that satisfies it with real
> detection — over operator-supplied local text only. It makes
> no network request, invokes no scanner, touches no target,
> and never checks whether a matched credential is live.

## What it detects

Well-known credential formats in the `content` string of a
local input record — text the operator already holds (for
example file contents or a response body captured in the lab)
and hands to the CLI:

```text
sentinel detect --detector secret-scan --input <record.json>
  [--session-id <id>] [--target-id <id>] [--asset-id <id>]
  [--out <findings.json>]
```

| Pattern id | Format | Evidence class |
| --- | --- | --- |
| `aws-access-key-id` | `AKIA` + 16 uppercase/digits | information disclosure |
| `github-classic-token` | `ghp\|gho\|ghu\|ghs\|ghr` + `_` + 36 alphanumerics | information disclosure |
| `github-fine-grained-token` | `github_pat_` + 82 alphanumerics/underscores | information disclosure |
| `slack-token` | `xox[baprs]-` + 10 or more alphanumerics/dashes | information disclosure |
| `private-key-pem` | `-----BEGIN [RSA \|EC \|OPENSSH \|DSA \|PGP ]PRIVATE KEY-----` | information disclosure |

The patterns are fixed-format only, chosen for a low
false-positive rate. There are deliberately NO generic
entropy or `key=value` heuristics — those are false-positive
prone and belong to a different detector with its own
precision budget. A documentation example (an AKIA key
printed in a how-to) WILL match: the detector reports what
it sees in the text; the operator triages it, and the
validator's `false_positive` verdict exists for exactly
that.

## Input contract

A single content record:

```json
{
  "content": "…text to scan…",
  "source": "lab-notes.txt",
  "session_id": "sess-1",
  "target_id": "tgt-1",
  "asset_id": "ast-1"
}
```

- `content` (required, non-empty string) is the text to scan.
  A record without it is counted in `skipped` with its error
  recorded, never thrown; a bad record never aborts a batch.
- `source` (optional, non-empty string when present) names
  where the text came from; it is carried into the finding's
  description and evidence, never invented.
- `session_id` / `target_id` / `asset_id` come from the
  record itself, else from `defaults` (the CLI
  `--session-id` / `--target-id` / `--asset-id` options); a
  record missing an id after defaults is counted in
  `skipped`, never invented — the same rule as the stub.
- A batch record `{ tool, results: [...] }` scans each result
  with the batch `tool` forced as `discovery_tool` on every
  finding (the stub convention from round 31); otherwise the
  finding carries `discovery_tool: 'secret-scan'`.
- A non-object input throws `DETECTOR_INVALID_INPUT`,
  exactly like the stub detector.
- Content over 1,000,000 characters is skipped, not scanned
  (the CLI already bounds the input file to 10 MiB; this
  bound keeps the scan itself bounded).

## Findings

One finding per distinct (pattern, matched value) per
record; the first occurrence line is reported, later
duplicates of the same value are dropped. At most 100
findings per record; further matches are dropped and the
drop is recorded in `errors` (`… additional matches
truncated in this record (first 100 reported)`), so a
truncated scan is visible, never silent.

Every finding:

- `vulnerability_type: 'information disclosure'`,
  `severity: 'high'`, `cwe_id: 'CWE-200'`,
  `confidence: 'potential'` (the default — see below).
- `finding_id` is deterministic:
  `secret-scan-` + the first 16 hex chars of
  SHA-256(`secret-scan:<pattern>:<value>`). The same secret
  in two records is the same finding (correct for dedup);
  distinct secrets are distinct findings.
- `proof_of_concept` and the evidence carry only a redacted
  form of the match: first 4 + `****` + last 4 characters.
  The PEM header is not secret material, so it is carried
  verbatim. **A finding never contains the full matched
  secret** (tested: the serialized finding, the JSON report,
  and the Markdown report are all asserted secret-free).
- `evidence` is one `{ type: 'pattern-match', pattern,
  line, match_redacted, source? }` object per finding.
- `steps_to_reproduce` names the detect command, the
  pattern and line, and the out-of-band liveness check.

## What it does NOT prove

- **Liveness.** The detector never contacts any service, so
  it cannot tell whether a matched credential is still
  valid. Every finding is `potential` until the operator
  verifies liveness out of band. A finding that validates
  as `needs_evidence` (the information-disclosure checklist
  also requires a `response_log` — the distribution
  evidence) is the pipeline working as designed, not a
  detector failure.
- **Distribution.** A match proves the secret string is
  present in the supplied text. It does not prove the text
  was ever published, shared, or reachable.
- **Anything about a target.** The detector only ever sees
  the text the operator hands it. There is no target, no
  request, and no response involved.

## Pipeline

Findings are normalized finding records, directly consumable
by the validator and the report generator:

```text
sentinel detect --detector secret-scan --input record.json
  → validateFinding → dedupeFindings → sentinel report
```

The end-to-end path is proven by test
(`tests/secret-scan.test.js`): detect → validate
(`needs_evidence` — the `response_log` is still missing)
→ dedupe (the same secret dedupes to one finding) →
report (JSON carries the `information disclosure` evidence
checklist; Markdown and JSON never carry the full secret).

## Limits of this round

- Five fixed patterns only. More patterns (other token
  formats, other secret families) are new pattern entries in
  `src/detection/secret-scan.js`, each with its own tests —
  not a redesign.
- No automatic run: detection stays a manual,
  operator-invoked step (`sentinel detect` produces
  findings; the operator feeds them to `sentinel report`
  deliberately). Whether detection should ever run
  automatically is still an open user decision.
- Synchronous only, by the round-51 contract. An async
  detector (one that calls an external tool or model) needs
  an async pipeline round, still an open user decision.
- The detector is loadable by path as well as by its
  built-in name (`--detector secret-scan`), under the same
  loader safety rules as every custom detector module.
