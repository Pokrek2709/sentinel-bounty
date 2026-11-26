# Report anonymize for sharing (round 69, Phase 7)

`sentinel report anonymize <report.json> [--out <anon.json>]
[--salt <hex>]` strips internal identifiers from a JSON
report so it can be shared with a program, a colleague, or a
public write-up without leaking the internal environment. An
operator who wants to share a report previously had no way to
remove the identifiers in it — `target_id`, `session_id`,
`asset_id`, and any internal hostnames in the evidence text
all name the internal environment.

The implementation lives in `src/report/anonymize.js`
(`anonymizeReport`, `anonymizeFinding`, `anonymizeValue`,
`scrubText`, `validateSalt`); the CLI handler is
`runReportAnonymize` in `bin/sentinel.js`, reached as a
subcommand of `report` (the round-67 intercept pattern:
`report anonymize` is intercepted in `runReport` before
`parseOptions`, which would otherwise reject `anonymize` as
an unknown option).

## Inputs

One JSON report file in the round-31 JSON report format (an
object with `report_id` and a `findings` array). It is read
with `readReportFile` from `report-diff.js` (round 64):
bounded (10 MiB, depth 100), a symlinked input is refused.
Shape failures therefore carry `REPORT_DIFF_*` codes — the
reader is shared, not re-implemented — and fail before any
output is produced, so a bad input can never leave a
half-written file behind. A duplicate `finding_id` inside
the input is refused by the same reader
(`REPORT_DIFF_DUPLICATE_FINDING_ID`). Each finding is
checked with `validateOneFinding` (round 67's path: the
strict generator check first, then the rule verdict); a
finding that fails the strict check is a
`REPORT_ANONYMIZE_INVALID_FINDING`. An empty finding set
fails with `REPORT_ANONYMIZE_EMPTY` (a report with no
findings has nothing to share), and a report with no usable
`generated_at` fails with
`REPORT_ANONYMIZE_NO_GENERATED_AT` (the input's own
`generated_at`, else the newest finding `created_at` — the
module never invents a timestamp from the wall clock, the
same rule as round 68).

The input file is never modified (read-only proof: bytes
and mtime unchanged).

## Identifier mapping

`target_id`, `session_id`, and every finding's `asset_id`
are replaced with:

```text
anon-<sha256(salt + ':' + original).slice(0, 12)>
```

The mapping is deterministic: the same original always
maps to the same replacement within a run (and across runs
with the same salt), so diffs and merges of anonymized
reports still work, and re-running the command with the
same salt reproduces the same output byte-for-byte. The
`anon-` prefix keeps anonymized values visibly distinct
from real ids in every consumer (diff, merge, validate,
CSV).

The salt defaults to the FIXED documented constant
`sentinel-report-anonymize-v1`, so two runs with no `--salt`
give byte-identical output; determinism matters more than
secrecy here. `--salt <hex>` lets the operator supply their
own salt: hex, 8–64 characters, else
`REPORT_ANONYMIZE_INVALID_SALT`. The salt is NEVER printed
— not in the output, not in the summary line, not in an
error message (the invalid-salt error does not echo the
supplied value) — and is NOT recorded in the output's
metadata block (only `salt_source: "default" | "provided"`).

## Reversibility warning

This is de-identification for sharing, NOT cryptographic
redaction. Anyone holding the original report and the salt
can recompute the mapping and reverse it. The default salt
is public (it is in `src/report/anonymize.js` and in this
doc), so the default mapping is reversible by anyone who
has the original report. A provided salt only helps if it
is kept private. Do not present the output as irreversibly
anonymized.

## Text scrubbing

The scrub applies to `description` and to the `notes`
field of each `evidence` entry (the evidence checklist
item `evidence_notes` maps to `finding.evidence[].notes` —
see `src/analysis/validator.js hasEvidenceSubfield`). Two
conservative patterns, nothing else:

- **IPv4 dotted quad** (`ipv4-dotted-quad`): four groups of
  1–3 digits (e.g. `10.0.4.17`) -> `anon-ip`. Octets are
  deliberately NOT range-validated (0–255): a
  version-looking string like `1.2.3.4` in evidence text is
  scrubbed the same way.
- **Hostname ending `.local` or `.internal**
  (`hostname-.local/.internal`): one or more labels of
  letters, digits, and hyphens, then the suffix (e.g.
  `db01.corp.internal`) -> `anon-host`.

Arbitrary URLs, emails, and other hostnames are NOT
scrubbed. The `request` / `response` evidence entries are
NOT scrubbed either: they are logs, and scrubbing them
would destroy the evidence a program needs to reproduce
the finding. `title`, `impact`, `remediation`,
`steps_to_reproduce`, `proof_of_concept`, and `references`
are likewise untouched.

`asset_url` is NOT scrubbed. Its host names the same asset
`asset_id` names, so an `asset_url` like
`https://lab.example.internal/login` still leaks the
internal hostname even after `asset_id` is replaced. That
is a known limitation of this round, pinned by a test so a
future change is deliberate, not accidental; a future
round may extend the scrub to it. Operators sharing a
report with a sensitive `asset_url` should check it by
hand.

## Output

The output is re-rendered by `generateReport` itself
(format `'json'`, `allowMixedTargets: true`), so its
`report_id`, groups, counts, and mixed-target fields are
the generator's own, and the output is a valid round-31
JSON report by construction — a multi-target input
anonymizes as `target_ids` + `mixed_targets: true`, exactly
the round-49 convention. A platform-template report (one
finding, `template` set to a non-generic name) keeps its
template marker; anything else renders generic.

Because the report-id derivation inputs (`program_name`
and the sorted finding ids) are exactly what anonymization
preserves, the recomputed `report_id` is the SAME as the
input's. That is deliberate, not a bug: it lets the
operator correlate the anonymized report with the
original, and it means `report validate` (round 67) passes
the anonymized report with `report_id_matches: true`.

The output carries `anonymized: true` plus an
`anonymization` metadata block:

```json
"anonymization": {
  "salt_source": "default",
  "patterns": ["ipv4-dotted-quad", "hostname-.local/.internal"]
}
```

so no consumer can mistake it for the original. The salt
itself is never recorded.

Everything else is preserved in substance: severity, CVSS
scores and vectors, verdict (`validation_status`),
confidence, the evidence checklist, `ai_verdict` when
present, `finding_id`s, `merged_from`, and the finding
order (grouped order, as in the input).

The anonymized JSON goes to stdout (pipeable) or `--out`
via safe-write mode 0600 (parent directories created;
with `--out` stdout carries only `Anonymized report
written to <path>`). The one-line summary always goes to
stderr, so stdout stays a clean report:

```text
anonymized N findings (I identifiers replaced, S text substitutions)
```

Exit 0 on success; exit 1 on any named error (message on
stderr, no output file written).

## What it deliberately does not do

- No re-scoring, no semantic dedup, no AI verdict, no
  audit-chain verification (that is `audit verify`'s job).
- No redaction of finding text beyond the two documented
  scrub patterns, and no scrubbing of `asset_url`,
  `request` / `response` logs, `title`, `impact`,
  `remediation`, `steps_to_reproduce`, `proof_of_concept`,
  or `references` (see above).
- No crypto-grade anonymization: the mapping is a salted
  hash, reversible by anyone holding the original report
  and the salt (see the reversibility warning). The mapping
  is not stored anywhere; re-running with the same salt
  reproduces it.
