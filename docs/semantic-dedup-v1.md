# Conservative Semantic Dedup v1 (round 48)

`semanticDedupeFindings` in `src/analysis/validator.js` is a SECOND
dedup pass, run AFTER the exact-key dedup (`dedupeFindings`, round
32), over that pass's representatives (first finding of each exact
group). It merges findings that describe the same underlying issue
with different wording or different reproduction steps — but only
under a deliberately narrow rule, because aggressive merging risks
hiding distinct findings. The looser-matching question stays open
for the user (see "Open policy question" below).

## The rule

Two findings merge ONLY when ALL four hold:

- (a) **Same normalized `vulnerability_type`** — trim +
  lowercase, the same normalization `rootCauseKey` uses.
- (b) **Same `asset_id`** — exact, case-sensitive (assets are
  identifiers).
- (c) **Same CVSS base vector AND same severity** — the eight base
  metrics (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`), parsed
  with `parseCvssVector`; temporal and environmental metrics are
  ignored for the comparison. OR, when NEITHER finding carries a
  vector, the same severity band (severity is itself the band name).
- (d) **At least one shared evidence entry** — same entry value
  (canonicalized: `{request, response, notes}` with missing fields
  as `null`, fixed key order). An entry counts only when at least
  one of its three subfields is a non-empty string; an empty `{}`
  entry can never be the shared item.

The same-severity requirement in the vector branch is a deliberate
tightening beyond the brief's minimum: identical base vectors imply
identical computed scores, so two valid findings with the same
vector always share a severity — a pair that differs there is
mislabelled input, and merging it would silently drop one label.

Pairs that do NOT merge (all tested in
`tests/semantic-dedup.test.js`):

- different base vector (even in the same severity band);
- different asset;
- same type + asset + vector but no shared evidence entry;
- different vulnerability type;
- different severity;
- one finding with a vector, one without;
- one vector malformed (a malformed vector never merges: it cannot
  prove "same base vector", and it is not vector-less either, so
  neither branch of (c) can hold);
- only an empty `{}` evidence entry in common.

## Grouping algorithm

Greedy in input order: each finding is compared against the
representative (first finding) of each existing group, and joins
the first group it matches. Deterministic for a given input order,
and deliberately NOT transitive-closure: A~B and B~C with A!~C
leaves C in its own group rather than pulling it into A's group on
B's say-so (tested).

Returns `{ groups: [{ key, findings, merged }], duplicates }`,
where `duplicates` is the count of findings beyond the first per
group. A singleton group's `merged` is the finding itself, so no
report gains a spurious `merged_from`. A non-array input returns
`{ groups: [], duplicates: 0 }`, mirroring `dedupeFindings`.

## The merged finding

For a group of two or more members, `merged` is a copy of the
representative (first member in input order) with:

- **Evidence union** — all members' evidence entries, first-seen
  order, deduped by canonical entry value.
- **Steps union** — all members' `steps_to_reproduce`, first-seen
  order, exact-string dedup.
- **References union** — same treatment, when any member carries
  references.
- **`merged_from`** — every member id, including the
  representative's, so the list is the complete member set. Also
  declared in `schemas/finding.schema.json` as an optional
  property, so JSON reports stay schema-conformant.
- **Highest effective base score** — with a shared vector, the
  merged `cvss_score` is the score the VECTOR computes (all
  members share the base metrics, so the computed score is the
  same for every member) — never the max of declared scores,
  because a declared score that disagrees with the vector would
  make the merged finding fail the generator's strict vector rule.
  Without a vector, it is the max of the declared scores present.
- **Vector and temporal/environmental scores** — with a shared
  vector, the representative's full vector string and its declared
  temporal/environmental scores are kept (the merged finding's
  temporal score is the representative's, not a mix). Without a
  vector, temporal/environmental scores are the max of the
  declared values present.

Title, description, impact, remediation, proof of concept,
confidence, and validation status stay the representative's.
Because the members share a severity (rule (c) enforces it), carry
a score that agrees with the kept vector, and union evidence that
each member evidenced, the merged finding still validates — the
tests assert `validateFinding(merged).verdict === 'valid'` for
both the vector and the no-vector merge cases.

## Report rendering

The generator renders a merged finding's `merged_from` in all
three formats: Markdown adds a `- **Merged from:** <ids>` line
right after the finding id; HTML adds a `Merged from` definition
row; JSON carries it through the spread, on the finding in both
the flat `findings` array and the grouped `groups`. A finding
without `merged_from` renders exactly as before — no line is
added for singletons, so an unmerged report is byte-identical to
the pre-round-48 output. That is not just a claim: the golden
hashes in `tests/report-html.test.js` ("Markdown and JSON output
are unchanged by the HTML addition") still pass unchanged after
this round.

## Pipeline placement

```text
runStubDetector(fixture, defaults)   # src/detection/stub-detector.js
  -> validateFinding(finding)         # src/analysis/validator.js
  -> dedupeFindings(findings)         # exact-key dedup (round 32)
  -> semanticDedupeFindings(reps)     # semantic pass (round 48)
  -> generateReport(merged, opts)     # src/report/generator.js
```

The semantic pass takes the exact pass's representatives
(`groups.map(g => g.findings[0])`) and the report is built over
`groups.map(g => g.merged)`. `tests/pipeline-integration.test.js`
commits this chain: the exact dedup keeps the pair (different
first steps), the semantic pass merges it, and the report shows
`Merged from: F-PIPE-SEM-A, F-PIPE-SEM-B`.

## Deliberate limitations

- **No fuzzy matching.** Similarity of titles, descriptions, or
  steps is never computed; two findings with the same root cause
  in different words and no shared evidence entry do not merge.
- **Representative wins.** The merged finding's prose fields come
  from the first member in input order; a later member's better
  wording is not picked. (Input order in the pipeline is the
  exact-dedup group order, which is first-seen order — stable for
  a given detector output.)
- **No cross-asset merging.** Same flaw on two assets stays two
  findings; the asset is part of the identity.
- **No verdict change.** The pass merges findings; it never
  re-validates or re-labels them. A `false_positive` member keeps
  its verdict in the merged finding only if it is the
  representative — merging a false positive with a valid finding
  is possible when the four conditions hold, and the merged
  finding then carries the representative's confidence. Callers
  that exclude false positives from reports should do so BEFORE
  this pass (that exclusion is itself an open policy decision).

## Open policy question

Whether looser matching should ever be enabled, and under what
rule — e.g. same type + asset + vector without shared evidence,
or a text-similarity threshold on titles/steps. This round
implements the conservative version only; any loosening needs the
user's decision, because it trades recall (fewer duplicate
reports) against the risk of hiding a genuinely distinct finding.

## Enforcement at report generation (round 96)

The pass itself is unchanged, but round 96 found two gaps in
how it was (not) applied, and fixed both without changing the
four conditions:

- **No operator path ran the pass.** `semanticDedupeFindings`
  had no production caller: `sentinel report` rendered
  duplicate findings, and a report with two identical findings
  failed its own `report validate` with
  `REPORT_VALIDATE_DUPLICATE_FINDING_ID`. Round 96 wires the
  pass into `sentinel report` generation from raw findings
  via `enforceReportPolicies` (`src/analysis/policies.js`):
  false-positive exclusion first, then this pass. The pass
  runs directly, NOT after the exact-key dedup — exact-key
  grouping would fold findings that share a first
  reproduction step but differ in vector or severity, and
  taking only the representative would silently drop a finding
  this rule refuses to merge.
- **Dedup never merges across rule verdicts at report
  generation.** The pass itself still merges a valid finding
  with a false_positive one when the four conditions hold
  (the representative's confidence wins — see "No verdict
  change" above), but the report path partitions by rule
  verdict first, so that order-dependence cannot hide a
  triage in a generated report. The partition lives in
  `enforceReportPolicies`, not in the pass.
- **Structured evidence can now satisfy rule (d).** The
  canonical evidence entry only recognized the classic
  `{request, response, notes}` shape, so findings whose
  evidence carries other fields — the round-95 AST
  detector's `{type, sink, kind, line, column, call, taint}`
  entries — could never share an entry, and the policy
  silently did not apply to a whole detector class. The
  canonicalization now falls back to the full entry (sorted
  keys, `full:` prefix) when none of the three classic
  subfields is present, and it counts only when the entry
  carries at least one non-empty string leaf, so an empty or
  all-blank entry still can never be the shared item. The
  classic canonicalization is unchanged: entries with a
  classic subfield keep the exact `{request, response,
  notes}` key, extra fields ignored as before. The fallback
  also fixes the evidence union in `mergeFindingGroup`,
  which previously collapsed distinct AST entries onto one
  key.
- **`merged_from` is an id set.** Two members can share one
  finding_id (deterministic detector ids — two identical
  records), and the merged finding lists it once, matching
  how report-diff treats `merged_from` as an id set.
