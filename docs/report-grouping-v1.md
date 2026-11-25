# Report Grouping by Asset v1

Phase 7 of Sentinel Bounty. Findings render grouped by `asset_id`
in both output formats of `sentinel report` (generic template only).

## Rules

- **Grouping key:** the finding's `asset_id`. A missing, empty,
  whitespace-only, or non-string `asset_id` maps to the group
  `"unassigned"`. In practice the generator rejects such a finding
  first (`asset_id` is a required field of
  `schemas/finding.schema.json`), so the unassigned bucket is
  defensive for direct callers of `groupFindingsByAsset` — it is
  never reachable through `sentinel report`.
- **Group order:** `asset_id` ascending, plain string comparison
  (never `localeCompare`, which is locale-dependent).
- **Within a group:** severity first (critical, high, medium, low,
  informational — the existing `SEVERITY_ORDER`), then `finding_id`
  ascending.
- **Determinism:** the order is a pure function of the finding SET,
  never of the input order. The same findings fed in any input order
  produce byte-identical Markdown and JSON (tested).
- **Global numbering:** the Markdown finding number is global and
  sequential across groups (`## 1.`, `## 2.`, …), so a single-finding
  report keeps its existing numbering and only gains the group
  header.
- **Verdicts:** grouping never changes a verdict. Validation and
  (when the caller runs it) deduplication happen before grouping;
  grouping is a pure reorder of the validated set.

## Markdown

After the summary table, each group gets a section:

```markdown
## Asset: lab-app/login — 1 finding (critical: 1, high: 0, medium: 0, low: 0, informational: 0)
```

followed by that group's findings with their usual sections
(description, steps, PoC, evidence checklist, impact, remediation,
references). A single-finding report is unchanged in content apart
from the group header.

## JSON

Generic reports carry a `groups` array alongside the flat `findings`
array (see `schemas/report.schema.json`):

```json
{
  "asset_id": "lab-app/login",
  "findings_count": 1,
  "findings_summary": { "critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0, "total": 1 },
  "findings": [ { "...": "...", "evidence_checklist": { "...": "..." } } ]
}
```

The flat `findings` array is kept for backward compatibility and
follows the same grouped order as the Markdown rendering (it is the
flattened groups). `target_id` / `session_id` come from the first
finding in grouped order.

## Platform templates

Immunefi and Code4rena templates are OUT of scope for regrouping:
they render exactly one finding per report, so grouping adds
nothing. Their Markdown keeps the platform's fixed sections, and
their JSON keeps its previous flat shape — no `groups` key. This is
deliberate and tested, not an oversight.

## What is NOT implemented

- **Mixed-target grouping is still an open policy decision.**
  Findings from different targets in one report are REFUSED by
  default (`REPORT_MIXED_TARGETS_REFUSED`) since round 49: the
  pre-round-49 generator rendered mixed input silently and put only
  the first finding's target into JSON `target_id`. With
  `--allow-mixed-targets` the report groups by target first, then
  by asset, and states the full target list in its header — see
  [report-mixed-targets-v1](report-mixed-targets-v1.md). Grouping by
  asset within one report is not the same as grouping across
  targets; the cross-target policy (split, tag, or refuse) is
  decided as "refuse by default, tag + group with opt-in".
- No grouping by severity alone, by CWE, or by vulnerability type —
  asset is the only grouping key in v1.

## Implementation

- `src/report/generator.js` — `groupFindingsByAsset(findings)`
  (exported), wired into `generateReport`; `renderMarkdown` takes
  groups; `renderJson` takes an optional `groups` (generic only).
- `schemas/report.schema.json` — `groups` property documented.
- Tests: `tests/report-grouping.test.js` (group order, within-group
  severity order, unassigned bucket, single-finding report,
  determinism across input orders, verdict stability, JSON shape,
  dedupe-before-grouping via the pipeline fixture, template JSON
  exclusion, CLI end-to-end).
