# Report Templates v1

Phase 7 of Sentinel Bounty. Renders a single validated finding into the
section layout a bounty platform expects, via
`sentinel report --finding <finding.json> --template <name>`.

## Templates

| Template | Platform | Sections (in order) |
| --- | --- | --- |
| `immunefi` | Immunefi | Vulnerability Details, Proof of Concept, Impact, Recommendation, References |
| `code4rena` | Code4rena | Description, Proof of Concept, Impact, Recommended Mitigation, Links |
| `hackerone` | HackerOne | Vulnerability Description, Steps to Reproduce, Impact, Recommended Fix, Supporting Material |

Both templates start with the same header block: the finding title with
its severity, then CVSS (score and vector), CWE, vulnerability type,
affected component, finding ID, confidence, validation status, program,
and generated time. The default template is `generic` — the existing
multi-finding report from [reporting-v1](reporting-v1.md), unchanged.

## Which finding fields feed each section

| Section | Finding field(s) | Required? |
| --- | --- | --- |
| Header | `title`, `severity`, `cvss_score`, `cvss_vector`, `cwe_id`, `vulnerability_type`, `asset_id`, `asset_url`, `finding_id`, `confidence`, `validation_status` | Yes (`title`, `severity`) |
| Vulnerability Details / Description / Vulnerability Description | `description` | Yes |
| Proof of Concept / Steps to Reproduce | `proof_of_concept`, `steps_to_reproduce`, `evidence` | Yes (`proof_of_concept`) |
| Impact | `impact` | Yes |
| Recommendation / Recommended Mitigation / Recommended Fix | `remediation` | Yes |
| References / Links / Supporting Material | `references` | No — omitted when absent |

`description`, `impact`, `remediation`, and `steps_to_reproduce` are
already required by the finding schema, so their sections can only fail
if the finding itself is invalid. `proof_of_concept` is optional in the
schema but required by all three platform templates: a finding without one
fails with a named error
(`Template "immunefi" requires field(s) "proof_of_concept" for section
"Proof of Concept" ...`; HackerOne requires it for section
"Steps to Reproduce") instead of rendering a report with an empty
PoC section. `references` is optional in both the schema and the
templates; a finding without references renders fine and the section is
simply omitted. Fields that are absent from a finding (no CVSS score,
no CWE, no asset URL) are omitted from the header — nothing is invented
to fill them in.

## One finding per report

A named template renders exactly one finding. The platforms accept one
bug per submission, so `--findings` with more than one entry fails
cleanly (`Template "immunefi" renders one finding per report; got 3
findings. Generate one report per finding, or use the generic
template.`). Generate one report per finding and submit each separately.

## JSON output

`--format json --template <name>` keeps the generic JSON shape
(`schemas/report.schema.json`) and adds a `"template": "<name>"` field
so the consumer knows which platform layout the Markdown sibling
follows. The generic JSON report carries no `template` field. `report_id`
is the same deterministic id as the generic report for the same program
and finding.

## Cantina

Cantina's report structure uses the same section set as Code4rena
(title, severity, description, proof of concept, impact, recommended
mitigation, links), so there is no separate Cantina template: use
`--template code4rena` for Cantina submissions. Caveat: this template
encodes the section layout only, not Cantina-specific submission
metadata (severity labels, program fields, or form requirements) — check
Cantina's current submission form before sending.

## HackerOne — not platform-verified

The HackerOne template encodes the platform's standard report
structure as commonly documented (title, vulnerability description,
steps to reproduce, impact, recommended fix, supporting material).
Unlike Immunefi and Code4rena, whose layouts were taken from their
public report formats, the HackerOne section order and names here were
derived offline and have **not** been checked against the live
platform's submission form. The template renders the finding's own
fields only — nothing is invented — but verify the section names and
order against HackerOne's current form before sending a real
submission. If the platform's layout differs, update the JSON data
file (`knowledge/report-templates/hackerone.json`) and its tests, not
the renderer.

## Templates are data, not code

Each template is a JSON file in `knowledge/report-templates/`
(`immunefi.json`, `code4rena.json`, `hackerone.json`) declaring its `name`, `platform`,
and `sections`. A section declares an `id`, a `heading` (null for the
header block), the `fields` that feed it, whether it is `required`, and
its `required_fields`. `src/report/templates.js` loads the file at
runtime, validates its shape, and renders fields by type (strings as
paragraphs, `steps_to_reproduce` as a numbered list, `evidence` as
request/response/notes blocks, `references` as a bulleted list). Adding
a platform is a data change — a new JSON file — not a code change.
An unknown template name fails with the available list
(`Unknown report template: "nosuch" (available: code4rena, hackerone, immunefi).`);
a name containing anything outside `[a-z0-9-]` is rejected the same way,
so a value like `../finding` can never escape the templates directory.

## Determinism

Same finding, same options → byte-identical output, Markdown or JSON.
The `Generated:` line uses the same resolution as the generic report
(`--generated-at`, else the newest finding `created_at`, else
"Not specified") and never reads the wall clock.

## Known limitations

- Mixed-target findings are rendered as-is, not grouped — the same
  caveat as the generic generator (round 31). Grouping findings by
  target is not implemented.
- Templates render the validated finding only; they do not re-validate
  severity, check the program's scope, or confirm the finding is
  in-scope for the platform. The author is responsible for submitting
  to the right program.
- Section headings follow the platforms' public formats as documented
  here; if a platform changes its expected layout, update the JSON
  data file and its tests, not the renderer.
