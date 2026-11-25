# Standalone HTML report export (round 44, Phase 7)

`sentinel report --format html` renders the same validated, grouped
findings as the Markdown/JSON reports into one self-contained HTML
file. It is the generic template only: platform templates
(Immunefi/Code4rena) are Markdown-only, and requesting one with
`--format html` fails cleanly with a named error instead of
producing a half-templated file.

## Format

- One file, no build step: `<!DOCTYPE html>` with `<meta
  charset="utf-8">`, a `<title>`, one inline `<style>` block, and the
  report body. No JavaScript anywhere, no external resources — no
  CDN links, no external images or fonts, no `@import`, no `url()`,
  no `href`/`src` attribute of any kind. The file opens correctly
  offline and from `file://`.
- Content mirrors the Markdown report: report ID (`RPT-<12 hex>`,
  same deterministic derivation), program name, generated time (or
  "Not specified"), severity summary table, executive summary, then
  one section per asset group (`Asset: <id> — N finding(s)
  (critical: …, high: …, …)`), with the same grouping order as
  Markdown (groups by `asset_id` ascending, findings inside a group
  by severity then `finding_id`, global finding number across
  groups). Each finding carries title, severity badge, CVSS base /
  temporal / environmental scores where present, CWE, vulnerability
  type, affected component, confidence, validation status,
  description, steps to reproduce, proof of concept, evidence items,
  the per-class evidence checklist with `[x]`/`[ ]` marks, impact,
  remediation, and references.
- Determinism: the same findings in any input order produce
  byte-identical HTML (grouping order is a pure function of the
  finding set; `generated_at` is caller-supplied or "Not specified",
  never the wall clock). Verified by test, including a reversed
  input order.
- Markdown and JSON output are unchanged by this round: golden
  SHA-256 hashes for the three-finding array fixture are pinned in
  `tests/report-html.test.js` (Markdown
  `df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779`,
  JSON
  `82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf`).

## Escaping (the security rule for this format)

Finding content is untrusted: titles, descriptions, asset IDs, and
references can contain attacker-controlled strings. Every
interpolated value goes through `escapeHtml` (`src/report/generator.js`),
which escapes `& < > " '`. References and asset URLs render as
inert text, never as links, so the output contains no `href`/`src`
attribute at all.

The precise test is tag-based (`tests/report-html.test.js`): every
tag in the output must be one the generator itself emits (`html`,
`head`, `meta`, `title`, `style`, `body`, `h1`–`h4`, `p`, `table`,
`tr`, `th`, `td`, `dl`, `dt`, `dd`, `ol`, `ul`, `li`, `article`,
`span`), and no tag may carry an `href`/`src` attribute. A hostile
fixture (title `<script>alert(1)</script>`, asset ID breaking out of
an attribute with a quote, description with `<img src=x
onerror=...>`, references `javascript:alert(1)` and an `https://`
URL) renders entirely as escaped text. Note the honest subtlety the
test pins down: the strings `onerror`, `onload`, `src=`, and
`javascript:` still appear in the file — inside `&lt;...&gt;`
escaped text, where a browser renders them as text, never as
markup. Asserting their absence would be wrong; asserting no
attacker tag exists is the correct check. Reference URLs appear as
text too: the `https://` strings in the file are references, not
fetched resources — nothing in the file can make a browser fetch
them.

## Known limitations

- No interactivity: no JavaScript means no collapsing sections,
  filtering, or search. The file is a static render.
- No platform-template HTML variant: Immunefi/Code4rena templates
  stay Markdown-only. If a platform ever needs an HTML submission,
  that is a new template, not a format flag.
- Severity colours are the only semantic styling; with styles
  disabled the page stays readable because every value is also
  present as text (severity label, `[x]`/`[ ]` marks).
- The HTML report does not carry `target_id`/`session_id` (the
  Markdown report does not either); those live in the JSON report.
