# Per-class evidence checklists v1

`src/analysis/validator.js` resolves a finding's `vulnerability_type`
to one of twelve classes in `knowledge/evidence-checklists.json` and
enforces that class's required evidence items. The generic checklist
is the round-31/32 fallback: it is what every finding gets when its
type matches no class. All verification is local, over fixtures only;
no model call, no network, no live target.

## The twelve classes

| class id | label | extra required item(s) beyond the generic three | why |
| --- | --- | --- | --- |
| `cross-site scripting` | Cross-Site Scripting (XSS) | `response_log` | The rendered response is the proof the payload executed. |
| `sql injection` | SQL Injection (SQLi) | `response_log` | The database error or extracted data in the response proves the injection. |
| `server-side request forgery` | Server-Side Request Forgery (SSRF) | `request_log`, `response_log` | Both halves of the loop: the outbound request and the response it received. |
| `broken access control` | Broken Access Control | `response_log` | The response proving the unauthorized access succeeded. |
| `authentication bypass` | Authentication Bypass | `response_log` | The response showing access granted without valid credentials. |
| `cross-site request forgery` | Cross-Site Request Forgery (CSRF) | `request_log` | The forged request itself is the proof; the response is secondary. |
| `reentrancy` | Reentrancy | `evidence_notes` | The call sequence / transaction trace, recorded in evidence notes — the schema has no dedicated trace field. |
| `information disclosure` | Information Disclosure | `response_log` | The disclosed data must appear in a recorded response. |
| `xml external entity` | XML External Entity (XXE) | `request_log`, `response_log` | The malicious XML payload and the response showing the entity was resolved. |
| `insecure deserialization` | Insecure Deserialization | `evidence_notes` | The crafted serialized payload and the observed object-state change, recorded in evidence notes — the schema has no dedicated payload/state field. |
| `path traversal` | Path Traversal | `request_log`, `response_log` | The traversal payload and the file content returned. |
| `business logic flaw` | Business Logic Flaw | `evidence_notes` | The legitimate-vs-abused flow comparison, recorded in evidence notes — no single request or response proves a logic flaw. |

Round 57 added the last four rows (XXE, insecure deserialization,
path traversal, business logic flaw). The matching, verdict, and
loading rules below are unchanged; the new classes follow the round-40
pattern exactly (required items + recommended items + `match`
aliases + a `why`).

Every class also requires the generic three: `proof_of_concept`,
`evidence`, `steps_to_reproduce`. Recommended items (checked and
rendered, but not verdict-gating) are the remaining generic items
plus the class-relevant evidence subfields; see the JSON file for the
exact lists.

## Matching

`vulnerability_type` is a free-form string in the schema (not an
enum), so matching normalizes it the same way `rootCauseKey` does
(trim + lowercase) and matches when the normalized type equals, or
contains, one of the class's `match` strings. The first class whose
match strings hit wins; the file order is the precedence order. So
`Stored Cross-Site Scripting`, `Reflected XSS`, and `xss` all resolve
to the XSS class; `idor` resolves to broken access control;
`Open Redirect` and `Missing Authentication` match no class and get
the generic checklist. A missing or non-string type also gets the
generic checklist — a finding with no class is never silently
accepted; the required-field rule still flags a missing
`vulnerability_type` as `needs_evidence`.

## Item predicates

All items are presence checks only — they verify that a piece of
evidence EXISTS, never that it is true, correct, or sufficient:

| item | present when |
| --- | --- |
| `proof_of_concept` | a non-empty string |
| `evidence` | a non-empty array |
| `steps_to_reproduce` | a non-empty array |
| `impact` | a non-empty string |
| `remediation` | a non-empty string |
| `cwe_id` | a non-empty string |
| `cvss_vector` | a non-empty string |
| `request_log` | at least one evidence entry carries a non-empty `request` string |
| `response_log` | at least one evidence entry carries a non-empty `response` string |
| `evidence_notes` | at least one evidence entry carries a non-empty `notes` string |

## Verdict interaction

`validateFinding` enforces the required items of the finding's class
(including the class extras). A missing class-required item is a
`needs_evidence` reason named `missing <item> (required for <class
id>)`. One redundancy rule: an item derived from the evidence array
(`request_log`, `response_log`, `evidence_notes`) is only checked
when the evidence array itself is present — when evidence is missing,
`missing evidence` already covers it. The `false_positive`
short-circuit still wins over every missing item (precedence step 2),
and the severity/CVSS rules are unchanged.

## Loading contract

`loadEvidenceChecklists([filePath])` THROWS on a missing,
unparseable, or malformed spec (unknown item name, an item listed
twice in one class, a class without an id or match list), so a bad
edit to the knowledge file fails loudly in the tests instead of being
silently shipped. `evidenceChecklistForClass()` catches load failures
and falls back to the generic checklist, so `validateFinding()` keeps
its never-throws contract: a broken knowledge file degrades
validation to the generic checklist instead of crashing it. The
fallback is a deliberate degradation, not a silent one — it is
documented here and the loader's throw contract is tested.

The severity bands (`knowledge/cvss/cvss-calc.json`) are loaded
lazily on first use for the same reason the checklist spec is: the
CLI requires the validator eagerly (via the report generator), and
the operator-CLI tests run a `bin/`+`src/`-only copy of the skill as
`nobody` — a top-level require of a knowledge file would crash that
copy with `MODULE_NOT_FOUND` before any command runs. This was a
real round-40 regression, caught by the operator-CLI suite, fixed
by making the ratings lazy (see the capability report).

## Generator rendering

`src/report/generator.js` renders the checklist for every finding:

- **Markdown (generic):** an `### Evidence Checklist` section after
  the Proof of Concept, naming the class (`Class: Cross-Site
  Request Forgery (CSRF)`, or `Class: Generic (no class match)` with
  a note that the generic checklist applies) and listing each item
  as `- [x] <item> (required|recommended)` or `- [ ] <item>
  (required|recommended) — missing`.
- **JSON (generic and template forms):** each finding carries an
  `evidence_checklist` object `{ classId, label, items: [{ item,
  present, required }] }`.
- **Platform templates (Immunefi/Code4rena):** their Markdown
  renders the platform's fixed sections only and does not carry the
  checklist; their JSON form still does. Changing a platform's
  section layout is out of scope for this round.

## Known limitations

- Checklists verify PRESENCE, not truth: a `response_log` containing
  a 404 still counts as present. Judging whether evidence actually
  proves the finding is an AI-model verdict (Phase 6, needs a
  decision), not a checklist.
- Twelve classes only. Web/API classes dominate the list; smart
  contracts get one class (`reentrancy`). Adding a class is a
  knowledge-file edit plus one full + one missing-item fixture — no
  code change, unless the class needs a new item predicate.
- `reentrancy`'s trace lives in evidence `notes` because the finding
  schema has no dedicated trace field. A structured trace field is a
  schema decision for a later round.
- The load-failure fallback (generic checklist) is code-reviewed but
  not test-covered: triggering it in-process would require hiding
  the real knowledge file mid-run. The loader's throw contract IS
  tested; the fallback path itself is three lines in
  `evidenceChecklistForClass`.
- Substring matching can over-match a contrived type (e.g. a type
  containing `xss` as part of another word). No such type exists in
  the fixtures; the match lists are reviewed when a class is added.
