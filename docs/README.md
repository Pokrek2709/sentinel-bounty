# Documentation index

Every document in `docs/`, with one line each. Start with [adapt-to-agent](adapt-to-agent.md) if you are installing the skill, and [uninstall-restore](uninstall-restore.md) if you are removing it. The repository README is at [../README.md](../README.md); the platform-neutral skill contract is at [../skills/sentinel-bounty/SKILL.md](../skills/sentinel-bounty/SKILL.md).

## Install, adapt, remove

- [adapt-to-agent](adapt-to-agent.md) — Step-by-step procedure (paste-to-agent prompt) for adapting the skill contract to your agent platform; for anyone installing the skill.
- [uninstall-restore](uninstall-restore.md) — Step-by-step procedure (paste-to-agent prompt) for removing the skill and restoring the machine; for anyone uninstalling it.
- [github-prototype-readiness](github-prototype-readiness.md) — What this repository is safe to share as (a private experimental prototype) and what it is not; for anyone considering sharing the repo.
- [implementation-status](implementation-status.md) — Phase-by-phase implementation status as of 2026-11-21, with evidence links; for reviewers tracking what is built versus still open.

## Core components (v1)

- [approval-gate-v1](approval-gate-v1.md) — Bound, single-use, fail-closed approval gate primitive; for implementers and reviewers of the approval flow.
- [check-env-audit-v1](check-env-audit-v1.md) — Round-41 audit of `sentinel check-env` against the documented requirements (Node >= 18 enforcement, config-sourced tool list, actionable missing-tool messages, kill-switch probe); for implementers and reviewers of the environment checker.
- [controlled-wrapper-v1](controlled-wrapper-v1.md) — Fixed-command execution boundary for local lab execution; for implementers and reviewers of controlled execution.
- [scope-manager-v1](scope-manager-v1.md) — Default-deny target registration and HTTP(S) DNS-host scope matching; for implementers and reviewers of scope enforcement.
- [request-governor-v1](request-governor-v1.md) — Per-domain token-bucket rate governor, request budgets, concurrency limits, and backoff state; for implementers and reviewers of request policy.
- [kill-switch-v1](kill-switch-v1.md) — In-memory, fail-closed kill switch core; for implementers and reviewers of cancellation.
- [persistent-kill-switch-v1](persistent-kill-switch-v1.md) — Cross-process, file-backed persistent kill switch with a token-gated operator CLI; for operators and implementers of the lab kill switch.
- [backup-restore-v1](backup-restore-v1.md) — State backup/restore (`sentinel backup` / `sentinel restore`, schema-versioned envelope with SHA-256, fail-closed refusals) and audit-log rotation proof (archive corruption reporting, `readAllEvents()`); for operators backing up or recovering kill-switch state.
- [audit-integrity-v1](audit-integrity-v1.md) — Audit-log hash chain (SHA-256, genesis-anchored) and `sentinel audit verify`: chain format with a worked example, verify output and break reasons, legacy-record prefix rule, rotation interaction, and the honest limits (prefix/last-record deletion undetectable, full rewrite outside the mechanism); for operators proving the audit trail was not tampered with.
- [drill-v1](drill-v1.md) — Incident-response drill (`sentinel drill`, `--recover`): kill-switch end-to-end against fake lab workers, SIGTERM→SIGKILL escalation, double-arm refusal, and recovery of an interrupted run; for operators proving the kill-switch works before relying on it.
- [state-permissions-v1](state-permissions-v1.md) — State-file permission standard (files 0600, directories 0700, no symlinks): the `verify-install` seventh check, `verify-install --fix` repair, writer hardening (`ensurePrivateDir`), and the honest limits (local-OS control only); for operators keeping kill-switch state and audit records private on disk.
- [pending-promise-audit-v1](pending-promise-audit-v1.md) — Audit of every unawaited async call in `src/` and `bin/` (the adapter's fire-and-forget `unregister()`, the wrapper's throwing `terminate()`, the adapter poller's unguarded `cancel()`, lock close/unlink ordering), the fixes, and the regression guard (`tests/pending-promise-guard.test.js` + allowlist); for implementers and reviewers of async safety.
- [local-http-adapter-v1](local-http-adapter-v1.md) — GET-only `localhost` HTTP adapter for the local lab; for implementers and reviewers of lab network access.

## Finding pipeline (phases 5–7, fixtures only)

- [detection-stub-v1](detection-stub-v1.md) — Fixture-only detector stub that reshapes local JSON fixtures into normalized findings (no real scanner); for implementers of the finding pipeline.
- [validation-v1](validation-v1.md) — Rule-based finding validator with deduplication and an evidence checklist; for implementers and reviewers of finding validation.
- [semantic-dedup-v1](semantic-dedup-v1.md) — Conservative semantic dedup v1 (second pass after exact-key dedup: same type + asset + base vector/severity band + shared evidence entry; merged finding keeps the evidence union, highest score, and `merged_from`; fuzzy matching out of scope, open policy question); for implementers and reviewers of finding validation.
- [ai-verdict-v1](ai-verdict-v1.md) — Pluggable AI-verdict interface (synchronous verifier contract, built-in stub that always answers needs_evidence, safe loader for custom modules, advisory-only precedence); for implementers and reviewers of finding validation.
- [evidence-checklists-v1](evidence-checklists-v1.md) — Per-class evidence checklists (8 classes in `knowledge/evidence-checklists.json`, runtime-loaded, generic fallback): which evidence each class must carry, how classes are matched, and the generator rendering; for implementers and reviewers of finding validation.
- [cvss-vector-v1](cvss-vector-v1.md) — CVSS 3.1 base-vector parsing and scoring (parser, formulas, vector-vs-score precedence, known limitations); for implementers and reviewers of scoring.
- [cvss-temporal-environmental-v1](cvss-temporal-environmental-v1.md) — CVSS 3.1 temporal (E, RL, RC) and environmental (CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA) metrics: parser extensions, formulas, precedence rules, and the no-offline-oracle limitation; for implementers and reviewers of scoring.
- [pipeline-v1](pipeline-v1.md) — End-to-end lab-local pipeline (stub detector → validator → dedup → report generator) over fixtures; for implementers and reviewers of the full chain.
- [reporting-v1](reporting-v1.md) — Deterministic bug-bounty report generator (`sentinel report`, Markdown, JSON, or standalone HTML); for implementers and users rendering validated findings.
- [report-html-v1](report-html-v1.md) — Standalone HTML report export (`--format html`, self-contained, no JavaScript, no external resources, every value HTML-escaped); for implementers and users sharing a report as a single file.
- [report-grouping-v1](report-grouping-v1.md) — Findings grouped by `asset_id` in reports (group order, within-group severity order, JSON `groups` shape, template exclusion); for implementers and users rendering multi-finding reports.
- [report-mixed-targets-v1](report-mixed-targets-v1.md) — Mixed-target reports refused by default (`REPORT_MIXED_TARGETS_REFUSED`), opt-in with `--allow-mixed-targets` (group by target, then asset; full target list in the header of all three formats); for implementers and users rendering multi-target reports.
- [report-templates-v1](report-templates-v1.md) — Platform report templates (`--template immunefi|code4rena`, data files in `knowledge/report-templates/`); for users submitting to Immunefi, Code4rena, or Cantina.

## Muse capability evidence (user-supplied lab reports)

- [muse-capability-evidence-2026-11-18](muse-capability-evidence-2026-11-18.md) — Initial Muse capability evidence: custom-skill discovery and CLI invocation in a direct trial; for engineering decisions on Muse feasibility.
- [muse-capability-followup-2026-11-19](muse-capability-followup-2026-11-19.md) — Follow-up Muse trial results: Python detection and discovery only when `SKILL.md` is at the skill root; for engineering decisions.
- [muse-capability-pgid-2026-11-20](muse-capability-pgid-2026-11-20.md) — PGID and cross-process kill-switch evidence (process-group termination, concurrent triggers, locking); for reviewers of process-group cancellation.
- [muse-kill-switch-lab-evidence-2026-11-20](muse-kill-switch-lab-evidence-2026-11-20.md) — Muse lab evidence for kill-switch cancellation behaviour (SIGTERM, isolated process tree); for reviewers of cancellation.
- [muse-wrapper-lab-followup-2026-11-20](muse-wrapper-lab-followup-2026-11-20.md) — Wrapper and cancellation follow-up evidence (process-tree termination, persistent state directory, file modes); for reviewers.
- [muse-http-adapter-evidence-2026-11-21](muse-http-adapter-evidence-2026-11-21.md) — Real-run Muse evidence for the `localhost` HTTP adapter (rejects external hosts, no redirect following); for reviewers of the lab adapter.
- [muse-secure-vm-poc](muse-secure-vm-poc.md) — Muse Secure VM feasibility PoC procedure and its partially-verified status; for anyone assessing Muse Secure VM.
