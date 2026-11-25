# Sentinel Bounty

Sentinel Bounty is an early-stage, safety-first foundation for an AI-assisted security research workflow. Its skill contract defines two role-based operating modes—a Lead Bug Hunter and an independent Security Architect / Reviewer—to improve hypothesis quality and challenge findings without claiming human credentials or expanding authorization. It has been tested as a **custom local Muse skill** that invokes its CLI through the shell, but it is **not an official or verified Meta Muse manifest integration**. See [initial Muse capability evidence](docs/muse-capability-evidence-2026-11-18.md) and its [follow-up](docs/muse-capability-followup-2026-11-19.md).

The repository is safe to clone and inspect as a private prototype. The documented CLI commands perform local validation only: they do not resolve hosts, make network requests, or run security scanners. The separate HTTP adapter is restricted to an explicitly local `localhost` lab and is not exposed as a public-target command.

## Status

Implemented locally:

- Environment capability checker with explicit `verified`, `unavailable`, `not_tested`, and `not_verified` states.
- Default-deny target registration and HTTP(S) DNS-host scope matching.
- Allowlists, excluded domains, and safe-path exclusions.
- Per-domain token-bucket rate governor, request budgets, concurrency limits, and local server-pressure backoff state.
- Bound single-use approval gate, fixed-command wrapper, persistent kill-switch state, and token-gated operator CLI for local lab execution.
- GET-only `localhost` HTTP adapter with bounded audit logging for the local lab.
- Lab-local finding pipeline over fixtures only: a fixture-based detector stub that emits normalized findings ([detection-stub-v1](docs/detection-stub-v1.md)), a rule-based finding validator with deduplication and an evidence checklist ([validation-v1](docs/validation-v1.md)), CVSS 3.1 base-vector parsing and scoring ([cvss-vector-v1](docs/cvss-vector-v1.md)), and a deterministic report generator (`sentinel report`, [reporting-v1](docs/reporting-v1.md)) with platform templates for Immunefi and Code4rena ([report-templates-v1](docs/report-templates-v1.md)). No scanner is invoked and nothing here performs detection against any target.

Not implemented yet:

- Meta Muse manifest, installation, activation, or tool-permission integration.
- DNS resolution guard, real scanner integration (only a fixture-based detector stub exists), crawling, or any public-target network adapter.
- Persistent approval/session state and a Muse-native operator API.

An in-scope decision does not authorize execution. No real target may be tested unless authorization, scope enforcement, approval, kill switch, audit, and a reviewed network adapter are all in place.

## Requirements

- Node.js 18 or later.
- No npm dependencies are currently required.

## Install (for other people)

Install this prototype as a local custom skill. It is not an official or verified Meta Muse integration, and installing it does not authorize testing any real target.

1. Clone the repository:

   ```sh
   git clone https://github.com/Pokrek2709/sentinel-bounty.git
   cd sentinel-bounty
   ```

2. Check the requirements: Node.js 18 or later; no npm dependencies are currently required.
3. Install it as a custom skill by following [docs/adapt-to-agent.md](docs/adapt-to-agent.md). That document is the step-by-step adaptation procedure: read `skills/sentinel-bounty/SKILL.md`, copy the skill (the contract plus `bin/`, `src/`, `schemas/`, `policies/`, `examples/`, `knowledge/`, `agents/`) to your agent platform's skill location, and record what was changed. For Muse, `SKILL.md` goes at the installed skill directory's root (for example `~/workspace/custom-skills/sentinel-bounty/SKILL.md`). Do not describe the result as an official or verified integration.
4. Verify the install from the repository (or installed) root. These commands are local-only and make no network request:

   ```sh
   npm test
   node bin/sentinel.js verify-install
   node bin/sentinel.js check-env
   node bin/sentinel.js kill-switch status
   node bin/sentinel.js check-scope --target examples/local-target.example.json --url https://app.example.test/docs
   ```

   Expected: `npm test` passes; `verify-install` exits 0 with all six checks PASS (Node >= 18, CLI reachable, kill-switch inactive, audit log healthy, scope config present, skill files present); `check-env` exits 0 with `runtime` and `binaryExecution` `verified`; `kill-switch status` reports `active: false` with no workers running; `check-scope` reports `decision.allowed: true` with reason `IN_SCOPE` for the `example.test` lab URL and `safety: "No network request was made."` The full expected output is in [docs/adapt-to-agent.md](docs/adapt-to-agent.md). If a command fails, record the exact command, exit code, and output; do not work around it by changing the target, the state directory, or the command.

   If you installed the package binary (`sentinel`, see the `bin` field in `package.json`), the same subcommands apply as `sentinel verify-install`.
5. Uninstall by following [docs/uninstall-restore.md](docs/uninstall-restore.md). Resolve any leased operator token and any armed kill-switch state first; the state directory (`~/workspace/sentinel-bounty/state/`) is kept by default. Do not delete an armed kill-switch state to finish faster.

For the full documentation list, see the [docs index](docs/README.md).

## Quick start: local-only checks

```sh
git clone <your-private-repository-url>
cd sentinel-bounty
npm test
node bin/sentinel.js check-env
node bin/sentinel.js check-scope --target examples/local-target.example.json --url https://app.example.test/docs
```

The example uses the reserved `example.test` domain. The scope command parses local JSON and a URL string only; it does not send a request to that URL.

To persist an environment report locally, use:

```sh
node bin/sentinel.js check-env --probe-dir storage --output storage/environment-report.json
```

`storage/` is intentionally ignored by Git.

For a local lab kill-switch, keep the presented reset token in a secure environment or vault and provision its SHA-256 digest separately; do not pass the token as a CLI argument:

```sh
node bin/sentinel.js kill-switch status
node bin/sentinel.js kill-switch audit-health
node bin/sentinel.js kill-switch trigger --actor local-operator --reason "stop lab run"
SENTINEL_OPERATOR_RESET_TOKEN="provided-by-secure-vault" SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE="/secure/path/operator-reset-token.sha256" node bin/sentinel.js kill-switch reset --actor local-operator
SENTINEL_OPERATOR_RESET_TOKEN="current-token" SENTINEL_OPERATOR_NEW_RESET_TOKEN="replacement-token" SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE="/secure/path/operator-reset-token.sha256" node bin/sentinel.js kill-switch rotate-token --actor local-operator
SENTINEL_OPERATOR_RESET_TOKEN="current-token" SENTINEL_OPERATOR_RESET_TOKEN_HASH_FILE="/secure/path/operator-reset-token.sha256" node bin/sentinel.js kill-switch revoke-token --actor local-operator
```

The default state directory is `~/workspace/sentinel-bounty/state/`, outside the reinstallable skill directory. Reset remains fail-closed while another process has a live worker lease. Trigger/reset/rotation/revocation events are recorded in `audit.jsonl`; if a trigger audit append fails, the trigger still completes with a non-zero audit-integrity signal, while reset, rotation, and revocation require a healthy audit path first. Repair an unhealthy audit path before retrying reset; do not delete the active kill-switch state. Concurrent rotations are serialized. Token validity defaults to approximately 90 days with immediate invalidation on rotation.

## Project layout

- `src/environment/` — local environment checker.
- `src/scope/` — target registration and default-deny scope matching.
- `src/policy/` — local request governor.
- `src/detection/` — normalized finding record + fixture-based detector stub (no real scanner).
- `src/analysis/` — rule-based finding validation, deduplication, evidence checklist.
- `src/report/` — deterministic bug-bounty report generator (`sentinel report`), with platform templates loaded from `knowledge/report-templates/`.
- `skills/sentinel-bounty/SKILL.md` — source custom-skill contract, not an official Muse manifest.
- `policies/` and `schemas/` — design policies and data contracts.
- `docs/` — PoC, implementation, and sharing status. Full list: [docs index](docs/README.md). Adapting the skill to an agent platform: [adapt-to-agent](docs/adapt-to-agent.md). Removing it again: [uninstall-restore](docs/uninstall-restore.md).

## Sharing and Muse trial

Read [GitHub prototype readiness](docs/github-prototype-readiness.md) before sharing. A Muse agent may download this repository and run the local Node commands above. Custom-skill discovery has been observed when `SKILL.md` is placed at the installed skill directory's root, but the project cannot yet activate as an official verified Muse skill. That requires Meta's supported manifest format and a successful official integration invocation. To adapt the contract to an agent platform, follow [adapt-to-agent](docs/adapt-to-agent.md); to remove the skill again, follow [uninstall-restore](docs/uninstall-restore.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
