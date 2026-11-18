# Sentinel Bounty

Sentinel Bounty is an early-stage, safety-first foundation for an AI-assisted security research workflow. It has been tested as a **custom local Muse skill** that invokes its CLI through the shell, but it is **not an official or verified Meta Muse manifest integration**. See [Muse capability evidence](docs/muse-capability-evidence-2026-11-18.md).

The repository is safe to clone and inspect as a private prototype. Its implemented commands perform local validation only: they do not resolve hosts, make network requests, or run security scanners.

## Status

Implemented locally:

- Environment capability checker with explicit `verified`, `unavailable`, `not_tested`, and `not_verified` states.
- Default-deny target registration and HTTP(S) DNS-host scope matching.
- Allowlists, excluded domains, and safe-path exclusions.
- Per-domain token-bucket rate governor, request budgets, concurrency limits, and local server-pressure backoff state.

Not implemented yet:

- Meta Muse manifest, installation, activation, or tool-permission integration.
- Controlled network execution wrapper, DNS resolution guard, scanner integration, or crawling.
- Human approval workflow, audit log, global kill switch, and evidence storage.

An in-scope decision does not authorize execution. No real target may be tested unless authorization, scope enforcement, approval, kill switch, and the future execution wrapper are all in place.

## Requirements

- Node.js 18 or later.
- No npm dependencies are currently required.

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

## Project layout

- `src/environment/` — local environment checker.
- `src/scope/` — target registration and default-deny scope matching.
- `src/policy/` — local request governor.
- `skills/sentinel-bounty/SKILL.md` — source custom-skill contract, not an official Muse manifest.
- `policies/` and `schemas/` — design policies and data contracts.
- `docs/` — PoC, implementation, and sharing status.

## Sharing and Muse trial

Read [GitHub prototype readiness](docs/github-prototype-readiness.md) before sharing. A Muse agent may download this repository and run the local Node commands above. Custom-skill discovery has been observed when `SKILL.md` is placed at the installed skill directory's root, but the project cannot yet activate as an official verified Muse skill. That requires Meta's supported manifest format and a successful official integration invocation.

## License

Licensed under the [Apache License 2.0](LICENSE).
