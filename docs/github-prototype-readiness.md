# GitHub prototype readiness

## Intended use

This repository may be shared as a **private experimental prototype**. It is suitable for source review and local, non-networked checks only.

It is not a packaged Meta Muse skill, a scanner, or authorization to test a real target.

## Included safety boundaries

- Runtime reports and local state are ignored through `.gitignore`.
- The only documented target configuration is `examples/local-target.example.json`, using the reserved `.test` domain and an explicitly local-only authorization reference.
- No implemented CLI command resolves hosts, sends HTTP requests, or invokes a security scanner.
- Scope evaluation is default-deny; an in-scope result is only one prerequisite for future controlled execution.

## Before sharing outside a trusted team

1. Review all target/configuration files and ensure they contain no credentials or authorization records.
2. Run `npm test` and record the result in the pull request or release note.
3. Do not describe this repository as Muse-compatible until a supported manifest and an activation test in Muse have been documented.
4. Do not enable network tooling until the controlled execution wrapper, approval gate, audit log, and kill switch are implemented and independently tested.
