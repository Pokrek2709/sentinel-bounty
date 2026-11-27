# GitHub prototype readiness

## Intended use

This repository may be shared as a **private experimental prototype**. It is suitable for source review and local checks, plus the gated public-fetch path, only.

It is not a packaged Meta Muse skill, a scanner, or authorization to test a real target.

## Included safety boundaries

- Runtime reports and local state are ignored through `.gitignore`.
- The only documented target configuration is `examples/local-target.example.json`, using the reserved `.test` domain and an explicitly local-only authorization reference.
- No implemented CLI command invokes a security scanner. One command
  does use the network, under a gate: `sentinel fetch` (rounds 93–94)
  resolves a hostname and sends a GET-only request, and only to a
  registered public target, only after a preview and explicit human
  approval, and only while the kill switch is disarmed. Nothing runs
  against a real target without all five activation requirements
  (registered target + authorization reference, scope acceptance,
  policy/budget/approval acceptance, kill switch enabled, capability
  checks passed) — see the skill contract's Activation requirements.
- Scope evaluation is default-deny; an in-scope result is only one prerequisite for future controlled execution.

## Before sharing outside a trusted team

1. Review all target/configuration files and ensure they contain no credentials or authorization records.
2. Run `npm test` and record the result in the pull request or release note.
3. Do not describe this repository as Muse-compatible until a supported manifest and an activation test in Muse have been documented.
4. Network use is gated, not open: the controlled execution wrapper,
   approval gate, audit log, and kill switch are implemented and
   independently tested (rounds 93–94 drill the public-fetch
   activation end to end), and `sentinel fetch` refuses without a
   registered target, a preview, and explicit human approval. Never
   run it against a target that is not registered with a verified
   authorization reference, and never present this repository as
   authorization to test a real target.
