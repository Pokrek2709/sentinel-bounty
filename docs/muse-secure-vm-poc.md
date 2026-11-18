# Muse Secure VM feasibility PoC

Status: **partially verified by a user-provided direct test in a Muse Secure VM on 2026-11-18.** See [capability evidence](muse-capability-evidence-2026-11-18.md). The tests did not establish a supported Muse manifest or Sentinel-controlled network execution.

This repository does not contain a Muse runtime manifest, documented Muse skill API, or a runtime attestation supplied by Meta. Consequently, a local Node.js run is not evidence that a capability exists in Muse Secure VM.

## Safe PoC procedure

Run the checker from the intended Muse Secure VM, twice, with a persistent workspace mounted for the skill:

```text
node bin/sentinel.js check-env --probe-dir storage --output storage/environment-report-1.json
node bin/sentinel.js check-env --probe-dir storage --output storage/environment-report-2.json
```

The checker executes version commands only for its configured local tools. It makes zero network requests and runs no security scanner. It must not be used as evidence of target authorization.

## What the report can verify

| Capability | Evidence | Pass condition |
| --- | --- | --- |
| Node runtime | Current process metadata | `runtime.status` is `verified` |
| External-binary execution | Child process running a version command | `binaryExecution.status` is `verified` |
| Python | `python3 --version`, then `python --version` as fallback | `python.status` is `verified` |
| Tool availability | Tool-specific version command exits successfully | The individual `tools.<name>.status` is `verified` |
| Writable storage | A local marker is written then read back | `filesystem.status` is `verified` |
| Cross-run persistence | Marker from the first run exists at the start of the second | `filesystem.persistence.status` is `verified` |

## Capabilities deliberately left unverified

- Outbound networking: this checker does not make a network request. Verify only with an approved, non-target endpoint and a separately documented test.
- Muse skill invocation: requires Meta's supported skill manifest/activation mechanism and an actual invocation.
- CPU, memory, disk, and execution-duration quotas: host-visible values are not Secure VM quotas.
- Process cancellation: requires the future execution wrapper and a controlled local test subprocess.
- Docker: a detected CLI is not evidence that a Docker daemon or container execution is usable.

## Current decision

The storage-persistence test and custom-skill discovery have now been reported as successful in an actual Muse Secure VM. Keep network/scanner features disabled until the controlled wrapper, Sentinel approval gate, and Sentinel kill switch have been implemented and verified. Do not claim official Meta Muse manifest integration.
