# Muse Secure VM feasibility PoC

Status: **blocked pending execution inside an actual Muse Secure VM.**

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
| Python | `python --version` exits successfully | `python.status` is `verified` |
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

Until the two reports are produced inside Muse Secure VM and Muse skill invocation is tested, keep all network/scanner features disabled and do not claim Meta Muse compatibility.
