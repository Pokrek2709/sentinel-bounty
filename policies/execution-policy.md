# Sentinel Bounty — Execution Policy

## 1. Controlled Wrapper Invocation

- Agents must never execute arbitrary shell commands directly.
- All tool invocations must pass through designated tool wrappers that enforce:
  1. Input parameter validation
  2. Scope verification
  3. Timeout bounds (default 60s per tool call, configurable)
  4. Concurrency limits
  5. Audit logging

## 2. Least Privilege

- Each agent has a restricted set of capabilities:
  - `orchestrator`: Plan formulation and delegation only. No direct network tools.
  - `recon-specialist`: Passive discovery and safe probing only.
  - `web-vulnerability-hunter`: Template-based scanning within strict severity limits.
  - `vulnerability-validator`: Non-destructive reproduction verification only.
  - `severity-analyzer`: Read-only score calculation.
  - `bug-report-writer`: Read-only report formulation.

## 3. Human Approval Gate

- Human confirmation is mandatory before executing:
  - Active vulnerability scans with disruptive potential
  - Authentication tests using non-sandbox credentials
  - Parameter fuzzing with high request counts (>500 reqs)
  - Any method flagged with `requires_approval: true`

Approval must bind the target, action, request estimate, and scope fingerprint. Approval for a shell command alone is not sufficient Sentinel approval.
