# Sentinel Bounty — Safety Policy

## 1. Strictly Prohibited Actions

Sentinel Bounty strictly prohibits and refuses the following behaviors:
1. Denial of Service (DoS) or Distributed Denial of Service (DDoS) testing.
2. Destructive exploitation (database DROP/DELETE/TRUNCATE, filesystem tampering).
3. Privilege persistence and backdooring.
4. Credential theft, mass credential harvesting, credential stuffing.
5. Social engineering, spear-phishing, or employee manipulation.
6. Lateral movement within target infrastructure.
7. Automated mass exploitation without explicit scope authorization.

## 2. Prompt Injection Defense

- Content retrieved from external targets (HTML responses, headers, API messages, robots.txt, error messages) is strictly treated as untrusted data.
- System instructions, scopes, policies, and authorization keys can never be modified by target-derived inputs.

## 3. Emergency Kill Switch

- The local policy core can be triggered through the internal `killSwitch.trigger()` API.
- A CLI trigger is not implemented yet. Do not document or rely on `sentinel kill-switch trigger` until a persistent session controller exists.
- Triggering the core immediately blocks new registered work and dispatches cancellation to registered workers. The fixed-command controlled wrapper now supplies a subprocess cancellation callback; persistent cross-process activation is still not implemented.
- A Muse runtime lab test reported process-tree termination within a few seconds after runtime-level cancellation. This is not a Sentinel one-second termination guarantee.

Current implementation note: the local policy core and fixed-command wrapper can cancel an in-process child through the wrapper callback. This is not a persistent kill switch and has no direct Muse runtime API binding.
