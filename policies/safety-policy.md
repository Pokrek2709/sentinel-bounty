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

- The user can trigger the emergency kill switch at any time via:
  - CLI: `sentinel kill-switch trigger`
  - Calling the internal `killSwitch.trigger()` API
- When triggered, all in-flight workers, subprocesses, and requests terminate within 1 second.
