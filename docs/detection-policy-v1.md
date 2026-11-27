# Detection policy v1 (round 90, Phase 5)

Three open decisions from the detector rounds — which
further detectors to build, whether detection should ever
run automatically, and whether detectors may be
asynchronous — decided by the user on 2026-11-28
(~01:03 WIB, "Semua yang di daftar"). The decisions are
recorded here and pinned in code by
`src/analysis/policies.js` (`DETECTION_AUTO_RUN = false`,
`DETECTOR_ASYNC = false`) and
`tests/policies-f6.test.js`.

## 1. The detector set is complete — for the synchronous regex approach

Five real detectors now exist, all following the same
contract (a synchronous function over operator-supplied
local text, one finding per call site / secret / assignment
site, confidence `potential`, never executing the code it
scans, never making a request):

| Detector | Class(es) | Round |
| --- | --- | --- |
| secret-scan | information disclosure (CWE-200) | 86 |
| dangerous-call | code injection, OS command injection, XSS, insecure deserialization | 87 |
| insecure-crypto | cryptographic failure | 88 |
| hardcoded-credential | use of hard-coded credentials (CWE-798) | 89 |
| insecure-transport | cleartext transmission (CWE-319), improper certificate validation (CWE-295) | 90 |

The regex-able call-site space is now exhausted. The
classes the earlier rounds explicitly ruled out stay out:

- SQL string-concatenation injection, template injection,
  LDAP/XPath injection — their call sites are too fuzzy
  for strict regexes; they belong to a parser-based
  detector, not this one (round 87).
- Key management (hardcoded keys are covered; key length,
  key reuse), certificate validation beyond the
  verification switch, and password-storage policy (the
  detector sees the hash call, not the iteration count or
  salt) — not visible at a call site (round 88).
- Path traversal, SSRF, open redirect, XXE, ReDoS — all
  need taint or data-flow analysis to tell a dangerous
  call from a safe one; a regex over call text cannot
  (round 90).

A sixth detector therefore needs either a parser (a new
architecture decision) or a genuinely new regex-able
call-site class the operator can name. Until one of those
exists, F5's detector work is DONE — the phase's
remaining work is the auto-run/async questions below,
which are also decided here.

## 2. Detection never auto-runs

A detector runs only when the operator invokes
`sentinel detect` with an explicit `--detector`. No
watcher, no hook, no scheduled scan, no implicit trigger
from another command. `DETECTION_AUTO_RUN = false`.

Rationale: detection over operator-supplied text is safe
precisely because the operator chooses the text and the
moment. Auto-running it over anything the tool happens
to see would turn a deliberate action into ambient
surveillance of the operator's own files — and would
need its own scope, budget, and approval story first.

## 3. Detectors stay synchronous

A detector is a synchronous function
`detector(input, defaults) -> { findings, skipped,
errors }`, and a detector that returns a Promise is
refused (`DETECTOR_INVALID_RESULT`, enforced by
`validateDetectorResult` in `src/detection/detector.js`
since round 51). An async model call belongs to an
adapter that pre-computes findings before the run.
`DETECTOR_ASYNC = false`.

Rationale: the pipeline is synchronous and deterministic
— the same input always produces the same output in the
same process. Async detectors would make detection
order-, timing-, and network-dependent, and would need
timeouts, cancellation, and a different audit story.
That is a future architecture decision, not a flag.

## What this round does not decide

- The parser decision is now MADE, in round 95
  (`docs/parser-taint-scope-v1.md`): a hand-written
  stdlib-only JavaScript subset parser plus
  intra-procedural taint, proven by the first parser-based
  detector (`tainted-deserialize`,
  `docs/detection-tainted-deserialize-v1.md`). The
  dependency question (Acorn, vendored) is deferred to
  the round that outgrows the subset grammar or adds a
  second language — it is a documented upgrade path, not
  a blocker.
- No model is chosen for the AI verifier (still open).
- No public-target execution is authorized (see
  `docs/public-http-adapter-v1.md` — the adapter exists
  behind the activation gate; the CLI invocation path
  exists since round 93 and is drilled since round 94,
  but no real-target fetch has been run).
