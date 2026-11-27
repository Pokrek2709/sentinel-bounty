// F6 policies (round 90, Phase 6): the open policy questions
// from rounds 48 (semantic dedup), 50 (AI verdict), and 67
// (false positives), decided by the user on 2026-11-28
// (~01:03 WIB, "Semua yang di daftar") and implemented here
// as EXECUTABLE policy, not prose. Each decision is recorded
// in docs/policies-f6-v1.md with its rationale and what would
// change it (a future explicit user decision — never a round's
// own judgment call).
//
// The decisions:
//   1. SEMANTIC_DEDUP_MODE = 'conservative': the semantic
//      dedup pass (src/analysis/validator.js
//      semanticDedupeFindings, round 48) merges only under
//      its four narrow conditions (same normalized type, same
//      asset, same CVSS base vector + severity or same
//      severity without a vector, at least one shared
//      evidence entry). No text-similarity merging, no
//      looser matching. The pass itself IS the conservative
//      implementation; this constant is the pin that ties
//      the doc to the code, and tests/policies-f6.test.js
//      asserts the constant and the non-merge cases.
//   2. FALSE_POSITIVE_REPORTING = 'exclude-from-reports':
//      a finding whose RULE verdict (round 67's
//      validateOneFinding) is `false_positive` is excluded
//      from a report generated from raw findings
//      (`sentinel report --finding/--findings`), unless the
//      operator passes --include-false-positives. The
//      exclusion lives in the CLI report path only —
//      generateReport itself is untouched, so report
//      transformations (merge, split, filter, render,
//      anonymize) keep whatever a stored report already
//      carries, and `report filter --verdict false_positive`
//      keeps working. A finding that FAILS the strict check
//      (status 'error') is never excluded: generateReport
//      throws on it, as today — exclusion must never mask a
//      structural defect.
//   3. AI_VERDICT_OVERRIDE = false: the AI verdict NEVER
//      overrides the rule-based verdict. It stays advisory
//      only, as round 50 built it (validateFinding computes
//      the rule verdict first; attachAiVerdict never changes
//      a verdict, a score, or the mixed-target check). No
//      downgrade-only override, no upgrade: an AI model is
//      not deterministic or auditable the way the rule is,
//      so it cannot change what the report claims.
//   4. DETECTION_AUTO_RUN = false: detection never runs
//      automatically. A detector runs only when the operator
//      invokes `sentinel detect` with an explicit
//      --detector. No watcher, no hook, no scheduled scan.
//   5. DETECTOR_ASYNC = false: detectors stay
//      synchronous. A detector that returns a Promise is
//      refused (DETECTOR_INVALID_RESULT, enforced by
//      validateDetectorResult in src/detection/detector.js
//      since round 51); an async model call belongs to an
//      adapter that pre-computes findings before the run.
//
// Node stdlib only. No network requests, no scanners, no
// live data.
'use strict';

const { validateOneFinding } = require('../report/validate');

const SEMANTIC_DEDUP_MODE = 'conservative';
const FALSE_POSITIVE_REPORTING = 'exclude-from-reports';
const AI_VERDICT_OVERRIDE = false;
const DETECTION_AUTO_RUN = false;
const DETECTOR_ASYNC = false;

// Split findings into kept/excluded by RULE verdict
// (round 67's validateOneFinding). A finding whose status is
// 'false_positive' is excluded; anything else — valid,
// needs_evidence, or 'error' (a strict-check failure, which
// generateReport must still throw on) — is kept. A finding
// validateOneFinding cannot classify (no finding_id at all)
// is kept too, so the generator's own named error surfaces
// instead of a policy helper's TypeError.
function excludeFalsePositives(findings) {
  const kept = [];
  const excluded = [];
  for (const finding of findings) {
    let status = null;
    try {
      status = validateOneFinding(finding).status;
    } catch {
      status = null;
    }
    if (status === 'false_positive') excluded.push(finding);
    else kept.push(finding);
  }
  return { kept, excluded };
}

module.exports = {
  SEMANTIC_DEDUP_MODE,
  FALSE_POSITIVE_REPORTING,
  AI_VERDICT_OVERRIDE,
  DETECTION_AUTO_RUN,
  DETECTOR_ASYNC,
  excludeFalsePositives,
};
