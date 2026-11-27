// F6 policies (round 90, Phase 6): the open policy questions
// from rounds 48 (semantic dedup), 50 (AI verdict), and 67
// (false positives), decided by the user on 2026-11-28
// (~01:03 WIB, "Semua yang di daftar") and implemented here
// as EXECUTABLE policy, not prose. Each decision is recorded
// in docs/policies-f6-v1.md with its rationale and what would
// change it (a future explicit user decision — never a round's
// own judgment call).
//
// Round 96 (policy hardening) wired the enforcement the v1
// doc only described: `enforceReportPolicies` below is the
// single enforcement entry point for report generation from
// raw findings — false-positive exclusion first, then the
// conservative semantic dedup pass — and `POLICY_VERSION`
// names the decision set it enforces. The wiring changes no
// decision: the version stays 1.0.0 because the version tracks
// the DECISION SET, not the enforcement code (see
// docs/policy-versioning-v1.md). `sentinel policy` prints the
// active version and decisions for the operator.
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
const { semanticDedupeFindings } = require('./validator');

// The policy version (round 96, docs/policy-versioning-v1.md).
// The version tracks the DECISION SET, not the enforcement code:
// MAJOR changes only when a decision changes (needs an explicit
// user decision), MINOR when enforcement surface is added without
// changing any decision, PATCH for doc/test clarifications.
// 1.0.0 is the v1 decision set approved 2026-11-28 ~01:03 WIB.
const POLICY_VERSION = '1.0.0';

const SEMANTIC_DEDUP_MODE = 'conservative';
const FALSE_POSITIVE_REPORTING = 'exclude-from-reports';
const AI_VERDICT_OVERRIDE = false;
const DETECTION_AUTO_RUN = false;
const DETECTOR_ASYNC = false;

// The active policy as a plain object, for `sentinel policy`
// (text and --json): the version plus the five decisions, in
// the same words the constants carry. Nothing here is computed
// from the environment — there is no flag or variable that can
// change a decision silently; a decision changes only by editing
// this file alongside docs/policies-f6-v1.md, which is exactly
// what the versioning doc requires a future user decision for.
function getPolicySummary() {
  return {
    version: POLICY_VERSION,
    decisions: {
      semanticDedupMode: SEMANTIC_DEDUP_MODE,
      falsePositiveReporting: FALSE_POSITIVE_REPORTING,
      aiVerdictOverride: AI_VERDICT_OVERRIDE,
      detectionAutoRun: DETECTION_AUTO_RUN,
      detectorAsync: DETECTOR_ASYNC,
    },
  };
}

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

// The single enforcement entry point for report generation
// from raw findings (round 96). Order matters and is pinned
// by tests:
//   1. False-positive exclusion FIRST (unless the operator opts
//      in with --include-false-positives): a valid finding can
//      never absorb a false_positive's evidence by merging, and
//      a false_positive can never survive inside a merged valid
//      finding. Findings that fail the strict check (status
//      'error') are never excluded — excludeFalsePositives
//      keeps them, so generateReport still throws on them.
//   2. Conservative semantic dedup SECOND, over the kept
//      findings only — and NEVER across rule verdicts: a valid
//      finding and a false_positive finding may describe the
//      same issue, but they carry different triage states, and
//      merging them would let input order pick the surviving
//      verdict and hide the other triage. The four merge
//      conditions are unchanged (semanticDedupeFindings itself
//      is untouched); the verdict partition is composition,
//      not a fifth condition. Findings that fail the strict
//      check pass through untouched, so generateReport still
//      throws on the first one, as today.
// The semantic pass runs directly, NOT after the exact-key
// dedup (`dedupeFindings`): exact-key grouping would fold
// findings that share a first reproduction step but differ in
// vector or severity, and taking only the representative would
// silently drop a finding the conservative rule refuses to
// merge. Semantic-only is strictly more conservative — it
// merges less, never more.
// Returns { kept, excluded, duplicates }: kept are the merged
// findings in first-appearance order, excluded are the
// false_positive findings removed in step 1, duplicates is the
// count of findings folded away by step 2. `sentinel detect`
// output stays raw by design — detect is a finding source, and
// policy enforcement happens here, at report generation,
// exactly like the false-positive exclusion round 90 placed
// here.
function enforceReportPolicies(findings, { includeFalsePositives = false } = {}) {
  let candidates = findings;
  let excluded = [];
  if (!includeFalsePositives) {
    const split = excludeFalsePositives(findings);
    candidates = split.kept;
    excluded = split.excluded;
  }
  const indexByFinding = new Map();
  candidates.forEach((finding, index) => {
    if (!indexByFinding.has(finding)) indexByFinding.set(finding, index);
  });
  const partitions = new Map();
  const passthrough = [];
  for (const finding of candidates) {
    let status = null;
    try {
      status = validateOneFinding(finding).status;
    } catch {
      status = null;
    }
    if (status === 'error' || status === null) {
      passthrough.push(finding);
      continue;
    }
    if (!partitions.has(status)) partitions.set(status, []);
    partitions.get(status).push(finding);
  }
  const merged = [];
  let duplicates = 0;
  for (const items of partitions.values()) {
    const deduped = semanticDedupeFindings(items);
    for (const group of deduped.groups) {
      const firstIndex = Math.min(...group.findings.map((member) => indexByFinding.get(member)));
      merged.push({ finding: group.merged, index: firstIndex });
      duplicates += group.findings.length - 1;
    }
  }
  const kept = [...merged, ...passthrough.map((finding) => ({ finding, index: indexByFinding.get(finding) }))]
    .sort((a, b) => a.index - b.index)
    .map((entry) => entry.finding);
  return { kept, excluded, duplicates };
}

module.exports = {
  POLICY_VERSION,
  SEMANTIC_DEDUP_MODE,
  FALSE_POSITIVE_REPORTING,
  AI_VERDICT_OVERRIDE,
  DETECTION_AUTO_RUN,
  DETECTOR_ASYNC,
  excludeFalsePositives,
  enforceReportPolicies,
  getPolicySummary,
};
