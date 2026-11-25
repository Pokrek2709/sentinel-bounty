// Fixture verifier module for the round-50 AI-verdict tests: a
// deterministic, class-dependent verifier. It returns 'valid' for
// cross-site scripting findings, 'false_positive' for cross-site
// request forgery findings, and 'needs_evidence' for everything
// else. It is a test double only — it proves the loader, the
// recording, and the advisory-only precedence, not any real model
// judgement.
'use strict';

module.exports = function classVerifier(finding) {
  const type = typeof finding.vulnerability_type === 'string'
    ? finding.vulnerability_type.toLowerCase()
    : '';
  if (type.includes('cross-site scripting')) {
    return { verdict: 'valid', confidence: 0.9, reasons: ['fixture: XSS class confirmed by model'] };
  }
  if (type.includes('cross-site request forgery')) {
    return { verdict: 'false_positive', confidence: 0.8, reasons: ['fixture: CSRF class rejected by model'] };
  }
  return { verdict: 'needs_evidence', confidence: 0.5, reasons: ['fixture: unknown class, model abstains'] };
};
