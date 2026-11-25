// Fixture verifier module for the round-50 AI-verdict tests: a
// MALFORMED module. It exports a string, not a function (and no
// object with a `verify` function), so loadVerifier must refuse it
// with AI_VERDICT_INVALID_MODULE.
'use strict';

module.exports = 'not a verifier';
