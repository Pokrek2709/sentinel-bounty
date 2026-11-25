// Fixture detector module for the round-51 detector-interface
// tests: a MALFORMED module. It exports a string, not a function
// (and no object with a `detect` function), so loadDetector must
// refuse it with DETECTOR_INVALID_MODULE.
'use strict';

module.exports = 'not a detector';
