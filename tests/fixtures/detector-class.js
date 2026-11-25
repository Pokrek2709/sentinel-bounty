// Fixture detector module for the round-51 detector-interface
// tests: a deterministic, class-dependent detector. It returns a
// normalized finding for cross-site scripting records, and an empty
// envelope for anything else. It is a test double only — it proves
// the loader, the envelope validation, and the detect → validate
// pipeline, not any real detection.
'use strict';

const { normalizeRawFinding } = require('../../src/detection/normalized-record');

module.exports = function classDetector(input, defaults) {
  const records = Array.isArray(input && input.results) ? input.results : [input];
  const tool = input && typeof input.tool === 'string' && input.tool.trim() !== '' ? input.tool : undefined;
  const findings = [];
  const errors = [];
  let skipped = 0;
  for (const record of records) {
    const type = typeof record.vulnerability_type === 'string' ? record.vulnerability_type.toLowerCase() : '';
    if (!type.includes('cross-site scripting')) continue;
    try {
      const raw = tool ? { ...record, tool, discovery_tool: tool } : record;
      findings.push(normalizeRawFinding(raw, defaults));
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  return { findings, skipped, errors };
};
