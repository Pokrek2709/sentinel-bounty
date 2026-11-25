// STUB detector interface (Phase 5, round 31) — scaffolding only.
//
// This module invokes NO scanner and performs NO detection against any
// target. It reads a LOCAL JSON fixture file shaped like a fake scanner
// output — `{ tool: <name>, results: [ <raw finding>, ... ] }` — and
// normalizes each result through normalizeRawFinding() so phases 6-7 have
// something real to consume. A single bad result never aborts the run:
// it is counted in `skipped` and its error message is recorded.
//
// The fixture `tool` name is authoritative for the whole file: it is
// recorded as `discovery_tool` on every finding it produces.
'use strict';

const fs = require('node:fs');
const { normalizeRawFinding } = require('./normalized-record');

function runStubDetector(fixturePath, defaults) {
  let text;
  try {
    text = fs.readFileSync(fixturePath, 'utf8');
  } catch (error) {
    throw new Error(`stub detector fixture not found or unreadable: ${fixturePath}: ${error.message}`);
  }

  let fixture;
  try {
    fixture = JSON.parse(text);
  } catch (error) {
    throw new Error(`stub detector fixture is not valid JSON: ${fixturePath}: ${error.message}`);
  }

  if (!fixture || typeof fixture !== 'object' || Array.isArray(fixture)) {
    throw new Error(`stub detector fixture must be an object with "tool" and "results": ${fixturePath}`);
  }
  if (typeof fixture.tool !== 'string' || fixture.tool.trim() === '') {
    throw new Error(`stub detector fixture must have a non-empty string "tool" field: ${fixturePath}`);
  }
  if (!Array.isArray(fixture.results)) {
    throw new Error(`stub detector fixture must have a "results" array: ${fixturePath}`);
  }

  const findings = [];
  const errors = [];
  let skipped = 0;

  for (const result of fixture.results) {
    try {
      // Fixture-level tool is authoritative: it overrides any per-result
      // tool/discovery_tool so every finding is attributed to the fixture.
      const raw = { ...result, tool: fixture.tool, discovery_tool: fixture.tool };
      findings.push(normalizeRawFinding(raw, defaults));
    } catch (error) {
      skipped += 1;
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  return { tool: fixture.tool, findings, skipped, errors };
}

module.exports = { runStubDetector };
