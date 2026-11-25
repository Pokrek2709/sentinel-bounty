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
const { runDetectorOnRecords } = require('./detector');

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

  // The normalization loop lives in detector.js (round 51) so the
  // stub detector and the detector interface normalize identically:
  // a single bad result is counted in `skipped` with its error
  // recorded, and the fixture-level tool is authoritative for every
  // finding's discovery_tool.
  const { findings, skipped, errors } = runDetectorOnRecords(fixture.results, fixture.tool, defaults);

  return { tool: fixture.tool, findings, skipped, errors };
}

module.exports = { runStubDetector };
