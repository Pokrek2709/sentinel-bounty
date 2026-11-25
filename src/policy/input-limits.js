// Bounded JSON input for CLI file arguments (Phase 8 hardening, round 34).
//
// `sentinel report` and `sentinel check-scope` read operator-supplied
// JSON files with no size or shape bound: a 12 MB finding file and a
// 31 MB / 20,000-finding file were both accepted and rendered in full,
// and a deeply nested value (5,000 levels inside an otherwise valid
// finding) made the JSON report path fail with a raw
// "Maximum call stack size exceeded" while the Markdown path rendered
// fine. The failures were bounded (exit 1, no hang, no crash), but an
// unbounded read is a resource-exhaustion primitive against any
// pipeline that hands the CLI a hostile file.
//
// Limits (generous for real findings, which are flat and small):
//   MAX_FINDING_FILE_BYTES  10 MiB per input file
//   MAX_FINDINGS            10,000 findings per --findings array
//   MAX_JSON_DEPTH          100 nesting levels
// The depth check is an explicit stack, never recursion, so the check
// itself cannot overflow. Files over the byte limit are refused before
// they are read; the byte count is re-checked after the read in case
// the file grew between the stat and the read.
'use strict';

const fs = require('node:fs/promises');

const MAX_FINDING_FILE_BYTES = 10 * 1024 * 1024;
const MAX_FINDINGS = 10_000;
const MAX_JSON_DEPTH = 100;

// Iterative depth check: a hostile nested value must not be able to
// exhaust the call stack in JSON.stringify (report JSON output) or any
// recursive walk downstream. Objects and arrays both count as levels;
// scalar leaves do not add depth beyond their container.
function checkJsonDepth(value, maxDepth = MAX_JSON_DEPTH) {
  const stack = [{ value, depth: 1 }];
  while (stack.length > 0) {
    const { value: current, depth } = stack.pop();
    if (depth > maxDepth) throw new Error(`JSON exceeds the maximum nesting depth of ${maxDepth}.`);
    if (current && typeof current === 'object') {
      const children = Array.isArray(current) ? current : Object.values(current);
      for (const child of children) stack.push({ value: child, depth: depth + 1 });
    }
  }
}

async function readJsonFileBounded(filePath, { maxBytes = MAX_FINDING_FILE_BYTES, maxDepth = MAX_JSON_DEPTH } = {}) {
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch (error) {
    throw new Error(`Cannot read ${filePath}: ${error.message}`);
  }
  if (stat.size > maxBytes) throw new Error(`File exceeds the ${maxBytes} byte limit: ${filePath}`);
  const text = await fs.readFile(filePath, 'utf8');
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`File exceeds the ${maxBytes} byte limit: ${filePath}`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${error.message}`);
  }
  checkJsonDepth(parsed, maxDepth);
  return parsed;
}

module.exports = { checkJsonDepth, readJsonFileBounded, MAX_FINDING_FILE_BYTES, MAX_FINDINGS, MAX_JSON_DEPTH };
