// Seventh REAL detector (Phase 5, round 100): tainted-command-execution.
//
// The second PARSER-BASED detector. It reuses the shared
// taint engine (`src/detection/taint-engine.js`, extracted
// in round 101 from the round-95 analyzer) on a new sink
// class: command execution. This module only supplies the
// detector's config (sink table, finding metadata) and
// re-exports the shared constants. See
// docs/parser-taint-scope-v1.md §5 for the scoping (the
// second AST class was named there: tainted command
// execution is the natural next one, the sink list exists
// in `dangerous-call`) and
// docs/detection-tainted-command-execution-v1.md for the
// detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument is tainted
//     (kind 'tainted-arg', evidence carries the taint chain
//     — since round 101 the chain may cross function
//     boundaries: call-site values -> callee parameter ->
//     sink);
//   - an ALIASED sink call (`const e = child_process.exec`,
//     `const { exec } = child_process`) with any first
//     argument (kind 'aliased-call', evidence carries the
//     alias binding — the regex detector cannot see these
//     calls at all).
// A direct sink call with a clean argument is NOT reported:
// the regex detector already flags that call site, and the
// AST detector adds nothing. There is no safe-loader
// analogue here: every exec-family call is a sink when its
// first argument is tainted. `child_process.fork` is NOT a
// sink (it spawns a Node module, not a shell command). A
// value that passed a sanitizer (`Number`, `parseInt`,
// `parseFloat`, `Boolean` — see
// docs/sanitizer-modeling-v1.md) is clean, so a sink call
// on it is not reported.
//
// Sinks (JavaScript, Node's child_process — the JS-relevant
// subset of dangerous-call's command-exec pattern):
// child_process.exec, child_process.execSync,
// child_process.spawn, child_process.spawnSync,
// child_process.execFile, child_process.execFileSync.
// Python's os.system / os.popen / subprocess.*, C's
// system() / popen(), and bare exec() stay regex-covered by
// dangerous-call — this parser is JavaScript-only by design.
// Only the FIRST argument is judged (the command): a tainted
// argument vector (second argument of spawn / execFile) is
// NOT covered in this round (documented limitation).
//
// Sources: every function parameter (untrusted input by
// definition) and member access rooted at `process.argv`.
// Since round 101 taint also flows across function
// boundaries (call graph) and through return values; a
// helper never called, or called only with clean arguments,
// is still analyzed with parameters-as-sources (the
// round-95 fallback), so its sink is flagged with
// confidence `potential` and no claim of reachability.
//
// Safety properties (tested, not assumed): see
// src/detection/taint-engine.js — a finding carries only
// the sink name, position, and a taint chain of IDENTIFIER
// NAMES, never a literal value or a source line; one
// finding per distinct sink call site per record; caps,
// determinism, and the no-regex-fallback rule are enforced
// by the shared engine.
//
// Node stdlib only. Synchronous, deterministic, no I/O.
'use strict';

const {
  MAX_CONTENT_CHARS,
  MAX_FINDINGS_PER_RECORD,
  findingIdFor,
  memberName,
  createTaintDetector,
} = require('./taint-engine');

// Canonical sink name -> { label }.
const SINKS = {
  'child_process.exec': { label: 'child_process.exec() call' },
  'child_process.execSync': { label: 'child_process.execSync() call' },
  'child_process.spawn': { label: 'child_process.spawn() call' },
  'child_process.spawnSync': { label: 'child_process.spawnSync() call' },
  'child_process.execFile': { label: 'child_process.execFile() call' },
  'child_process.execFileSync': { label: 'child_process.execFileSync() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { exec } = child_process` binds `exec` to
// `child_process.exec`.
const SINK_ROOTS = {
  child_process: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'],
};

const CONFIG = {
  detectorName: 'tainted-command-execution',
  vulnerabilityType: 'os command injection',
  severity: 'high',
  cweId: 'CWE-78',
  impact: 'These calls hand a string (or a program path) to the operating-system shell or a new process, so attacker-controlled input reaching them is arbitrary command execution on the host.',
  remediation: 'Avoid shell execution: use an allow-listed argument vector with no shell (spawn/execFile with shell: false) and never interpolate untrusted input into a command string.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
};

const taintedCommandExecutionDetector = createTaintDetector(CONFIG);

module.exports = taintedCommandExecutionDetector;
module.exports.taintedCommandExecutionDetector = taintedCommandExecutionDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-command-execution', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
