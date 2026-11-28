// Eighth REAL detector (Phase 5, round 103): tainted-sql.
//
// The third PARSER-BASED detector, and the first one built
// on the shared taint engine (`src/detection/taint-engine.js`)
// without touching it. It reuses the engine on a new sink
// class: SQL query calls. This module only supplies the
// detector's config (sink table, finding metadata) and
// re-exports the shared constants. See
// docs/parser-taint-scope-v1.md §7 for the scoping (SQL was
// the next named AST class after tainted command execution)
// and docs/detection-tainted-sql-v1.md for the detector doc.
//
// A sink call is reported ONLY when it carries information
// the regex detector (`dangerous-call`, round 87) cannot:
//   - a DIRECT sink call whose first argument is tainted
//     (kind 'tainted-arg', evidence carries the taint chain
//     — since round 101 the chain may cross function
//     boundaries: call-site values -> callee parameter ->
//     sink);
//   - an ALIASED sink call (`const q = db.query`,
//     `const { query } = db`) with any first argument
//     (kind 'aliased-call', evidence carries the alias
//     binding — the regex detector cannot see these
//     calls at all).
// A direct sink call with a clean argument is NOT reported:
// the regex detector already flags that call site, and the
// AST detector adds nothing. A PARAMETERIZED query — a
// constant SQL string with placeholders plus a parameter
// array (`db.query('SELECT ... WHERE id = $1', [userId])`)
// — is not reported either: only the FIRST argument is
// judged, and the SQL string itself is constant there. A
// value that passed a sanitizer (`Number`, `parseInt`,
// `parseFloat`, `Boolean` — see
// docs/sanitizer-modeling-v1.md) is clean, so a sink call
// on it is not reported.
//
// Sinks (JavaScript, the JS-relevant subset of
// `dangerous-call`'s SQL pattern — the common driver
// call-site shapes: node-postgres `pool`/`client`,
// mysql/mysql2 `connection`/`pool`, and the generic `db` /
// `conn` receiver names; `query` and `execute` each).
// Only the listed two-part member calls are sinks: a bare
// `query(...)` is deliberately NOT a sink (the name is too
// generic — it would false-positive on non-SQL `query`
// calls), and a three-part call (`app.db.query(...)`) is
// not resolved either. `prepare` is NOT a sink in this
// round (a prepared statement is created, not executed;
// judging it is future work). Other drivers' shapes
// (knex, Prisma, Sequelize, ORMs) stay regex-covered by
// dangerous-call — this parser is JavaScript-only by
// design. Only the FIRST argument is judged (the SQL
// string): a tainted second argument (the parameter
// vector) is NOT covered in this round (documented
// limitation — by convention that vector holds bound
// parameters, not SQL text).
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
  'db.query': { label: 'db.query() call' },
  'db.execute': { label: 'db.execute() call' },
  'pool.query': { label: 'pool.query() call' },
  'pool.execute': { label: 'pool.execute() call' },
  'connection.query': { label: 'connection.query() call' },
  'connection.execute': { label: 'connection.execute() call' },
  'client.query': { label: 'client.query() call' },
  'client.execute': { label: 'client.execute() call' },
  'conn.query': { label: 'conn.query() call' },
  'conn.execute': { label: 'conn.execute() call' },
};

// Object roots whose destructured members resolve to sinks:
// `const { query } = db` binds `query` to `db.query`.
const SINK_ROOTS = {
  db: ['query', 'execute'],
  pool: ['query', 'execute'],
  connection: ['query', 'execute'],
  client: ['query', 'execute'],
  conn: ['query', 'execute'],
};

const CONFIG = {
  detectorName: 'tainted-sql',
  vulnerabilityType: 'sql injection',
  severity: 'high',
  cweId: 'CWE-89',
  impact: 'These calls hand a SQL string to a database, so attacker-controlled input reaching them is SQL injection: data exfiltration, modification, or deletion beyond what the application intends.',
  remediation: 'Use parameterized queries (placeholders with a bound parameter array) and never interpolate untrusted input into the SQL string; validate identifiers (table/column names) against an allow-list when they must be dynamic.',
  sinks: SINKS,
  sinkRoots: SINK_ROOTS,
};

const taintedSqlDetector = createTaintDetector(CONFIG);

module.exports = taintedSqlDetector;
module.exports.taintedSqlDetector = taintedSqlDetector;
module.exports.SINKS = SINKS;
module.exports.SINK_ROOTS = SINK_ROOTS;
module.exports.MAX_CONTENT_CHARS = MAX_CONTENT_CHARS;
module.exports.MAX_FINDINGS_PER_RECORD = MAX_FINDINGS_PER_RECORD;
module.exports.findingIdFor = (sink, lineNumber, column, kind) => (
  findingIdFor('tainted-sql', sink, lineNumber, column, kind)
);
module.exports.memberName = memberName;
