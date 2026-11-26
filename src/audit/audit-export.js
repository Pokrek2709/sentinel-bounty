// Verifiable audit export rendering (round 56). Pure functions: they
// take the result of AuditLog#verifyChainPerRecord() and render it as
// a string. No timestamps are added (no generatedAt): the same log
// must produce a byte-identical export, so an auditor can compare two
// exports by hash.
//
// JSON: one object { exportVersion, verified, summary, records },
// where `verified` is the overall boolean (true exactly when no
// record is broken) and the summary carries the per-status COUNTS
// (verifiedRecords / legacyRecords / brokenRecords) — counts, not
// booleans, so the two `verified` meanings never collide.
// JSONL: one compact line per record, then a final summary line
// marked { "type": "audit-export-summary", ... } so a consumer can
// tell it apart from the record lines (record lines carry no `type`
// field). A consumer that only wants records stops before the last
// line; a consumer that only wants the verdict reads the last line.
const EXPORT_VERSION = 1;
const AUDIT_EXPORT_FORMATS = ['json', 'jsonl'];

function renderAuditExport(result, format) {
  if (!AUDIT_EXPORT_FORMATS.includes(format)) {
    throw new Error(`Invalid audit export format: ${format} (expected "json" or "jsonl").`);
  }
  if (!result || typeof result !== 'object' || !result.summary || typeof result.summary !== 'object' || !Array.isArray(result.records)) {
    throw new TypeError('renderAuditExport expects a verifyChainPerRecord() result.');
  }
  if (format === 'json') {
    return `${JSON.stringify({ exportVersion: EXPORT_VERSION, verified: result.verified, summary: result.summary, records: result.records }, null, 2)}\n`;
  }
  const lines = result.records.map((entry) => JSON.stringify(entry));
  lines.push(JSON.stringify({ type: 'audit-export-summary', exportVersion: EXPORT_VERSION, verified: result.verified, summary: result.summary }));
  return `${lines.join('\n')}\n`;
}

module.exports = { renderAuditExport, AUDIT_EXPORT_FORMATS, EXPORT_VERSION };
