// Report generated_at helper (round 73): the four report commands
// (filter, split, merge, anonymize) each carried their own copy of
// pickGeneratedAt — same selection rule (newest valid generated_at
// among the inputs, else newest finding created_at, never the wall
// clock), different named error when nothing is available (merge
// takes the newest of TWO inputs). Round 73 extracts one shared
// helper from the generator and refactors all four call sites to
// it, preserving every error code. These tests pin the four
// commands' byte output BEFORE the refactor (golden sha256) and the
// per-module error codes, so the refactor is provably
// byte-identical. Fixtures only; no scanner, no network.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { generateReport, pickGeneratedAt } = require('../src/report/generator');
const { filterReport } = require('../src/report/filter');
const { splitReport } = require('../src/report/split');
const { mergeReports } = require('../src/report/merge');
const { anonymizeReport } = require('../src/report/anonymize');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

const ALL = loadFixture('report-findings-array.json');
const CRIT = ALL[0];
const MED = ALL[1];
const LOW = ALL[2];
// HIGH and INFO are clones of MED/LOW with a changed score only:
// neither carries a cvss_vector, so no vector can disagree with
// the new score, and the strict check passes.
const HIGH = { ...clone(MED), finding_id: 'FND-HIGH-001', severity: 'high', cvss_score: 7.0 };
const INFO = { ...clone(LOW), finding_id: 'FND-INFO-001', severity: 'informational', cvss_score: 0.0 };
const FIVE = [CRIT, HIGH, MED, LOW, INFO];
const PROGRAM = 'Lab Program';
const GENERATED_AT = '2026-11-26T02:00:00.000Z';

// Golden sha256 pins, computed on the pre-refactor code
// (/tmp/r73-pins.js, round 73): the byte output of each command on
// the fixed FIVE fixture set. If the refactor changes even one
// byte, a pin fails — that is the point.
const PINS = {
  filterHigh: 'eb8117b18135e8dcac6527ad8826e8277c468c5ae878b37b5ec143e18b065690',
  filterEmpty: '23722db392c76a9ea2b7b101bd47a4a329da363fd7a90d618887e33ecc40f9f3',
  splitSeverity: 'f6872f8f99c37da601a46f9aefd8dcf3a1a63ce9508408db2b2045d40386ee63',
  splitVerdict: '8d906cb5976ca1c87dbd2477059c89b5cb3e6a2ac1a4098e545a85d44b73a899',
  mergeSame: '302282df151ab56712a5ec1a7b3864a4a1c98f6a22ad2b9a69010c471c0c838d',
  mergeNewer: '477a8d8614d3e0f89ea14e9f48ff4338b343a0f8e8008685ae7dab1caf6af51f',
  anonymize: '2d1b264221987824981e1d7e247cc1eb0fc13849d59a6e9736ae3154cddab8c7',
  filterFallback: '8900fc3997112bb7385414f9278ccd8059b5ec9cb821b0e5e38938d545816c44',
  splitFallback: '1715cf56be34f682d9c814c74982bf2e60346748c66410d56e3614eba8347933',
};

// A generator-produced JSON report for the given findings
// (program "Lab Program", fixed generated_at so ids are stable).
function generatedReport(findings, generatedAt = GENERATED_AT, programName = PROGRAM) {
  return JSON.parse(generateReport(findings, {
    programName,
    generatedAt,
    format: 'json',
  }));
}

// A source report with no generated_at at all (findings keep their
// created_at), exercising the created_at fallback in each module.
function sourceWithoutGeneratedAt(findings = FIVE) {
  const report = generatedReport(findings);
  delete report.generated_at;
  return report;
}

// A source report with no timestamp anywhere: no generated_at and
// no finding carries created_at. Each module must fail with its
// OWN named error, not a shared one.
function sourceWithoutAnyTimestamp(findings = FIVE) {
  const report = generatedReport(findings);
  delete report.generated_at;
  report.findings.forEach((finding) => { delete finding.created_at; });
  return report;
}

test('golden: filter --severity high output is byte-identical', () => {
  const source = generatedReport(FIVE);
  assert.equal(sha256(filterReport(source, { severity: 'high' }).report), PINS.filterHigh);
});

test('golden: filter empty result output is byte-identical', () => {
  const source = generatedReport(FIVE);
  const result = filterReport(source, { severity: 'critical', verdict: 'false_positive' });
  assert.equal(result.summary.kept, 0);
  assert.equal(sha256(result.report), PINS.filterEmpty);
});

test('golden: split --by severity output is byte-identical', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'severity' });
  assert.equal(sha256(split.files.map((file) => file.report).join('\n')), PINS.splitSeverity);
});

test('golden: split --by verdict output is byte-identical', () => {
  const source = generatedReport(FIVE);
  const split = splitReport(source, { groupBy: 'verdict' });
  assert.equal(sha256(split.files.map((file) => file.report).join('\n')), PINS.splitVerdict);
});

test('golden: merge of two reports with the same generated_at is byte-identical', () => {
  const a = generatedReport(FIVE);
  const b = generatedReport([CRIT, HIGH]);
  assert.equal(sha256(mergeReports(a, b).report), PINS.mergeSame);
});

test('golden: merge takes the newer generated_at of the two inputs', () => {
  const a = generatedReport(FIVE);
  const b = generatedReport([CRIT, HIGH], '2026-11-26T05:00:00.000Z');
  const merged = JSON.parse(mergeReports(a, b).report);
  assert.equal(merged.generated_at, '2026-11-26T05:00:00.000Z');
  assert.equal(sha256(mergeReports(a, b).report), PINS.mergeNewer);
});

test('golden: anonymize output is byte-identical', () => {
  const source = generatedReport(FIVE);
  assert.equal(sha256(anonymizeReport(source).report), PINS.anonymize);
});

test('golden: filter falls back to the newest finding created_at', () => {
  const source = sourceWithoutGeneratedAt();
  const result = filterReport(source, { severity: 'high' });
  assert.equal(JSON.parse(result.report).generated_at, '2026-11-26T00:00:00.000Z');
  assert.equal(sha256(result.report), PINS.filterFallback);
});

test('golden: split falls back to the newest finding created_at', () => {
  const source = sourceWithoutGeneratedAt();
  const split = splitReport(source, { groupBy: 'severity' });
  split.files.forEach((file) => {
    assert.equal(JSON.parse(file.report).generated_at, '2026-11-26T00:00:00.000Z');
  });
  assert.equal(sha256(split.files.map((file) => file.report).join('\n')), PINS.splitFallback);
});

test('error codes preserved: filter keeps its own NO_GENERATED_AT', () => {
  const source = sourceWithoutAnyTimestamp();
  assert.throws(() => filterReport(source, { severity: 'high' }), /REPORT_FILTER_NO_GENERATED_AT/);
});

test('error codes preserved: split keeps its own NO_GENERATED_AT', () => {
  const source = sourceWithoutAnyTimestamp();
  assert.throws(() => splitReport(source, { groupBy: 'severity' }), /REPORT_SPLIT_NO_GENERATED_AT/);
});

test('error codes preserved: merge keeps its own NO_GENERATED_AT', () => {
  const a = sourceWithoutAnyTimestamp();
  const b = sourceWithoutAnyTimestamp([CRIT, HIGH]);
  assert.throws(() => mergeReports(a, b), /REPORT_MERGE_NO_GENERATED_AT/);
});

test('error codes preserved: anonymize keeps its own NO_GENERATED_AT', () => {
  const source = sourceWithoutAnyTimestamp();
  assert.throws(() => anonymizeReport(source), /REPORT_ANONYMIZE_NO_GENERATED_AT/);
});

// Direct contract tests for the shared helper exported by the
// generator (round 73). These run against the helper itself, not
// through the four commands, so a future caller inherits the
// same tested rule.
test('helper: returns the single report generated_at when valid', () => {
  assert.equal(pickGeneratedAt([{ generated_at: GENERATED_AT }], FIVE), GENERATED_AT);
});

test('helper: an invalid generated_at falls back to the newest created_at', () => {
  assert.equal(
    pickGeneratedAt([{ generated_at: 'not-a-date' }], FIVE),
    '2026-11-26T00:00:00.000Z',
  );
});

test('helper: two reports — the newer generated_at wins', () => {
  assert.equal(
    pickGeneratedAt(
      [{ generated_at: '2026-11-26T02:00:00.000Z' }, { generated_at: '2026-11-26T05:00:00.000Z' }],
      FIVE,
    ),
    '2026-11-26T05:00:00.000Z',
  );
  assert.equal(
    pickGeneratedAt(
      [{ generated_at: '2026-11-26T05:00:00.000Z' }, { generated_at: '2026-11-26T02:00:00.000Z' }],
      FIVE,
    ),
    '2026-11-26T05:00:00.000Z',
  );
});

test('helper: one valid generated_at among invalid ones still wins over created_at', () => {
  assert.equal(
    pickGeneratedAt([{ generated_at: 'garbage' }, { generated_at: '2026-11-26T01:00:00.000Z' }], FIVE),
    '2026-11-26T01:00:00.000Z',
  );
});

test('helper: no generated_at anywhere — newest created_at', () => {
  const findings = [
    { created_at: '2026-11-26T00:00:00.000Z' },
    { created_at: '2026-11-26T03:30:00.000Z' },
    { created_at: '2026-11-26T01:15:00.000Z' },
  ];
  assert.equal(pickGeneratedAt([{}], findings), '2026-11-26T03:30:00.000Z');
});

test('helper: returns null when no timestamp exists anywhere', () => {
  assert.equal(pickGeneratedAt([{}], [{}, { created_at: null }]), null);
  assert.equal(pickGeneratedAt([], []), null);
});

test('helper: non-string and unparseable values are ignored', () => {
  assert.equal(
    pickGeneratedAt([{ generated_at: 12345 }, { generated_at: '2026-13-45T99:99:99.000Z' }], [{ created_at: 12345 }]),
    null,
  );
});
