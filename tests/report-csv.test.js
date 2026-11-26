// Flat CSV report export (round 55): `sentinel report --format csv`
// renders the same grouped findings as Markdown/JSON into one row per
// finding plus a header row — a machine-readable export for
// spreadsheets and triage tooling. Every field is RFC 4180 escaped;
// finding content is untrusted, so hostile values (`<script>`,
// `=cmd`, `+cmd`, `@cmd`) render verbatim as inert text and the file
// itself never executes anything (formula injection is a spreadsheet
// consumer risk — see docs/report-csv-v1.md). An empty finding set
// renders the header row only; a platform template with CSV output is
// refused, like HTML. Fixtures only; no scanner, no network, no live
// target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport, escapeCsvField, CSV_COLUMNS } = require('../src/report/generator');
const { makeTempDir } = require('./helpers/temp-dir');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

const EXPECTED_HEADER = 'finding_id,target_id,asset_id,severity,cvss_base_score,cvss_temporal_score,cvss_environmental_score,verdict,evidence_checklist,merged_from,ai_verdict';

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// Minimal RFC 4180 parser for the round-trip test: handles quoted
// fields, doubled quotes, and newlines inside quoted fields. Returns
// an array of rows, each an array of field strings.
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (inQuotes) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      field = '';
      rows.push(row);
      row = [];
    } else if (char === '\r') {
      // A bare CR outside a quoted field is a line break too; inside
      // quotes it was already appended above. Skip a following LF.
      if (text[i + 1] === '\n') i += 1;
      row.push(field);
      field = '';
      rows.push(row);
      row = [];
    } else {
      field += char;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

test('escapeCsvField leaves plain values verbatim and quotes the rest', () => {
  assert.equal(escapeCsvField('plain text'), 'plain text');
  assert.equal(escapeCsvField(''), '');
  assert.equal(escapeCsvField(null), '');
  assert.equal(escapeCsvField(undefined), '');
  assert.equal(escapeCsvField(9.8), '9.8');
  assert.equal(escapeCsvField('a,b'), '"a,b"');
  assert.equal(escapeCsvField('say "hi"'), '"say ""hi"""');
  assert.equal(escapeCsvField('line one\nline two'), '"line one\nline two"');
  assert.equal(escapeCsvField('a\rb'), '"a\rb"');
  // A formula-looking value is NOT altered: the file is inert text
  // and the value must survive a parse round-trip unchanged.
  assert.equal(escapeCsvField('=2+5+cmd|calc'), '=2+5+cmd|calc');
  assert.equal(escapeCsvField('+cmd'), '+cmd');
  assert.equal(escapeCsvField('@cmd'), '@cmd');
});

test('CSV header is the documented fixed column order', () => {
  assert.deepEqual(CSV_COLUMNS, [
    'finding_id', 'target_id', 'asset_id', 'severity',
    'cvss_base_score', 'cvss_temporal_score', 'cvss_environmental_score',
    'verdict', 'evidence_checklist', 'merged_from', 'ai_verdict',
  ]);
  const csv = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'csv' });
  assert.equal(csv.split('\n')[0], EXPECTED_HEADER);
});

test('CSV rows carry the exact fixture values, in grouped order', () => {
  const csv = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'csv' });
  // Hand-checked against the fixtures: CRIT 9.8 (SQLi, 9/9 checklist
  // complete), MED 5.0 and LOW 2.5 (information disclosure, 3/10,
  // same seven missing items). No temporal/environmental scores are
  // declared or derivable from these base-only vectors, so those
  // cells are empty; no merged_from and no ai_verdict, so those
  // cells are empty too. Row order is the asset-group order
  // (lab-app/login < lab-app/profile < lab-app/robots), the same
  // order Markdown renders.
  const expected = [
    EXPECTED_HEADER,
    'FND-CRIT-001,TGT-LAB-001,lab-app/login,critical,9.8,,,validated,9/9 (complete),,',
    'FND-MED-001,TGT-LAB-001,lab-app/profile,medium,5,,,validated,3/10 (missing: proof_of_concept; evidence; response_log; cwe_id; cvss_vector; request_log; evidence_notes),,',
    'FND-LOW-001,TGT-LAB-001,lab-app/robots,low,2.5,,,validated,3/10 (missing: proof_of_concept; evidence; response_log; cwe_id; cvss_vector; request_log; evidence_notes),,',
    '',
  ].join('\n');
  assert.equal(csv, expected);
  // Every row parses back to exactly 11 fields.
  const rows = parseCsv(csv);
  assert.equal(rows.length, 4, 'header + 3 finding rows');
  for (const row of rows) assert.equal(row.length, 11, `row has 11 fields: ${row[0]}`);
});

test('CSV carries temporal and environmental scores when present', () => {
  const finding = clone(loadFixture('report-critical.json'));
  finding.cvss_temporal_score = 9.1;
  finding.cvss_environmental_score = 8.4;
  const csv = generateReport([finding], { ...OPTIONS, format: 'csv' });
  const rows = parseCsv(csv);
  assert.equal(rows[1][5], '9.1', 'temporal score in its column');
  assert.equal(rows[1][6], '8.4', 'environmental score in its column');
});

test('CSV carries merged_from and the advisory AI verdict', () => {
  const finding = clone(loadFixture('report-critical.json'));
  finding.merged_from = ['FND-A-001', 'FND-B-002'];
  const csv = generateReport([finding], { ...OPTIONS, format: 'csv', verifier: 'stub' });
  const rows = parseCsv(csv);
  assert.equal(rows[1][9], 'FND-A-001; FND-B-002', 'merged_from joined with "; "');
  assert.equal(
    rows[1][10],
    'needs_evidence (confidence 0, source: stub) — no AI model configured',
    'advisory AI verdict in its column',
  );
  // Without a verifier the ai_verdict cell is empty, and the row is
  // otherwise identical.
  const plain = generateReport([finding], { ...OPTIONS, format: 'csv' });
  const plainRows = parseCsv(plain);
  assert.equal(plainRows[1][10], '');
  assert.equal(plainRows[1][9], 'FND-A-001; FND-B-002');
});

test('CSV is deterministic: same findings in any input order produce byte-identical output', () => {
  const array = loadFixture('report-findings-array.json');
  const first = generateReport(array, { ...OPTIONS, format: 'csv' });
  const second = generateReport([...array].reverse(), { ...OPTIONS, format: 'csv' });
  assert.equal(sha256(first), sha256(second), 'reversed input order must not change the output');
  assert.equal(first, second);
});

test('CSV escapes hostile finding content and round-trips it exactly', () => {
  const hostile = clone(loadFixture('report-critical.json'));
  hostile.finding_id = 'FND-"X",1';
  hostile.asset_id = 'app, "quoted"\nnewline';
  hostile.merged_from = ['=2+5+cmd|calc', 'FND-B'];
  hostile.title = '<script>alert(1)</script>';
  const csv = generateReport([hostile], { ...OPTIONS, format: 'csv' });
  // The hostile values survive only as inert text: quoted per
  // RFC 4180, never as executable markup, and the formula string is
  // written verbatim (no silent alteration of the finding's data).
  assert.ok(csv.includes('"FND-""X"",1"'), 'finding id quoted with doubled quotes');
  assert.ok(csv.includes('"app, ""quoted""\nnewline"'), 'asset id quoted with newline inside');
  assert.ok(csv.includes('=2+5+cmd|calc; FND-B'), 'formula value verbatim');
  assert.ok(!csv.includes('<script'), 'no script markup in the file');
  // A parse round-trip recovers the exact original values.
  const rows = parseCsv(csv);
  assert.equal(rows.length, 2, 'header + 1 finding row');
  assert.equal(rows[1][0], 'FND-"X",1');
  assert.equal(rows[1][2], 'app, "quoted"\nnewline');
  assert.equal(rows[1][9], '=2+5+cmd|calc; FND-B');
});

test('CSV with an empty finding set renders the header row only', () => {
  assert.equal(generateReport([], { format: 'csv' }), `${EXPECTED_HEADER}\n`);
  // Every other format still requires at least one finding.
  assert.throws(() => generateReport([], { format: 'markdown' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'json' }), /At least one finding is required/);
  assert.throws(() => generateReport([], { format: 'html' }), /At least one finding is required/);
  assert.throws(() => generateReport('not-an-array', { format: 'csv' }), /expects an array/);
});

test('CSV rejects a platform template, like HTML does', () => {
  assert.throws(
    () => generateReport([loadFixture('report-critical.json')], { ...OPTIONS, format: 'csv', template: 'immunefi' }),
    /renders Markdown only; CSV output uses the generic template/,
  );
  assert.throws(
    () => generateReport([], { format: 'csv', template: 'code4rena' }),
    /renders Markdown only; CSV output uses the generic template/,
  );
});

test('CSV refuses mixed-target input by default and renders it with the opt-in', () => {
  const mixed = loadFixture('mixed-target-findings.json');
  assert.throws(
    () => generateReport(mixed, { ...OPTIONS, format: 'csv' }),
    /REPORT_MIXED_TARGETS_REFUSED/,
  );
  const csv = generateReport(mixed, { ...OPTIONS, format: 'csv', allowMixedTargets: true });
  const rows = parseCsv(csv);
  assert.equal(rows.length, 3, 'header + 2 finding rows');
  // Targets render in ascending order (local-lab before local-lab-2).
  assert.equal(rows[1][1], 'local-lab');
  assert.equal(rows[2][1], 'local-lab-2');
  assert.equal(rows[1][0], 'F-R31-CONFIRMED-FULL');
  assert.equal(rows[2][0], 'F-R31-POTENTIAL-FULL');
});

test('an unknown format is still rejected with a named error', () => {
  assert.throws(
    () => generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'yaml' }),
    /Invalid format: yaml \(expected "markdown", "json", "html", "csv", or "summary"\)/,
  );
});

test('Markdown and JSON output are unchanged by the CSV addition (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  // Hashes captured from the pre-change generator (round 43, commit
  // c3bec85): adding a format must not move a byte of the old ones.
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
});

test('CLI report --format csv --out writes a flat file with mode 0600', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r55-');
  const output = path.join(directory, 'report.csv');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
    '--format', 'csv', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
    '--out', output,
  ]);
  assert.match(stdout, /Report written to/);
  const csv = fs.readFileSync(output, 'utf8');
  assert.ok(csv.startsWith(`${EXPECTED_HEADER}\n`), 'header row first');
  assert.ok(csv.includes('FND-CRIT-001,TGT-LAB-001,lab-app/login,critical,9.8'), 'critical row present');
  assert.equal(fs.statSync(output).mode & 0o777, 0o600, 'report file is private');
});

test('CLI report --format csv with an empty findings file writes the header only', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r55-');
  const input = path.join(directory, 'empty.json');
  const output = path.join(directory, 'report.csv');
  fs.writeFileSync(input, '[]', 'utf8');
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--findings', input, '--format', 'csv', '--out', output,
  ]);
  assert.match(stdout, /Report written to/);
  assert.equal(fs.readFileSync(output, 'utf8'), `${EXPECTED_HEADER}\n`);
});

test('CLI report --format csv --template immunefi fails cleanly and writes no file', async (t) => {
  const directory = await makeTempDir(t, 'sentinel-r55-');
  const output = path.join(directory, 'report.csv');
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
      '--format', 'csv', '--template', 'immunefi', '--out', output,
    ]),
    (error) => {
      assert.match(error.stderr, /renders Markdown only; CSV output uses the generic template/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
  assert.equal(fs.existsSync(output), false);
});
