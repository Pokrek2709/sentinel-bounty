// Report anonymize (round 69): `sentinel report anonymize
// <report.json>` strips internal identifiers from a JSON report
// so it can be shared — target_id, session_id, and asset_id are
// replaced with deterministic `anon-<sha256>` values, and
// internal hostnames/IPs in `description` and evidence `notes`
// are scrubbed. Severities, scores, verdicts, finding_ids, and
// the evidence checklist are preserved, and the output is
// re-rendered by generateReport itself, so it stays a valid
// round-31 JSON report. Fixtures only; no scanner, no network,
// no live target.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const {
  DEFAULT_SALT,
  SCRUB_PATTERNS,
  validateSalt,
  anonymizeValue,
  scrubText,
  anonymizeReport,
} = require('../src/report/anonymize');
const { validateReport } = require('../src/report/validate');
const { makeTempDir } = require('./helpers/temp-dir');
const { assertPrivateModeSync } = require('./helpers/private-mode');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const ALL = loadFixture('report-findings-array.json');
const CRIT = ALL[0];
const MED = ALL[1];
const LOW = ALL[2];
const PROGRAM = 'Lab Program';
const GENERATED_AT = '2026-11-26T02:00:00.000Z';

// A generator-produced JSON report for the given findings
// (program "Lab Program", fixed generated_at so ids are stable).
// Extra generateReport options (e.g. allowMixedTargets) pass
// through as the third argument.
function generatedReport(findings, generatedAt = GENERATED_AT, programName = PROGRAM, extraOptions = {}) {
  return JSON.parse(generateReport(findings, {
    programName,
    generatedAt,
    format: 'json',
    ...extraOptions,
  }));
}

// The expected anonymized value, derived independently of the
// module under test (plain crypto, same documented formula).
function expectedAnon(salt, original) {
  const digest = crypto.createHash('sha256').update(`${salt}:${original}`).digest('hex');
  return `anon-${digest.slice(0, 12)}`;
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

test('anonymizes identifiers and keeps the findings intact', () => {
  const report = generatedReport(ALL);
  const anonymized = anonymizeReport(report);
  assert.deepEqual(anonymized.summary, {
    total: 3,
    identifiers_replaced: 9,
    text_substitutions: 0,
    salt_source: 'default',
  });
  const parsed = JSON.parse(anonymized.report);
  assert.equal(parsed.anonymized, true);
  assert.deepEqual(parsed.anonymization, {
    salt_source: 'default',
    patterns: ['ipv4-dotted-quad', 'hostname-.local/.internal'],
  });
  // The report id is the generator's own derivation (program +
  // sorted finding ids), and anonymization preserves exactly
  // those inputs — so it is unchanged by design, which lets the
  // operator correlate the anonymized report with the original.
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
  assert.equal(parsed.program_name, PROGRAM);
  assert.equal(parsed.generated_at, GENERATED_AT);
  assert.equal(parsed.target_id, expectedAnon(DEFAULT_SALT, 'TGT-LAB-001'));
  assert.equal(parsed.session_id, expectedAnon(DEFAULT_SALT, 'SES-REPORT-001'));
  assert.deepEqual(
    parsed.findings.map((f) => f.finding_id),
    ['FND-CRIT-001', 'FND-MED-001', 'FND-LOW-001'],
  );
  assert.deepEqual(
    parsed.findings.map((f) => f.asset_id),
    ['lab-app/login', 'lab-app/profile', 'lab-app/robots'].map((asset) => expectedAnon(DEFAULT_SALT, asset)),
  );
  // Severity, scores, and verdicts are preserved.
  assert.deepEqual(parsed.findings.map((f) => f.severity), ['critical', 'medium', 'low']);
  assert.deepEqual(parsed.findings.map((f) => f.cvss_score), [9.8, 5.0, 2.5]);
  assert.deepEqual(parsed.findings.map((f) => f.validation_status), ['validated', 'validated', 'validated']);
  // Descriptions and evidence notes are untouched when nothing matches.
  assert.equal(parsed.findings[0].description, CRIT.description);
  assert.equal(parsed.findings[0].evidence[0].notes, CRIT.evidence[0].notes);
  // No original identifier string remains anywhere in the output.
  const serialized = anonymized.report;
  for (const original of ['TGT-LAB-001', 'SES-REPORT-001', 'lab-app/login', 'lab-app/profile', 'lab-app/robots']) {
    assert.ok(!serialized.includes(original), `output still contains ${original}`);
  }
});

test('the mapping is deterministic and independently derived', () => {
  const a = expectedAnon(DEFAULT_SALT, 'TGT-LAB-001');
  const b = expectedAnon(DEFAULT_SALT, 'TGT-LAB-001');
  assert.equal(a, b);
  assert.equal(a, anonymizeValue(DEFAULT_SALT, 'TGT-LAB-001'));
  assert.match(a, /^anon-[0-9a-f]{12}$/);
  // Different originals map to different values.
  assert.notEqual(
    anonymizeValue(DEFAULT_SALT, 'TGT-LAB-001'),
    anonymizeValue(DEFAULT_SALT, 'TGT-LAB-002'),
  );
  // The same original in two findings maps to the same value
  // (the fixture set shares one target and one session).
  const report = generatedReport(ALL);
  const parsed = JSON.parse(anonymizeReport(report).report);
  assert.equal(parsed.findings[0].target_id, parsed.findings[1].target_id);
  assert.equal(parsed.findings[0].session_id, parsed.findings[2].session_id);
});

test('anonymize is deterministic across runs, with and without --salt', () => {
  const report = generatedReport(ALL);
  assert.equal(anonymizeReport(report).report, anonymizeReport(report).report);
  const salted = anonymizeReport(report, { salt: 'abcdef1234567890' });
  assert.equal(anonymizeReport(report, { salt: 'abcdef1234567890' }).report, salted.report);
  // A provided salt changes the mapping (and the metadata).
  assert.notEqual(salted.report, anonymizeReport(report).report);
  assert.equal(salted.summary.salt_source, 'provided');
  assert.equal(JSON.parse(salted.report).anonymization.salt_source, 'provided');
  assert.equal(
    JSON.parse(salted.report).target_id,
    expectedAnon('abcdef1234567890', 'TGT-LAB-001'),
  );
});

test('scrubText replaces IPs and internal hostnames only', () => {
  const result = scrubText('Call 10.0.4.17 and db01.corp.internal, see web02.lab.local, version 1.2.3.4, public example.com stays.');
  assert.equal(
    result.text,
    'Call anon-ip and anon-host, see anon-host, version anon-ip, public example.com stays.',
  );
  assert.equal(result.substitutions, 4);
  assert.deepEqual(scrubText('nothing to scrub here'), { text: 'nothing to scrub here', substitutions: 0 });
});

test('description and evidence notes are scrubbed, logs and other text are not', () => {
  const med = clone(MED);
  med.description = `${MED.description} (seen on 10.0.4.17 and db01.corp.internal)`;
  med.evidence = [{
    notes: 'Host web01.corp.local answered 10.1.2.3.',
    request: 'GET /profile from 10.9.9.9',
    response: 'HTTP 200 from api.corp.internal',
  }];
  const report = generatedReport([med]);
  const anonymized = anonymizeReport(report);
  assert.equal(anonymized.summary.text_substitutions, 4);
  const finding = JSON.parse(anonymized.report).findings[0];
  assert.equal(
    finding.description,
    `${MED.description} (seen on anon-ip and anon-host)`,
  );
  assert.equal(finding.evidence[0].notes, 'Host anon-host answered anon-ip.');
  // The request/response logs are NOT scrubbed: they are the
  // evidence a program needs to reproduce the finding.
  assert.equal(finding.evidence[0].request, 'GET /profile from 10.9.9.9');
  assert.equal(finding.evidence[0].response, 'HTTP 200 from api.corp.internal');
});

test('anonymized output passes report validate cleanly', () => {
  const report = generatedReport(ALL);
  const anonymized = anonymizeReport(report);
  const result = validateReport(JSON.parse(anonymized.report));
  assert.equal(result.status, 'VALID');
  assert.equal(result.report_id_matches, true);
  assert.deepEqual(result.counts, { findings: 3, valid: 1, false_positive: 0, needs_evidence: 2, errors: 0 });
});

test('different targets anonymize as a mixed-target report', () => {
  const lowOther = { ...clone(LOW), target_id: 'TGT-LAB-002' };
  const report = generatedReport([CRIT, lowOther], GENERATED_AT, PROGRAM, { allowMixedTargets: true });
  const parsed = JSON.parse(anonymizeReport(report).report);
  assert.equal(parsed.mixed_targets, true);
  assert.deepEqual(
    [...parsed.target_ids].sort(),
    [expectedAnon(DEFAULT_SALT, 'TGT-LAB-001'), expectedAnon(DEFAULT_SALT, 'TGT-LAB-002')].sort(),
  );
  const byId = new Map(parsed.findings.map((f) => [f.finding_id, f]));
  assert.equal(byId.get('FND-CRIT-001').target_id, expectedAnon(DEFAULT_SALT, 'TGT-LAB-001'));
  assert.equal(byId.get('FND-LOW-001').target_id, expectedAnon(DEFAULT_SALT, 'TGT-LAB-002'));
});

test('salt validation: non-hex, too short, and too long are refused without echoing the salt', () => {
  const report = generatedReport(ALL);
  for (const bad of ['zzzzzzzz', 'abc1234', 'a'.repeat(65), 'abcdef12 ', '']) {
    assert.throws(
      () => anonymizeReport(report, { salt: bad }),
      (error) => {
        assert.match(error.message, /REPORT_ANONYMIZE_INVALID_SALT/);
        // The error must never echo the salt (the empty string
        // is contained in every string, so it is skipped here).
        if (bad.trim() !== '') assert.ok(!error.message.includes(bad.trim()), 'error must never echo the salt');
        return true;
      },
    );
  }
  // The boundaries are accepted: 8 and 64 hex chars.
  assert.equal(validateSalt('abcdef12'), 'abcdef12');
  assert.equal(validateSalt('a'.repeat(64)), 'a'.repeat(64));
  assert.equal(SCRUB_PATTERNS.length, 2);
});

test('a finding that fails the strict check fails anonymization', () => {
  const report = generatedReport(ALL);
  report.findings[1].severity = 'critical'; // MED still scores 5.0: band mismatch
  assert.throws(
    () => anonymizeReport(report),
    (error) => {
      assert.match(error.message, /REPORT_ANONYMIZE_INVALID_FINDING/);
      assert.match(error.message, /FND-MED-001/);
      return true;
    },
  );
});

test('an empty report fails as empty, not as a zero-finding report', () => {
  const empty = { report_id: 'RPT-A', program_name: PROGRAM, generated_at: GENERATED_AT, findings: [] };
  assert.throws(() => anonymizeReport(empty), /REPORT_ANONYMIZE_EMPTY/);
});

test('no generated_at anywhere fails instead of inventing a timestamp', () => {
  const noCreated = (finding) => {
    const copy = clone(finding);
    delete copy.created_at;
    return copy;
  };
  const report = { report_id: 'RPT-A', program_name: PROGRAM, findings: [noCreated(MED)] };
  assert.throws(() => anonymizeReport(report), /REPORT_ANONYMIZE_NO_GENERATED_AT/);
});

test('generated_at falls back to the newest finding created_at', () => {
  const report = generatedReport([MED, LOW]);
  delete report.generated_at;
  const parsed = JSON.parse(anonymizeReport(report).report);
  assert.equal(parsed.generated_at, MED.created_at);
});

test('malformed inputs fail with the shared reader’s named errors', () => {
  const report = generatedReport(ALL);
  assert.throws(() => anonymizeReport(null), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => anonymizeReport({ findings: [] }), /REPORT_DIFF_INVALID_REPORT/);
  assert.throws(() => anonymizeReport({ report_id: 'RPT-A' }), /REPORT_DIFF_INVALID_REPORT/);
  const dup = generatedReport([MED, MED]);
  assert.throws(() => anonymizeReport(dup), /REPORT_DIFF_DUPLICATE_FINDING_ID/);
});

test('the input report is not mutated', () => {
  const report = generatedReport(ALL);
  const before = JSON.stringify(report);
  anonymizeReport(report);
  assert.equal(JSON.stringify(report), before);
});

test('asset_url is NOT scrubbed (documented limitation of this round)', () => {
  // The CRIT finding's asset_url names an internal host
  // (https://lab.example.internal/login). This round scrubs
  // description and evidence notes only, so the URL survives
  // verbatim — pinned here so a future change is deliberate,
  // not accidental. See docs/report-anonymize-v1.md.
  const report = generatedReport(ALL);
  const parsed = JSON.parse(anonymizeReport(report).report);
  assert.equal(parsed.findings[0].asset_url, 'https://lab.example.internal/login');
});

test('the other report goldens do not move', () => {
  const markdown = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'markdown' });
  const json = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf');
});

test('CLI: stdout is pure JSON and the summary line goes to stderr', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath]);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
  assert.equal(parsed.anonymized, true);
  assert.equal(parsed.target_id, expectedAnon(DEFAULT_SALT, 'TGT-LAB-001'));
  assert.equal(stderr, 'anonymized 3 findings (9 identifiers replaced, 0 text substitutions)\n');
});

test('CLI: --out writes mode 0600 and stdout carries only the confirmation', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  const outPath = path.join(dir, 'anon.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath, '--out', outPath]);
  assert.equal(stdout, `Anonymized report written to ${outPath}\n`);
  assert.equal(stderr, 'anonymized 3 findings (9 identifiers replaced, 0 text substitutions)\n');
  assertPrivateModeSync(outPath, 0o600);
  const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  assert.equal(parsed.anonymized, true);
  assert.equal(parsed.report_id, 'RPT-0536be9278ec');
});

test('CLI: --salt changes the mapping and is never printed', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath, '--salt', 'abcdef1234567890']);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.target_id, expectedAnon('abcdef1234567890', 'TGT-LAB-001'));
  assert.equal(parsed.anonymization.salt_source, 'provided');
  assert.ok(!stdout.includes('abcdef1234567890'), 'stdout must never contain the salt');
  assert.ok(!stderr.includes('abcdef1234567890'), 'stderr must never contain the salt');
  assert.equal(stderr, 'anonymized 3 findings (9 identifiers replaced, 0 text substitutions)\n');
});

test('CLI: an invalid salt fails with exit 1 and writes no file', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  const outPath = path.join(dir, 'anon.json');
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath, '--out', outPath, '--salt', 'not-hex!!']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_ANONYMIZE_INVALID_SALT/);
      assert.ok(!error.stderr.includes('not-hex!!'), 'the error must never echo the salt');
      return true;
    },
  );
  assert.equal(fs.existsSync(outPath), false);
});

test('CLI: malformed and symlinked inputs fail with named errors', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  const linkPath = path.join(dir, 'link.json');
  fs.writeFileSync(inPath, '{not json');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_INVALID_REPORT/);
      return true;
    },
  );
  fs.writeFileSync(inPath, generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' }));
  fs.symlinkSync(inPath, linkPath);
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'anonymize', linkPath]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /REPORT_DIFF_SYMLINK_REFUSED/);
      return true;
    },
  );
});

test('CLI: the input file is read-only (bytes and mtime unchanged)', async (t) => {
  const dir = await makeTempDir(t, 'sentinel-anonymize-');
  const inPath = path.join(dir, 'report.json');
  const content = generateReport(ALL, { programName: PROGRAM, generatedAt: GENERATED_AT, format: 'json' });
  fs.writeFileSync(inPath, content);
  const beforeBytes = fs.readFileSync(inPath, 'utf8');
  const beforeMtime = fs.statSync(inPath).mtimeMs;
  await execFileAsync(process.execPath, [CLI, 'report', 'anonymize', inPath]);
  assert.equal(fs.readFileSync(inPath, 'utf8'), beforeBytes);
  assert.equal(fs.statSync(inPath).mtimeMs, beforeMtime);
});

test('CLI: no file argument fails with the usage error', async (t) => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'report', 'anonymize']),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /report anonymize requires a report file/);
      return true;
    },
  );
});
