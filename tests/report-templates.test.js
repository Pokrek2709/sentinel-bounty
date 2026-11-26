const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport } = require('../src/report/generator');
const { listTemplates, loadTemplate, renderTemplateReport } = require('../src/report/templates');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

const critical = () => loadFixture('report-critical.json');
const medium = () => loadFixture('report-medium.json');
const findingsArray = () => loadFixture('report-findings-array.json');

test('listTemplates returns the data-file templates, sorted', () => {
  assert.deepEqual(listTemplates(), ['code4rena', 'hackerone', 'immunefi']);
});

test('loadTemplate loads the template from its data file, not from code', () => {
  for (const name of ['immunefi', 'code4rena', 'hackerone']) {
    const fromDisk = JSON.parse(fs.readFileSync(
      path.resolve(__dirname, '..', 'knowledge', 'report-templates', `${name}.json`), 'utf8',
    ));
    assert.deepEqual(loadTemplate(name), fromDisk);
  }
});

test('loadTemplate rejects unknown names with the available list', () => {
  assert.throws(() => loadTemplate('nosuch'), /Unknown report template: "nosuch" \(available: code4rena, hackerone, immunefi\)/);
  assert.throws(() => loadTemplate(''), /Unknown report template/);
});

test('loadTemplate rejects a name that tries to escape the templates directory', () => {
  assert.throws(() => loadTemplate('../finding'), /Unknown report template/);
  assert.throws(() => loadTemplate('..\\finding'), /Unknown report template/);
});

test('immunefi markdown has the platform sections in order', () => {
  const report = generateReport([critical()], { ...OPTIONS, template: 'immunefi' });
  assert.match(report, /^# SQL injection in login username parameter \[CRITICAL\]/m);
  assert.match(report, /- \*\*Severity:\*\* critical/);
  assert.match(report, /- \*\*CVSS:\*\* 9\.8 \(CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:H\/A:H\)/);
  assert.match(report, /- \*\*CWE:\*\* CWE-89/);
  assert.match(report, /- \*\*Program:\*\* Lab Program/);
  const headings = [...report.matchAll(/^## (.+)$/gm)].map((match) => match[1]);
  assert.deepEqual(headings, ['Vulnerability Details', 'Proof of Concept', 'Impact', 'Recommendation', 'References']);
  // NOTE (round 35): the fixture's PoC reads "password=x => HTTP 200 ..."
  // in its real bytes (sha256 41a59c18...); tool output displays the
  // credential-looking value as "<redacted>". Assert on the real bytes.
  assert.match(report, /POST \/login username=' OR 1=1 -- password=x => HTTP 200 with session cookie for user id 1\./);
  assert.match(report, /1\. Send a POST request to \/login/);
  assert.match(report, /Evidence 1:/);
  assert.match(report, /Full authentication bypass/);
  assert.match(report, /Use parameterized queries/);
  assert.match(report, /- https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html/);
});

test('code4rena markdown has its own headings and the same finding data', () => {
  const report = generateReport([critical()], { ...OPTIONS, template: 'code4rena' });
  assert.match(report, /^# SQL injection in login username parameter \[CRITICAL\]/m);
  const headings = [...report.matchAll(/^## (.+)$/gm)].map((match) => match[1]);
  assert.deepEqual(headings, ['Description', 'Proof of Concept', 'Impact', 'Recommended Mitigation', 'Links']);
  assert.match(report, /The login endpoint concatenates/);
  assert.match(report, /Use parameterized queries/);
  assert.match(report, /- https:\/\/www\.first\.org\/cvss\/v3\.1\/specification-document/);
});

test('hackerone markdown has its own headings and the same finding data', () => {
  const report = generateReport([critical()], { ...OPTIONS, template: 'hackerone' });
  assert.match(report, /^# SQL injection in login username parameter \[CRITICAL\]/m);
  assert.match(report, /- \*\*Severity:\*\* critical/);
  assert.match(report, /- \*\*CVSS:\*\* 9\.8 \(CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:H\/A:H\)/);
  assert.match(report, /- \*\*Program:\*\* Lab Program/);
  const headings = [...report.matchAll(/^## (.+)$/gm)].map((match) => match[1]);
  assert.deepEqual(headings, ['Vulnerability Description', 'Steps to Reproduce', 'Impact', 'Recommended Fix', 'Supporting Material']);
  assert.match(report, /The login endpoint concatenates/);
  assert.match(report, /POST \/login username=' OR 1=1 -- password=x => HTTP 200 with session cookie for user id 1\./);
  assert.match(report, /1\. Send a POST request to \/login/);
  assert.match(report, /Evidence 1:/);
  assert.match(report, /Full authentication bypass/);
  assert.match(report, /Use parameterized queries/);
  assert.match(report, /- https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html/);
});

test('template rendering is deterministic: same input, byte-identical output', () => {
  for (const template of ['immunefi', 'code4rena', 'hackerone']) {
    const first = generateReport([critical()], { ...OPTIONS, template });
    const second = generateReport([critical()], { ...OPTIONS, template });
    assert.equal(first, second);
    const firstJson = generateReport([critical()], { ...OPTIONS, template, format: 'json' });
    const secondJson = generateReport([critical()], { ...OPTIONS, template, format: 'json' });
    assert.equal(firstJson, secondJson);
  }
});

test('a finding without proof_of_concept fails all templates with a named field', () => {
  // The medium fixture is schema-valid but carries no proof_of_concept.
  // Immunefi and Code4rena require it for "Proof of Concept"; HackerOne
  // requires it for "Steps to Reproduce".
  const sections = { immunefi: 'Proof of Concept', code4rena: 'Proof of Concept', hackerone: 'Steps to Reproduce' };
  for (const template of ['immunefi', 'code4rena', 'hackerone']) {
    assert.throws(
      () => generateReport([medium()], { ...OPTIONS, template }),
      /Template "immunefi"|Template "code4rena"|Template "hackerone"/,
    );
    assert.throws(
      () => generateReport([medium()], { ...OPTIONS, template }),
      new RegExp(`requires field\\(s\\) "proof_of_concept" for section "${sections[template]}"`),
    );
  }
});

test('a finding without references renders fine and omits the optional section', () => {
  const finding = critical();
  delete finding.references;
  const immunefi = generateReport([finding], { ...OPTIONS, template: 'immunefi' });
  assert.doesNotMatch(immunefi, /^## References$/m);
  assert.match(immunefi, /## Recommendation/);
  const code4rena = generateReport([finding], { ...OPTIONS, template: 'code4rena' });
  assert.doesNotMatch(code4rena, /^## Links$/m);
  assert.match(code4rena, /## Recommended Mitigation/);
});

test('a finding without a CVSS score renders the template without a CVSS line', () => {
  const finding = critical();
  delete finding.cvss_score;
  delete finding.cvss_vector;
  const report = generateReport([finding], { ...OPTIONS, template: 'immunefi' });
  assert.doesNotMatch(report, /\*\*CVSS:\*\*/);
  assert.match(report, /- \*\*CWE:\*\* CWE-89/);
});

test('a template with more than one finding fails with the one-finding rule', () => {
  assert.throws(
    () => generateReport(findingsArray(), { ...OPTIONS, template: 'immunefi' }),
    /Template "immunefi" renders one finding per report; got 3 findings/,
  );
});

test('JSON output with a template keeps the generic shape and names the template', () => {
  const parsed = JSON.parse(generateReport([critical()], { ...OPTIONS, template: 'immunefi', format: 'json' }));
  for (const key of ['report_id', 'program_name', 'generated_at', 'executive_summary', 'findings_summary', 'findings']) {
    assert.ok(key in parsed, `missing required key: ${key}`);
  }
  assert.equal(parsed.template, 'immunefi');
  assert.equal(parsed.findings.length, 1);
  assert.match(parsed.report_id, /^RPT-[0-9a-f]{12}$/);
  const generic = JSON.parse(generateReport([critical()], { ...OPTIONS, format: 'json' }));
  assert.equal(generic.report_id, parsed.report_id);
  assert.ok(!('template' in generic), 'generic JSON must not carry a template field');
});

test('JSON output with the hackerone template names the template', () => {
  const parsed = JSON.parse(generateReport([critical()], { ...OPTIONS, template: 'hackerone', format: 'json' }));
  for (const key of ['report_id', 'program_name', 'generated_at', 'executive_summary', 'findings_summary', 'findings']) {
    assert.ok(key in parsed, `missing required key: ${key}`);
  }
  assert.equal(parsed.template, 'hackerone');
  assert.equal(parsed.findings.length, 1);
  const generic = JSON.parse(generateReport([critical()], { ...OPTIONS, format: 'json' }));
  assert.equal(generic.report_id, parsed.report_id);
});

test('the generic template is unchanged when no --template is given', () => {
  const report = generateReport(findingsArray(), OPTIONS);
  assert.match(report, /# Bug Bounty Report — Lab Program/);
  assert.match(report, /## Summary/);
  assert.match(report, /## 1\. SQL injection in login username parameter \[CRITICAL\]/);
  const explicit = generateReport([critical()], { ...OPTIONS, template: 'generic' });
  assert.match(explicit, /# Bug Bounty Report — Lab Program/);
});

test('renderTemplateReport never invents a wall-clock time', () => {
  const finding = critical();
  delete finding.created_at;
  const report = renderTemplateReport(loadTemplate('immunefi'), finding, { programName: 'Lab' });
  assert.match(report, /- \*\*Generated:\*\* Not specified/);
});

test('CLI report --template immunefi prints the platform sections', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
    '--template', 'immunefi', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
  ]);
  assert.match(stdout, /^# SQL injection in login username parameter \[CRITICAL\]/m);
  assert.match(stdout, /## Vulnerability Details/);
  assert.match(stdout, /## Recommendation/);
});

test('CLI report --template hackerone prints the platform sections', async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
    '--template', 'hackerone', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
  ]);
  assert.match(stdout, /^# SQL injection in login username parameter \[CRITICAL\]/m);
  assert.match(stdout, /## Vulnerability Description/);
  assert.match(stdout, /## Steps to Reproduce/);
  assert.match(stdout, /## Recommended Fix/);
  assert.match(stdout, /## Supporting Material/);
});

test('CLI report --template code4rena --format json --out writes JSON naming the template', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-template-'));
  try {
    const output = path.join(directory, 'report.json');
    const { stdout } = await execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
      '--template', 'code4rena', '--format', 'json', '--program', 'Lab Program',
      '--generated-at', '2026-11-26T02:00:00.000Z', '--out', output,
    ]);
    assert.match(stdout, /Report written to/);
    const parsed = JSON.parse(fs.readFileSync(output, 'utf8'));
    assert.equal(parsed.template, 'code4rena');
    assert.equal(parsed.findings.length, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI report with an unknown template exits non-zero', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
      '--template', 'nosuch',
    ]),
    (error) => {
      assert.match(error.stderr, /Unknown report template: "nosuch" \(available: code4rena, hackerone, immunefi\)/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
});

test('CLI report with --findings and a template exits non-zero and writes nothing', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-template-'));
  try {
    const output = path.join(directory, 'report.md');
    await assert.rejects(
      execFileAsync(process.execPath, [
        CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
        '--template', 'immunefi', '--out', output,
      ]),
      (error) => {
        assert.match(error.stderr, /renders one finding per report; got 3 findings/);
        assert.notEqual(error.code, 0);
        return true;
      },
    );
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI report with a finding lacking a proof of concept fails for the template', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [
      CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-medium.json'),
      '--template', 'code4rena',
    ]),
    (error) => {
      assert.match(error.stderr, /requires field\(s\) "proof_of_concept" for section "Proof of Concept"/);
      assert.notEqual(error.code, 0);
      return true;
    },
  );
});
