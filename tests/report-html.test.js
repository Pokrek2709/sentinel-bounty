// Standalone HTML report export (round 44): `sentinel report --format
// html` renders the same grouped findings as Markdown/JSON into one
// self-contained HTML file — inline CSS only, no JavaScript, no
// external resources. Finding content is untrusted, so every
// interpolated value must be HTML-escaped; reference URLs render as
// inert text, never as links. Fixtures only; no scanner, no network,
// no live target.
'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const { generateReport, escapeHtml } = require('../src/report/generator');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '..', 'bin', 'sentinel.js');
const OPTIONS = { programName: 'Lab Program', generatedAt: '2026-11-26T02:00:00.000Z' };

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

test('escapeHtml escapes all five HTML-special characters', () => {
  assert.equal(escapeHtml('<a href="x">&\'y\'</a>'), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;y&#39;&lt;/a&gt;');
  assert.equal(escapeHtml('plain text'), 'plain text');
});

test('HTML contains every finding title and id', () => {
  const html = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'html' });
  for (const finding of loadFixture('report-findings-array.json')) {
    assert.ok(html.includes(escapeHtml(finding.title)), `title present: ${finding.finding_id}`);
    assert.ok(html.includes(finding.finding_id), `id present: ${finding.finding_id}`);
  }
  assert.match(html, /<!DOCTYPE html>/);
  assert.match(html, /<title>Bug Bounty Report — Lab Program<\/title>/);
  assert.match(html, /Report ID: RPT-/);
  assert.match(html, /Generated: 2026-11-26T02:00:00.000Z/);
});

test('HTML grouping order matches Markdown for the same input', () => {
  const array = loadFixture('report-findings-array.json');
  const [critical, medium, low] = array;
  const input = [
    { ...clone(critical), asset_id: 'zeta-app' },
    { ...clone(medium), asset_id: 'alpha-app' },
    { ...clone(low), asset_id: 'alpha-app' },
  ];
  const html = generateReport(input, { ...OPTIONS, format: 'html' });
  const markdown = generateReport(input, OPTIONS);
  const htmlAlpha = html.indexOf('Asset: alpha-app');
  const htmlZeta = html.indexOf('Asset: zeta-app');
  const mdAlpha = markdown.indexOf('## Asset: alpha-app');
  const mdZeta = markdown.indexOf('## Asset: zeta-app');
  assert.ok(htmlAlpha !== -1 && htmlZeta !== -1, 'both asset sections are present in HTML');
  assert.ok(htmlAlpha < htmlZeta, 'alpha-app group renders before zeta-app in HTML');
  assert.ok((htmlAlpha < htmlZeta) === (mdAlpha < mdZeta), 'HTML and Markdown agree on group order');
  // Within alpha-app, the medium finding renders before the low one.
  assert.ok(html.indexOf('FND-MED-001') < html.indexOf('FND-LOW-001'), 'severity order inside a group');
  // Global finding numbers run across groups, like Markdown.
  assert.match(html, /1\. .*FND-MED-001/s);
  assert.match(html, /2\. .*FND-LOW-001/s);
  assert.match(html, /3\. .*FND-CRIT-001/s);
  // Severity summary and evidence checklist render per finding.
  assert.match(html, /Asset: alpha-app — 2 findings \(critical: 0, high: 0, medium: 1, low: 1, informational: 0\)/);
  assert.match(html, /Evidence Checklist/);
  assert.match(html, /\[x\] response_log \(required\)/);
});

test('HTML is deterministic: same findings in any input order produce byte-identical output', () => {
  const array = loadFixture('report-findings-array.json');
  const first = generateReport(array, { ...OPTIONS, format: 'html' });
  const second = generateReport([...array].reverse(), { ...OPTIONS, format: 'html' });
  assert.equal(sha256(first), sha256(second), 'reversed input order must not change the output');
  assert.equal(first, second);
});

test('HTML escapes hostile finding content: no executable markup, no fetchable references', () => {
  const hostile = clone(loadFixture('report-critical.json'));
  hostile.title = '<script>alert(1)</script> SQL injection';
  hostile.asset_id = 'x" onmouseover="alert(1)';
  hostile.description = 'Payload <img src=x onerror=alert(1)> rendered here.';
  hostile.references = ['javascript:alert(1)', 'https://evil.example.internal/steal'];
  hostile.proof_of_concept = '"><svg onload=alert(1)>';
  const html = generateReport([hostile], { ...OPTIONS, format: 'html' });
  // The hostile strings are visible as inert text, escaped.
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'script tag escaped');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'img tag escaped');
  assert.ok(html.includes('x&quot; onmouseover=&quot;alert(1)'), 'attribute-breaking quote escaped');
  assert.ok(html.includes('&quot;&gt;&lt;svg onload=alert(1)&gt;'), 'svg payload escaped');
  // Nothing in the file can execute or fetch. The precise check is
  // tag-based: every tag in the output must be one the generator
  // itself emits, and no tag may carry an href/src attribute. The
  // hostile strings survive only as escaped text (so `onerror`,
  // `onload`, `src=` and `javascript:` still appear as inert text
  // inside `&lt;...&gt;` — that is expected, not a hole: a browser
  // renders them as text, never as markup). References render as
  // plain text, never as links.
  const tags = [...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g)];
  const allowedTags = new Set(['html', 'head', 'meta', 'title', 'style', 'body', 'h1', 'h2', 'h3', 'h4', 'p', 'table', 'tr', 'th', 'td', 'dl', 'dt', 'dd', 'ol', 'ul', 'li', 'article', 'span']);
  for (const tag of tags) {
    assert.ok(allowedTags.has(tag[1].toLowerCase()), `unexpected tag in output: ${tag[0]}`);
    assert.ok(!/href\s*=|src\s*=/.test(tag[0]), `fetchable attribute in tag: ${tag[0]}`);
  }
  assert.ok(!html.includes('<script'), 'no script element');
  assert.ok(!html.includes('<img'), 'no img element');
  assert.ok(!html.includes('<svg'), 'no svg element');
  assert.ok(!html.includes('<iframe'), 'no iframe element');
  assert.ok(!html.includes('<link'), 'no link element');
  assert.ok(!html.includes('@import'), 'no CSS import');
  assert.ok(!html.includes('url('), 'no CSS url()');
  // The reference URLs appear only as inert text: the https URL is in
  // the file (it is a reference, not a fetched resource), but no tag
  // or attribute can make the browser fetch it.
  assert.ok(html.includes('https://evil.example.internal/steal'), 'reference URL visible as text');
  assert.ok(html.includes('javascript:alert(1)'), 'javascript: reference visible as inert text only');
});

test('HTML has no JavaScript and no external resources on the clean fixtures', () => {
  const html = generateReport(loadFixture('report-findings-array.json'), { ...OPTIONS, format: 'html' });
  assert.ok(!html.includes('<script'), 'no script element');
  assert.ok(!html.includes('href='), 'no href attribute');
  assert.ok(!html.includes('src='), 'no src attribute');
  assert.ok(!html.includes('@import'), 'no CSS import');
  assert.ok(!html.includes('url('), 'no CSS url()');
  assert.match(html, /<style>/, 'inline style block present');
});

test('HTML carries CVSS temporal and environmental scores where present', () => {
  const finding = clone(loadFixture('report-critical.json'));
  finding.cvss_temporal_score = 9.1;
  finding.cvss_environmental_score = 8.4;
  const html = generateReport([finding], { ...OPTIONS, format: 'html' });
  assert.match(html, /CVSS temporal<\/dt><dd>9\.1<\/dd>/);
  assert.match(html, /CVSS environmental<\/dt><dd>8\.4<\/dd>/);
});

test('Markdown and JSON output are unchanged by the HTML addition (golden hashes)', () => {
  const findings = loadFixture('report-findings-array.json');
  const markdown = generateReport(findings, OPTIONS);
  const json = generateReport(findings, { ...OPTIONS, format: 'json' });
  // Hashes captured from the pre-change generator (round 43, commit
  // c3bec85): adding a format must not move a byte of the old ones.
  assert.equal(sha256(markdown), 'df1c6adc7892f3afc6fb2b7dc4a3a6831fa241a037c291b2ea6295d1d4ea1779', 'markdown unchanged');
  assert.equal(sha256(json), '82e08ebb92bfaa7d61aaa3fe50407b2c0fe5f40550a5294674cf7657a0c515bf', 'json unchanged');
});

test('generateReport rejects a platform template with HTML output', () => {
  assert.throws(
    () => generateReport([loadFixture('report-critical.json')], { ...OPTIONS, format: 'html', template: 'immunefi' }),
    /renders Markdown only/,
  );
});

test('CLI report --format html --out writes a self-contained file', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-report-html-'));
  try {
    const output = path.join(directory, 'report.html');
    const { stdout } = await execFileAsync(process.execPath, [
      CLI, 'report', '--findings', path.join(__dirname, 'fixtures', 'report-findings-array.json'),
      '--format', 'html', '--program', 'Lab Program', '--generated-at', '2026-11-26T02:00:00.000Z',
      '--out', output,
    ]);
    assert.match(stdout, /Report written to/);
    const html = fs.readFileSync(output, 'utf8');
    assert.match(html, /<!DOCTYPE html>/);
    assert.ok(html.includes('FND-CRIT-001') && html.includes('FND-MED-001') && html.includes('FND-LOW-001'));
    assert.ok(!html.includes('<script'), 'no script element in the written file');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI report --format html --template immunefi fails cleanly and writes no file', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-report-html-'));
  try {
    const output = path.join(directory, 'report.html');
    await assert.rejects(
      execFileAsync(process.execPath, [
        CLI, 'report', '--finding', path.join(__dirname, 'fixtures', 'report-critical.json'),
        '--format', 'html', '--template', 'immunefi', '--out', output,
      ]),
      (error) => {
        assert.match(error.stderr, /renders Markdown only/);
        assert.notEqual(error.code, 0);
        return true;
      },
    );
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
