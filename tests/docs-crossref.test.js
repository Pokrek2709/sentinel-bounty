'use strict';

// Docs cross-reference guard (round 76, Phase 7): the documentation
// lists drifted silently for several rounds (round 75 F4: the SKILL.md
// See-list lacked the filter/stats/helpers-export/generated-at-helper
// doc links from rounds 71-74, and the SKILL.md command code block
// lacked ten usage lines plus the --allow-mixed-targets/--verifier
// flags). These tests pin the cross-references so a future round that
// adds a doc or a command and forgets the lists fails here instead of
// drifting.
//
// What is asserted (and what is deliberately NOT asserted):
// - Every docs/*.md file is listed in the docs index (docs/README.md).
//   The repo README is NOT a full index by design: it names the key
//   docs in prose and defers the full list to the docs index, so the
//   guard asserts the README links the docs index instead of naming
//   every doc.
// - Every docs/report-*.md file is referenced in SKILL.md (the report
//   paragraph's See-list is where report docs live), except files in
//   the NO_SKILL_ANCHOR allowlist (the audit meta-doc).
// - Every `report <subcommand>` in the CLI help appears in SKILL.md.
// - The SKILL.md command code block is exactly the CLI help usage
//   lines (same set, same flags). The help goes to stderr.
// - Every docs/<x>.md reference in docs/, README.md, SKILL.md, and
//   CHANGELOG.md resolves to a file that exists.
// - Every backticked `sentinel ...` usage span in docs/*.md uses only
//   flags the CLI help defines. (Hypothetical flags named in plain
//   prose, e.g. a future `--where` filter, and non-sentinel flags
//   like `rsync --delete` are not in backticked sentinel spans, so
//   they do not trip this test.)
// - Every docs/*.md file is either referenced in SKILL.md or in the
//   explicit NO_SKILL_ANCHOR allowlist below, with a stated reason.
//   A new doc must get a SKILL.md anchor or an explicit allowlist
//   entry with a reason — it cannot drift silently.

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const test = require('node:test');

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(__dirname, '..');
const DOCS_DIR = path.join(REPO_ROOT, 'docs');
const SKILL_MD = path.join(REPO_ROOT, 'skills', 'sentinel-bounty', 'SKILL.md');
const CLI = path.join(REPO_ROOT, 'bin', 'sentinel.js');

// Docs that have no SKILL.md anchor by deliberate decision, not by
// drift. Each entry states why; a doc added later must either gain a
// SKILL.md anchor or an entry here with a reason.
const NO_SKILL_ANCHOR = {
  // The index itself.
  'README.md': 'the docs index; it lists the docs, it is not listed by SKILL.md',
  // Meta-doc about this audit; no SKILL.md paragraph describes the docs audit.
  'report-docs-audit-v1.md': 'meta-doc about the docs cross-references; no SKILL.md paragraph describes the audit',
  // Dated snapshot, not operator reference.
  'implementation-status.md': 'phase-by-phase status snapshot as of 2026-11-21, not operator reference',
  // Sharing doc; linked from the repo README, its proper place.
  'github-prototype-readiness.md': 'sharing-readiness doc; linked from the repo README',
  // User-supplied lab evidence / PoC procedure; two capability docs are
  // already linked from the repo README.
  'muse-capability-evidence-2026-11-18.md': 'user-supplied lab evidence, not operator reference',
  'muse-capability-followup-2026-11-19.md': 'user-supplied lab evidence, not operator reference',
  'muse-capability-pgid-2026-11-20.md': 'user-supplied lab evidence, not operator reference',
  'muse-kill-switch-lab-evidence-2026-11-20.md': 'user-supplied lab evidence, not operator reference',
  'muse-wrapper-lab-followup-2026-11-20.md': 'user-supplied lab evidence, not operator reference',
  'muse-http-adapter-evidence-2026-11-21.md': 'user-supplied lab evidence, not operator reference',
  'muse-secure-vm-poc.md': 'PoC procedure; no SKILL.md paragraph describes the Secure VM feasibility study',
  // No SKILL.md paragraph describes the end-to-end pipeline as a whole.
  'pipeline-v1.md': 'end-to-end pipeline doc; no SKILL.md paragraph describes the pipeline as a whole',
  // Temporal/environmental CVSS metrics are not mentioned in SKILL.md prose.
  'cvss-temporal-environmental-v1.md': 'temporal/environmental metrics not mentioned in SKILL.md prose',
  // Lab HTTP adapter; no SKILL.md paragraph describes it.
  'local-http-adapter-v1.md': 'lab HTTP adapter; no SKILL.md paragraph describes it',
  // Implementer async-safety audit; no SKILL.md paragraph describes async safety.
  'pending-promise-audit-v1.md': 'implementer async-safety audit; no SKILL.md paragraph describes async safety',
};

async function listDocs() {
  const entries = await fs.readdir(DOCS_DIR);
  return entries.filter((name) => name.endsWith('.md')).sort();
}

async function readSkill() {
  return fs.readFile(SKILL_MD, 'utf8');
}

async function cliHelp() {
  // --help writes the usage block to stderr and exits 1 (the CLI's
  // usage-error path); the text is what matters here, not the code.
  try {
    const { stdout, stderr } = await execFileAsync('node', [CLI, '--help']);
    return `${stdout}\n${stderr}`;
  } catch (error) {
    return `${error.stdout || ''}\n${error.stderr || ''}`;
  }
}

function helpUsageLines(helpText) {
  return helpText
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('sentinel '))
    .map((line) => line.replace(/\s+/g, ' '));
}

function skillCodeBlockLines(skillText) {
  const blocks = [...skillText.matchAll(/```text\n([\s\S]*?)```/g)];
  assert.equal(blocks.length, 1, 'expected exactly one ```text code block in SKILL.md');
  return blocks[0][1]
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('sentinel '))
    .map((line) => line.replace(/\s+/g, ' '));
}

test('docs index: every docs/*.md file is listed in docs/README.md', async () => {
  const docs = await listDocs();
  const index = await fs.readFile(path.join(DOCS_DIR, 'README.md'), 'utf8');
  const listed = new Set([...index.matchAll(/\]\(([a-z0-9\-]+\.md)\)/g)].map((m) => m[1]));
  const missing = docs.filter((name) => name !== 'README.md' && !listed.has(name));
  assert.deepEqual(missing, [], `docs not listed in docs/README.md: ${missing.join(', ')}`);
  const dangling = [...listed].filter((name) => !docs.includes(name));
  assert.deepEqual(dangling, [], `docs/README.md lists files that do not exist: ${dangling.join(', ')}`);
});

test('repo README links the docs index', async () => {
  const readme = await fs.readFile(path.join(REPO_ROOT, 'README.md'), 'utf8');
  assert.match(readme, /docs\/README\.md/, 'README.md must link docs/README.md (the full docs index)');
});

test('SKILL.md references every docs/report-*.md file', async () => {
  const docs = await listDocs();
  const skill = await readSkill();
  const reportDocs = docs.filter(
    (name) => name.startsWith('report-') && !(name in NO_SKILL_ANCHOR),
  );
  const missing = reportDocs.filter((name) => !skill.includes(`docs/${name}`));
  assert.deepEqual(missing, [], `report docs not referenced in SKILL.md: ${missing.join(', ')}`);
});

test('SKILL.md mentions every report subcommand in the CLI help', async () => {
  const helpText = await cliHelp();
  const skill = await readSkill();
  const subcommands = new Set();
  for (const line of helpUsageLines(helpText)) {
    const m = line.match(/^sentinel report ([a-z]+) /);
    if (m) subcommands.add(m[1]);
  }
  assert.ok(subcommands.size > 0, 'expected report subcommands in CLI help');
  const missing = [...subcommands].filter((sub) => !skill.includes(`sentinel report ${sub}`));
  assert.deepEqual(missing, [], `report subcommands missing from SKILL.md: ${missing.join(', ')}`);
});

test('SKILL.md command code block matches the CLI help usage lines', async () => {
  const helpText = await cliHelp();
  const skill = await readSkill();
  const expected = [...new Set(helpUsageLines(helpText))].sort();
  const actual = [...new Set(skillCodeBlockLines(skill))].sort();
  assert.deepEqual(actual, expected, 'SKILL.md code block must list exactly the CLI help usage lines');
});

test('every docs/<x>.md reference resolves to an existing file', async () => {
  const docs = await listDocs();
  const existing = new Set(docs);
  const files = [
    path.join(REPO_ROOT, 'README.md'),
    SKILL_MD,
    path.join(REPO_ROOT, 'CHANGELOG.md'),
    ...docs.map((name) => path.join(DOCS_DIR, name)),
  ];
  const broken = [];
  for (const file of files) {
    const text = await fs.readFile(file, 'utf8');
    for (const ref of [...text.matchAll(/docs\/([a-z0-9\-]+\.md)/g)].map((m) => m[1])) {
      if (!existing.has(ref)) broken.push(`${path.basename(file)}: docs/${ref}`);
    }
    // Relative links inside docs/ (e.g. [x](other-doc.md), [../README.md]).
    if (file.startsWith(DOCS_DIR)) {
      for (const ref of [...text.matchAll(/\]\(([^)]+)\)/g)].map((m) => m[1])) {
        const target = ref.split('#')[0];
        if (!target || /^(https?:|mailto:)/.test(target)) continue;
        const resolved = path.normalize(path.join(DOCS_DIR, target));
        try {
          await fs.stat(resolved);
        } catch {
          broken.push(`${path.basename(file)}: ${target}`);
        }
      }
    }
  }
  assert.deepEqual(broken, [], `broken doc references: ${broken.join('; ')}`);
});

test('backticked sentinel usage spans in docs use only real CLI flags', async () => {
  const helpText = await cliHelp();
  const helpFlags = new Set([...helpText.matchAll(/--[a-z][a-z0-9\-]*/g)].map((m) => m[0]));
  const docs = await listDocs();
  const bad = [];
  for (const name of docs) {
    const text = await fs.readFile(path.join(DOCS_DIR, name), 'utf8');
    for (const span of [...text.matchAll(/`([^`]*sentinel [^`]*)`/g)].map((m) => m[1])) {
      for (const flag of [...span.matchAll(/--[a-z][a-z0-9\-]*/g)].map((m) => m[0])) {
        if (!helpFlags.has(flag)) bad.push(`${name}: ${flag} in \`${span.slice(0, 80)}\``);
      }
    }
  }
  assert.deepEqual(bad, [], `unknown flags in docs usage spans: ${bad.join('; ')}`);
});

test('every docs/*.md file has a SKILL.md anchor or an explicit allowlist entry', async () => {
  const docs = await listDocs();
  const skill = await readSkill();
  const unanchored = docs.filter((name) => !skill.includes(`docs/${name}`) && !(name in NO_SKILL_ANCHOR));
  assert.deepEqual(
    unanchored,
    [],
    `docs with neither a SKILL.md anchor nor an allowlist reason: ${unanchored.join(', ')}`,
  );
  const staleAllowlist = Object.keys(NO_SKILL_ANCHOR).filter((name) => !docs.includes(name));
  assert.deepEqual(staleAllowlist, [], `allowlist entries with no such doc: ${staleAllowlist.join(', ')}`);
});
