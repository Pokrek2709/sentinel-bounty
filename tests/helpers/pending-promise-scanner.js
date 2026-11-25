// Syntactic guard against fire-and-forget promises (round 47).
//
// This is NOT a data-flow analysis: it scans src/ and bin/ for four
// syntactic patterns that have bitten this codebase before and
// requires each occurrence to be either awaited or allowlisted:
//
//   A. `unregister()` called without `await` — the async
//      PersistentKillSwitch.unregisterWorker write. (Round 46's drill
//      flake and round 47's adapter race were both this.)
//   B. `.then(` — a promise chain that must have its rejection
//      handled (both handlers, or a chained .catch()).
//   C. `setTimeout(async` / `setInterval(async` — an async timer
//      callback whose rejection would escape unhandled (there is no
//      unhandledRejection handler anywhere in src/ or bin/).
//   D. `finishRun(` called without `await` or `void` — the adapter's
//      never-rejecting finisher; synchronous call sites must mark
//      the call `void` explicitly.
//
// The allowlist (tests/pending-promise-allowlist.json) excuses an
// occurrence with a stated reason. The guard fails if an occurrence
// has no allowlist entry, or if an allowlist entry matches nothing
// (stale — the code moved on, so the excuse must go too).
//
// Known limits, stated honestly: comment stripping is quote-aware
// but does not understand `${}` inside template literals; a
// `//` inside a template literal can confuse it. Awaited calls
// spread over two lines (`await\n  foo()`) are not recognised as
// awaited. The guard is a tripwire for the common shapes, not a
// proof — code review still owns the unusual ones.
'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

function stripComments(source) {
  const withoutBlocks = source.replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, ' '));
  return withoutBlocks.split('\n').map((line) => {
    let inSingle = false;
    let inDouble = false;
    let inTemplate = false;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const ch = line[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        continue;
      }
      if (ch === "'" && !inDouble && !inTemplate) inSingle = !inSingle;
      else if (ch === '"' && !inSingle && !inTemplate) inDouble = !inDouble;
      else if (ch === '`' && !inSingle && !inDouble) inTemplate = !inTemplate;
      else if (ch === '/' && line[index + 1] === '/' && !inSingle && !inDouble && !inTemplate) return line.slice(0, index);
    }
    return line;
  }).join('\n');
}

async function listJsFiles(root) {
  const found = [];
  async function walk(directory) {
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const entry of entries) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && entry.name.endsWith('.js')) found.push(full);
    }
  }
  await walk(path.join(root, 'src'));
  await walk(path.join(root, 'bin'));
  return found.sort();
}

function scanText(relativeFile, source) {
  const occurrences = [];
  const lines = stripComments(source).split('\n');
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    if (line.includes('new Promise(async')) {
      occurrences.push({ file: relativeFile, line: lineNumber, kind: 'async-executor', text: line.trim() });
    }
    const unregisterIndex = line.indexOf('unregister()');
    if (unregisterIndex !== -1) {
      const before = line.slice(0, unregisterIndex);
      const isDefinition = /unregister\s*[:=]/.test(line) || /^\s*(let|const|var)\s+unregister\b/.test(line);
      if (!isDefinition && !before.includes('await')) {
        occurrences.push({ file: relativeFile, line: lineNumber, kind: 'bare-unregister', text: line.trim() });
      }
    }
    const finishIndex = line.indexOf('finishRun(');
    if (finishIndex !== -1) {
      const before = line.slice(0, finishIndex);
      const isDefinition = /finishRun\s*=/.test(line);
      if (!isDefinition && !before.includes('await') && !before.includes('void')) {
        occurrences.push({ file: relativeFile, line: lineNumber, kind: 'bare-finish-run', text: line.trim() });
      }
    }
    if (line.includes('.then(')) {
      occurrences.push({ file: relativeFile, line: lineNumber, kind: 'then', text: line.trim() });
    }
    if (line.includes('setTimeout(async') || line.includes('setInterval(async')) {
      occurrences.push({ file: relativeFile, line: lineNumber, kind: 'timer', text: line.trim() });
    }
  });
  return occurrences;
}

async function scanPendingPromises(root, allowlist) {
  const files = await listJsFiles(root);
  const occurrences = [];
  for (const file of files) {
    const source = await fs.readFile(file, 'utf8');
    occurrences.push(...scanText(path.relative(root, file), source));
  }
  const matched = new Set();
  const violations = occurrences.filter((occurrence) => {
    const hit = allowlist.findIndex((entry) => entry.file === occurrence.file && entry.kind === occurrence.kind && occurrence.text.includes(entry.substring));
    if (hit !== -1) matched.add(hit);
    return hit === -1;
  });
  const stale = allowlist.filter((_, index) => !matched.has(index));
  return { violations, stale };
}

module.exports = { scanPendingPromises, scanText, stripComments };
