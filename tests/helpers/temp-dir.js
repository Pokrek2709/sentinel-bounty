'use strict';

// Shared temp-dir helper for tests (round 46, Phase 8).
//
// Problem: test files created temp dirs with `fs.mkdtemp` and removed
// them at the end of the test body. Any assertion that threw before the
// removal left the dir behind; files with no removal at all leaked on
// every run. Over rounds 34-45 that accumulated ~1,700 dirs in /tmp
// (512M tmpfs) and filled it twice (rounds 39 and 45).
//
// Fix: register the removal with `t.after()`, which node:test runs when
// the test ends — including when the test fails. Callers keep no
// cleanup code of their own; the helper owns it. Existing end-of-test
// `fs.rm` calls were left in place as early cleanup (they are
// force:true, so the later `t.after` removal is a no-op).
//
// Sync tests that already clean up in a `try...finally` (report
// generator/html/templates, pipeline-integration, evidence-checklists)
// were left untouched — they are already failure-safe.
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

async function makeTempDir(t, prefix) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });
  return dir;
}

module.exports = { makeTempDir };
