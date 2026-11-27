// Windows simulation guard (round 99).
//
// Rounds 91-98 ran the simulation with a /tmp preload, and nothing in
// the repo proved the simulation was actually faking the platform: a
// stale or missing /tmp copy would have run the suite as plain Linux
// and the "win32 simulation" numbers would have been Linux numbers.
// These tests pin both halves: the committed preload really overrides
// process.platform, and a simulated run really reads 'win32'.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const REPO_ROOT = path.resolve(__dirname, '..');
const PRELOAD = path.join(REPO_ROOT, 'scripts', 'fake-win32.cjs');

test('committed win32 preload exists and overrides process.platform to win32', () => {
  const content = fs.readFileSync(PRELOAD, 'utf8');
  assert.match(content, /Object\.defineProperty\(process, 'platform', \{ value: 'win32' \}\)/);
  assert.match(content, /SENTINEL_WIN32_SIM/);
});

test('under the win32 simulation, process.platform reads win32', { skip: process.env.SENTINEL_WIN32_SIM !== '1' }, () => {
  assert.equal(process.platform, 'win32');
  assert.equal(process.env.SENTINEL_WIN32_SIM, '1');
});
