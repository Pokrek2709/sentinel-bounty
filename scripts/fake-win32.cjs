// Windows simulation preload (round 99).
//
// Rounds 91-98 ran the Windows simulation with a one-line preload kept
// in /tmp (/tmp/fake-win32.cjs): `Object.defineProperty(process,
// 'platform', { value: 'win32' })`. /tmp is wiped on every VM restart,
// so round 95 had to rebuild the file mid-round before the simulation
// could run at all — and nothing in the repo recorded which file the
// simulation used, so a stale or missing /tmp copy would have run the
// suite as plain Linux and proved nothing about Windows branching.
// This is the committed copy: CI (.github/workflows/ci-guards.yml)
// and operators use this path, never /tmp. The `verify-install`
// ci-guards check and tests/ci-guards.test.js pin that the workflow
// references this file.
//
// The preload also sets SENTINEL_WIN32_SIM=1 so tests can tell a
// simulated run from a real one (tests/win32-sim.test.js asserts
// process.platform reads 'win32' only when the marker is set).
'use strict';

Object.defineProperty(process, 'platform', { value: 'win32' });
process.env.SENTINEL_WIN32_SIM = '1';
