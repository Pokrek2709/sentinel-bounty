// Windows CI log archiver tests (round 99).
//
// The archiver turns the round 91-92 hand procedure (download a run's
// logs zip, extract it as logs_<check_suite_id>-<shortsha>/) into a
// command. The pure pieces (URLs, folder name, rate-limit
// classification) are unit-tested, and the download+extract path is
// tested against a local stub GitHub API serving the committed
// fixture zip — no network, no token, no real run.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsPromises = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');

const { makeTempDir } = require('./helpers/temp-dir');
const {
  buildRunUrl, buildLogsUrl, archiveFolderName, classifyApiError, downloadAndExtract,
} = require('../scripts/fetch-windows-logs.cjs');

const REPO = 'Pokrek2709/sentinel-bounty';
const RUN_ID = '46052614644';
const META = {
  id: 46052614644,
  head_sha: 'fd4ed995b48ee409ad5d8064a71528b1e73bfae5',
  check_suite_id: 124588672723,
  status: 'completed',
  conclusion: 'success',
};

test('log archiver: URLs and folder name follow the archive convention', () => {
  assert.equal(buildRunUrl('https://api.github.com', REPO, RUN_ID), `https://api.github.com/repos/${REPO}/actions/runs/${RUN_ID}`);
  assert.equal(buildLogsUrl('https://api.github.com', REPO, RUN_ID), `https://api.github.com/repos/${REPO}/actions/runs/${RUN_ID}/logs`);
  assert.equal(archiveFolderName(124588672723, 'fd4ed995b48ee409ad5d8064a71528b1e73bfae5'), 'logs_124588672723-fd4ed99');
});

test('log archiver: rate-limit classification reads the quota headers', () => {
  const limited = classifyApiError(403, new Headers({ 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1790000000' }));
  assert.equal(limited.code, 'RATE_LIMITED');
  assert.match(limited.detail, /rate limit/i);
  assert.match(limited.detail, /GITHUB_TOKEN/);
  assert.equal(classifyApiError(403, new Headers({ 'x-ratelimit-remaining': '59' })).code, 'HTTP_403');
  assert.equal(classifyApiError(404, new Headers()).code, 'RUN_NOT_FOUND');
});

function stubApi(t, handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      t.after(() => new Promise((done) => server.close(done)));
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
    server.on('error', reject);
  });
}

test('log archiver: stub API run downloads and extracts into the archive folder', async (t) => {
  const fixture = await fsPromises.readFile(path.join(__dirname, 'fixtures', 'logs-sample.zip'));
  const apiBase = await stubApi(t, (req, res) => {
    if (req.url === `/repos/${REPO}/actions/runs/${RUN_ID}`) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(META));
    } else if (req.url === `/repos/${REPO}/actions/runs/${RUN_ID}/logs`) {
      res.writeHead(302, { Location: '/files/logs.zip' });
      res.end();
    } else if (req.url === '/files/logs.zip') {
      res.writeHead(200, { 'Content-Type': 'application/zip' });
      res.end(fixture);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  const outDir = await makeTempDir(t, 'sentinel-logs-');
  const record = await downloadAndExtract({ runId: RUN_ID, outDir, apiBase, repo: REPO });
  assert.equal(record.folder, 'logs_124588672723-fd4ed99');
  assert.equal(record.conclusion, 'success');
  assert.equal(fs.readFileSync(path.join(record.dest, '0_test.txt'), 'utf8'), '2026-11-28T02:00:00.0000000Z sample log line\n');
  assert.equal(fs.readFileSync(path.join(record.dest, 'test', 'system.txt'), 'utf8'), 'sample system info\n');

  // A second archive of the same run is refused, not overwritten.
  await assert.rejects(
    downloadAndExtract({ runId: RUN_ID, outDir, apiBase, repo: REPO }),
    (error) => error.code === 'ARCHIVE_EXISTS',
  );
});

test('log archiver: a rate-limited run fails with RATE_LIMITED, an unknown run with RUN_NOT_FOUND', async (t) => {
  const apiBase = await stubApi(t, (req, res) => {
    if (req.url === `/repos/${REPO}/actions/runs/999`) {
      res.writeHead(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1790000000', 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'API rate limit exceeded' }));
    } else if (req.url === `/repos/${REPO}/actions/runs/123`) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Not Found' }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  const outDir = await makeTempDir(t, 'sentinel-logs-');
  await assert.rejects(
    downloadAndExtract({ runId: '999', outDir, apiBase, repo: REPO }),
    (error) => error.code === 'RATE_LIMITED',
  );
  await assert.rejects(
    downloadAndExtract({ runId: '123', outDir, apiBase, repo: REPO }),
    (error) => error.code === 'RUN_NOT_FOUND',
  );
});
