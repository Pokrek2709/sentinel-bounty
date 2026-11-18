const assert = require('node:assert/strict');
const test = require('node:test');
const { RequestGovernor } = require('../src/policy/request-governor');

function clockAt(initial = 0) {
  let now = initial;
  return { clock: () => now, advance: (milliseconds) => { now += milliseconds; } };
}

test('enforces token-bucket rate limiting per domain without consuming budget on denial', () => {
  const time = clockAt();
  const governor = new RequestGovernor({ requestsPerSecond: 1, concurrency: 2, requestBudget: 10, clock: time.clock });
  for (let index = 0; index < 5; index += 1) {
    const reservation = governor.acquire('app.example.test');
    assert.equal(reservation.allowed, true);
    governor.release(reservation.reservationId);
  }
  const limited = governor.acquire('app.example.test');
  assert.deepEqual(limited, { allowed: false, reason: 'RATE_LIMITED', domain: 'app.example.test', retryAfterMs: 1000 });
  assert.equal(governor.snapshot().requestsUsed, 5);
  time.advance(1_000);
  assert.equal(governor.acquire('app.example.test').allowed, true);
});

test('enforces session concurrency and releases only known reservations', () => {
  const governor = new RequestGovernor({ concurrency: 1, requestBudget: 10, clock: () => 0 });
  const first = governor.acquire('a.example.test');
  assert.equal(governor.acquire('b.example.test').reason, 'CONCURRENCY_LIMIT');
  assert.equal(governor.release('unknown'), false);
  assert.equal(governor.release(first.reservationId), true);
  assert.equal(governor.acquire('b.example.test').allowed, true);
});

test('warns at 80 percent, halts at budget exhaustion, and needs explicit renewal', () => {
  const time = clockAt();
  const governor = new RequestGovernor({ requestsPerSecond: 100, requestBudget: 5, clock: time.clock });
  for (let index = 0; index < 3; index += 1) {
    const reservation = governor.acquire('app.example.test');
    governor.release(reservation.reservationId);
    time.advance(10);
  }
  const fourth = governor.acquire('app.example.test');
  assert.deepEqual(fourth.warnings, ['REQUEST_BUDGET_80_PERCENT']);
  governor.release(fourth.reservationId);
  time.advance(10);
  const fifth = governor.acquire('app.example.test');
  governor.release(fifth.reservationId);
  assert.equal(governor.acquire('app.example.test').reason, 'REQUEST_BUDGET_EXHAUSTED');
  governor.renewBudget(6);
  assert.equal(governor.acquire('app.example.test').allowed, true);
});

test('backs off on server pressure and halts after three consecutive 429 or 503 responses', () => {
  const time = clockAt();
  const governor = new RequestGovernor({ clock: time.clock });
  assert.deepEqual(governor.recordResponse('app.example.test', 429), {
    domain: 'app.example.test', action: 'BACKOFF', pauseMs: 15_000, consecutivePressure: 1,
  });
  assert.equal(governor.acquire('app.example.test').reason, 'SERVER_BACKOFF');
  time.advance(15_000);
  assert.equal(governor.recordResponse('app.example.test', 503).pauseMs, 30_000);
  time.advance(30_000);
  assert.equal(governor.recordResponse('app.example.test', 429).reason, 'SERVER_PRESSURE_HALT');
  assert.equal(governor.acquire('app.example.test').reason, 'SERVER_PRESSURE_HALT');
});

test('rejects unsafe concurrency and budget configurations', () => {
  assert.throws(() => new RequestGovernor({ concurrency: 3 }), /may not exceed 2/);
  assert.throws(() => new RequestGovernor({ requestBudget: 10_001 }), /may not exceed 10000/);
});
