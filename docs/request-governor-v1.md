# Request Governor v1

`src/policy/request-governor.js` is a local policy primitive. It does not send requests and must be called by a future controlled execution wrapper immediately before a network action.

## Enforced limits

- Per-domain token bucket: configurable RPS, maximum burst of five requests.
- Session-wide concurrency: maximum two active reservations.
- Session request budget: default 1,000, hard maximum 10,000.
- A warning is returned when the successful reservation reaches 80% of its current budget.
- Further reservations are denied at 100% until `renewBudget()` is invoked explicitly.
- `429` and `503` can be recorded by a wrapper: the affected domain pauses for 15 seconds, then 30 seconds, then halts after a third consecutive pressure response.

## Reservation lifecycle

1. Scope and policy must already have accepted a hostname.
2. Call `acquire(hostname)` before starting one request.
3. Run exactly one controlled action only when `allowed` is true.
4. Always call `release(reservationId)` in a `finally` block when the action is complete.
5. Pass the response status to `recordResponse(hostname, statusCode)`.

The governor alone is not a permission boundary. A future wrapper must compose scope validation, approval, kill-switch, timeout, audit logging, and this governor before any network I/O.
