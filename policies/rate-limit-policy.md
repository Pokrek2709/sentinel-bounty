# Sentinel Bounty — Rate Limit Policy

## 1. Request Budgets

- Every testing session has a defined `request_budget` (default: 1,000 requests; maximum hard cap: 10,000 requests).
- When 80% of the budget is consumed, a warning is logged.
- When 100% of the budget is exhausted, all active testing halts until explicitly renewed by the researcher.

## 2. Rate Limiting Defaults

- Default rate limit: 2 requests per second (RPS) per domain.
- Max burst size: 5 requests.
- Concurrency limit: 2 simultaneous worker threads.

## 3. Backoff on Server Pressure

- On encountering HTTP status `429 Too Many Requests` or `503 Service Unavailable`:
  1. Immediately pause sending for 15 seconds.
  2. Double the inter-request delay (exponential backoff).
  3. If 3 consecutive 429/503 responses occur, halt testing and notify user.
