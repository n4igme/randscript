# ptest Code Review — June 2026

## Fixes Applied (3 rounds)

### Round 1 — Core Bugs
1. `import random` moved to module-level in tools/http.py (was in hot path)
2. Exception handler ordering: KeyboardInterrupt/CancelledError before Exception
3. All `asyncio.get_event_loop()` → `asyncio.get_running_loop()` (6 occurrences)
4. Boolean blind SQLi: threshold 50→200 bytes, XOR check, proportional distance
5. Crawl-time endpoint dedup via `_add_endpoint()` helper
6. Hunt progress: disk I/O removed from inner loop, replaced with callback
7. `_run_module` exception handling (was dead code)
8. XSS + LFI reproduction script generators added
9. `_gen_generic` f-string interpolation bug fixed
10. Test API drift: `set_cookies` → `configure` in IDOR tests

### Round 2 — Architecture
1. All post-crawl sources (nextdata, JS, sourcemaps, robots, brute, OpenAPI) use `_add_endpoint()`
2. Incremental findings save in progress callback (crash-safe)
3. Atomic session writes (tempfile + os.replace)
4. Endpoint dedup key includes params
5. Progress callback throttled to 10s intervals
6. Concurrent crawl for aggressive/brutal (5/10 workers)
7. Response body size check for chunked responses
8. `_is_likely_api_path` noise filtering (template vars, i18n, deep nesting)
9. Scan-level endpoint dedup before module dispatch
10. E2E integration tests (5 tests)

### Round 3 — Robustness
1. `_extract_links` regex: unquoted attrs, whitespace, case-insensitive
2. `_confirm_findings` concurrent (semaphore=10)
3. Signal expansion streams during hunt (not batched after)
4. Subprocess stdin=DEVNULL
5. Session file locking (fcntl.flock)
6. OAuth JSON parse guard
7. Scope enforcement port-stripping fix (critical — dropped all findings on non-standard ports)
8. Tests for scope, rate limiter, auth refresh (8 new tests)

## Test Count
98 → 111 passing (no regressions)

## Remaining Known Debt
- `fastapi`/`uvicorn` deps unused (planned API server?)
- `playwright` optional dep with no implementation (SPA headless crawl placeholder)
- No per-subdomain rate limiting
- `_extract_forms` regex still misses multi-line attributes (BeautifulSoup would be more robust but adds dep)
