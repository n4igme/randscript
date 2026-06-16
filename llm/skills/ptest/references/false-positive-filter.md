# False Positive Filter — 2-Minute Validation

Before spending 30 min on full PoC, run this 2-minute check per finding type.

---

## By Finding Type

### BOLA/IDOR
**Quick check:** Does the response actually contain OTHER user's data?
- Same response body for both users = NOT BOLA (just a public endpoint)
- 200 but empty/generic body = NOT BOLA (auth checked, just bad error code)
- errorCode 0 + zero/empty data for ANY ID (including random) = param is IGNORED, not IDOR. True IDOR shows different data shape (different currency, region, balance) for different IDs.
- **SoundOn pattern (June 2026):** `/api/revenue/royalty/total?artistId=OTHER` returned errorCode 0 with empty storeIncomeList for ALL artistIds tested — same currency (IDR), same structure. The backend extracts artistId from the session, not the query param. Spent 20+ min on inconclusive testing that could have been ruled out in 2 min by checking if a random/nonexistent ID returns the same shape as own ID.
- **2-min IDOR validation:** (1) Call with own ID → note response structure. (2) Call with random nonexistent ID → if same structure returned, param is ignored. (3) Only if different structure/error for random vs own, test with real victim ID.
- Confirm: response contains data identifiable as belonging to victim user

### SQL Injection
**Quick check:** Is the error real or just input validation?
- Generic "invalid input" error = probably input validation, NOT SQLi
- Confirm: time-based (`sleep(5)`) or boolean-based (true vs false response differs)
- Stack trace with SQL syntax = real. "Bad request" = likely filter

### SSRF
**Quick check:** Did the server actually make the request?
- Timeout ≠ SSRF (could be connection refused)
- Confirm: use Burp Collaborator/interactsh — did DNS/HTTP callback arrive?
- Response containing metadata content = confirmed. Timeout alone = unconfirmed

### XSS
**Quick check:** Is the payload actually reflected in browser-executable context?
- Reflected in JSON response with `Content-Type: application/json` = NOT exploitable
- Reflected inside JS string but properly escaped = NOT exploitable
- Confirm: payload renders in HTML context OR breaks out of attribute/script

### CORS
**Quick check:** Is it actually exploitable?
- `Access-Control-Allow-Origin: *` WITHOUT `Allow-Credentials: true` = Low (no cookies sent)
- Origin reflected but no sensitive data on that endpoint = Low
- Confirm: credentials + sensitive data + reflected origin = exploitable

### Auth Bypass
**Quick check:** Are you actually accessing protected functionality?
- 200 but response is login page / redirect = NOT bypass
- 200 with error message in body = NOT bypass
- Confirm: response contains data/functionality that requires auth

### Rate Limiting
**Quick check:** Is the limit actually absent?
- 200 responses but account locked after N attempts = rate limit EXISTS
- Confirm: can you actually brute-force successfully? (not just send requests)

---

## Universal Quick Checks

1. **Reproduce twice** — one-off anomalies aren't findings
2. **Check response body** — status 200 doesn't mean success
3. **Compare with baseline** — is the "vulnerable" response actually different?
4. **Verify scope** — is this asset actually in scope before investing time?

---

## Time Rule

- 2 min validation passes → invest in full PoC (30 min max)
- 2 min validation fails → mark as FP, move on
- Uncertain after 2 min → spend 5 more minutes max, then decide
