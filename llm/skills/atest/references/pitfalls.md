# API Testing Pitfalls

## Operational

**Burp MCP output:** Results from `get_proxy_http_history_regex` are 100-200KB single-line JSON. NEVER let raw output into context or use `read_file` on it. Always:
1. Write parsing logic to `/tmp/script.py`
2. Run via `terminal("python3 /tmp/script.py")`
3. Print <20 line summary (method+path+status only)
Never use heredoc for scripts with regex — shell escaping of `\r\n` and brackets breaks.

**Large file writes:** Max 300 lines per operation. Split reports: skeleton first, then patch findings in groups of 2-3.

**DNS resolution failure in terminal but browser works:**
- Some targets (Akamai/CDN-fronted) may fail DNS resolution from Python `requests` in terminal while the browser resolves fine
- Workaround: run API tests via browser `fetch()` calls in `browser_console` instead of terminal Python
- This preserves httpOnly session cookies that aren't accessible via `document.cookie`

**Rate limit bypass attempts:**
- Header spoofing (X-Forwarded-For, X-Real-IP, Client-IP) does NOT work against Akamai/CDN — they use real TCP source IP
- Only true bypass: different source IP (proxy, VPN, different network)

**React SPA form automation pitfalls:**
- Controlled components: use `Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set` + `dispatchEvent(new Event('input', {bubbles:true}))` to properly update React state
- Field disabling on state change: fill ALL fields BEFORE triggering state-changing buttons
- httpOnly cookies: session cookies not visible in `document.cookie` — verify login by navigating to authenticated page

## Engagement Lessons

**WRITE ENDPOINTS: TEST WITH AND WITHOUT COOKIES (BlueSpider, June 2026):**
- Laravel Sanctum (and similar cookie-aware middleware) enforces CSRF only when a session cookie is PRESENT
- Without ANY cookies, the request may bypass middleware entirely and hit the controller directly
- Rule: for every write endpoint (POST/PUT/PATCH/DELETE), test THREE ways: (1) with valid session+XSRF, (2) with expired/invalid session, (3) with ZERO cookies/headers
- BlueSpider: `/api/reset-default-password` returned 401 WITH cookies but 200 with NO cookies — Critical ATO
- Applies to ANY framework with cookie-triggered middleware (Laravel, Django, Rails)

**Multi-step flow testing (Phase 3):**
1. Map full flow from Burp history
2. Call LATER steps WITHOUT earlier steps (prerequisite skip)
3. Call steps OUT OF ORDER
4. Check consent/approval endpoints independently — often lack prerequisite validation

**SPA catch-all false positives (Phase 3):**
- If ALL paths return same HTTP status + body size → SPA frontend routing, NOT real endpoints
- Instead: extract API routes from JS bundles, target the BACKEND host for real fuzzing

**Referer bypass for API access:**
- APIs returning `RefererCheckFailed` check Referer header
- Bypass: set Referer to internal domain found in site config
- RefererCheck bypass upgrades response from "failed" to proper auth-check — confirms valid API path

**Unauthenticated endpoint mass-testing (JS bundle → batch POST):**
1. Extract all `.json` endpoints from JS bundles
2. POST each with `{}` body + valid Referer
3. Filter: responses containing `"redirectURL"` = auth-protected. Everything else = processes without auth
4. Proven yield (Antom 2026-06): 291 endpoints → 30+ process without authentication

**Webhook/callback endpoint testing (Capital.com, June 2026):**
- Test ALL callback endpoints for missing HMAC/signature verification
- Proof pattern: (1) POST valid JSON with forged/missing signature → 200, (2) verify input validation exists (415/400/500), (3) proves real processing not catch-all
- Prometheus `uri=` field reveals ALL callback routes
- Sumsub signature header is `X-Payload-Digest` (HMAC-SHA1)

**Consent/Step-Skip Testing (Business Logic):**
1. Skip prerequisite: submit consent without calling prerequisite endpoint
2. Replay: submit same consent multiple times
3. Arbitrary keys: unexpected consentKey/consentType values
4. Cross-user: manipulate user-identifying headers (x-cuid) vs JWT subject

**Auth gate before parameter processing (middleware-level enforcement):**
- Signal: ALL protected endpoints return the SAME auth error regardless of method/path/params
- Consequence: CANNOT test BOLA, injection, mass assignment without valid token — auth gate fires first
- Strategy: prioritize token acquisition. If unobtainable, document gate and run unauth-only testing

## Auth Chain Quirks (Mobile APIs)

- Login often returns `tokenId` (not JWT directly) — requires second call to `/access-token`
- Always test both documented flow AND shortcuts (skip steps, replay consent)
