# Attack Recipes — Proven Patterns

Scan these triggers during Phase 2/3 entry. If trigger matches → MUST test the recipe.

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

## Usage Protocol

When entering Phase 2/3 on ANY engagement:
1. List all triggers observed during recon
2. For each matching trigger → execute the recipe
3. If recipe yields a finding → check if it chains with another recipe
4. Document recipe name in finding for future pattern tracking

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
