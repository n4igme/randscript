# Phase 3: Enumeration

## Automated Setup

Run first when entering this phase:

```python
from hermes_tools import read_file
exec(read_file("~/.hermes/skills/security/ptest/scripts/phase3_enumerate.py")["content"])
```

---

## Critical Pitfalls (BlueSpider, June 2026)

### JS Bundle Diff Between Environments (MANDATORY)
When multiple environments exist (dev/staging/prod), extract and DIFF the JS bundles from each. Prod may contain endpoints not present in dev bundles. The `/api/load-user` endpoint that enabled the full production compromise was only in the prod JS bundle (`app-6750147a.js`) — not the dev bundle (`app-50814d1f.js`). A simple `diff` of extracted endpoint lists between environments catches this.

### Parameterized Endpoint Enumeration
When an endpoint like `/api/get-params/{type}` is found, do NOT only test the param values seen in JS (e.g., `VERIFIKASI`). Systematically enumerate common param types: `passDefault`, `CATEGORY`, `STATUS`, `DEPARTMENT`, `CHANNEL`, `SLA`, `EMAIL`, `PASSWORD`, `CONFIG`, `SECRET`. The `passDefault` param leaked the system's default password unauthenticated — this single finding led to 69-account mass ATO on production.

### Username ≠ Login Credential
User enumeration endpoints may return usernames (e.g., `MGR01`, `SPV01`) while the login form requires email addresses. Always search for a secondary endpoint that exposes full user objects with email fields (e.g., `/api/load-user`). If no email-returning endpoint exists, try common email patterns: `username@domain.com`, `firstname.lastname@domain.com` against discovered domains.

## When to Use
- Third phase of any engagement (Gateway 3 is OPEN).
- After active recon has identified live hosts and services.

## MANDATORY: JS Bundle Environment Diff (BlueSpider, June 2026)
When target has multiple environments (dev/staging/prod) with Vite/Webpack JS bundles:
1. Extract JS bundle filenames from EACH environment's login page (`grep -oE 'src="[^"]*app-[^"]*\.js"'`)
2. Note the hash differs between envs (e.g., `app-50814d1f.js` vs `app-6750147a.js`)
3. Extract API endpoints from EACH unique bundle
4. DIFF the endpoint lists — prod may have endpoints not in dev
5. Test any prod-only endpoints for unauthenticated access IMMEDIATELY

This step found `/api/load-user` (full user dump with emails) that existed only on prod but not dev — the single endpoint that enabled a 69-account mass ATO including Super Admin.

## ALL-Hosts Coverage Rule (WinTicket, June 2026)

**Phase 3 must cover EVERY live subdomain, not just the primary app/API.**

Common mistake: fuzzing only www + api and calling Phase 3 done, while 10+ other live hosts (GCS buckets, Firebase hosting, SGTM, SparkPost, tracking services) go untested.

**Per-host-type enumeration:**
| Host Type | Techniques |
|-----------|-----------|
| GCS/Cloud Storage | Bucket listing, known object paths, /.env, /config.json, sensitive file probe |
| Firebase Hosting | /__/firebase/init.json, /__/auth/handler, /__/auth/action, /__/auth/iframe |
| Server-side GTM | /healthy, /healthz, /gtm.js, /gtag/js, /g/collect, /_ah/health |
| SparkPost/Email | /q/, /f/, /track, /open, /click, /c/, /o/ |
| OpenResty/nginx | /health, /status, /click, /api, common paths |
| API (Istio/Envoy) | JS-extracted routes, ffuf with domain-specific wordlist |

**Exit gate addition:** Before requesting Phase 3 sign-off, verify every row in domains-live.md has a corresponding enumeration entry or explicit N/A notation.

## Fast-Triage Fingerprint (Large Scope — 15+ live hosts)

Before deep enumeration, quickly categorize ALL live hosts to avoid wasting time on dead-end targets:

```bash
# Step 1: Quick fingerprint (status + size + redirect + server)
for host in $(cat live-hosts.txt); do
  curl -sk -o /dev/null -w "${host}: %{http_code}|%{size_download}|%{redirect_url}\n" "https://${host}/" -m 10
done

# Step 2: POST differentiation (CDN/OSS vs real API)
# CDN/OSS returns XML MethodNotAllowed; real APIs return JSON errors
for host in $(cat live-hosts.txt); do
  resp=$(curl -sk -X POST -H 'Content-Type: application/json' -d '{}' "https://${host}/" -m 8 2>/dev/null | head -c 100)
  echo "${host}: ${resp}"
done
```

**Category → Action:**

| Fingerprint | Category | Action |
|-------------|----------|--------|
| 200 + fixed size for ALL paths | SPA catch-all | Extract inline config (tern-site-config, __NEXT_DATA__), find backend URL, skip path fuzzing |
| POST → XML `<Error><Code>MethodNotAllowed</Code>` + `webapp-origin.marmot-cloud.com` | CDN/OSS bucket | Dead end — static hosting only |
| 204 + size 0 on all paths + `server: ESA` | Tracking beacon | Dead end |
| 200 + body = "success" (7 bytes) + all paths same | Health/proxy stub | Dead end |
| 302 → /platform or /index.html + body = "index page" | Empty OSS app | Dead end |
| 302 → /error or /index.html for ALL unknown paths (nginx/Spanner) | API catch-all (server-side routing) | ffuf will produce mass false positives — use `-fc 302` or verify manually. Real endpoints return JSON (200/400/401/403), not 302. |
| JS has `sourceMappingURL` but .map returns 404 | Source maps stripped at deploy | Not exploitable — note and move on, don't waste time trying variants |
| JSON error response (RefererCheckFailed, Invalid request, resultCode) | Real API backend | Deep enumerate — high priority |
| 403 + JSON body | API with auth gate | Try Referer/header bypass, enumerate sub-paths |
| 405 + Tengine | WAF-fronted API | Test methods, check for path-specific rules |

**Multi-host same-backend detection:** If two hosts return identical response patterns (same error format, same field names), they likely share a backend. Confirm by checking one endpoint on both. Document but don't duplicate enumeration effort — just verify both are affected when reporting.

**Antom example (June 2026):** 24 live hosts → 5 real API backends, 4 SPA frontends (all proxying to same 2 backends), 15 dead ends (CDN, beacon, stubs). Deep enum only needed on 5 targets, saving ~70% effort.

## CRITICAL: Full Subdomain Coverage Check (MANDATORY at phase entry)

Before starting any technique, verify your target list covers ALL subdomains:

```bash
# Diff master list vs live-hosts from Phase 2
sort -u ./ptest-output/recon-passive/subdomains-master.txt > /tmp/master.txt
sort -u ./ptest-output/recon-active/live-hosts.txt > /tmp/live.txt
comm -23 /tmp/master.txt /tmp/live.txt > /tmp/missed.txt
echo "Missed subdomains: $(wc -l < /tmp/missed.txt)"

# Batch-probe all missed (filter out _cert-validation, mail tracking)
grep -v "^_\|^em[0-9]\|^url[0-9]\|^img\.\|^r\." /tmp/missed.txt | \
  xargs -P 10 -I{} curl -sk --max-time 5 -o /dev/null \
  -w '%{http_code} %{size_download} {}\n' 'https://{}/' | sort
```

**Pitfall (Bank Jago, May 2026):** Phase 2 live-hosts.txt had only 67 entries out of 343 in master list. 184 subdomains were never probed. User caught this gap at Phase 3 sign-off. Among the missed hosts: workstations.jago.com (Guacamole), iam.jago.com (IAP), multiple GCS buckets, and CF Access-protected apps. Always diff and batch-probe before declaring Phase 3 complete.

**Pitfall (LINE WORKS, June 2026):** Master list had 36 subdomains but only 8 were HTTP-probed in Phase 2. The remaining 28 were marked "dead DNS" in Phase 1 notes and never re-verified at Phase 3 entry. Two of them (alpha.line-works.com, stage.line-works.com) actually resolved to private IPs — confirming they exist but are unreachable. The handoff diff MUST run regardless of Phase 1 notes, because DNS can change between phases.

## Scope
This phase covers **application-layer discovery**:
- Directory and file brute-forcing
- API endpoint discovery and mapping
- Parameter discovery
- Virtual host enumeration
- CMS-specific enumeration
- JavaScript analysis and source map extraction
- Authentication endpoint mapping

Network-layer discovery (port scanning, service detection) belongs in Phase 2 (Active Recon).

## Techniques & Tools

### 1. Directory & File Brute-Force (MANDATORY: gobuster or feroxbuster)
Discover hidden paths, files, and directories on web targets.
```bash
# gobuster — directory mode
gobuster dir -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/gobuster-dirs.txt -t 50

# gobuster — file mode (common extensions)
gobuster dir -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-files.txt -x php,html,js,json,xml,txt,bak,env,conf -o ./ptest-output/enumeration/gobuster-files.txt

# feroxbuster — recursive
feroxbuster -u https://target.com -w $SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/ferox.txt --depth 3

# Targeted wordlists for specific tech stacks
# Pimcore: /admin, /bundles, /var, /bin
# WordPress: /wp-content, /wp-includes, /wp-json
# Laravel: /api, /storage, /vendor
```

**Requirements:**
- Run against ALL confirmed-live web hosts (from Phase 1 domains-live.md)
- Use appropriate wordlists for the identified technology stack
- If gobuster/feroxbuster unavailable, document gap and use alternative (dirsearch, dirb)

**Pitfalls:**
- **SPA catch-all: Many modern apps (Flutter, React, Angular) return 200 for ALL paths. Use `--exclude-length <spa-size>` to filter. First check a random UUID path to determine the catch-all response size.
- **CloudFront rate limiting (429):** Targets behind CloudFront often rate-limit at ~30 req/s. ffuf/gobuster with default threads will trigger 429 within seconds. Solutions: (1) use `-rate 5 -t 2` in ffuf, (2) fall back to Python httpx with `time.sleep(0.3)` between requests, (3) for targeted checks, use a manual path list (20-30 high-value paths) instead of full wordlists. When 429 hits, wait 5-10 seconds before retrying — the limit resets quickly. Note: nginx 429 (body contains `<center>nginx</center>`) = origin rate limit; CloudFront 429 = CDN-level throttle.
- gobuster `-s` and `-b` conflict: Don't use `-s` (status codes) without clearing `-b` (blacklist) first. Use `-b ""` to clear the default 404 blacklist when specifying `-s`.
- Rate-limited targets: gobuster/feroxbuster may timeout. Fall back to `xargs -P` with curl for parallel path discovery on slow targets.

### 2. API Endpoint Discovery (MANDATORY: ffuf)
Map API endpoints, methods, and response patterns.
```bash
# ffuf — API endpoint fuzzing
ffuf -u https://target.com/api/FUZZ -w $SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403,405 -o ./ptest-output/enumeration/ffuf-api.json

# ffuf — versioned API paths
ffuf -u https://target.com/api/v1/FUZZ -w $SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404

# Check common API documentation endpoints
# CRITICAL: Test at BOTH root AND every discovered context path prefix!
# AltoCMS lesson (June 2026): /jago/api/v2/api-docs returned 401 but /jago/v3/api-docs
# was unauthenticated (97KB, 95 endpoints, 130 schemas). Spring Boot 3.x serves OpenAPI v3
# at a PARENT context level that often bypasses the API security filter chain.
for base in "" "/jago" "/api" "/app" "/service" "/backend"; do
  for path in /v3/api-docs /v2/api-docs /swagger-ui.html /swagger-ui/ /swagger-resources /api-docs /openapi.json /openapi.yaml /swagger.json /docs /redoc; do
    code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "https://target.com${base}${path}")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "${base}${path} -> $code"
  done
done
# Also check with /api/ prefix (common: /api/v3/api-docs vs /v3/api-docs)
# If ANY returns 200 with size > 1000, download and analyze immediately

# GraphQL introspection
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

### 2b. Parameterized Endpoint Type Brute-Force (MANDATORY)

**BlueSpider lesson (June 2026):** JS bundle revealed `/api/get-params-inbound/VERIFIKASI` — tested it, found verification fields exposed unauth. But MISSED `/api/get-params/passDefault` which exposed the system default password (`JAGO1234!` on prod, `12345678` on dev) unauthenticated. User had to point this out. Combined with user enumeration → instant ATO.

**Rule:** When a parameterized endpoint like `/api/get-params/{type}` is found, ALWAYS brute-force the type parameter:
```
passDefault, password, DEFAULT_PASSWORD, admin, config, secret, key, token,
CATEGORY, STATUS, DEPARTMENT, CHANNEL, VERIFIKASI, ROLE, PERMISSION, LEVEL,
EMAIL, SMTP, API_KEY, DB, DATABASE, REDIS, QUEUE, MAIL, APP_KEY, SIP, PBX
```

**Attack chain:** config param endpoint (passDefault) + user enumeration = ATO on any new/reset user.

### 3. Parameter Discovery
Identify hidden parameters on discovered endpoints.
```bash
# arjun — parameter discovery
arjun -u https://target.com/endpoint -o ./ptest-output/enumeration/arjun-params.json

# Manual parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w $SECLISTS_PATH/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -fs <baseline-size>
```

### 4. Virtual Host Enumeration
Discover additional virtual hosts on the same IP.
```bash
# gobuster vhost mode
gobuster vhost -u https://target.com -w $SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# ffuf vhost fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w $SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fc 404 -fs <baseline-size>
```

### 5. CMS-Specific Enumeration
Run targeted enumeration based on identified CMS/framework.
```bash
# WordPress
wpscan --url https://target.com --enumerate ap,at,u -o ./ptest-output/enumeration/wpscan.txt
```

#### WordPress Hardened Sites (all REST locked behind auth)

When WordPress returns `{"code":"rest_not_logged_in"}` on ALL wp-json endpoints, use these alternative enumeration techniques:

```python
import httpx, re

client = httpx.Client(verify=False, timeout=10)

# 1. Plugin discovery via readme.txt (always accessible even on hardened sites)
plugins = ["elementor", "elementor-pro", "wp-fastest-cache", "autoptimize",
           "redirection", "contact-form-7", "wordfence", "wp-mail-smtp",
           "all-in-one-wp-migration", "updraftplus"]
for plugin in plugins:
    r = client.get(f"https://target.com/wp-content/plugins/{plugin}/readme.txt")
    if r.status_code == 200:
        ver = re.search(r'Stable tag:\s*(.+)', r.text)
        print(f"[+] {plugin}: {ver.group(1).strip() if ver else 'trunk'}")

# 2. Version from /feed/ generator tag
r = client.get("https://target.com/feed/")
gen = re.search(r'<generator>.*\?v=([0-9.]+)</generator>', r.text)
print(f"WP version: {gen.group(1) if gen else 'hidden'}")

# 3. User enumeration via ?author=N (may leak slugs on subsites)
for i in range(1, 20):
    r = client.get(f"https://target.com/?author={i}", follow_redirects=False)
    if r.status_code == 301:
        loc = r.headers.get('location', '')
        slug = re.search(r'/author/([^/]+)/', loc)
        if slug:
            print(f"User {i}: {slug.group(1)}")

# 4. Elementor nonce from public page source
r = client.get("https://target.com/")
nonces = re.findall(r'"nonce":"([^"]+)"', r.text)
ajax_url = re.search(r'"ajaxurl":"([^"]+)"', r.text)
# Elementor nonce enables: elementor_pro_forms_send_form (test form submission)

# 5. Sitemap from Yoast SEO (reveals content structure)
r = client.get("https://target.com/sitemap_index.xml")
sitemaps = re.findall(r'<loc>([^<]+)</loc>', r.text)

# 6. admin-ajax nopriv actions (work without auth)
for action in ["heartbeat", "elementor_pro_forms_send_form", "load_more"]:
    r = client.post("https://target.com/wp-admin/admin-ajax.php",
                    data={"action": action})
    if r.status_code == 200 and len(r.content) > 1:
        print(f"[+] {action}: {r.text[:80]}")

# 7. Apple App Site Association + Android Asset Links
r1 = client.get("https://target.com/apple-app-site-association")  # root, NOT .well-known
r2 = client.get("https://target.com/.well-known/assetlinks.json")
# Extract deep link paths from AASA → probe server-side
```

# Pimcore
# Check: /admin/login, /bundles/, /js/routing, /_profiler, /_wdt
# Enumerate admin routes via FOS routing bundle if exposed

# Drupal
droopescan scan drupal -u https://target.com

# Joomla
joomscan -u https://target.com
```

### 6. JavaScript Analysis (includes Source Map Extraction)
Extract endpoints, secrets, and functionality from client-side code.

**SOURCE MAP CHECK (MANDATORY):** Before analyzing minified JS, check for `.map` files. Append `.map` to every discovered JS bundle URL. Source maps expose the FULL original source code — auth implementations, API configs, crypto functions, business logic. LoanPlatform (June 2026): two source maps (6.1MB + 5.6MB, 848 files) revealed PBKDF2 password hashing implementation, full API URL config (service prefixes), self-registration flow, and session timeout endpoint — none discoverable from the minified bundle alone. Source maps are a **finding** (info disclosure) AND an **attack enabler** (white-box analysis).

**What to extract from source maps:**
- `sourcesContent` → full original source files
- Search for: API base URLs, OAuth client IDs/secrets, encryption implementations, hardcoded credentials
- Auth flow: identify how passwords are hashed/encrypted client-side before transmission
- Config files (config.js, environment.js): service URLs, feature flags, endpoint mappings

**CRITICAL: Analyze ALL JS files, not just app chunks.** Third-party SDKs (platform-websdk, auth0-spa-js, okta-auth-js, transmit-security) often reveal entire hidden auth layers with different endpoints, error formats, and session handling. These SDKs are typically 100-300KB and contain hardcoded path definitions the main app never references directly.

**Checklist (MANDATORY):**
1. Download and search ALL `<script src=...>` files (vendor, SDK, GTM, polyfills)
2. Search for path patterns: `"/(api|v1|v2|cis|auth|fido|webauthn|session|identity|verify|oauth)[^"]*"`
3. Test discovered paths on ALL in-scope hosts (not just the obvious one)
4. If a path 404s, try with prefix: `/cis/path`, `/auth/path`, `/identity/path`
5. Check for different error format (JSON structure change = different backend)

**Lesson (bitbank.cc, June 2026):** Main app chunks revealed standard `/v1/user/*` paths. But `ts-platform-websdk.js` (241KB vendor SDK) revealed `/v1/auth-session/*`, `/v1/webauthn/*`, `/fido/login/authenticate/*` — an entire Transmit Security CIS layer invisible from the main API. These endpoints used a completely different error format and accepted unauthenticated requests.

**Flutter Web Apps:** If target serves `main.dart.js` + `flutter.js`, see `references/flutter-web-app-analysis.md` for specialized extraction (JWT decode, auth headers, partner IDs, internal domains from 4-10MB Dart-compiled JS).

**Transmit Security CIS:** If `ts-platform-websdk.js` found, see `references/transmit-security-cis-testing.md`.

**Identity SDKs:** If target loads a third-party identity SDK (`ts-platform-websdk.js`, `auth0-spa-js`, `@okta/okta-auth-js`, etc.), see `references/identity-sdk-endpoint-extraction.md` for extracting hidden auth endpoints, determining their host/prefix, and the CloudFront behavior policy gotcha. These SDKs often reveal undocumented auth paths (`/cis/v1/auth-session/*`, `/fido/*`, `/login`, `/signup`) that standard API fuzzing misses entirely.

**SPA chunk analysis (Angular/React/Vue):** Download ALL lazy-loaded chunks (not just main.js) and grep across them. The auth service, API URL map, and request body constructors are typically in a separate chunk from the main bundle. Search for:
- Route/URL enums: `t.Login="/login",t.Signup="/signup"` pattern
- Request body construction: `post(this.apiUrl+ut.Login,{body:c})` pattern  
- Field names near auth calls: `{mail:i,password:n,"g-recaptcha-response":o}`

**Angular SPAs:** Check ALL chunks (chunk-*.js), not just main.js. Also check vendor SDKs loaded separately (e.g., `ts-platform-websdk.js` for Transmit Security, `platform-websdk-*`). These third-party identity SDKs often reveal:
- Undocumented API paths (e.g., `/cis/v1/auth-session/*`, `/fido/login/authenticate/*`)
- Different API base paths than the documented ones (root-level vs /v1/ prefix)
- Auth flow field names (e.g., `mail` vs `email`, `g-recaptcha-response` with hyphens vs underscores)
- Error code mappings (search for `code:NNNNN` patterns)

**CRITICAL lesson (bitbank.cc, June 2026):** Main API docs showed only HMAC-authenticated `/v1/user/*` endpoints. The platform-websdk.js (241KB) revealed an entire undocumented auth layer: `/login`, `/signup`, `/reset_password`, `/fido/*`, `/register_mail`, `/signedup` — all at the API root without /v1 prefix, using different auth (reCAPTCHA instead of HMAC). Without analyzing this SDK, the whole unauthenticated attack surface would have been missed.

**Angular/React SPAs with identity SDKs:** If target embeds third-party auth SDKs (Transmit Security `ts-platform-websdk.js`, Auth0, Okta), see `references/spa-js-endpoint-extraction.md` for multi-layer extraction. These SDKs reveal entire hidden API surfaces (auth-session, webauthn, verification endpoints) that standard fuzzing will NEVER find. **Always analyze ALL script src references, not just the app's own chunks.**

**Key lesson (bitbank.cc, June 2026):** ffuf found 0 undocumented endpoints. JS analysis found 90+ endpoints, root-level auth paths, and an entire CIS service prefix. JS bundles ARE the API documentation for hardened targets.

**Third-Party Identity SDKs (CRITICAL — often missed):** SPAs frequently embed identity platform SDKs (Transmit Security, Auth0, Okta, Firebase Auth) as separate JS bundles. These SDKs contain hardcoded API paths that may differ from the main API's path structure. Always:
1. Identify ALL `<script src=...>` tags — not just `main.js` chunks
2. Download and analyze vendor/third-party scripts separately (e.g., `ts-platform-websdk.js`, `auth0-spa-js`, `firebase-auth.js`)
3. Search for API paths — they often live on a different prefix (e.g., `/cis/v1/` instead of `/v1/`)
4. Test discovered paths on ALL in-scope hosts — the SDK may call a proxy path on the app domain (e.g., `app.target.com/cis/v1/auth-session/status`) rather than a separate identity subdomain

**Bitbank lesson (2026-06):** `ts-platform-websdk.js` (Transmit Security, 241KB) revealed `/cis/v1/auth-session/*`, `/v1/webauthn/*`, `/fido/login/authenticate/*` endpoints. These existed at `api.bitbank.cc/` root (no /v1 prefix) and were NOT documented in the public API docs. Also revealed root-level `/login`, `/signup`, `/register_mail`, `/reset_password` endpoints returning undocumented error codes (30004, 30005).
```bash
# linkfinder — extract endpoints from JS files
linkfinder -i https://target.com -o ./ptest-output/enumeration/linkfinder.txt

# Download and analyze JS bundles
curl -s https://target.com/static/js/main.*.js | grep -ioE '(https?://[^\s"]+|/api/[^\s"]+|/v[0-9]/[^\s"]+)' | sort -u

# Check for source maps
curl -sI https://target.com/static/js/main.*.js | grep -i sourcemap
curl -s https://target.com/static/js/main.*.js.map | head -100

# Extract hardcoded secrets/tokens from JS
curl -s https://target.com/static/js/main.*.js | grep -ioE '(api[_-]?key|token|secret|password|auth)["\s]*[:=]["\s]*[^\s",}]+' | sort -u
```

### 6b. Referer-Based Access Control Bypass (Enumeration Technique)

### 6a. SPA Path Prefix Proxy Bypass (MANDATORY when SPA has base path)

**LoanPlatform lesson (Bank Jago, June 2026):** When a SPA serves from a sub-path (e.g., `<base href=/app-jfs/jfs-client/>`), the SPA's reverse proxy may forward API requests placed under that prefix to backend services WITHOUT auth — even when the direct API path is blocked. This turned a 400 (Istio blocked) into 200 (full financial data access) and escalated from "needs auth" to Critical (unauth repayment execution).

**When to test:** ANY SPA that has a non-root base path (check `<base href>` tag or HTML source).

**Procedure:**
1. Extract SPA base path from HTML: `<base href=/app-jfs/jfs-client/>`
2. Extract API service prefixes from JS config/source maps (e.g., `loan/v1`, `jfs`, `private`)
3. For each API path, test via SPA prefix: `{SPA_BASE}/{API_PATH}`
4. Compare: if direct path returns 400/401 but SPA prefix returns 200 → **auth bypass via proxy**
5. Test BOTH read (GET) and write (POST) methods on discovered endpoints

**Key indicator:** The direct API path (e.g., `/app-jfs/loan-service/`) returns 400 "Bad Request" from Envoy/Istio (not 401/403 from the app). This means routing is blocked, but the SPA proxy provides an alternate route.

See `references/spa-recon-techniques.md` §"SPA Backend Discovery via Path Prefix Proxying" for full technique.

### 6b. Referer-Based Access Control Bypass (Enumeration Technique)

```bash
# Common Referer values to try (derive from tern-site-config, dns-prefetch links, or known frontend URLs)
REFERERS=(
  "https://dashboard.target.com/"         # Main frontend
  "https://global-testpre.alipay.com/"    # Pre-production (Ant Group pattern)
  "https://render-intl.alipay.com/"       # CDN origin
)

for ref in "${REFERERS[@]}"; do
  resp=$(curl -sk -H "Referer: ${ref}" -X POST -H 'Content-Type: application/json' \
    -d '{}' "https://api.target.com/endpoint.json" -m 8 2>/dev/null)
  if ! echo "$resp" | grep -q "RefererCheckFailed"; then
    echo "[+] Bypass with: ${ref}"
    echo "    Response: ${resp:0:100}"
    break
  fi
done
```

**Key insight:** Different Referers may work for different endpoint groups. Production frontends bypass prod endpoints; pre-prod Referers bypass PRE endpoints. Some endpoints (like password/key material) may need NO Referer at all — always test without Referer first.

**Behavioral clue (Ant Group, June 2026):** When a Referer bypasses the check, the response may be EMPTY (not the config data) — this means the Referer passed but the request body/params/session is still invalid. Empty response ≠ failure; it means you're past the first gate. Next step: add required body params or session cookies.

**Ant Group / Antom specifics:** See `references/intel-alibaba-cloud-infrastructure.md` §"Referer-Based Access Control Bypass" for known working values. See also `references/engagement-antom-antgroup.md` for tested Referer values and endpoint map.

### 7. Authentication Endpoint Mapping
Document all authentication mechanisms and entry points.

**MANDATORY: Test OAuth/Auth endpoints with GET individually (BIFast, June 2026):**
When JS analysis reveals OAuth endpoints (e.g., `/oauth/internal/authorize`, `/oauth/internal/preauthorize`, `/oauth/internal/token`), do NOT assume they all behave the same because one returned 302. Test EACH endpoint individually with GET AND POST — some may be unauthenticated while others require auth. The BIFast engagement missed `/oauth/internal/preauthorize` returning 400 JSON (unauthenticated, processing requests) because all OAuth paths were batch-tested and the single non-302 was overlooked. This endpoint accepted arbitrary client_ids and leaked OAuth flow implementation details via sequential error messages.

**Error code sequence mapping (MANDATORY for APIs with structured errors):**
When an API returns structured error codes (e.g., `{"success":0,"data":{"code":30004}}`), systematically determine the validation sequence by sending requests with progressively more fields:
```python
# Step 1: Empty body → identifies "missing required field" code
# Step 2: Add one field at a time → identifies which field triggers next error
# Step 3: Add all required fields with invalid values → identifies validation order
# Example sequence discovered (bitbank.cc):
#   {} → 30004 (missing mail+password)
#   {mail} → 30010 (missing password) 
#   {mail, password} → 40018 (missing/empty recaptcha)
#   {mail, password, g-recaptcha-response:"fake"} → 20022 (invalid recaptcha)
# This reveals: field presence check → empty check → reCAPTCHA → credential validation
```

**Finding the exact field names from JS (critical for non-standard APIs):**
Don't guess field names. Search the JS for the POST body construction:
```bash
# Find the service method that calls the auth endpoint
grep -C5 'post.*Login\|post.*login\|"/login"' /tmp/chunk-*.js | grep -oE '"[a-z_-]+":' | sort -u
# Look for patterns like: post(this.apiUrl+ut.Login,{body:c})
# Then trace back what 'c' contains
```
```bash
# Identify login pages
for path in /login /signin /auth /admin/login /api/auth /oauth /sso; do
  code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "HTTP $code $path"
  fi
done

# Check auth mechanisms
curl -sI https://target.com/api/protected 2>/dev/null | grep -iE "www-authenticate|x-auth|authorization"

# OAuth/OIDC discovery
curl -s https://target.com/.well-known/openid-configuration | python3 -m json.tool
curl -s https://target.com/.well-known/oauth-authorization-server | python3 -m json.tool
```

### 8. Framework Detection & Targeted Enumeration

Identify the web framework, then load the appropriate attack playbook.

```bash
# Detect framework from response headers/body
# Next.js: __NEXT_DATA__ in source, /_next/ paths
# Laravel: laravel_session cookie, /telescope, /horizon
# Django: csrftoken cookie, /admin/
# WordPress: /wp-content/, /wp-json/
# Rails: _session_id cookie, X-Request-Id header
# Spring Boot: /actuator, x-envoy-* headers
# Spring Boot OpenAPI: /{context}/v3/api-docs (often outside auth filter — see below)
# GraphQL: /graphql, /graphiql, /playground
# Tyk Gateway: /hello returns JSON with "Tyk GW", 403 "Requested endpoint is forbidden"
# n8n: /rest/settings returns config JSON, /healthz returns {"status":"ok"}
# Flutter Web: main.dart.js + flutter.js in page source

# Quick framework fingerprint
curl -sk "https://target.com" -D - -o /tmp/fw-detect.html 2>/dev/null
grep -qi "__NEXT_DATA__" /tmp/fw-detect.html && echo "[+] Next.js detected"
grep -qi "laravel_session" /tmp/fw-detect.html && echo "[+] Laravel detected"
grep -qi "csrftoken" /tmp/fw-detect.html && echo "[+] Django detected"
grep -qi "wp-content" /tmp/fw-detect.html && echo "[+] WordPress detected"
```

**When framework is identified:** Load `references/framework-specific-attacks.md` for targeted enumeration paths specific to that framework.

### 9. GraphQL Endpoint Discovery & Introspection

```bash
# Find GraphQL endpoints
for path in /graphql /graphiql /playground /api/graphql /v1/graphql /query /gql; do
  code=$(curl -sk -X POST "https://target.com${path}" -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' -o /dev/null -w "%{http_code}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[+] GraphQL at ${path} -> ${code}"
done

# Full introspection (if enabled)
curl -sk "https://target.com/graphql" -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | python3 -m json.tool | head -50
```

**Deep dive:** See `references/framework-specific-attacks.md` §6 and `references/web-vuln-bypass-tables.md` (GraphQL section).

### 10. WebSocket Endpoint Discovery

```bash
# Search for WebSocket URLs in page source and JS files
curl -sk "https://target.com" | grep -ioE "wss?://[^\"' ]+"

# Check common WebSocket paths
for path in /ws /websocket /socket /socket.io /hub /signalr /cable /live; do
  code=$(curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    "https://target.com${path}" -o /dev/null -w "%{http_code}")
  [ "$code" = "101" ] && echo "[+] WebSocket upgrade at ${path}"
  [ "$code" = "400" ] && echo "[?] Possible WS at ${path} (400 = bad handshake)"
done
```

**Deep dive:** See `references/advanced-web-attacks.md` §1 for WebSocket security testing.

### 11. Deserialization Sink Identification

Look for serialized data in cookies, headers, and request bodies.

```bash
# Check cookies for serialized data
curl -skI "https://target.com" | grep -i "set-cookie" | grep -iE "base64|eyJ|rO0AB|AAEAAAD|O:[0-9]"

# Java serialization magic bytes (base64 of AC ED 00 05 = rO0AB)
# PHP serialization (O:4:"User":...)
# .NET BinaryFormatter (AAEAAAD...)
# Python pickle (base64 blob in cookie/session)

# Check ViewState (.NET)
curl -sk "https://target.com" | grep -oE '__VIEWSTATE[^"]*"[^"]*"' | head -3
```

**Deep dive:** See `references/insecure-deserialization.md` for full exploitation methodology.

### 12. Bulk Actuator/Admin Scan (MANDATORY)

**Prometheus URI Extraction → Systematic Unauth Testing (CRITICAL):**
When /actuator/prometheus is exposed, extract ALL `uri=` labels and test EVERY discovered path without authentication. This is MORE effective than directory brute-force for Spring Boot apps because it reveals the exact registered routes.

**LoanPlatform (June 2026):** Prometheus revealed 50 URI labels. Systematic unauth testing of each found `/user-resources/users/{login}` returning full PII (email, phone, roles) for all 33 users — a High finding invisible to ffuf/gobuster because the path contains a regex pattern (`{login:^[_'.@A-Za-z0-9-]*$}`). Also found `/task-approvals/created-by` leaking all usernames, `/oauth/token_key` exposing JWT public key, and 5.6MB address mapping dump — all unauthenticated.

**Procedure:**
1. `curl /actuator/prometheus | grep -oE 'uri="[^"]+"' | sort -u` → full route list
2. For EACH uri: test with GET (no auth) → filter out 401/403/404
3. Any 200/400/500 response = endpoint is PROCESSING without auth (investigate further)
4. 400 with validation error = accepts input without auth (potential write access)
5. Document all unauth-accessible endpoints as findings or attack surface

```bash
# Run against ALL live hosts, not just priority targets
# See references/bulk-actuator-scanning.md for the full script
bash scripts/bulk-actuator-scan.sh ./ptest-output/recon-passive/resolving-subs.txt

# Quick manual check
while read sub; do
  for path in /actuator /actuator/health /actuator/env /swagger-ui.html /api-docs /admin /console; do
    code=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://${sub}${path}")
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "${sub}${path} -> ${code}"
  done
done < live-subs.txt
```

**Deep dive:** See `references/bulk-actuator-scanning.md` and `references/framework-specific-attacks.md` §7.

## Scope Type Adjustments

- **web/API:** All techniques apply. Focus on techniques 1, 2, 3, 6, 7.
- **network:** Skip web-specific techniques. Focus on service-specific enumeration (SMB shares, SNMP walks, NFS exports).
- **cloud:** Focus on storage bucket enumeration, API gateway discovery, serverless function endpoints.
- **mobile:** Focus on API endpoints the app communicates with (extract from APK/IPA), certificate pinning checks.

## Output

Document findings in `./ptest-output/enumeration/`:
- `summary.md` — consolidated enumeration results
- `directories.md` — discovered paths per host
- `api-endpoints.md` — API endpoints with methods and auth requirements
- `parameters.md` — discovered parameters per endpoint
- `auth-mechanisms.md` — authentication mechanisms per application
- `js-analysis.md` — findings from JavaScript analysis
- `gobuster-*.txt` — raw tool output
- `ffuf-*.json` — raw tool output

Write `./ptest-output/enumeration/checklist.md`:

```markdown
# Enumeration Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Directory & File Brute-Force (MANDATORY) | PENDING | |
| 2 | API Endpoint Discovery (MANDATORY) | PENDING | |
| 3 | Parameter Discovery | PENDING | |
| 4 | Virtual Host Enumeration | PENDING | |
| 5 | CMS-Specific Enumeration | PENDING | |
| 6 | JavaScript Analysis | PENDING | |
| 7 | Authentication Endpoint Mapping | PENDING | |
| 8 | Framework Detection & Targeted Enumeration | PENDING | |
| 9 | GraphQL Endpoint Discovery | PENDING | |
| 10 | WebSocket Endpoint Discovery | PENDING | |
| 11 | Deserialization Sink Identification | PENDING | |
| 12 | Bulk Actuator/Admin Scan (MANDATORY) | PENDING | |
```

Mark each technique as `DONE`, `SKIPPED (reason)`, or `FAILED (reason)` after execution.

## 13. Cloud Misconfiguration Checks

Systematic checks for cloud-specific misconfigurations on all discovered subdomains.

### Storage Bucket Enumeration
```bash
# Check all subdomains for open S3/Spaces bucket listing
for url in $(cat live-urls.txt); do
  resp=$(curl -s "$url" | head -5)
  if echo "$resp" | grep -qi "ListBucket\|<Key>\|<Contents>"; then
    echo "OPEN BUCKET: $url"
    # Check write access
    curl -s -X PUT "$url/test-write-check" -d "test" -w "%{http_code}"
  fi
done

# Check for non-package files in open buckets (internal tools, scripts, keys)
# Look for: install scripts, GPG keys, config files, internal binaries NOT on GitHub
```

### Exposed Monitoring/Observability
```bash
# Sentry DSN extraction from CSP headers
curl -sI https://target.com | grep -i "content-security-policy" | grep -oP 'https://[a-f0-9]+@[^/]+\.sentry\.io/\d+'

# Prometheus metrics endpoints
for path in /metrics /api/v1/metrics /actuator/prometheus; do
  curl -s "https://target.com$path" -w "\n%{http_code}" | tail -3
done

# Health/readiness endpoints (may leak versions, dependencies)
for path in /health /healthz /readyz /status /api/health; do
  curl -s "https://target.com$path" -w "\n%{http_code}" | tail -3
done
```

### Exposed API Documentation
```bash
# OpenAPI/Swagger specs — test at EVERY discovered context path
# AltoCMS lesson: /jago/v3/api-docs was unauth while /jago/api/v2/api-docs was 401
# Spring Boot 3.x serves at context root, bypassing /api/* security filters
for base in "" $(grep -oE '/[a-z]+' live-paths.txt 2>/dev/null | sort -u); do
  for path in /v3/api-docs /v2/api-docs /openapi.json /swagger.json /swagger-ui /swagger-ui.html /api-docs /docs /redoc; do
    code=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" "https://target.com${base}${path}")
    echo "$code" | grep -qvE "^(404|000) " && echo "${base}${path} -> $code"
  done
done
```
**When found:** Download immediately, extract all paths, count schemas, check for sensitive field names (password, token, pin, secret). Report as finding if accessible without auth.

**CRITICAL NEXT STEP — Systematic Unauth Endpoint Testing (AltoCMS, June 2026):**
When an OpenAPI spec is found unauthenticated, do NOT stop at documenting the spec exposure. Immediately test EVERY endpoint in the spec for missing auth:
```python
# Parse OpenAPI spec and test all endpoints without auth
import json
with open('api-docs.json') as f:
    spec = json.load(f)
for path, methods in spec['paths'].items():
    for method in methods:
        # POST endpoints with empty body, GET endpoints bare
        # Filter: status != 401 AND size > 0 = UNAUTH ACCESS
```
**AltoCMS result:** 95 endpoints tested → found `/api/download/remove-files` (POST) accessible without auth, accepting file deletion requests. This endpoint was NOT discoverable via ffuf/gobuster (would need exact path), only via systematic OpenAPI-guided testing. The OpenAPI spec is not just an info disclosure finding — it's the TOOL to find auth bypass on individual endpoints.

### Container Registry Exposure
```bash
# Docker Registry V2 API
curl -s "https://registry.target.com/v2/" -w "\n%{http_code}"
curl -s "https://registry.target.com/v2/_catalog" -w "\n%{http_code}"
# Check www-authenticate header for auth realm
curl -sI "https://registry.target.com/v2/" | grep -i "www-authenticate"
```

## Pitfalls

### Coverage Discipline (CRITICAL)
- **Enumerate ALL live hosts, not just "interesting" ones.** Phase 2 produces a full live-hosts list. Phase 3 MUST touch every one of them — even if just a quick probe to confirm they're blocked. The user corrected this: testing 13/54 hosts is not "Phase 3 complete."
- **NEVER assume a host is "dead" or "abandoned" and skip enumeration.** A default page (Apache2, nginx welcome, IIS default) does NOT mean there's nothing behind it. Run gobuster/feroxbuster on EVERY live host regardless of what the index page shows. Hidden apps, forgotten admin panels, and exposed files often sit behind default pages. User correction (BFI, May 2026): "don't be assume dude" — skipped gobuster on e-pmo2.bfi.co.id because it showed Apache2 default page. Manual spot-checks (`.git`, `.env`) are NOT a substitute for proper directory brute-forcing.
- **Workflow:** (1) Get unique live host count from Phase 2. (2) Categorize: accessible vs blocked/unreachable. (3) Run techniques on ALL accessible hosts. (4) Document blocked hosts with reason (CF 403, IAP redirect, timeout). (5) Only then claim exit criteria met.
- **Same path on all environments:** If `/partner-webview/` works on `api.jago.com`, also check `dev-api`, `stg-api`, `pt-api`. Dev/staging may have debug features, source maps, or weaker auth.

### Catch-All Response Detection
- **GCP health endpoints** (e.g., `dev-data-jit.jago.com`) may return `{"ok":true}` for ALL paths — test a random UUID path first to detect catch-all behavior before marking actuator endpoints as "found."
- **SPA catch-all:** Flutter/React/Angular apps return 200 with fixed-size HTML for all paths. Always check a random path first, note the response size, then use `--exclude-length` in gobuster or `-fs` in ffuf.
- **SPA proxy prefix bypass (LoanPlatform, June 2026):** When a backend service path returns 400 "Bad Request" from Istio/Envoy (11 bytes, text/plain), the SPA base path may proxy the same requests WITHOUT the routing restriction. Test ALL discovered API paths (from JS/source maps) via the SPA prefix (e.g., `/app/client/api/endpoint` instead of `/app/service/api/endpoint`). Check source maps for empty `baseURL`/`serviceUrl` config — means API calls are relative to SPA base. This bypassed auth on 5,327 financial records + disbursement PII.
- **Source map false positive:** When `.map` files return the same size as the SPA catch-all, they are NOT real source maps — they are the catch-all HTML. Always verify content-type and first bytes before concluding source maps are exposed. (bitbank.cc lesson: all 10 chunk.js.map files returned 496038 bytes = exact SPA size, content-type text/html.)
- **Multiple catch-all sizes:** A single target may have DIFFERENT catch-all sizes for different route groups. bitbank.cc returned 40445 for root paths, 9492 for sub-404 paths, and 113446 for /announcement/* paths (client-rendered routes with more content). Test multiple random paths at different depths to map all catch-all patterns before filtering.
- **CloudFront POST-vs-GET differential:** When CloudFront serves a cacheable-only distribution (S3 origin), GET returns the SPA catch-all for ALL paths but POST returns a CloudFront 403 ("distribution supports only cachable requests") with ~1053 bytes. Use this differential to detect real backend paths: if POST on `/prefix/path` returns 403/1053 while GET returns the SPA catch-all, there IS a backend route configured at that prefix — CloudFront is just blocking non-cacheable methods. The backend likely handles these via a different CloudFront behavior (e.g., origin pointing to an API server). Test the path on other in-scope hosts where the behavior might allow POST.

### Cloudflare "CNAME Cross-User Banned"
- Response: 403 with ~8KB body, title "CNAME Cross-User Banned | Cloudflare"
- This means the subdomain's DNS points to Cloudflare IPs but no CF zone claims it — **subdomain takeover vector** (different from dangling CNAME to external service like Aiven/Heroku).
- Verify: `dig +short <subdomain>` returns CF IPs (104.18.x.x / 172.64.x.x) but the zone isn't configured.

### Google IAP-Protected Hosts
- Hosts behind GCP Identity-Aware Proxy redirect to `accounts.google.com/o/oauth2/v2/auth` with a `client_id` parameter.
- The client_id itself is not sensitive (it's a public OAuth client) but document it for completeness.
- **IAP bypass attempts:** Try `/healthz`, `/_/healthz`, `/readiness`, `/api/health` — these are sometimes excluded from IAP rules. Usually they still redirect, but worth checking.

## Exit Criteria
- [ ] **ALL live hosts from Phase 2** have been probed (not just "interesting" ones).
## Phase 2→3 Handoff Verification (MANDATORY)

Before starting Phase 3 techniques, verify the target list is complete:

```bash
# Compare master subdomain list vs live-hosts.txt from Phase 2
sort -u subdomains-master.txt > /tmp/master.txt
sort -u live-hosts.txt > /tmp/live.txt
comm -23 /tmp/master.txt /tmp/live.txt > /tmp/missed.txt
echo "Missed from Phase 2: $(wc -l < /tmp/missed.txt)"
```

**If missed count > 0:** Batch-probe all missed subdomains before proceeding. Phase 2 may have only probed a subset (e.g., from DNS brute-force results but not the full passive enumeration list). Use `xargs -P 10 curl` for fast batch probing.

**Bank Jago lesson (2026-05-29):** Phase 2 live-hosts.txt had 67 entries but master list had 343 subdomains. 184 were never probed — including hosts with exposed APIs, GCP IAP services, and subdomain takeover targets. User caught this gap during Phase 3 review.

## Exit Criteria
- [ ] **Phase 2→3 handoff verified** — ALL subdomains from master list probed (not just live-hosts.txt).
- [ ] All live web applications have directory/file enumeration completed.
- [ ] API endpoints mapped with methods and parameters.
- [ ] Authentication mechanisms identified per application.
- [ ] Hidden content and functionality discovered.
- [ ] Cloud misconfiguration checks completed (buckets, monitoring, API docs, registries).
- [ ] Mandatory tools (gobuster/feroxbuster, ffuf) executed — or gap documented.
- [ ] Checklist shows all applicable techniques executed.
