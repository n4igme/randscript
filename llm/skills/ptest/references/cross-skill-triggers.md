## Cross-Skill Triggers

See `references/cross-skill-triggers.md` for full table and chains.

| Signal | Trigger Skill |
|--------|--------------|\
| Cloud infrastructure (AWS/GCP/Azure) | `ctest` |
| API-heavy target | `atest` |
| Mobile app discovered | `mtest` |
| Web3/blockchain | `w3hunt` |
| Source code available | `scode` |
| Istio/service mesh detected | `references/istio-mesh-assessment.md` |
| Geo-restricted target | `references/geo-restriction-bypass.md` |
| Cloudflare API Shield detected (401 MISSING_API_TOKEN) | `references/cloudflare-api-shield-bypass.md` — classify responses (CF-blocked vs backend-auth vs backend-forbidden), test all methods per path, check for path whitelist misconfig, path-based bypass discovery, cross-host testing |
| GCS-hosted SPAs / Keycloak / Spring Boot microservices | `references/engagement-bfi.md` — JS bundle config extraction, realm discovery, actuator/swagger detection, 302 internal name leak, CORS on gateway, accidental security control (double Vary masking missing auth), Django LMS ORM error + hijack, service-wide auth differential |
| DigitalOcean / Snapshooter / Stripe webhooks (Intigriti) | `references/engagement-digitalocean-intigriti.md` — Stripe webhook bypass pattern, S3 bucket listing, hackathon-tracker JWT, GenAI API, CSP intel extraction. See also `references/intel-digitalocean-program.md` for scope, infrastructure map, hardened vectors, auth-required next steps |
| Japanese crypto exchange / bitbank / IssueHunt | `references/engagement-bitbank-issuehunt.md` — scope (3 domains: bitbank.cc, app.bitbank.cc, api.bitbank.cc), HMAC-SHA256 API auth (not cookies, CSRF N/A), PubNub Access Manager, CloudFront+S3+Next.js, Angular SPA chunk analysis, Socket.IO streams, CORS *.bitbank.cc reflection, GitHub org intel, IssueHunt UUID program URLs. Also see `references/engagement-bitbank.md` for attack strategy |
| n8n/workflow automation found | `references/n8n-workflow-assessment.md` — check /rest/settings (unauthenticated config leak), enumerate webhooks (RCE vector via CVE-2026-42231), test telemetry key, check version for CVEs. Also check `references/n8n-mcp-oauth-exploitation.md` for CVE-2026-42236 (unauth OAuth client registration via /.well-known/oauth-authorization-server → /mcp-oauth/register) |
| Flutter web app detected | `references/flutter-web-app-analysis.md` — extract JWTs, auth headers, internal domains, partner IDs from main.dart.js (4-10MB). Check version.json + source maps on all environments |
| Tyk API Gateway detected (/hello or 403 "forbidden") | `references/tyk-gateway-enumeration.md` — check /hello (version+health leak), brute admin secret, enumerate registered APIs via 403 differential. Also see `references/n8n-mcp-oauth-exploitation.md` §Tyk for x-tyk-authorization header brute |
| Transmit Security CIS SDK detected (ts-platform-websdk.js, /cis/ paths, auth_session_id) | `references/transmit-security-cis-testing.md` — FIDO/WebAuthn endpoint probing, anti-enum verification, device_binding_token flow. Extract `/cis/v1/auth-session/*`, `/v1/webauthn/*`, `/fido/login/*` paths. Test on app domain proxy path AND api domain root. SDK reveals undocumented auth endpoints at API root (no /v1 prefix): /login, /signup, /reset_password, /register_mail, /signedup. Field names differ from main API (mail vs email, g-recaptcha-response with hyphens). CloudFront may block POST (cacheable-only distributions) but confirms backend exists. Different error format = separate microservice. Also see `references/identity-sdk-endpoint-extraction.md` for CloudFront behavior policy gotcha |
| Tight-scope bounty (≤5 explicit domains, no wildcard) | `references/tight-scope-bounty-testing.md` — JS-first approach, exhaustion checklist, self-audit at phase transitions |

| Meta/Instagram target | `references/intel-meta-instagram-infrastructure.md` — app IDs, auth endpoints, CORS patterns, anti-bot, OIDC config |
| JWT auth with verbose errors | `references/jwt-algorithm-enumeration.md` — enumerate accepted algorithm via error differentiation ("Signature verification failed" = accepted, "Algorithm not allowed" = blocked, "not supported" = unavailable). Then brute HMAC secret with SecLists scraped-JWT-secrets.txt |
| Unauthenticated token endpoint (email confirm, withdrawal approve) | `references/token-format-oracle.md` — length oracle via error code differentiation, rate limit check, timing oracle, severity matrix |
| Third-party identity SDK in SPA (Transmit Security, Auth0, Okta, Descope) | `references/identity-sdk-endpoint-extraction.md` — extract hidden auth endpoints from SDK JS, determine host/prefix, CloudFront behavior policy gotcha, multi-layer JS analysis: app chunks, SDK endpoints, path prefix discovery, root-level auth endpoints |

| LINE WORKS / line-works.com (IssueHunt/HackerOne) | `references/engagement-lineworks.md` — wildcard scope (*.line-works.com + mobile apps), Naver DNS (tight, no brute-force yield), WordPress 5.8.4 (hardened nginx, static-served), cxtalk-service GCP behind CF ("Invalid Path" routing), 12 Android packages in assetlinks.json, worksmobile.com shared infra, OIDC+AI plugin endpoints. HackerOne program SUSPENDED (Dec 2025), line-works.com = Other Assets only, Tier A = messenger/pay/store. See also `references/intel-line-works-ly-corp.md` |
| Marketing-site-only scope (WP hardened, real app elsewhere) | `references/engagement-lineworks.md` — when scope is *.domain.com but actual product lives on a different root domain. Mobile app analysis first — extract API calls that might route through in-scope domain. WP exploitation requires auth (check registration, Elementor subscriber CVEs). Static-served WP sites bypass most unauth WP vulns because nginx serves HTML before PHP processes cookies. Signals: Naver/Akamai NS, assetlinks.json pointing elsewhere, Shodan hostnames, static-served WP with all REST locked. Consider early fast-track if Phase 1 reveals this pattern |
| Stripe/payment webhook endpoint found (`/stripe/webhook`, `/webhooks/stripe`, `/billing/webhook`) | `references/stripe-webhook-exploitation.md` — signature bypass verification, event type impact matrix, escalation path, framework-specific defaults. Also `references/webhook-signature-bypass.md` — test without signature, with fake signature, prove active processing via 500 differential. CWE-345, typically High (8.6). Check CSP for `*.stripe.com`, Laravel Cashier routes |
| nginx blocking paths with 403 (wp-json/users, xmlrpc, debug.log) | `references/nginx-case-sensitivity-bypass.md` — try capitalized path segments (`/Users` instead of `/users`). nginx location rules are case-sensitive on Linux but app routing is often case-insensitive. Chain with XSS for data exfiltration |
| Elementor plugin detected (< 3.5.8) | `references/elementor-dom-xss-lightbox.md` — CVE-2022-29455 DOM XSS via `#elementor-action:action=lightbox&settings=<b64>` with `type:html`. Verify in browser console (click trigger required). Chain with nginx bypass for user data exfil |
| Mobile app in scope / assetlinks.json found | Check BOTH `/.well-known/assetlinks.json` (Android) AND `/apple-app-site-association` (iOS, check root path too). Extract: package names (prod/stage/debug), deep link paths (`/line-auth/*`, `/invite/*`, `/meeting/*`), signing certs. Deep link paths reveal app URL structure — probe them server-side for auth callbacks |

| Django app detected (allauth, CSRF middleware, /accounts/) | Test: registration for ORM errors (info leak — submit valid form, check for unhandled exceptions leaking model paths like `nems.users.models.User`), `/hijack/acquire/` + `/hijack/release/` (django-hijack impersonation — 400=needs params, 302→login=exists, 403=exists; also try `/id/hijack/acquire/` for i18n-prefixed apps), `/admin/` + `/__debug__/` (debug toolbar), password reset for user enumeration (compare responses for valid vs invalid emails — Django allauth returns same redirect for both = no enum), `/static/` for JS secrets, `/.git/HEAD` (403=exists but blocked, vs 404=not present). Check sidebar/HTML comments for internal path disclosure. Version in footer (`<b>Version X.Y.Z</b>`) or error pages. Look for `/static/hijack/hijack-styles.css` in page source as indicator of django-hijack. Try `/id/` prefix (common for i18n-prefixed Django apps). Registration ORM errors that leak model paths are Medium severity (info disclosure + broken functionality). Django-hijack on production is Medium (attack surface — enables lateral movement if any account is compromised). Also test: broken registration as DoS on user onboarding (server error = no new users can register), `<meta name="userToken">` in page source (auth state leak), `/i18n/setlang/` for open redirect via `next` param. |
| Spring Boot service with mixed 500/401 responses | **Accidental security control detection:** If some endpoints return 500 (app error like "Duplicate key Vary") while others on the same service return data freely, auth is likely MISSING on the entire service — the 500 is from infrastructure (CORS conflict, proxy bug, header collision), not access control. Prove by: (1) find one working endpoint on same service prefix (e.g., `/master/v1/general` returns data), (2) confirm broken endpoints return 500 with app-error message (not 401/403), (3) check response headers for JSESSIONID (session created = request reached app, no auth rejected it), (4) raw TCP request shows no `WWW-Authenticate` header. Document the "fix path" — when devs fix the CORS/proxy bug (routine maintenance), all data becomes exposed. This upgrades severity from "one open endpoint" to "entire service unauthenticated, masked by accidental control." BFI lesson (2026-05): gateway added `Vary: Origin` + Spring `@CrossOrigin` also added `Vary: Origin` = duplicate header = HTTP 500 on 12+ endpoints. Only `/general` (missing `@CrossOrigin`) was accessible — proving zero auth underneath. |
| CORS misconfiguration + missing auth (compound pattern) | When CORS reflects arbitrary origin with `credentials: true` AND the service behind it lacks auth, the CORS vuln becomes a force multiplier. Test: (1) confirm CORS reflects on token/userinfo endpoints, (2) check if token endpoint allows cross-origin POST (preflight returns `allow-methods: POST`), (3) verify no auth on underlying service. Attack chain: victim visits attacker page → JS reads `/userinfo` cross-origin (session theft) OR exchanges auth codes cross-origin. If admin endpoints also reflect CORS, escalation to admin API access is possible. Double Vary header conflict (gateway + app both adding `Vary: Origin`) is a specific indicator — it means CORS is configured at TWO layers, increasing the chance of misconfiguration at one. |
| Legacy PHP login form (action=*.php, no framework) | Test SQLi immediately — comment bypass (`admin'-- -`), error-based (`'\\\\`), then UNION if WAF allows. Check `build_sys/`, `includes/`, `config/` paths. MD5 client-side hashing = weak auth. If default page hides apps, try org-specific path names. **Cloudflare WAF bypass**: switch POST body from `application/x-www-form-urlencoded` to `multipart/form-data` (`curl -F`). CF inspects urlencoded bodies more aggressively — multipart often passes UNION SELECT, ORDER BY, FROM, LIMIT while urlencoded blocks them. Test both content types early. **Privilege enum**: use `INTO OUTFILE '/tmp/x'` to check FILE priv (error msg confirms denied vs allowed), `information_schema.tables` via UNION to confirm schema access, `ORDER BY <col_name>` as column existence oracle (302=exists, error=not). **Test ALL SQLi endpoints on the same server** — different apps may connect with different DB users having different privileges (one app may lack FILE while another has it). When errors are suppressed (no error output), the absence of "Access denied" doesn't confirm success — write to a web-accessible path and verify with GET. Silent failure = same restricted privilege, just no error display. |
| OTP/2FA/verification code endpoint found | `references/otp-bruteforce-pattern.md` — authenticated oracle technique: compare error codes for correct vs wrong code with session cookie, rate limit differential between sibling endpoints, PoC structure with real tested values |
| Meta/Facebook/Instagram target | `references/meta-auth-surface.md` — auth endpoints, 2FA/recovery oracle targets, protections (Arkose, fb_dtsg, encrypted pw), payout tiers, strategy |

## ptest → atest Handoff (API-Dominant Targets)

**Trigger:** After Phase 4 attack surface mapping, if >50% of live targets are API endpoints (REST/GraphQL/gRPC) with no meaningful browser UI.

**Decision criteria:**
- Target is primarily API-backed (no server-rendered pages, no DOM-based attack surface)
- Endpoints follow REST/GraphQL/gRPC patterns (JSON request/response, OpenAPI docs, introspection)
- Auth is token-based (JWT, API key, OAuth bearer) rather than session/cookie-based

**Handoff procedure:**
1. Complete ptest Phase 4 (attack surface confirmed with user)
2. Initialize atest with `start` — but skip Phase 1 gate requirements by carrying over:
   - Endpoint inventory from `ptest-output/enumeration/checklist.md` or `ptest-output/attack-surface/`
   - Auth tokens from `ptest-output/credential-inventory.md`
   - API type classification (REST/GraphQL/gRPC) from Phase 3 enumeration
3. Start atest at **Phase 2 (AuthN/AuthZ)** directly
4. atest Phase 1 gate is satisfied by: "Inheriting from ptest Phase 3+ with endpoints mapped and valid token confirmed"
5. Findings from atest flow back to ptest's findings-log.md with `source: "atest"` tag

**What NOT to redo in atest:**
- Endpoint discovery (already done in ptest Phase 3)
- Token acquisition (already in credential-inventory.md)
- Tech fingerprinting (already in ptest Phase 2)

**What atest adds over continuing in ptest Phase 5-6:**
- Systematic BOLA testing with bola_scanner.py on every ID-bearing endpoint
- GraphQL-specific exploitation (batching, depth, alias abuse)
- gRPC-specific testing (reflection, protobuf manipulation)
- API-type decision tree routing (different priorities per protocol)
- background_recon.py for parallel auth-diff scanning
- Mass assignment mandatory checks on every write endpoint

**When to stay in ptest instead:**
- Target has significant browser UI (DOM XSS, CSRF, clickjacking surface)
- Mixed content: API + server-rendered pages + file uploads
- Infrastructure-level findings are expected (SSRF to cloud metadata, port-based services)
- Scope includes non-HTTP services (SSH, FTP, custom protocols)

---

Cross-skill work runs **parallel** to the current phase (doesn't block gateway). Findings tagged with `source: "{skill-name}"` in findings-log.md. Each skill maintains its own state; only findings flow back to ptest.

---