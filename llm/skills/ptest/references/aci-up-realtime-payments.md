# ACI Worldwide UP (Universal Payments) — Real-Time Payments Platform

## Identification Signals
- Title: "Real-Time Payments - Login Page"
- `window.apsContextPath = "/Responsive"`
- Cookie suffix pattern: `apsfa011-1` (server identifier in JSESSIONID)
- Header: `X-Powered-By: JSP/2.3`
- TLS CN pattern: `UICBIF*.jago.io` (Bank Jago deployment)
- ExtJS/Sencha login form + AngularJS SPA shell (hybrid)
- CSRF token: `APSF_SEC_TOKN` (UUID, per-session, exposed in init)

## Architecture
- **Backend:** Java/JBoss (WildFly), JSP/2.3
- **Frontend:** ExtJS/Sencha (login page) + AngularJS + Angular (hybrid SPA, ag-grid)
- **Auth:** OAuth2 internal + Entitlements API + MFA (OTP/Password)
- **Build:** Webpack, versioned static assets at `/Responsive/{timestamp}/`

## Key Unauthenticated Endpoints

| Endpoint | Returns |
|----------|---------|
| `/Responsive/desktop/login` | Login page (ExtJS form) |
| `/Responsive/desktop/doLogin` | POST login handler |
| `/Responsive/desktop/init?clientType=up` | Config: language, CSRF token, features, translations, resources |
| `/Responsive/desktop/init?clientType=admin` | Larger config (743 extra translation keys) |
| `/Responsive/desktop/timeZoneList` | Timezone data |
| `/Responsive/desktop/timeout` | Login page variant (shown after session expiry) |
| `/Responsive/desktop/error?success=false` | Login error page |
| `/Responsive/platform/index.html` | SPA shell (AngularJS bootstrap) |
| `/Responsive/{version}/js/src/PortalUI.js` | Portal registration/SSO logic |
| `/Responsive/{version}/js/src/CustomerAuthNUI.js` | Auth flow (OAuth, MFA routes) |

Everything else returns 302 → login. Extremely hardened.

## Login Form Fields
- `loginUser` — username
- `loginPwdId` — password
- `loginOrg` — organization (default "Root", free-text INPUT type)
- `loginLang` — language (en_US, en_AU)
- `APSF_SEC_TOKN` — CSRF token (from init response)

## Login Flow
1. GET `/desktop/login` → sets JSESSIONID
2. GET `/desktop/init?clientType=up` → provides CSRF token
3. POST `/desktop/doLogin` with form fields → 302 to `/desktop/error?success=false` (failure) or `/desktop/home` (success)

## Auth Error Behavior
- Generic message for ALL failures: "Contact your system administrator to reset your username."
- Same response for invalid user, wrong password, invalid org
- No user enumeration via error messages
- No account lockout detected (20+ rapid attempts succeed)
- No rate limiting on doLogin endpoint

## Features Exposed via init
- `forgotCredentialsLink: true` — but endpoint requires auth
- `alertInbox: true`
- `serviceWorker: false`
- Organization type: INPUT (free text, default "Root")

## Auth Architecture (from CustomerAuthNUI.js)
- OAuth internal: `/Responsive/oauth/internal/{authorize,preauthorize,clientinfo,consent,scopes}`
- Entitlements: `/Responsive/Entitlements/1.0/Authentication/AuthenticationAttemptAnalyze`
- Factor verify: `/Responsive/Entitlements/1.0/Authentication/AuthenticationFactorVerify`
- Auth routes: `/auth/login`, `/auth/password`, `/auth/sfa`, `/auth/consent`
- MFA types: ONE_TIME_PASSWORD, PASSWORD

## Business Modules (from translations)
- BI-FAST payment processing (ISO 20022: pacs.002, pacs.004, pacs.008, pacs.009)
- Inbound/Outbound Credit Transfers
- Payment Returns
- Liquidity Position monitoring
- Transaction Statistics
- Batch Manager
- Exception Queues
- Settlement Data

## Hardening Observed
- JBoss /console disabled (302 → /noconsole.html)
- All REST/API/OAuth endpoints behind auth
- Security headers: HSTS, X-Frame-Options, X-XSS-Protection, nosniff
- HttpOnly + Secure on session cookies
- No directory listing
- No actuator/swagger/api-docs exposed
- VHost ignored (same response for any Host header)
- Self-signed TLS (internal deployment)

## Attack Vectors
1. **Login brute-force** — no rate limit, no lockout. Try ACI UP default accounts.
2. **Default credentials** — ACI platforms may ship with default operator/admin accounts.
3. **CSRF token predictability** — analyze if APSF_SEC_TOKN is sequential/predictable.
4. **Session fixation** — JSESSIONID set before authentication.
5. **clientType parameter** — admin/mobile/portal return different configs (info disclosure).
6. **Post-auth exploitation** — OAuth internal endpoints, payment APIs if creds obtained.

## Naming Convention (Bank Jago)
- `UICBIFSYDCB001` = UIC BI-Fast SY (Staging) DCB001
- `UICBIFDCB001` = UIC BI-Fast (Prod) DCB001
- Server: `apsfa011-1` = APS (Appian Payment Services) FA (Financial Application) 011
