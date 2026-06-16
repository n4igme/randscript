# ACI UP (Universal Payments) Real-Time Payments — Testing Reference

## Platform Identification

- Title: "Real-Time Payments - Login Page"
- Framework: ExtJS/Sencha + AngularJS (hybrid) on JBoss/WildFly
- Header: `X-Powered-By: JSP/2.3`
- Cookie: `JSESSIONID=<value>.apsfa011-1` (server ID suffix)
- Init endpoint: `/Responsive/desktop/init?clientType=up` (unauthenticated)
- CSRF token: `APSF_SEC_TOKN` (UUID per session, but NOT validated on doLogin)
- Auth: OAuth2 internal + Entitlements MFA API

## Critical Bypass: POST + JSON + X-Requested-With Header

**Discovery (BIFast, June 2026):** GET requests to auth-gated endpoints return 302→login. However, POST with `Content-Type: application/json` + `X-Requested-With: XMLHttpRequest` BYPASSES the 302 redirect and reaches the application layer directly.

**Behavior:**
- GET /oauth/internal/authorize → 302 (normal auth)
- POST JSON+XHR /oauth/internal/authorize → 403 JSON error (app-layer response!)
- POST JSON+XHR /Entitlements/1.0/Authentication/AuthenticationFactorVerify → 400 JSON (processes request!)

**Affected endpoints (all bypass 302 with POST+JSON+XHR):**
| Endpoint | GET | POST+JSON+XHR |
|----------|-----|---------------|
| /oauth/internal/preauthorize | 302 or 400 JSON | 500 + IOException class leak |
| /oauth/internal/authorize | 302 | 403 JSON |
| /oauth/internal/token | 302 | 403 JSON |
| /oauth/internal/clientinfo | 302 | 403 JSON |
| /oauth/internal/consent | 302 | 403 JSON |
| /oauth/internal/scopes | 302 | 403 JSON |
| /Entitlements/1.0/Authentication/AuthenticationFactorVerify | 302 | 400/500 JSON |
| /Entitlements/1.0/Authentication/AuthenticationAttemptAnalyze | 302 | 403 JSON |

**Root cause:** The session filter treats XmlHttpRequests differently — instead of redirecting (which would break AJAX), it returns JSON errors. But this means the auth check is SKIPPED for the error path.

## AuthenticationFactorVerify — Direct Credential Validation

The FactorVerify endpoint accepts password verification requests WITHOUT a session:

```json
POST /Responsive/Entitlements/1.0/Authentication/AuthenticationFactorVerify
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{
  "identity": {"loginAndOrgIdent": {"loginIdent": "USERNAME", "orgIdent": "Root"}},
  "authenticationPolicy": [{"ident": "PASSWORD"}],
  "factor": [{"ident": "PASSWORD", "factorText": [{"secretText": "PASSWORD"}]}],
  "newSessionRqInd": true
}
```

**Responses:**
- `{}` (empty body) → 400 `{"error":"minimum_one_factor_required"}`
- Valid structure → 500 `{"error":"technical_error"}` (processes but fails at backend)
- Request format found in: `/Responsive/<version>/js/src/CustomerAuthNUI.js`

## OAuth Preauthorize — Client Validation Bypass

`GET /Responsive/oauth/internal/preauthorize` is unauthenticated and reveals validation sequence:
1. No params → `{"error":"clientid_required"}`
2. + client_id (any value) → `{"error":"Missing state"}`
3. + state → `{"error":"Missing scope"}`
4. + scope → 500 `{"error":"technical_error"}`
5. response_type=token → `{"error":"unsupported_response_type"}`

No client_id validation — accepts ANY value.

## Init Endpoint Intelligence

`/Responsive/desktop/init?clientType=<up|admin|mobile|portal>` returns:
- CSRF token (APSF_SEC_TOKN)
- Features config (forgotCredentialsLink, alertInbox, serviceWorker)
- Application version (timestamp)
- Organization config
- Full translation keys (reveal module names: ip_ng_*, ipLiqPos*, ipTrnStats*)
- `clientType=admin` returns 743 extra keys vs `clientType=up`

## Login Behavior

- Endpoint: POST `/Responsive/desktop/doLogin`
- Fields: loginUser, loginPwdId, loginOrg, loginLang, APSF_SEC_TOKN
- CSRF NOT validated (works without token)
- No rate limiting, no account lockout
- Generic error for all failures: "Contact your system administrator to reset your username."
- No user enumeration (no timing difference either)
- loginOrg reflects in init JS response but special chars blocked (', ", <, >, ;, &)

## Typical Findings on ACI UP

1. No rate limiting on login (Medium)
2. CSRF token not validated on doLogin (Medium)
3. POST+JSON+XHR bypasses auth redirect (High)
4. AuthenticationFactorVerify accessible unauthenticated (High)
5. OAuth preauthorize unauthenticated + no client_id validation (Medium)
6. Self-signed SHA1 certificates (Low)
7. SSH password auth enabled (Low)
8. Missing security headers — CSP, Referrer-Policy, Permissions-Policy (Info)
9. Application version disclosure in init (Info)
10. Java exception type disclosure in error responses (Info)
