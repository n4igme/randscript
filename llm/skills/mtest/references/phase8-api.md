# Phase 8: API Testing (Server-side)

### Gate: at least BOLA, auth bypass, and injection tests completed (OR documented N/A with justification if no server-side API exists)

**Delegation to atest:** Phase 8 focuses on mobile-API-specific patterns (attestation replay, device-bound tokens, mobile headers). For comprehensive API testing (full BOLA sweep, injection matrix, business logic), invoke `atest` with the API surface mapped in Phase 4. Pass:
- Base URLs from traffic capture
- Auth mechanism (JWT + attestation token structure)
- API type (REST/GraphQL/gRPC)
- Any rate limit observations from Phase 4

**Mobile-API-specific patterns (test these HERE, not in atest):**
- Device attestation token replay (Eversafe, Play Integrity, AppAttest)
- Mobile-specific headers manipulation (`x-device-id`, `x-app-version`, `x-platform`, `x-cuid`)
- App version downgrade — older API versions may lack attestation checks
- Push notification token theft → impersonate device
- Device registration endpoint abuse (register multiple devices, steal sessions)
- Certificate pinning bypass → capture tokens that are normally invisible to proxy

**Eversafe/attestation-protected APIs — partial unblock workflow:**

1. **Keep the app active** with proxy intercepting traffic (SSL bypass + iptables)
2. **Capture fresh tokens** from Burp: both the attestation token and JWT/session token
3. **Immediately replay** with curl within the JWT TTL window (typically 5 min for banking apps):
   ```bash
   EVERSAFE=$(grep -oP 'x-eversafe-verification-token: \K.*' /tmp/latest_request.txt)
   JWT=$(grep -oP 'Bearer \K[^ ]+' /tmp/latest_request.txt)
   
   curl -s "https://stg-api.example.com/account/accounts?include=balance" \
     -H "authorization: Bearer $JWT" \
     -H "x-eversafe-verification-token: $EVERSAFE" \
     -H "x-device-id: <device_id>" \
     -H "x-cuid: OTHER_CUSTOMER_ID"
   ```
4. **Automate capture-and-replay** if testing multiple endpoints
5. **Document the constraint** in the report

If attestation token expires before you can test (< 5 min validity), mark Phase 8 as N/A with justification.

**Steps (mobile-specific only):**

1. **Device attestation replay** — capture, replay within TTL, test binding
2. **Mobile header manipulation** — remove/swap device-id, downgrade app-version, change platform
3. **App version downgrade** — find older API paths, test without attestation
4. **Device registration abuse** — register multiple devices, test session invalidation
5. **Attestation-free endpoints** — map which endpoints skip attestation, test those directly

**Delegation to atest:** For comprehensive BOLA/IDOR sweep, injection matrix, auth bypass, business logic, and rate limiting — invoke `atest`.

---

## mtest → atest Handoff Checklist

When transitioning to atest, export these artifacts so atest Phase 1 starts with full context:

### 1. Auth Script (MANDATORY)
- Path to working token acquisition script (e.g., `mtest-output/phase6-api/jago_auth.py`)
- Script must be self-contained: run it, get a Bearer token, no manual steps
- If attestation forge is needed, it must be embedded in the script

### 2. Required Headers Template
Document ALL custom headers the API requires beyond standard Bearer:
```
Authorization: Bearer <token>
X-Tyk-Auth: <static gateway key>
X-Eversafe-Verification-Token: <forged per-request>
X-Device-Id: <enrolled device ID>
X-Device-Model: <model string>
X-Build: <build number>
X-Build-Version: <version string>
X-Cuid: <customer ID>
Accept-Api-Version: resource=1.0, protocol=1.0
```

### 3. Host Mapping
Which endpoints live on which host:
```
stg-mobile.jago.com  → auth, loan, consent, config (mobile gateway)
stg-api.jago.com     → account, customer, notification, card (API gateway)
```

### 4. Device Context
- Device ID used during enrollment
- RSA key pair (private key path for signing)
- Attestation forge method (function name, file path)
- Any device-specific values baked into tokens

### 5. Endpoint List
- All endpoints captured in Phase 4 traffic (method + path + host)
- Which require auth vs public
- Any observed rate limits or WAF behavior

### 6. Known Constraints
- Token TTL (e.g., 300s for JWT, 30s for Eversafe)
- Rate limits discovered
- HTTP version requirement (HTTP/2 only, etc.)
- Cloudflare/WAF behavior observed

### Handoff Format

Write a `phase8-handoff.md` in `mtest-output/phase8-api/` with the above sections filled. This becomes atest's Phase 1 input — no re-discovery needed.

### 7. Flow Collections (Postman/HTTP Archive)
Export multi-step business flows as Postman collections for reproducibility:
- Capture the sequential requests from Burp (e.g., loan application: offer → simulation → compliance-check → consent)
- Export as `.postman_collection.json` with variables for Bearer token and device context
- Include in `mtest-output/phase8-api/` alongside the handoff doc
- This saves atest from reconstructing flows by parsing raw Burp history

---

**Cross-reference:** Load `atest` skill for full API testing. Load ptest `references/geo-restriction-bypass.md` if API is geo-blocked.
