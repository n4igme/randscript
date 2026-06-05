# Unauthenticated Integration/Callback/Webhook Endpoint Testing

Testing exposed callback and webhook endpoints that lack authentication.

---

### Unauthenticated Integration/Callback Endpoint Testing (MANDATORY Phase 3/6)

When actuator metrics or error messages reveal `/integration/*`, `/callback`, or `/webhook` paths, test them WITHOUT authentication. These endpoints are designed to receive calls from partner services (GoPay, payment gateways, KYC providers) and often lack auth by design — but this is a vulnerability when internet-facing.

**Discovery technique:**
1. Check actuator metrics URI tags for `/integration/*` or `/callback` paths
2. Check error messages for internal routing (e.g., `executing POST http://internal-service/path`)
3. Try POST with empty JSON body `{}` — look for 400 (parameter validation) vs 401 (auth required)
4. If 400/500 returned (not 401): endpoint processes requests without auth

**Key insight (Findaya, May 2026):**
- `/integration/gopay/kyc/v1/{id}/callback` — no auth, 500 error leaked internal service name + domain
- `/legalEntityKYC/v1/onboarding-doc` — no auth, returned signed GCS URLs to production KYC documents (Critical)
- `/v1/user/progressive-kyc/callback` — no auth, 500 (processes request)
- Pattern: callback/integration endpoints bypass auth middleware because they're meant for server-to-server calls

**Checklist:**
- [ ] Identify all `/integration/*`, `/**/callback`, `/webhook/*` paths from metrics/errors/JS bundles
- [ ] Test each with POST + empty body (no auth header)
- [ ] If response is NOT 401/403: document as unauthenticated endpoint
- [ ] Check if response contains sensitive data (signed URLs, user records, status changes)
- [ ] Test with crafted payloads to assess impact (can you approve KYC? change status? trigger actions?)

---

## Extended Webhook Testing

### Unauthenticated Callback/Webhook Endpoint Testing (MANDATORY Phase 3/6)

**When you discover `/integration/*`, `/callback/*`, `/webhook/*`, `/hook/*`, or `*/callback` paths (from actuator metrics, JS bundles, or path brute-force), ALWAYS test them without authentication.** These endpoints are designed to receive calls from partner services and often skip auth entirely.

**Why callbacks are high-priority:**
- They're meant to be called by external services (GoPay, payment gateways, KYC providers)
- Developers often rely on "security through obscurity" (hard-to-guess URLs) instead of proper auth
- They frequently return or accept sensitive data (KYC documents, payment status, account approvals)
- Error messages on callbacks often disclose internal service names and routing

**Discovery techniques:**
1. Actuator `/metrics` → check `uri` tags for `/integration/*`, `*/callback` patterns
2. JS bundle analysis → search for "callback", "webhook", "integration" in source
3. Path brute-force with callback-specific wordlist
4. Error-based discovery: POST to guessed paths, check for 500 (processed) vs 404 (doesn't exist)

**Testing procedure:**
```bash
# For each discovered callback/integration path:
for method in GET POST PUT; do
  curl -sk -X $method "$URL" -H "Content-Type: application/json" -d '{}' -w " [%{http_code}]"
done
```

**Interpretation:**
- 400 (bad request) → endpoint processes requests without auth, needs correct payload
- 500 (internal error) → endpoint processes requests without auth, backend issue (check error message for info disclosure)
- 200 with data → **CRITICAL: unauthenticated data access**
- 401/403 → auth enforced (safe)
- 404 → path doesn't exist
- 405 → method not allowed but path exists (try other methods)

**Real-world example (Findaya, May 2026):**
```
POST /legalEntityKYC/v1/onboarding-doc → 200 with 9 signed GCS URLs to production KYC documents
POST /integration/gopay/kyc/v1/test/callback → 500 disclosing internal service name "kyc-service"
POST /v1/user/progressive-kyc/callback → 500 (processed without auth)
```
Result: Critical finding — unauthenticated access to production KYC documents (KTP, NPWP, akta pendirian) of legal entities.

**Checklist (add to Phase 3 enumeration + Phase 6 exploitation):**
- [ ] Identify all callback/integration/webhook paths (from actuator, JS, brute-force)
- [ ] Test each with POST + empty JSON body (no auth headers)
- [ ] If 400: analyze error message for required fields, construct minimal valid payload
- [ ] If 500: document error message (often discloses internal services)
- [ ] If 200 with data: **ESCALATE** — document as Critical if PII/financial data