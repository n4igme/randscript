# Laravel /api/get-params/{type} Parameter Brute-Force

## When to Use
- Target is Laravel with `/api/get-params/{type}` or `/api/get-params-inbound/{type}` pattern
- Discovered during Phase 3 JS bundle extraction or Phase 5/6 exploitation

## Technique

Many Laravel contact center / CRM apps (e.g., BlueSpider by AOS Graha) store system configuration in a `params` table with a `param_type` column. The `/api/get-params/{type}` endpoint is often unprotected or inconsistently gated across different host instances of the same codebase.

### Critical param_type values to test:

```
passDefault          ← DEFAULT PASSWORD (highest priority!)
password
defaultPassword
VERIFIKASI           ← verification/KYC parameters
CATEGORY
STATUS
DEPARTMENT
CHANNEL
EMAIL
SMS
OTP
SECRET
API_KEY
TOKEN
WEBHOOK
```

### Attack pattern:

```bash
# Test passDefault first — exposes the system default password
curl -sk "https://target.com/api/get-params/passDefault"

# If found, combine with user enumeration for instant ATO on new/reset accounts
# Example response: [{"param_type":"passDefault","param_value":"JAGO1234!"}]
```

### Key observations (BlueSpider, June 2026):

1. **Different instances have different auth requirements for the same endpoint:**
   - dev-bsjago: requires auth (redirects to login)
   - dev-amar, dev-outbound, dev.aosgraha.com: NO auth required
   - bsjago (PROD): NO auth required (exposed `JAGO1234!`)

2. **Dev vs prod may have DIFFERENT default passwords:**
   - Dev instances: `12345678`
   - Production: `JAGO1234!`

3. **Attack chain:** 
   - F-14 (passDefault exposed) + F-1 (user enumeration via /api/user-combo-username)
   - = Monitor for newly created users → login with known default password → full account takeover

4. **The endpoint returning empty `[]` does NOT mean it's protected** — it means no param of that type exists on that instance. Try multiple param_type values.

## Severity
- If default password is exposed on PROD: **High** (account takeover on new/reset users)
- If exposed only on DEV: **Medium** (information disclosure + potential lateral movement)
