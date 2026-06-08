# WinTicket IssueHunt Engagement

## Scope
- *.winticket.jp
- Program: https://issuehunt.io/programs/72c9712d-1727-47a1-8b1e-e51940135e64
- Operator: CyberAgent, Inc.

## Critical Lesson: Firebase ≠ App Auth

**The mistake:** Claimed "Critical ATO" via Firebase pre-registration + provider unlinking without proving access to victim data through WinTicket's actual session system.

**What was actually proved:** Firebase API-level manipulation (pre-registration, deleteProvider, email change). None of these translate to WinTicket account access because:
1. The app has its OWN session system at `POST /z/auth` (separate from Firebase)
2. The session exchange body format is unknown (all 50+ attempts returned 400)
3. The backend likely validates `sign_in_provider` claim — rejecting password-provider tokens
4. `/v1/auth/email/token` returns tokens to ANYONE (it's a tracking token, not auth)

**The rule:** Firebase token ≠ app session. You must prove the FULL chain: Firebase auth → app session exchange → access victim endpoints.

## Architecture
- TWA (Trusted Web Activity) — Android app is Chrome wrapper around www.winticket.jp
- Firebase project: winticket-firebase
- API key: AIzaSyAqFWjtrN44xcvDikKA2zSSnzGDeT8uodE
- CDN: Fastly/Varnish
- Backend: GCP (Istio/Envoy, asia-northeast1)
- Auth proxy: www.winticket.jp/z/auth (body format UNKNOWN)
- Login methods: phone, email-link, Google, Apple

## Auth Flow (partially mapped)
1. `POST /v1/auth/email/token` → tracking token (NOT auth)
2. `POST /v1/auth/email` with {email, token} + Bearer pre-token → sends email link (204)
3. User clicks link → Firebase `signInWithEmailLink` → gets idToken
4. `POST /z/auth` with UNKNOWN body → real WinTicket session
5. Session used as Bearer on `api.winticket.jp/v1/*` endpoints

## Key Config (from window.__CONFIG__)
```
API_URL: https://api.winticket.jp/v1
PROXY_ENDPOINT_PREFIX: /z
CMS_ENDPOINT_PREFIX: /cms
AUTHENTICATED_PATH_PREFIX: /my
FIREBASE_AUTH_DOMAIN: auth.winticket.jp
SENTRY_DSN: https://1e2b4364...@o245467.ingest.sentry.io/1426523
GMO_MP_API_KEY: MTRmMmQ4OTU1MWEy...
```

## Confirmed Findings

### PROVED (with real evidence)
- **Email Bombing (Medium):** POST /v1/auth/email sends unlimited emails to ANY address from info@mail.winticket.jp. 5 rapid requests → 5 emails delivered (verified in inbox via mail.tm). No rate limiting. Timestamps 11:43:15-11:43:19 confirm ~1/sec delivery.
- **Firebase Unrestricted Account Creation (Medium):** signUp endpoint creates accounts with any email+password. No invitation required on what should be invite/registration-flow-only.
- **Firebase Email Change Without Verification (Medium):** accounts:update changes email instantly without confirmation email. Changed ctest-probe@wshu.net → victim-takeover@wshu.net in one API call.
- **Firebase Email Enumeration (Low):** createAuthUri returns registered=true/false. Confirmed admin@winticket.jp exists. Also: signInWithPassword returns INVALID_PASSWORD (not INVALID_LOGIN_CREDENTIALS) leaking account existence.
- **Firebase Account Self-Deletion (Low):** accounts:delete with idToken deletes account immediately. Bypasses any app-level deletion flow/cooldown.
- **Firebase Password Reset Flood (Low):** sendOobCode PASSWORD_RESET sends to any registered email (confirmed sent to admin@winticket.jp).
- **GCP Project Number Leak (Info):** Dynamic Links 403 reveals consumer: "projects/459015971859"
- **Staging Bucket Exists (Info):** staging.winticket-firebase.appspot.com returns 403 (exists, ACL'd)

### Confirmed but Low-Impact
- CDN path traversal: `%2e%2e` in any /v1/* path → 302 to api-origin.winticket.bet
- Intent injection: POST /v1/auth/apple reflects body into intent:// (CSRF-able but OOS as redirect)
- Internal domains: admin.winticket.bet (IAP), stg.winticket.bet (Basic Auth)

### NOT exploitable (properly secured)
- GCS buckets: all ACL'd (winticket, winticket-firebase.appspot.com)
- Firebase RTDB: permission denied even with auth token
- Firestore: 404 (not used)
- Firebase Storage: 412 (service account misconfigured but not exploitable)
- Cloud Functions: none exposed
- GCR/Artifact Registry: auth required
- AWS openresty box (dwuzxuvwlq.winticket.jp): 403 root, 404 all paths except /health (200)
- Brute-force: Firebase locks after ~5 attempts (TOO_MANY_ATTEMPTS_TRY_LATER)

## To Complete (requires Burp on real device)
- Intercept POST /z/auth to learn body format
- Test if password-provider Firebase tokens are accepted (proves/kills ATO)
- If accepted: full pre-registration ATO chain is exploitable
- If rejected: finding is only "Firebase misconfiguration" (Low/Info)

## Temp Email Flow (for emailLink testing)
```bash
# Use mail.tm API for receiving Firebase email links
# 1. Create account: POST https://api.mail.tm/accounts {address, password}
# 2. Get token: POST https://api.mail.tm/token {address, password}
# 3. Send Firebase link: POST identitytoolkit.googleapis.com/v1/accounts:sendOobCode
# 4. Wait 5s, read: GET https://api.mail.tm/messages + /messages/{id}
# 5. Extract oobCode from HTML link
# 6. Sign in: POST accounts:signInWithEmailLink {email, oobCode}
```
