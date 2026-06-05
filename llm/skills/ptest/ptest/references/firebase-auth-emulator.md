# Firebase Email-Link Auth Session Emulator

## Pattern
When a target uses Firebase Authentication with email-link (passwordless) sign-in,
build a Flask app to manage the full auth flow and obtain authenticated sessions.

## Auth Flow (Firebase signInWithEmailLink)

```
1. sendOobCode (email) → Firebase sends magic link to email
2. User clicks link → oobCode extracted from URL params
3. signInWithEmailLink (oobCode + email) → Firebase idToken + refreshToken
4. Exchange idToken with target API → session cookie/token
5. Use session for authenticated testing
```

## Firebase Identity Toolkit Endpoints

```bash
BASE="https://identitytoolkit.googleapis.com/v1"

# Send sign-in link (MUST include Referer header if API key is restricted)
curl -H "Referer: https://TARGET/" "$BASE/accounts:sendOobCode?key=API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"requestType":"EMAIL_SIGNIN","email":"EMAIL","continueUrl":"CALLBACK","canHandleCodeInApp":true}'

# Exchange oobCode for idToken
curl -H "Referer: https://TARGET/" "$BASE/accounts:signInWithEmailLink?key=API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"oobCode":"CODE_FROM_EMAIL","email":"EMAIL"}'

# Refresh token
curl "https://securetoken.googleapis.com/v1/token?key=API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"grant_type":"refresh_token","refresh_token":"REFRESH_TOKEN"}'

# Check if email is registered
curl -H "Referer: https://TARGET/" "$BASE/accounts:createAuthUri?key=API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"identifier":"EMAIL","continueUri":"https://TARGET/login"}'
```

## Key Notes

- Firebase API keys are often **referer-restricted** — add `-H "Referer: https://target.domain/"` to all calls
- `createAuthUri` reveals if an email is registered (`"registered": true/false`) — potential user enumeration
- `sendOobCode` succeeds even for unregistered emails (creates account on link click)
- The Flask emulator should try multiple body formats for the target's session exchange:
  - `{"token": idToken}`
  - `{"firebaseToken": idToken}`
  - `{"idToken": idToken}`
  - Bearer header: `Authorization: Bearer <idToken>`

## WinTicket Implementation

See `ptest-output/exploit/winticket_session.py` for working Flask emulator:
- Port 5001 (5000 blocked by macOS AirPlay)
- Handles full flow: send link → extract oobCode → exchange → WinTicket session → API tester
- Discovered: token endpoint returns timestamp.hmac (not user-bound), no rate limiting
