# Transmit Security CIS (Customer Identity Service) Testing

## Detection Signal
- `ts-platform-websdk.js` or `platform-websdk` in page source
- Paths containing `/cis/` in the app domain
- Error format: `{"error_code":"...", "message":"..."}` (different from app's own error format)
- Endpoints: `/v1/auth-session/*`, `/v1/webauthn/*`, `/api/v1/verification/*`

## Architecture Pattern
- CIS SDK loaded in the frontend SPA (Angular/React)
- CIS endpoints proxied via the app's domain (e.g., `app.target.com/cis/v1/...`)
- May also be accessible on the API domain at `/fido/login/authenticate/*`
- Uses `auth_session_id` as session identifier
- Uses `device_binding_token` for device trust

## Key Endpoints
```
POST /fido/login/authenticate/start    — Initiate FIDO challenge
POST /fido/login/authenticate/complete — Complete FIDO auth (needs device_binding_token)
POST /cis/v1/auth-session/status       — Session status
POST /cis/v1/auth-session/attach-device — Bind device
POST /cis/v1/webauthn/register/start   — Register new passkey
POST /cis/v1/webauthn/authenticate/passkey/start — Passkey auth
```

## Testing Procedure

### 1. Check if /fido/login/authenticate/start accepts arbitrary auth_session_id
```python
resp = client.post('https://api.target.com/fido/login/authenticate/start', 
                   json={"auth_session_id": "test"})
# If returns webauthn_session_id + credential_request_options → endpoint is open
```

### 2. Check for user enumeration via allowCredentials
```python
# Send username parameter — does credential ID change per user?
resp1 = client.post(url, json={"auth_session_id": "x", "username": "real@user.com"})
resp2 = client.post(url, json={"auth_session_id": "x", "username": "fake@nobody.xyz"})
# If SAME credential returned for all → anti-enumeration (WebAuthn spec §14.6.2)
# If DIFFERENT and deterministic → still anti-enum (generates fake cred per username)
# If different COUNT of credentials → real enumeration oracle!
```

### 3. Verify determinism (real vs derived credentials)
```python
# Same username 3x — if always same cred_id → deterministic (likely fake/derived)
# Different cred_id each time → real lookup (actual vulnerability)
```

### 4. Test /complete endpoint
```python
resp = client.post('https://api.target.com/fido/login/authenticate/complete', json={
    "auth_session_id": "test",
    "webauthn_session_id": "<from start response>",
    "webauthn_encoded_result": "fake"
})
# Check if it validates session before accepting assertion
```

## WebAuthn Anti-Enumeration Spec
Per WebAuthn Level 2 §14.6.2: servers SHOULD return a deterministic fake credential
for non-existent users to prevent enumeration. Signs of compliant implementation:
- Always returns exactly 1 credential regardless of username
- Credential ID is deterministic (same input → same output)
- No timing difference between real and fake users
- `transports` array is always identical

## CloudFront + CIS Gotcha
If CIS is behind CloudFront with "cacheable-only" behavior policy:
- GET requests → SPA catch-all (200, full HTML)
- POST requests → 403 "distribution supports only cachable requests"
- The CIS endpoints only work via POST, so CloudFront blocks them
- Check if they're accessible on a different domain/path (e.g., api.target.com/fido/*)

## Findings Assessment
| Observation | Severity | Rationale |
|-------------|----------|-----------|
| /fido/start accepts any auth_session_id | Info | If anti-enum is compliant |
| /fido/start leaks REAL credential IDs | Medium-High | Enables targeted phishing |
| /fido/complete skips session validation | High | Potential auth bypass |
| Different credential count per user | Medium | User enumeration |
