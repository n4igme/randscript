# WebAuthn & Passkeys Security Testing

Testing FIDO2, WebAuthn, and passkey implementations. Use during Phase 5/6 when target uses passwordless or passkey authentication.

---

## Overview

```text
WebAuthn/FIDO2 provides phishing-resistant authentication using:
- Public key cryptography (no shared secrets)
- Hardware authenticators (YubiKey, Titan)
- Platform authenticators (Touch ID, Windows Hello, Face ID)
- Passkeys (synced across devices via iCloud/Google/Microsoft)

Components:
- Relying Party (RP): The website/service
- Authenticator: Hardware or platform key
- Client: Browser implementing WebAuthn API
```

## Attack Surface

| Area | Attack | Severity if Found |
|------|--------|-------------------|
| Fallback auth | Weaker method available (email, SMS, password) | High |
| Challenge generation | Predictable/static/reusable challenges | Critical |
| Origin validation | Accepts wrong origin in clientDataJSON | Critical |
| RP ID validation | Accepts subdomain or case variation | High |
| Counter validation | Doesn't detect cloned authenticator | Medium |
| User verification | Accepts UV=false when UV=required | High |
| Attestation | Accepts "none" when "direct" required | Medium |
| Account recovery | Recovery bypasses WebAuthn entirely | High |
| Session post-auth | Weak session after strong auth | Medium |

---

## Registration Flow Testing

### Intercept & Analyze

```javascript
// Monitor registration in browser console
navigator.credentials.create({
    publicKey: {
        challenge: new Uint8Array([...]),
        rp: { name: "Target", id: "target.com" },
        user: { id: new Uint8Array([...]), name: "user@target.com", displayName: "User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],  // ES256
        authenticatorSelection: { authenticatorAttachment: "platform" },
        timeout: 60000,
        attestation: "none"
    }
}).then(cred => console.log(cred));
```

### Registration Test Cases

| # | Test | Technique | Impact |
|---|------|-----------|--------|
| 1 | Replay registration response | Capture authenticatorData + clientDataJSON, replay to different account | Account takeover |
| 2 | Tamper clientDataJSON origin | Modify origin field, check if server validates | Cross-origin attack |
| 3 | Tamper challenge | Use expired/different challenge | Replay attack |
| 4 | Weak attestation acceptance | Send "none" attestation when "direct" required | Fake authenticator |
| 5 | Multiple credential binding | Register same authenticator to multiple accounts | Shared credential abuse |
| 6 | No challenge validation | Use static/predictable challenge | Replay attack |

---

## Authentication Flow Testing

### Intercept & Analyze

```javascript
// Monitor authentication
navigator.credentials.get({
    publicKey: {
        challenge: new Uint8Array([...]),
        rpId: "target.com",
        allowCredentials: [{
            type: "public-key",
            id: new Uint8Array([...]),
            transports: ["usb", "nfc", "ble", "internal"]
        }],
        userVerification: "preferred",
        timeout: 60000
    }
}).then(assertion => console.log(assertion));
```

### Authentication Test Cases

| # | Test | Technique | Impact |
|---|------|-----------|--------|
| 1 | Signature replay | Capture assertion, replay on different session | Session hijack |
| 2 | Counter bypass | Send counter < stored value (cloned key) | Undetected clone |
| 3 | User verification bypass | Set UV="discouraged", check if accepted | Biometric bypass |
| 4 | Cross-origin attack | Modify origin in clientDataJSON | Phishing |
| 5 | RP ID mismatch | Use subdomain or case variation of rpId | Domain confusion |
| 6 | Expired challenge reuse | Use old challenge value | Replay |

---

## Common Vulnerabilities

### Weak Challenge Generation

```python
# VULNERABLE: Predictable challenge (timestamp-based)
def generate_challenge():
    return base64.b64encode(str(time.time()).encode())

# SECURE: Cryptographically random
def generate_challenge():
    return base64.b64encode(os.urandom(32))

# TEST: Request 10 challenges rapidly, check for patterns
# If sequential or time-based → Critical finding
```

### Origin Confusion Payloads

```python
# Test these origin values in clientDataJSON:
origins_to_test = [
    "https://target.com",       # Legitimate
    "https://target.com.",      # Trailing dot
    "https://Target.com",       # Case variation
    "https://target.com:443",   # Explicit port
    "https://evil.target.com",  # Subdomain
    "https://target.com.evil.com",  # Suffix
    "http://target.com",        # HTTP downgrade
]
# If any non-legitimate origin is accepted → Critical
```

### Fallback Authentication Bypass

```text
The #1 weakness in WebAuthn deployments:

1. Register WebAuthn credential (strong auth)
2. Trigger "lost authenticator" flow
3. Check what fallback is offered:
   - Email magic link → Medium (phishable)
   - SMS OTP → Medium (SIM swap)
   - Security questions → High (guessable)
   - Password reset → High (undermines entire WebAuthn)
   - Support ticket → Medium (social engineering)

If ANY fallback exists that doesn't require another FIDO2 key,
the WebAuthn security is effectively downgraded to the fallback's level.
```

### Counter Validation Bypass

```python
# Authenticators maintain a signature counter
# Cloned keys don't sync counters → counter goes backwards

# Test procedure:
# 1. Authenticate normally (server stores counter = 100)
# 2. Intercept next auth, modify counter to 50
# 3. If accepted → counter validation is broken
# 4. Impact: cloned authenticators go undetected

# Server SHOULD reject:
def verify_assertion(stored_counter, received_counter):
    if received_counter <= stored_counter:
        raise SecurityError("Possible cloned authenticator")
```

---

## Passkey-Specific Testing

### Synced Credential Risks

```text
Passkeys sync via cloud (iCloud Keychain, Google Password Manager):

Test scenarios:
1. Can credentials be exported/extracted from sync provider?
2. What happens when sync account is compromised?
3. Is credential revocation propagated across devices?
4. Can attacker add their device to victim's sync group?
5. Cross-platform sync gaps (Apple→Android transfer)
```

### Hybrid/Cross-Device Auth (CTAP 2.2)

```text
Phone-as-authenticator flow:
1. Desktop shows QR code
2. User scans with phone
3. BLE proximity verification
4. Phone authenticates, desktop gets credential

Attack vectors:
- QR code capture/replay (screenshot, shoulder surf)
- BLE relay attack (extend proximity range)
- MitM on transport layer
- Rogue QR code (phishing variant)
```

---

## Testing Tools

### Chrome DevTools WebAuthn Emulator

```text
1. DevTools → More tools → WebAuthn
2. Enable virtual authenticator environment
3. Create virtual authenticator (supports UV, resident keys)
4. Register/authenticate with virtual device
5. Inspect credentials, modify responses
```

### Python fido2 Library

```python
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# Create test server for validation testing
rp = PublicKeyCredentialRpEntity(id="localhost", name="Test")
server = Fido2Server(rp)

# Generate registration options
options, state = server.register_begin(
    {"id": b"user_id", "name": "test", "displayName": "Test"},
    credentials=[]
)

# Tamper with options and test server validation
# Modify challenge, origin, rpId in responses
```

### Burp Suite Approach

```text
1. Intercept registration/authentication POST requests
2. Decode base64 fields (clientDataJSON, authenticatorData)
3. Modify and re-encode:
   - Change origin in clientDataJSON
   - Modify challenge value
   - Alter counter in authenticatorData
   - Strip attestation statement
4. Forward modified request
5. Check if server accepts
```

---

## Implementation Verification Checklist

```text
[ ] Challenge is cryptographically random (32+ bytes)
[ ] Challenge expires (< 5 minutes)
[ ] Challenge is single-use (can't replay)
[ ] Origin validation is strict (exact match)
[ ] RP ID validation is correct (no subdomain confusion)
[ ] Signature counter is validated (detects clones)
[ ] User verification flag enforced when required
[ ] Attestation verified if required by policy
[ ] No weaker fallback auth methods available
[ ] Credential bound to specific user account
[ ] Rate limiting on authentication attempts
[ ] Session security post-WebAuthn is adequate
[ ] Credential revocation works across all devices
[ ] Registration requires existing auth (can't add rogue key)
```

---

## Reporting Guidance

**Severity mapping:**
- Fallback to password/email when WebAuthn is "required" → **High** (undermines entire deployment)
- Predictable/reusable challenge → **Critical** (replay attacks)
- Missing origin validation → **Critical** (phishing despite WebAuthn)
- Missing counter validation → **Medium** (cloned keys undetected)
- Accepts UV=false when required → **High** (biometric bypass)
- No attestation when required → **Medium** (fake authenticator)

**Key message for reports:** WebAuthn is only as strong as its weakest path. If a password reset flow exists alongside WebAuthn, the effective security level is that of the password reset, not WebAuthn.
