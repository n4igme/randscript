# Traffic Analysis Reference

## Capturing Baseline Traffic

### Initial Capture Strategy

```bash
# 1. Clear proxy history
# 2. Launch app fresh (kill first)
adb shell am force-stop <package>
frida -U -f <package> -l root_bypass.js -l ssl_pinning_bypass.js --no-pause

# 3. Capture these flows in order:
# - App startup (what loads before login?)
# - Registration flow (if testing new account)
# - Login flow (OTP, biometric, PIN)
# - Main dashboard load
# - Profile/settings access
# - Core business features (transfers, payments, etc.)
# - Push notification handling
# - Background sync/refresh
# - Logout flow

# 4. Export all requests from Burp/Caido
# Burp: Right-click > Save items (XML)
# Caido: Export session
```

### Identifying Traffic That Escapes Proxy

```bash
# Some traffic may bypass proxy:
# - Certificate pinning on specific domains (not all bypassed)
# - Non-HTTP protocols (MQTT, gRPC, custom TCP)
# - Traffic via VPN/tunnel within the app
# - WebSocket connections

# Check with tcpdump on device
adb shell "su -c 'tcpdump -i any -w /sdcard/capture.pcap'"
# Compare pcap traffic vs proxy traffic — any gaps?
adb pull /sdcard/capture.pcap
wireshark capture.pcap

# Check for non-proxied connections
adb shell "su -c 'netstat -tlnp'" | grep <package_pid>
```

---

## API Surface Mapping

### Endpoint Inventory

Document each endpoint with:

```markdown
| Method | Path | Auth | Purpose | Notes |
|--------|------|------|---------|-------|
| POST | /api/v1/auth/login | None | Login with phone+OTP | Rate limited? |
| GET | /api/v1/user/profile | Bearer JWT | Get user profile | IDOR candidate |
| POST | /api/v1/transfer | Bearer JWT | Fund transfer | Business logic |
| ... | ... | ... | ... | ... |
```

### Authentication Flow Documentation

```markdown
## Auth Flow: [App Name]

### Login Sequence:
1. POST /api/v1/auth/request-otp {phone: "+62xxx"}
   → 200 {request_id: "uuid", expires_in: 300}
2. POST /api/v1/auth/verify-otp {request_id: "uuid", otp: "123456"}
   → 200 {access_token: "jwt...", refresh_token: "rt_...", expires_in: 3600}
3. POST /api/v1/auth/set-pin {pin: "123456"}  (first time only)
   → 200 {status: "ok"}

### Token Lifecycle:
- Access token: JWT, expires in [X] seconds
- Refresh token: opaque, expires in [X] days
- Refresh endpoint: POST /api/v1/auth/refresh {refresh_token: "rt_..."}

### JWT Claims:
{
  "sub": "user_id",
  "iat": timestamp,
  "exp": timestamp,
  "scope": ["read", "write"],
  "device_id": "...",
  ...
}
```

### Request/Response Patterns

```bash
# Common headers to document:
# Authorization: Bearer <jwt>
# X-Device-ID: <device_fingerprint>
# X-App-Version: 1.2.3
# X-Platform: android/ios
# X-Request-ID: <uuid>
# X-Signature: <hmac/hash>  ← request signing!

# If request signing exists, find the signing logic:
grep -rn "X-Signature\|HMAC\|signature\|sign" --include="*.java" jadx_out/
# Hook the signing function to understand the algorithm
```

---

## Interesting Patterns to Flag

### IDOR Candidates

```bash
# Sequential/predictable IDs in URLs or request bodies:
# GET /api/v1/users/12345/profile  ← try 12346
# GET /api/v1/transactions/TXN-000001  ← try TXN-000002
# POST /api/v1/accounts {"account_id": "ACC123"}  ← try ACC124

# UUID-based IDs are harder but not impossible:
# Check if UUIDs are v1 (time-based, predictable)
# Check if UUIDs leak in other responses
```

### Missing/Weak Authentication

```bash
# Test each endpoint:
# 1. Remove Authorization header entirely
# 2. Use expired token
# 3. Use token from different user
# 4. Use token with modified claims (if JWT)

# Automated with Burp:
# - Autorize extension (automatic auth testing)
# - AuthMatrix (role-based access testing)
```

### Sensitive Data in Responses

```bash
# Look for over-exposure:
# - Full credit card numbers (should be masked)
# - Full phone numbers of other users
# - Internal IDs, database keys
# - Email addresses of other users
# - Stack traces in error responses
# - Internal IP addresses / hostnames
# - Debug information
```

### Rate Limiting Assessment

```bash
# Test critical endpoints:
# - OTP request (can we spam OTPs?)
# - OTP verification (can we brute-force 6 digits?)
# - Login attempts (lockout after N failures?)
# - Password reset
# - Transfer/payment endpoints

# Quick test with curl:
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://api.target.com/auth/verify-otp \
    -H "Content-Type: application/json" \
    -d "{\"request_id\":\"$REQ_ID\",\"otp\":\"$(printf '%06d' $i)\"}"
done | sort | uniq -c
# If all return 200/400 with no 429 → no rate limiting (HIGH for OTP)
```

### Request Signing / Anti-Tampering

```bash
# If requests have signatures (X-Signature, X-Hash, etc.):
# 1. Identify the signing algorithm (HMAC-SHA256, etc.)
# 2. Find the signing key (hardcoded? derived from device?)
# 3. Understand what's signed (body? headers? timestamp?)

# In decompiled source:
grep -rn "HmacSHA\|HMAC\|MessageDigest\|Signature" --include="*.java" jadx_out/
grep -rn "X-Signature\|x-sign\|checksum\|integrity" --include="*.java" jadx_out/
```

```javascript
// Hook signing function to extract key and algorithm
Java.perform(function() {
    var Mac = Java.use('javax.crypto.Mac');
    Mac.init.overload('java.security.Key').implementation = function(key) {
        var algo = this.getAlgorithm();
        var keyBytes = key.getEncoded();
        console.log('[Signing] Mac.init: algo=' + algo);
        console.log('[Signing] Key: ' + bytesToHex(keyBytes));
        this.init(key);
    };

    Mac.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        console.log('[Signing] Input: ' + Java.use('java.lang.String').$new(input));
        console.log('[Signing] Output: ' + bytesToHex(result));
        return result;
    };

    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});
```

### WebSocket Connections

```bash
# Identify WebSocket endpoints
grep -rn "wss\?://" --include="*.java" jadx_out/
grep -rn "WebSocket\|OkHttpClient.*newWebSocket\|Socket.IO" --include="*.java" jadx_out/

# Monitor WebSocket traffic (Burp supports this natively)
# Or hook with Frida:
```

```javascript
// websocket_monitor.js
Java.perform(function() {
    // OkHttp WebSocket
    try {
        var WebSocketListener = Java.use('okhttp3.WebSocketListener');
        WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function(ws, text) {
            console.log('[WS] Received: ' + text.substring(0, 500));
            this.onMessage(ws, text);
        };

        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
            console.log('[WS] Sent: ' + text.substring(0, 500));
            return this.send(text);
        };
    } catch(e) {}
});
```

---

## Platform-Specific Checks

### Android-Specific

```bash
# Check for backup transport (adb backup data exfiltration)
adb backup -f backup.ab <package>
# If backup succeeds and contains data → allowBackup=true finding

# Check for task hijacking (StrandHogg)
# Exported activities with taskAffinity set to another app's package
grep -i "taskAffinity" apktool_out/AndroidManifest.xml

# Check for tapjacking vulnerability
# Activities without filterTouchesWhenObscured
grep -rn "filterTouchesWhenObscured" --include="*.java" jadx_out/
```

### iOS-Specific

```bash
# Check for background snapshot protection
# When app goes to background, iOS takes a screenshot
# Sensitive screens should show a blur/placeholder
# Test: press home button on sensitive screen, check app switcher

# Check for pasteboard persistence
# Universal clipboard shares across devices
objection -g <bundle_id> explore
ios pasteboard monitor

# Check for keyboard cache
# Custom keyboards or autocorrect may cache sensitive input
# Look for secureTextEntry on password fields
grep -rn "secureTextEntry\|isSecureTextEntry" headers/
```

---

## Output Template

Save to `phase4-traffic/`:

```markdown
# Traffic Analysis Report

## API Base URLs
- Production: https://api.target.com/v1/
- Staging (if found): https://staging-api.target.com/v1/

## Authentication
- Type: [JWT / OAuth2 / Session / API Key]
- Token location: [Header / Cookie / Query param]
- Token lifetime: [X seconds/minutes/hours]
- Refresh mechanism: [endpoint / silent refresh / re-login]

## Endpoints Discovered
[Table of all endpoints]

## Security Observations
- [ ] Rate limiting present on auth endpoints
- [ ] Request signing implemented
- [ ] Certificate pinning (which domains)
- [ ] Sensitive data properly masked in responses
- [ ] Error messages don't leak internals
- [ ] CORS headers appropriate (if web API)
- [ ] Security headers present (HSTS, CSP, etc.)

## IDOR Candidates
[List endpoints with sequential/predictable IDs]

## Business Logic Targets
[List endpoints for Phase 6 deeper testing]
```
