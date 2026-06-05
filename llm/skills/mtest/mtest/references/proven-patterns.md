# Proven Mobile Attack Patterns

High-hit-rate findings from Bank Jago and bug bounty engagements. Check these first in Phase 7.

## Pattern 1: Deep Link Path Traversal

**Apps:** Banking, fintech, any app with deep link handlers
**Check:** Find deep link schemes in AndroidManifest → test path traversal in URI
```bash
adb shell am start -a android.intent.action.VIEW -d "scheme://host/../../../sensitive_path"
```
**Impact:** High — access internal activities, bypass navigation guards

## Pattern 2: Insecure Local Storage (SharedPreferences/Keychain)

**Apps:** Banking, auth-heavy apps
**Check:** After login, inspect stored data
```bash
adb shell run-as <package> cat /data/data/<package>/shared_prefs/*.xml
# Or with root:
cat /data/data/<package>/shared_prefs/*.xml | grep -i "token\|session\|pin\|password\|key"
```
**Impact:** High — session tokens, PINs, or credentials stored in plaintext

## Pattern 3: Certificate Pinning Bypass → API IDOR

**Apps:** Any app with pinning that hides API traffic
**Chain:** Bypass pinning (Phase 3) → intercept traffic → find user ID in requests → swap ID → access other user's data
**Impact:** High-Critical — BOLA/IDOR on authenticated endpoints

## Pattern 4: WebView JavaScript Bridge Abuse

**Apps:** Apps with WebView + `@JavascriptInterface`
**Check:** Find WebView with JS enabled + registered interfaces → test if deep link can load attacker URL in WebView
```javascript
// If attacker controls URL loaded in WebView:
Android.exposedMethod("malicious_input")
```
**Impact:** High-Critical — depends on what the bridge exposes (file read, token access, native function calls)

## Pattern 5: Exported Content Provider Data Leak

**Apps:** Apps with content providers (check AndroidManifest)
**Check:**
```bash
adb shell content query --uri content://<authority>/
adb shell content query --uri content://<authority>/users
```
**Impact:** Medium-High — PII exposure, internal data access

## Pattern 6: Intent Redirection / Unsafe Parcel

**Apps:** Apps that forward intents or unparcel data from untrusted sources
**Check:** Find activities that read extras and pass them to other components
**Impact:** High — launch arbitrary activities, bypass auth screens

## Pattern 7: Hardcoded API Keys in APK

**Apps:** All — especially those using third-party services
**Check:** During Phase 2 static analysis
```bash
grep -rn "AIza\|AKIA\|sk_live\|pk_live\|ghp_\|glpat-" ./decompiled_source/
```
**Impact:** Medium-High — depends on key permissions (Google Maps = Low, AWS = Critical)

---

## Banking App Specific (Bank Jago patterns)

- PIN/biometric bypass via activity export or intent manipulation
- Session token in SharedPreferences without encryption
- Transaction replay (same request ID accepted twice)
- OTP bypass via race condition or predictable generation
- Attestation bypass (SafetyNet/Play Integrity) → access protected APIs

## When to Add New Patterns

Add after engagement when:
- Pattern produced a confirmed finding
- Applies to multiple apps (not app-specific)
- Can be checked in <10 minutes
