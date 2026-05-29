# Phase 6: Runtime Test Categories

Detailed procedures for each test category. Apply based on Phase 2 findings — don't test blindly.

## 1. Data Storage

```bash
# Android SharedPreferences
adb shell "run-as <package> cat /data/data/<package>/shared_prefs/*.xml"
# Or with root:
adb shell "su -c 'cat /data/data/<package>/shared_prefs/*.xml'"

# Android SQLite
adb shell "run-as <package> ls /data/data/<package>/databases/"

# iOS Keychain
objection -g <bundle_id> explore
ios keychain dump

# iOS NSUserDefaults
ios nsuserdefaults get

# Clipboard monitoring
# Logcat sensitive data
adb logcat | grep -i "token\|password\|key\|secret"
```

**Local storage security checklist (rooted device):**
- **PIN/login attempt counters:** Check if `pinAuthAttempts`, `loginAttempts` etc. are in plaintext SharedPreferences. If resettable → client-side lockout bypass (Low, requires root).
  ```bash
  grep -iE "attempt|lock|pin|biometric" shared_prefs/FlutterSharedPreferences.xml
  # Reset test: modify value → force-stop → restart → verify app accepts new value
  ```
- **Token storage:** Check if JWT/refresh tokens are plaintext or encrypted. Look for:
  - Hive databases (`app_flutter/*.hive`) — run `strings` on them for plaintext tokens
  - `cipherImplementationKeystore.xml` — indicates Android Keystore encryption (good)
  - If tokens in Hive are binary blobs (not readable JWT strings) → encrypted at rest (good)
- **Cached sensitive data:** Check Hive boxes for plaintext PII:
  ```bash
  for f in app_flutter/*.hive; do
    echo "=== $f ==="; strings "$f" | grep -iE "token|password|account|card|[0-9]{10,}" | head -5
  done
  ```
- **Flutter SharedPreferences leakage:** Look for account numbers, customer IDs, phone numbers stored unencrypted. Low severity but worth documenting for banking apps.
- **Biometric flags:** Check if `activeFingerprint`, `validBiometricLimit` can be flipped to bypass biometric enrollment requirements.

## 2. Deep Link / URL Scheme Injection

```bash
# Android
adb shell am start -a android.intent.action.VIEW -d "scheme://path?param=INJECTED"

# iOS (via Frida)
# Test: open redirect, XSS via WebView, auth bypass
```

- **Parameter name fuzzing:** When a deep link handler fails to extract a value despite correct URI format, the parameter name may differ from what hardcoded URLs suggest. Enumerate candidate names from: (1) field names in decompiled source/metadata, (2) method names, (3) common variants (`url=`, `server=`, `target=`, `endpoint=`, `addr=`).
- **Deep link parameters leaked to analytics:** After triggering any deep link, check logcat for analytics SDK logging:
  ```bash
  adb shell am start -d "scheme://app/transfer?amount=1000000&to=9999999999" <package>
  adb logcat -d -t 30 | grep -iE "CleverTap|Mixpanel|firebase.*event" | grep -i "referrer\|page\|event"
  ```
  If the full URI appears in analytics events → data leakage finding (Low-Medium).

## 3. WebView Attacks

- JavaScript enabled + addJavascriptInterface = RCE potential
- File access from WebView context
- URL loading with user-controlled input

## 4. Intent/IPC Injection (Android)

```bash
adb shell am start -n <package>/.ExportedActivity
adb shell am broadcast -a <package>.ACTION --es "data" "injected"
adb shell content query --uri content://<package>.provider/table
```

## 5. Biometric/PIN Bypass

- Hook biometric callbacks via Frida (see `references/phase7-execution-procedures.md` → #7)
- Check if auth is client-side only vs server-validated
- Test fallback mechanisms

## 6. Screenshot/Screen Recording Protection

- Check FLAG_SECURE on sensitive screens
- Test screen capture during sensitive operations

## 7. Binary Patching

- Modify smali to skip checks
- Patch conditional jumps
- Re-sign and test modified behavior

## References

`runtime-testing.md`, `frida-scripts.md`, `deep-link-path-traversal.md`
