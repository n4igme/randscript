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

### 2a. BROWSABLE Deep Link Action Triggering (CSRF-like)

Deep links with `android.intent.category.BROWSABLE` can be triggered from web pages via `<a href="scheme://...">` or JS redirect. Test if they can trigger user-facing actions:

**Content injection (pre-fill):**
```bash
# Test if deep links pre-fill user content (posts, messages, search)
adb shell am start -a android.intent.action.VIEW -d "scheme://create?text=attacker-controlled-text"
adb shell am start -a android.intent.action.VIEW -d "scheme://compose?body=phishing-link"
adb shell am start -a android.intent.action.VIEW -d "scheme://search?query=attacker-term"
adb shell am start -a android.intent.action.VIEW -d "scheme://share?text=spam-content"
```

**Action triggering (follow, join, send):**
```bash
# Test if deep links trigger actions without confirmation
adb shell am start -a android.intent.action.VIEW -d "scheme://user?username=X&action=follow"
adb shell am start -a android.intent.action.VIEW -d "scheme://group_invite?id=X&auto_join=true"
adb shell am start -a android.intent.action.VIEW -d "scheme://send_message?to=X&text=Y"
```

**Validation:** Use `uiautomator dump` to check if:
- Text fields are pre-filled with attacker content
- Action buttons (Post, Send, Follow) are immediately visible
- Link previews render for attacker URLs
- No confirmation dialog before action

**Severity guide:**
- Auto-action (no user tap): High
- Pre-fill + one tap to execute: Low-Medium
- Pre-fill + multiple steps: Informational
- Navigation only (no action): Not a finding

**Full chain validation:** Host PoC HTML on HTTP server, open in device browser, tap link, confirm app opens with pre-filled content:
```bash
# Host PoC
python3 -m http.server 8889
# Open in Chrome on device
adb shell am start -a android.intent.action.VIEW -d "http://<host-ip>:8889/poc.html"
# Tap link → verify app opens with attacker content
```
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

## Appendix: Frida-less Dynamic Analysis (When Instrumentation Fails)

When Frida/hluda cannot attach (Meta apps, heavy anti-instrumentation), use these alternatives:

**Activity/navigation tracing:**
```bash
# What's in foreground?
adb shell dumpsys window | grep mCurrentFocus
adb shell dumpsys activity activities | grep topResumedActivity

# Full activity stack (detect Custom Tabs, WebViews, external browser launches)
adb shell dumpsys activity activities | grep -E "ActivityRecord.*<package>"

# Check if Chrome/external browser opened
adb shell dumpsys activity activities | grep -E "chrome|browser"
```

**UI state inspection (replaces Frida hooks on UI):**
```bash
# Dump current UI tree — shows all visible text, buttons, input fields
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml | grep -oE 'text="[^"]*"' | grep -v 'text=""'

# Get element bounds for tap simulation
adb shell cat /sdcard/ui.xml | grep "target_text" | grep -oE 'bounds="[^"]*"'

# Simulate tap at coordinates
adb shell input tap <x> <y>
```

**Screenshot size heuristic:**
```bash
# Take screenshot and check file size
adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png /tmp/
ls -la /tmp/screen.png
# ~14KB = screen off/locked
# ~100-200KB = simple UI (feed, profile)
# ~500KB+ = rich content (WebView, media, new screen)
# ~1MB+ = external browser with content loaded
```

**Logcat (limited but sometimes useful):**
```bash
# Filter by app PID
adb logcat --pid=$(adb shell pidof <package>) -v time | tee /tmp/logcat.txt
# Trigger action, then grep
grep -iE "url|redirect|webview|intent|deeplink" /tmp/logcat.txt
```

**Intent verification (did the app launch something?):**
```bash
# Check intent data in activity records
adb shell dumpsys activity activities | grep -A5 "chrome\|browser\|CustomTab" | grep "dat="
```

**Limitations:**
- Cannot hook internal method calls or return values
- Cannot bypass client-side checks
- Cannot trace URL parameter extraction logic
- Cannot monitor network requests at app level

**When to accept these limitations:** For bug bounty, if you can demonstrate impact via UI state (pre-filled content, navigation to attacker URL, action triggered), that's sufficient evidence. You don't need Frida traces to prove a finding — screenshots + `uiautomator dump` showing attacker-controlled content in the UI is valid PoC.
