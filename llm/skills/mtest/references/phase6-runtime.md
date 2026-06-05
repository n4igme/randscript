# Phase 6: Runtime Testing

### Gate: Data Storage (#1) tested + at least 2 other categories from the prioritized list; deep links tested if found in Phase 2

**Prioritization (hit these in order for maximum finding density):**
1. **[Both]** **Data Storage** — fastest, often yields Low-Medium findings in minutes (plaintext tokens, PII in SharedPrefs/Keychain, unencrypted Hive)
2. **[Android]** **Deep Link / Intent URI Injection** / **[iOS]** **URL Scheme Hijacking** — high-value, especially if Phase 2 found WebView + JS bridge
3. **[Android]** **Intent/IPC Injection** — if exported components found in Phase 2, test them now
4. **[Both]** **WebView Attacks** — only if JS bridge identified in Phase 2 static analysis
5. **[Both]** **Biometric/PIN Bypass** — only if client-side-only auth detected (check if server validates)
6. **[Both]** **Screenshot/Screen Recording** — quick check, usually Low severity
7. **[Both]** **Binary Patching** — last resort, time-intensive, only if specific bypass needed

**Skip guidance:** If Phase 2 found no exported components → skip #3 (Android-only anyway). If no WebView with JS enabled → skip #4. If biometric is server-validated → skip #5. If iOS-only engagement → skip #3 entirely. Don't test everything blindly — let Phase 2 findings guide you.

**Standalone script vs Frida hooks (decision point):**
If Phase 2 already extracted secrets (RSA keys, API keys, encryption keys, auth flow logic), write a standalone Python script (requests/httpx + cryptography) instead of hooking obfuscated native code via Frida. Frida is for EXTRACTION — once you HAVE the secrets, use them directly. Saves hours. See pitfall: "Don't over-engineer Frida when you have source code + keys."

**Production Validation Rule:** Before any finding can be rated Critical (Confirmed), it MUST be demonstrated on a non-rooted production device with a logged-in user account. Findings validated only on rooted/instrumented devices are capped at High (Probable) because:
- Feature flags may behave differently on rooted vs non-rooted
- Server-side checks may detect rooted devices and change responses
- Anti-tampering bypasses may alter app behavior in ways that create false positives

If you cannot test on a non-rooted device, explicitly state this limitation and cap severity at High.

> Full procedures per category: `references/phase6-test-categories.md`

**Reference:** `runtime-testing.md`, `frida-scripts.md`, `deep-link-path-traversal.md`
