# Phase 5: Attack Surface Mapping

### Gate: Feature map documented with entry points per feature; prioritized by risk

This phase creates the structured map that drives Phase 7 (Vulnerability Analysis). Every testable feature is catalogued with its entry points, data sensitivity, and applicable vulnerability classes.

**Auto-generation:** Build attack-surface-map.md directly from Phase 2 exported components + deep links + Phase 4 API endpoints. Don't re-discover — organize what you already found.

**Steps:**

1. Enumerate all user-facing features from:
   - App UI navigation (every screen, every action)
   - Deep link routes (from Phase 2 static analysis)
   - API endpoints (from Phase 4 traffic analysis)
   - Exported components (from Phase 2 manifest analysis)
   - WebView bridges (from Phase 2 JS interface analysis)
   - Background services and receivers

2. For each feature, document:
   - Feature name and description
   - Entry points (UI path, API endpoint, deep link, intent, broadcast)
   - Data handled (PII, financial, auth tokens)
   - Trust boundaries crossed (client→server, app→OS, app→other apps)
   - Authentication/authorization requirements
   - Third-party integrations (payment SDK, analytics, social login)

3. Prioritize by risk:
   - Financial transactions (transfer, payment, top-up) → Critical
   - Authentication/session (login, OTP, biometric, token refresh) → Critical
   - PII handling (profile, KYC, documents) → High
   - File operations (upload, download, share) → High
   - Communication (chat, notifications, deep links) → Medium
   - Social features (feed, comments, likes) → Medium
   - Settings/preferences (theme, language, notifications) → Low

4. Output: `attack-surface-map.md` in `mtest-output/phase5-attack-surface/`

**Attack Surface Map Template:**

```markdown
# Attack Surface Map — [App Name]

## Feature Inventory

| # | Feature | Risk | Entry Points | Data Sensitivity | Auth Required |
|---|---------|------|-------------|-----------------|---------------|
| 1 | Login/Auth | Critical | UI, POST /auth/login, deeplink://auth | Credentials, OTP, tokens | No (pre-auth) |
| 2 | Money Transfer | Critical | UI, POST /transfer/*, deeplink://pay | Account numbers, amounts | Yes |
| 3 | Profile | High | UI, GET/PUT /user/profile | PII, photos | Yes |
| 4 | File Upload | High | UI, POST /upload, content://provider | Documents, images | Yes |
| 5 | Chat/Messaging | Medium | UI, WebSocket /ws/chat | Messages, media | Yes |

## Per-Feature Detail

### Feature 1: Login/Auth
- **UI Path:** Launch → Login screen
- **API Endpoints:** POST /auth/login, POST /auth/otp/verify, POST /auth/refresh
- **Deep Links:** deeplink://auth/reset, deeplink://auth/verify
- **Intents:** com.app.LOGIN_COMPLETE (broadcast)
- **Data:** username, password, OTP, JWT, refresh token, device ID
- **Trust Boundaries:** Client→Server (credentials), Server→Client (tokens)
- **Third-party:** Firebase Auth, Google Sign-In
- **Applicable Vuln Classes:** Brute force, credential stuffing, OTP bypass, session fixation, token leakage, biometric bypass

[Repeat for each feature...]
```

**Cross-reference:** Feed this map directly into Phase 7 as the testing checklist.
