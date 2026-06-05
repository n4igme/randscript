# Finding Escalation Techniques

Techniques for escalating Low/Info findings into Medium+ severity through chaining and deeper exploitation.

## CSP Header → Sentry Event Injection

**Chain:** Info disclosure → Medium (monitoring manipulation)

1. Extract CSP header from target (especially `report-to` and `connect-src` directives)
2. Look for Sentry DSN patterns: `https://<key>@<org>.ingest.<region>.sentry.io/<project>`
3. DSN keys are write-only (can send events, cannot read)
4. Prove injection:
```bash
EVENT_ID=$(python3 -c "import uuid;print(uuid.uuid4().hex)")
curl -s "https://<org>.ingest.<region>.sentry.io/api/<project>/store/" \
  -H "X-Sentry-Auth: Sentry sentry_version=7, sentry_key=<key>, sentry_client=test/1.0" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"event_id\":\"$EVENT_ID\",\"message\":\"[BugBounty-Test] Security test\",\"level\":\"info\",\"platform\":\"javascript\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\"}"
```
5. Impact: alert fatigue, monitoring pollution, potential PagerDuty triggers, social engineering via fake errors

## Open S3 Bucket → Internal Tool Exposure

**Chain:** Low (bucket listing) → Low-Medium (internal tool RE)

1. List bucket contents beyond obvious packages
2. Look for files NOT available on public GitHub:
   - Internal agents/daemons (e.g., dotty-agent vs public droplet-agent)
   - GPG keys, install scripts, config files
   - Beta/unstable versions with debug symbols
3. Verify tool is internal: `curl -s "https://api.github.com/repos/<org>/<tool>" | grep "Not Found"`
4. Download and extract for offline analysis:
   - `strings <binary> | grep -E "http(s)?://"` for internal endpoints
   - Look for hardcoded metadata URLs, API paths, auth mechanisms
5. Impact: enables targeted vulnerability research on privileged internal software

## JWT Error Verbosity → Auth Bypass Attempts

**Escalation path (if successful):**
1. Identify JWT library from error messages (e.g., "JsonWebTokenError: jwt malformed")
2. Test `alg:none` bypass: if "signature is required" → not vulnerable
3. Test weak secrets with known wordlists
4. Test type confusion: send non-string values to trigger different error paths
5. Check for expired token handling differences

## CDN-Fronted Target Tactics

When targets are behind Cloudflare/CloudFront:
- Port scanning is useless (all filtered)
- ffuf/nuclei timeout due to rate limiting
- **Use manual targeted curl** with small wordlists instead
- Focus on: API endpoint discovery, CSP/header analysis, bucket misconfigs
- Look for non-CDN subdomains (staging, internal) that bypass WAF

## Firebase Password Provider → Full ATO (Medium → Critical)

**Chain:** Medium (pre-registration squatting) → Critical (full ATO + victim lockout)

Initial finding "password provider enabled on passwordless app" looks Medium — attacker squats email but victim can recover via email-link. Escalation:

1. **accounts:update email change** — Change email without verification. Firebase allows `setAccountInfo` with just an idToken (no re-auth for email change). `emailVerified` resets to `false` but the email IS changed.
2. **accounts:update deleteProvider** — Unlink victim's `emailLink` provider client-side. After this, only `password` (attacker's) remains. Victim has NO way to sign in.
3. **App token exchange** — If backend accepts any Firebase provider token, attacker gets valid app session with victim's UID.

**Escalation checklist (run when password provider is found):**
```
[ ] Can attacker sign in with password after victim uses emailLink? (shared UID)
[ ] Does accounts:update allow email change without verification?
[ ] Does accounts:update allow deleteProvider:["emailLink"]?
[ ] Does app backend accept password-provider tokens at token exchange endpoint?
[ ] Is there rate limiting on signUp? (mass pre-registration)
```

**Key insight:** Firebase "by design" behaviors (shared UID, client-side provider management) become vulnerabilities when the app relies on a single provider. The platform-level design is fine for multi-provider apps, but creates ATO chains on single-provider apps that forgot to disable others.

**Severity jump:** Medium (squatting) → Critical (ATO + permanent lockout + exclusive access)

## Config Endpoint Information Leverage

When you find unauthenticated config endpoints (e.g., `/api/v0/config/settings`):
1. Note password policies (MinPasswordLength:0 = weak)
2. Check if hidden features are still API-accessible (LoginFormVisible:false but login works)
3. Identify auth mechanisms (WebAuthn, OIDC, password) for targeted attacks
4. Version disclosure → check changelogs for security fixes between versions
