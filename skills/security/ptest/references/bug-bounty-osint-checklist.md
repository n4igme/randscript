# Bug Bounty OSINT Checklist

When running ptest against a bug bounty target (YesWeHack, HackerOne, Bugcrowd), passive OSINT must be thorough BEFORE moving to active phases. Bug bounties reward novel findings — shallow recon means missing the vectors that pay.

## Mandatory OSINT Techniques (Do ALL of these)

### 1. Standard DNS/WHOIS (always done)
- WHOIS, NS, MX, TXT, A, AAAA records
- SPF/DKIM analysis for infrastructure hints
- Domain verification TXT records (reveals services: Atlassian, Docker, Microsoft, Google)

### 2. Subdomain Enumeration (always done)
- subfinder, amass, crt.sh
- Merge and deduplicate

### 3. JavaScript Bundle Analysis (CRITICAL — often missed)
- Download Next.js `_buildManifest.js` → reveals all routes
- Download `_app` and page chunks → extract hardcoded URLs
- Look for: staging domains, API base URLs, internal service names, API keys
- Pattern: `grep -oE 'https?://[^"'\''` \\);,]+'` on all JS files
- **This is how staging domains get discovered** (e.g., dcxstage.com found in coindcx.com JS)

### 4. Firebase/Cloud Config Enumeration
- Check `/__/firebase/init.json` on Firebase-hosted subdomains
- Check `/.well-known/assetlinks.json` for Android app packages
- Check `/.well-known/apple-app-site-association` for iOS
- Test Firebase RTDB: `https://{project}.firebaseio.com/.json`
- Test Firebase Storage: `https://firebasestorage.googleapis.com/v0/b/{bucket}/o`
- Test Firebase Auth signup: identitytoolkit.googleapis.com

### 5. Wayback Machine
- Full URL dump: `web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=text&fl=original&collapse=urlkey`
- Filter for non-JS/CSS/image paths
- Look for: old API endpoints, removed admin panels, config files

### 6. GitHub/GitLab Code Search
- Search for domain name in public repos
- Search for API keys, secrets, internal URLs
- Check if target has official org/repos
- Check third-party repos that integrate with the target's API

### 7. Docker Hub / Container Registry
- Check `hub.docker.com/v2/orgs/{name}` for org existence
- Check `hub.docker.com/v2/repositories/{name}/` for public images

### 8. Shodan/Censys/InternetDB
- Check all direct (non-CDN) IPs via `internetdb.shodan.io/{ip}`
- Look for: open ports, historical services, CVEs

### 9. Mobile App Intelligence
- Apple App Store lookup: `itunes.apple.com/lookup?bundleId={id}`
- Android package names from assetlinks.json
- APK download (apkeep/APKPure) for endpoint extraction (Phase 3)

### 10. Statuspage/Public Monitoring
- Check `/api/v2/components.json` on Statuspage instances
- Reveals: internal service names, architecture, current issues

### 11. Third-Party Service Enumeration (from JS/DNS)
- Analytics: Mixpanel, Amplitude, Segment, Google Analytics
- Error tracking: Sentry, Datadog, TrackJS
- Push: MoEngage, OneSignal, Firebase Cloud Messaging
- Support: Zendesk, Freshdesk, Sprinklr, ManageEngine

### 12. Staging/Alt Domain Discovery
- Check JS bundles for non-production domains
- Check SPF records for IP ranges that host staging
- Check CT logs for related domains (same org)
- Common patterns: `{name}stage.com`, `staging-{name}.com`, `{name}-staging.com`

## What NOT to Skip

The user correction "did you perform the osint well?" was triggered by skipping items 3-12 above. The initial pass only covered items 1-2 plus basic tech fingerprinting. For bug bounties, items 3 (JS analysis), 4 (Firebase), 5 (Wayback), and 12 (staging domains) are the highest-ROI OSINT techniques because they reveal attack surface that other hunters miss.

## Bug Bounty Scope Verification

- **Ask about scope EARLY** — before active testing on discovered staging domains
- Staging domains found via OSINT may be out of scope even if they belong to the target
- Always confirm: "the scope is only *.{domain}.com" before testing alt domains
- Intelligence from out-of-scope domains is still valuable for understanding architecture

## Pre-Auth Endpoints (Test WITHOUT Account)

Before declaring "unauthenticated testing exhausted," always check these endpoints that work without auth:
- `/api/v1/send_otp` — rate limit bypass, OTP flooding, purpose rotation
- `/api/v1/forgot_password` — user enumeration via response differentiation
- `/api/v1/signup` — registration logic flaws
- Feature flags / experiments endpoints — info disclosure
- Health / status endpoints — infrastructure info leak
- Public API endpoints (ticker, markets) — rate limiting, parameter tampering

See `references/otp-endpoint-testing.md` for the full OTP testing playbook.

## Google VRP Target Selection (Lessons Learned)

Google's standard web apps (Pitchfork framework) are extremely hardened. Traditional web vulns (CSRF, IDOR, XSS, clickjacking) are systematically prevented at the framework level. Before investing time:

**Low-ROI targets (avoid unless you have a specific lead):**
- Any `*.google.com` Pitchfork app (ESF server, `/_/AppName/` pattern) — CSRF solid, IDOR user-scoped, XSS blocked by Trusted Types + nonces
- Sandbox/staging subdomains — behind ÜberProxy/corp auth, unreachable externally
- API keys in page source — referer-restricted by design, not vulns
- `nflpzd` Basic Auth tokens — intentional feed polling credentials, not leaks
- Internal URLs/codenames in page source — informational only, rarely pays bounty

**Higher-ROI targets on Google:**
- **Non-Pitchfork infra** — e.g., `colab.research.google.com` (TornadoServer), anything not on ESF
- **AI/agent layer attacks** — prompt injection, system prompt leakage, sandbox escape, tool permission abuse (Jules, Gemini, NotebookLM)
- **OAuth/GitHub integration flows** — state parameter validation, token scope abuse, cross-tenant access
- **Newer products with less testing** — Gemini Data Analytics, Illuminate (older builds = less patched)
- **Mobile apps** — often have weaker auth patterns than web

**Key insight:** On AI coding agents (Jules), the web layer is a dead end. The real attack surface is the agent's code execution sandbox, its GitHub App permissions, and prompt injection to leak system instructions or access unauthorized repos. These require interactive UI testing, not curl.

## Pace Adjustment for Bug Bounties

- Phase 1-2 combined should take 30-60 minutes max
- Don't over-invest in DNS brute-force on Cloudflare-heavy targets (diminishing returns)
- JS bundle analysis has better ROI than wordlist brute-force for modern SPA targets
- Move to exploitation vectors faster — other hunters are competing for the same bugs
- Socket.IO/WebSocket services without WAF are highest priority (direct K8s access)
