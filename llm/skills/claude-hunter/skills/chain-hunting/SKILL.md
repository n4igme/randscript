---
name: chain-hunting
description: "A→B Bug Signal Method (Cluster Hunting) — when you find bug A, systematically hunt for B and C nearby. Single bugs pay. Chains pay 3-10x more. Includes 10 known A→B→C chain tables (IDOR→write, SSRF→metadata, XSS→ATO, open redirect→OAuth, S3→secret→OAuth, rate limit→OTP→ATO, GraphQL→PII, debug→creds, CORS→theft, host header→reset→ATO), 6-step Cluster Hunt Protocol, real examples (Coinbase S3 chain, Vienna Chatbot chain), and Top 1% hacker mindset framework (crown jewel thinking, developer empathy, trust boundary mapping, feature interaction). Use when you find a first bug and want to escalate, when building exploit chains for higher payouts, or when /chain is invoked."
---

# A→B BUG SIGNAL METHOD (Cluster Hunting)

**When you find bug A, systematically hunt for B and C nearby.** This is one of the most powerful methodologies in bug bounty. Single bugs pay. Chains pay 3-10x more.

---

## Known A→B→C Chains

| Bug A (Signal) | Hunt for Bug B | Escalate to C |
|----------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full account data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM credential exfil → RCE |
| XSS (stored) | Check if HttpOnly is set on session cookie | Session hijack → ATO |
| Open redirect | OAuth redirect_uri accepts your domain | Auth code theft → ATO |
| S3 bucket listing | Enumerate JS bundles | Grep for OAuth client_secret → OAuth chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field-level auth | Mass PII exfil |
| Debug endpoint | Leaked environment variables | Cloud credential → infrastructure access |
| CORS reflects origin | Test with credentials: include | Credentialed data theft |
| Host header injection | Password reset poisoning | ATO via reset link |

---

## Cluster Hunt Protocol (6 Steps)

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

---

## Real Examples

**Coinbase S3→Bundle→Secret→OAuth chain:**
```
A: S3 bucket publicly listable (Low alone)
B: JS bundles contain OAuth client credentials
C: OAuth flow missing PKCE enforcement
Result: Full auth code interception chain → Critical
```

**Vienna Chatbot chain:**
```
A: Debug parameter active in production (Info alone)
B: Chatbot renders HTML in response (dangerouslySetInnerHTML)
C: Stored XSS via bot response visible to other users
Result: P2 finding with real impact
```

**Password Reset Poisoning chain:**
```
A: Host header reflected in password reset email link
B: Victim clicks link → token sent to attacker-controlled host
C: Attacker uses token to reset victim's password
Result: No-interaction ATO → Critical
```

**IDOR→ATO chain:**
```
A: IDOR on /api/users/{id}/profile (read PII — Medium alone)
B: Same endpoint accepts PUT with email field
C: Change victim's email → trigger password reset → ATO
Result: Critical via 2-step chain
```

---

## TOP 1% HACKER MINDSET

### Crown Jewel Thinking
Before touching anything, ask: "If I were the attacker and I could do ONE thing to this app, what causes the most damage?"
- Financial app → drain funds, transfer to attacker account
- Healthcare → PII leak, HIPAA violation
- SaaS → tenant data crossing, admin takeover
- Auth provider → full SSO chain compromise

### Developer Empathy
Think like the developer who built the feature:
- What was the simplest implementation?
- What shortcut would a tired dev take at 2am?
- Where is auth checked — controller? middleware? DB layer?
- What happens when you call endpoint B without going through endpoint A first?

### Trust Boundary Mapping
```
Client → CDN → Load Balancer → App Server → Database
         ^               ^              ^
    Where does app STOP trusting input?
    Where does it ASSUME input is already validated?
```

### Feature Interaction Thinking
- Does this new feature reuse old auth, or does it have its own?
- Does the mobile API share auth logic with the web app?
- Was this feature built by the same team or a third-party?

---

## The Top 1% Mental Checklist
- [ ] I know the app's core business model
- [ ] I've used the app as a real user for 15+ minutes
- [ ] I know the tech stack (language, framework, auth system, caching)
- [ ] I've read at least 3 disclosed reports for this program
- [ ] I have 2 test accounts ready (attacker + victim)
- [ ] I've defined my primary target: ONE crown jewel I'm hunting for today

---

## Mindset Rules from Top Hunters

**"Hunt the feature, not the endpoint"** — Find all endpoints that serve a feature, then test the INTERACTION between them.

**"Authorization inconsistency is your friend"** — If the app checks auth in 9 places but not the 10th, that's your bug.

**"New == unreviewed"** — Features launched in the last 30 days have lowest security maturity.

**"Think second-order"** — Second-order SSRF: URL saved in DB, fetched by cron job. Second-order XSS: stored clean, rendered unsafely in admin panel.

**"Follow the money"** — Any feature touching payments, billing, credits, refunds is where developers make the most security shortcuts.

**"The API the mobile app uses"** — Mobile apps often call older/different API versions. Same company, different attack surface, lower maturity.

---

## Related Skills

- **`hunt-idor`** — Most common chain starter. IDOR read → IDOR write → ATO.
- **`hunt-ssrf`** — SSRF → cloud metadata → credential exfil → RCE.
- **`hunt-xss`** — XSS → session hijack → ATO. XSS → CSRF token theft.
- **`hunt-oauth`** — Open redirect → OAuth redirect_uri → auth code theft.
- **`triage-validation`** — Run the 7-Question Gate on the CHAIN, not individual primitives.
