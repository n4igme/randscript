# Chain Hunting Methodology

## The A→B Bug Signal Method

**Core concept:** When you find bug A, don't report and move on. Systematically hunt for bugs B and C nearby.

Every vulnerability is a signal that the surrounding code, feature, or developer's work has weak spots. A single bug rarely exists in isolation — it indicates:

- The developer who wrote that code likely made similar mistakes nearby
- The feature area lacks security review
- The trust boundaries around that component are poorly enforced
- Adjacent endpoints share the same flawed patterns

**The method:**
1. Find bug A (your signal)
2. Map everything adjacent — same endpoint, same feature, same developer, same trust boundary
3. Hunt for B — what can you chain A into? What sibling bugs exist?
4. Escalate to C — can you reach account takeover, RCE, or mass data access?

A $500 IDOR becomes a $15,000 ATO chain. A medium SSRF becomes a critical RCE. The chain is where the money and impact live.

---

## Known A→B→C Chain Table

| # | Bug A (Signal) | Bug B (Pivot) | Bug C (Impact) | Final Severity |
|---|---|---|---|---|
| 1 | IDOR read (view other user's data) | PUT/DELETE on same object | Account Takeover | Critical |
| 2 | SSRF (blind or partial) | Cloud metadata endpoint (169.254.169.254) | IAM credential → RCE | Critical |
| 3 | XSS stored | HttpOnly flag missing on session cookie | Session hijack → ATO | Critical |
| 4 | Open redirect | OAuth redirect_uri manipulation | Auth code theft → ATO | Critical |
| 5 | S3 bucket listing | JS bundles exposed | OAuth client_secret leaked → OAuth chain | High-Critical |
| 6 | Rate limit bypass | OTP/2FA brute force | Account Takeover | Critical |
| 7 | GraphQL introspection enabled | Missing field-level authorization | Mass PII exfiltration | Critical |
| 8 | Debug endpoint exposed | Environment variables leaked | Cloud credentials → infra access | Critical |
| 9 | CORS reflects arbitrary Origin | credentials: include in response | Credentialed cross-origin data theft | High |
| 10 | Host header injection | Password reset link poisoning | ATO via reset token theft | Critical |

---

## 6-Step Cluster Hunt Protocol

When you find any bug, execute this protocol before moving on:

### Step 1: Freeze and Map
- Stop. Don't report yet.
- Map the entire feature area: every endpoint, parameter, role, and state transition.
- Identify the developer's pattern (naming conventions, auth checks, error handling).

### Step 2: Horizontal Expansion
- Test every HTTP method on the same endpoint (GET found? Try PUT, DELETE, PATCH).
- Test every parameter for the same bug class (one param has IDOR? Test all params).
- Test every role/privilege level (user, admin, unauthenticated, different tenant).

### Step 3: Vertical Escalation
- Can you chain the bug into a higher-impact outcome?
- Read access → Write access → Delete access → ATO?
- Information disclosure → Credential access → Lateral movement?

### Step 4: Trust Boundary Crossing
- What trust boundaries does this bug let you cross?
- User→Admin, Tenant→Tenant, Internal→External, Unauthenticated→Authenticated?
- Each boundary crossed multiplies severity.

### Step 5: Sibling Feature Audit
- Find other features built by the same developer or team.
- Look for the same anti-pattern repeated elsewhere.
- Check git blame or similar code patterns to find related code.

### Step 6: Document the Chain
- Write the full chain narrative: A enables B enables C.
- Calculate combined impact (not just individual bug severity).
- Report as a chain with clear reproduction steps for maximum bounty.

---

## Real-World Chain Examples

### Example 1: Coinbase S3 Chain

**Chain:** S3 bucket listing → JS source maps → API keys → Internal API access

1. **Bug A:** Public S3 bucket found via subdomain enumeration
2. **Bug B:** Bucket contained JavaScript source maps and build artifacts
3. **Bug C:** Source maps contained hardcoded API keys and internal endpoint URLs
4. **Impact:** Access to internal APIs, potential for further lateral movement

**Lesson:** Static asset storage is a goldmine. Always enumerate bucket contents fully. JS bundles and source maps frequently contain secrets that developers assumed would be "compiled away."

---

### Example 2: Password Reset Poisoning → ATO

**Chain:** Host header injection → Reset link poisoning → Token capture → ATO

1. **Bug A:** Application reflects the Host header in password reset emails
2. **Bug B:** Attacker sets `Host: attacker.com`, triggers reset for victim
3. **Bug C:** Victim clicks link → reset token sent to attacker's server → ATO

**Reproduction:**
```
POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

email=victim@target.com
```

**Lesson:** Always test Host header handling on any email-generating functionality. Check `Host`, `X-Forwarded-Host`, `X-Original-URL`, and absolute URL overrides.

---

### Example 3: IDOR Read → IDOR Write → ATO

**Chain:** IDOR on profile read → IDOR on email change → Account takeover

1. **Bug A:** `GET /api/users/123/profile` — can read any user's profile by changing ID
2. **Bug B:** `PUT /api/users/123/email` — same broken auth, can change any user's email
3. **Bug C:** Trigger password reset to attacker-controlled email → full ATO

**Lesson:** If GET has broken authorization, immediately test PUT, PATCH, DELETE, POST on the same resource. Developers often copy-paste handlers without auth checks. The read IDOR is a $500 bug. The chain to ATO is $10,000+.

---

## Top 1% Mindset

### Crown Jewel Thinking
Always ask: "What is the most valuable thing this application protects?"
- Authentication tokens and session management
- Payment processing and financial data
- PII and user credentials
- Admin/infrastructure access
- Business logic that generates revenue

Work backward from crown jewels. Every bug you find — ask "does this get me closer to a crown jewel?"

### Developer Empathy
Think like the developer who built this:
- They were under deadline pressure — where did they cut corners?
- They copy-pasted from Stack Overflow — what context did they miss?
- They built auth once and reused it — where does the reuse break down?
- They tested the happy path — what about edge cases, race conditions, state transitions?
- They trusted the framework — where did they override defaults insecurely?

### Trust Boundary Mapping
Draw the trust boundaries explicitly:
- Frontend ↔ Backend API
- User context ↔ Admin context
- Tenant A ↔ Tenant B
- Internal services ↔ External-facing services
- Authenticated ↔ Unauthenticated

Every bug is interesting only if it crosses or weakens a trust boundary. Focus your chain hunting on boundary-crossing combinations.

### Feature Interaction
The most critical bugs live where features interact:
- Authentication + File upload = Upload as another user
- Search + Export = Mass data exfiltration
- Notifications + URL handling = SSRF via webhook
- OAuth + Open redirect = Token theft
- API versioning + Auth = Old endpoint bypasses new auth

Map feature intersections. Test what happens when Feature A's output becomes Feature B's input.

---

## Mental Checklist (Run on Every Bug Found)

```
[ ] Can I escalate the HTTP method? (GET→PUT→DELETE)
[ ] Can I escalate the object? (my_id→other_id→admin_id)
[ ] Can I escalate the scope? (one record→all records)
[ ] Can I chain to authentication bypass?
[ ] Can I chain to account takeover?
[ ] Can I reach cloud metadata or internal services?
[ ] Is the same pattern repeated on other endpoints?
[ ] Does this cross a trust boundary?
[ ] Can I combine this with another bug I already found?
[ ] What would a developer assume is "safe" given this bug exists?
[ ] Is there a race condition variant?
[ ] Does this work across tenant boundaries?
```

---

## Quick Reference: Signal → Hunt Map

| When you find... | Immediately hunt for... |
|---|---|
| Any IDOR | PUT/DELETE/PATCH on same resource, other resources with same pattern |
| Any SSRF | Cloud metadata, internal services, port scanning |
| Any XSS | Cookie flags, token storage, admin panel injection |
| Any open redirect | OAuth flows, SAML, login redirects |
| Any info disclosure | Credentials in response, internal URLs, API keys |
| Any rate limit issue | OTP brute force, credential stuffing, enumeration |
| Any GraphQL endpoint | Introspection, field auth, nested query DoS, batching |
| Any file upload | Path traversal, SSRF via URL fetch, XSS via SVG/HTML |
| Any debug/status endpoint | Env vars, stack traces, internal IPs, credentials |
| Any CORS misconfiguration | Credentialed requests, data exfiltration |
| Any header injection | Email poisoning, cache poisoning, request smuggling |
| Any race condition | Double-spend, privilege escalation, limit bypass |

---

*Remember: A single bug is a finding. A chain is a story. Chains get critical ratings, maximum bounties, and real-world impact. Never stop at bug A.*
