# Tight-Scope Bug Bounty Testing (3 or fewer domains)

## When This Applies
- Bug bounty program with explicitly listed domains (not wildcard)
- Scope is 1-5 specific hostnames (e.g., "bitbank.cc, app.bitbank.cc, api.bitbank.cc")
- No subdomain enumeration findings possible (out of scope)

## Key Differences from Wildcard Scope

### Phase 1-2 Adjustments
- Subdomain enumeration is for INTEL only (infrastructure understanding), not findings
- Skip DNS brute-force/permutation for new subdomains (can't report them)
- Focus on: JS bundle analysis, Wayback URLs, GitHub repos, API docs
- TLS cert SANs still useful (confirms wildcard cert = other subdomains exist)

### Phase 3 Critical Technique: JS Bundle Deep Dive
For tight-scope targets, JS analysis is the #1 source of hidden attack surface:

1. **Download ALL JS chunks** (not just main bundle)
2. **Search for ALL URL patterns**: `grep -ohE '"/(api|v1|v2|user|account|auth|cis|fido|login|signup|register|reset|verify)[a-zA-Z0-9/_-]*"'`
3. **Check for third-party SDK paths** (platform-websdk, auth0, okta, transmit security)
4. **Test discovered paths on ALL in-scope hosts** (path may work on api.* but not app.*)
5. **Check path prefixes**: if `/v1/auth-session/status` 404s, try `/cis/v1/auth-session/status`

### Phase 5-6: Unauthenticated Exhaustion Checklist
Before declaring "surface exhausted," verify ALL of these:

| Category | Tests |
|----------|-------|
| Auth endpoints | Login, signup, reset_password, register_mail, verify, activate |
| Token endpoints | approve_*, confirm_*, validate_* — test with various token lengths |
| FIDO/WebAuthn | /fido/*, /webauthn/* — check if unauthenticated |
| reCAPTCHA bypass | Empty, null, wrong field name, form-urlencoded, GET method |
| Type confusion | Arrays, objects, null, boolean, NoSQL operators on all JSON fields |
| HMAC timing | 5+ samples, different sig formats |
| HTTP smuggling | CL.TE, TE.CL, TE obfuscation (6+ variants) |
| WebSocket | Connect, subscribe public channels, attempt private channels |
| Token format oracle | Try different lengths to find the accepted format |
| Method tampering | PUT, DELETE, PATCH on all endpoints |
| Host/cache | X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL |
| Open redirect | redirect, next, return_to, url params on all auth pages |

### "Did We Miss Something?" Self-Audit
Run this before each phase transition on tight-scope targets:
1. List all 3 domains
2. For each domain, list what was tested vs what wasn't
3. Check: did we test the SAME technique on ALL domains? (not just the "interesting" one)
4. Check: did we analyze ALL JS files? (websdk, gtm, vendor scripts — not just app chunks)
5. Check: did we try each path on EVERY host? (path found via JS might work on api.* not app.*)

## Lessons Learned (bitbank.cc, June 2026)
- `platform-websdk.js` (241KB) revealed entire CIS auth layer invisible from main API
- Root-level auth endpoints (/login, /signup) had different path from /v1/user/* endpoints
- Token format oracle: different error codes for 64-char vs other lengths
- WebSocket (stream.*) connected fine but private channels silently ignored
- reCAPTCHA blocks all auth testing without valid solve (no bypass found)
- /approve_withdrawal: unauthenticated, no rate limit, but 64-char entropy = theoretical only
- Anti-enum on FIDO: deterministic fake credentials per username (spec-compliant)
