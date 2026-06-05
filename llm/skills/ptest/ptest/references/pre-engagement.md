# Pre-Engagement Phase

Mandatory phase executed AFTER `start` initialization and BEFORE Phase 1 (Passive Recon). Prevents wasted effort on out-of-scope findings and ensures program compliance from the first request.

## Command

`ptest pre-engagement` — or automatically triggered as part of `ptest start` after scope collection.

## Purpose

1. Parse and document the program's full exclusion list
2. Configure OPSEC compliance (headers, user-agent, rate limits)
3. Create quick-reference "DO NOT TEST" checklist
4. Validate account/identity requirements
5. Load `opsec` skill for program-specific configuration

## Procedure

### Step 1: Read Program Rules of Engagement

Navigate to the bug bounty program page and extract:

- **Required headers** (e.g., `X-Intigriti-Username`, `X-Bug-Bounty`)
- **Required User-Agent format** (e.g., `Intigriti - <username> - <user agent>`)
- **Rate limits** (e.g., max 5 req/sec)
- **Required email alias** (e.g., `@intigriti.me`, `@wearehackerone.com`)
- **Required request identifiers** (custom headers for attribution)
- **Testing hours** (if restricted)
- **Restricted techniques** (e.g., no DoS, no social engineering)

Document in `scope.md` under a `## Rules of Engagement` section.

### Step 2: Parse Exclusion List (CRITICAL)

Read the program's **Out of Scope** section completely. Document EVERY exclusion in `scope.md` under `## Exclusions (Out of Scope)`.

Categorize exclusions into:

```markdown
## Exclusions — Quick Reference

### Vulnerability Types (DO NOT REPORT)
- [ ] Username/email enumeration
- [ ] Rate limiting / lack of rate limiting
- [ ] Missing security headers
- [ ] CSRF with no/low impact
- [ ] Clickjacking without proven impact
- [ ] Self-XSS
- [ ] CSV injection
- [ ] HTTP request smuggling without proven impact
- [ ] Host header injection without proven impact
- [ ] Tokens leaked to third parties
- [ ] ...

### Asset Exclusions (DO NOT TEST)
- [ ] *.formswift.com
- [ ] Dropbox Passwords
- [ ] ...

### Technique Exclusions (DO NOT USE)
- [ ] Automated scanning without verification
- [ ] Social engineering
- [ ] DoS/DDoS
- [ ] ...
```

### Step 3: Configure OPSEC Compliance

Load `opsec` skill context. Configure:

```yaml
# Add to state.yaml under config:
opsec:
  user_agent: ""          # Program-required UA string
  custom_headers:         # Required headers for all requests
    - "X-Intigriti-Username: {username}"
  rate_limit: 5           # Max requests per second
  email_alias: ""         # Required email for account registration
  proxy: ""               # If using platform proxy
```

**Tool configuration commands:**
```bash
# Set rate limit for ffuf
ffuf -rate 5 ...

# Set rate limit for nuclei
nuclei -rl 5 ...

# Set custom headers for all curl requests (alias or wrapper)
alias pcurl='curl -H "User-Agent: Intigriti - n4igme - curl/8.x" -H "X-Intigriti-Username: n4igme"'

# Set rate limit for gobuster
gobuster dir --delay 200ms ...
```

### Step 4: Validate Account Requirements

Check if the program requires:
- [ ] Platform-specific email alias for account creation
- [ ] Test accounts (self-created vs provided)
- [ ] VPN/geo requirements
- [ ] Specific browser/client requirements
- [ ] Two accounts for IDOR testing

Document in `scope.md` under `## Account Requirements`.

### Step 5: Create Exclusion Filter

Generate `./ptest-output/exclusions-quickref.md` — a one-page reference that gets checked:
- During Phase 1-3: Before investigating any potential finding
- During Phase 4: Mandatory cross-check (existing rule)
- During Phase 5-6: Before spending time on exploitation
- During Phase 8: Before including in final report

### Step 6: Finding Validation Gate

Every finding discovered in ANY phase must pass this check before being logged:

```
FINDING VALIDATION:
1. Does this match any exclusion in exclusions-quickref.md? → SKIP
2. Is the affected asset in scope? → If not, SKIP
3. Does the vulnerability type match an excluded category? → SKIP
4. Would this require a technique that's excluded? → SKIP
```

If a finding fails validation, log it in a separate `potential-oos.md` file (not findings-log.md) with the reason. These can be reviewed at the end to see if any are borderline-reportable.

## Exit Criteria

Pre-Engagement is PASSED when:
- [ ] Program exclusion list fully documented in `scope.md`
- [ ] `exclusions-quickref.md` created
- [ ] OPSEC configuration documented and tools configured
- [ ] Account requirements identified and actioned
- [ ] Rate limits set in tool configs
- [ ] Custom headers/UA configured

## Gateway State

```yaml
gateways:
  0_pre_engagement: OPEN    # ← New
  1_passive_recon: LOCKED
  2_active_recon: LOCKED
  ...
```

## Lessons Learned (Dropbox, May 2026)

Spent 4+ hours on Dropbox unauthenticated testing. Found 4 findings:
- User enumeration → OOS ("Username/email enumeration" excluded)
- Dev instance → OOS ("Demo sites and scripts" excluded)
- Info disclosure → Borderline (likely rejected)
- Leaked tokens → OOS ("Tokens leaked to third parties" excluded)

**All 4 findings were invalid.** Had we parsed the exclusion list first, we would have:
1. Known user enumeration is OOS → skipped community.dropbox.com API testing
2. Known leaked tokens are OOS → skipped GitHub credential search
3. Focused on authenticated testing vectors instead (IDOR, SSRF, privilege escalation)

Time wasted: ~4 hours. Time pre-engagement would have taken: ~15 minutes.
