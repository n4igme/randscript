# Second Look Protocol

Mandatory loop between Phase 3 completion and Reporting.

---

## When to Trigger

After Phase 3 (exploitation/injection testing), ask:

```
CHECK:
├─ Did I gain NEW credentials?        → YES → Re-run Phase 2 with new creds
├─ Did I discover internal endpoints?  → YES → Test those endpoints  
├─ Did I escalate privileges?          → YES → Re-enumerate from new role
├─ Did error messages reveal paths?    → YES → Add to endpoint list, test
├─ Did config leaks show new services? → YES → Expand scope, test
└─ ALL NO?                             → Proceed to reporting
```

If ANY answer is YES → do NOT go to reporting. Loop back.

---

## Protocol Steps

### Step 1: Inventory New Access
After Phase 3, document what you NOW have that you didn't before:
- New tokens/sessions (from auth bypass, token leaks, SSRF)
- New roles/permissions (from privilege escalation, mass assignment)
- New endpoints discovered (from error messages, config leaks, SSRF recon)
- New credentials (from metadata, config files, debug endpoints)

### Step 2: Re-enumerate from New Vantage Point
With each new access level:
1. Re-run endpoint enumeration — admin sees different routes
2. Re-test BOLA — admin token on user endpoints may leak all data
3. Check new functionality unlocked (admin panels, internal tools)
4. Look for second-order SSRF (admin can trigger fetches user cannot)

### Step 3: Test Second-Order Chains
Common second-order patterns:
- SSRF → internal API → no auth required internally → full data access
- Admin access → file upload → web shell (if admin has upload perms)
- Config leak → database creds → direct DB access (if exposed)
- JWT secret leaked → forge any user's token → account takeover at scale
- Service account token → cloud API access → lateral movement

### Step 4: Document the Full Chain
The second-look finding is reported as ONE chain, not separate bugs:
```
Initial finding: [what you found in Phase 3]
  → Gives access to: [what new access you gained]
    → Enables: [what you found in second look]
      → Final impact: [the worst-case scenario achieved]
```

---

## Time Budget

- Second look gets max 20% of remaining time budget
- If 3 re-enum checks find nothing new → stop, go to reporting
- Exception: if second look reveals Critical → spend whatever it takes to PoC it

---

## Examples from Real Engagements

**Pattern: Credential chain**
Phase 3 found: config endpoint leaks DB connection string
Second look: connect to DB → dump user table → find admin password hash
→ crack hash → admin login → full application control
Report as: Critical chain, not "config endpoint info disclosure"

**Pattern: SSRF escalation**
Phase 3 found: SSRF on webhook parameter
Second look: SSRF → hit internal admin API → no auth on internal network
→ create admin user → external admin login → full access
Report as: Critical (unauthenticated RCE equivalent via SSRF chain)

**Pattern: Privilege chain (Jago-style)**
Phase 3 found: attestation forge + device enrollment
Second look: enrolled device → sign own requests → access all user endpoints
→ re-enumerate as authenticated user → find consent-skip → regulatory bypass
Report as: Critical chain (device attestation bypass → full account control)

---

## Integration with Attack Recipes

After second look reveals new access, re-scan attack recipe triggers:
- New multi-step flow visible? → Prerequisite Skip recipe
- New JWT context? → JWT attacks recipe
- New API version accessible? → Version Downgrade recipe
- New URL-accepting endpoint? → SSRF recipe

The loop continues until no new access is gained.
