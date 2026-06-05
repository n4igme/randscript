# Bug Bounty Submission Guide

## Overview

Bug bounty submissions differ fundamentally from formal pentest reports. They're self-contained, platform-specific, and optimized for triage speed. This reference covers submission writing, disclosure policy, scope decisions, and multi-finding strategy.

## Platform-Specific Notes

- **IssueHunt**: Program URLs use UUID format: `https://issuehunt.io/programs/<uuid>` (not org/slug). Page is a JS SPA requiring browser rendering; curl gets empty HTML. Use browser_navigate + browser_console(`document.body.innerText.substring(N, M)`) to extract scope text in chunks.

## Submission Budget Strategy (Limited Submissions)

When a program limits remaining submissions (e.g., 2 left after rejections):

1. **Combine related findings into attack chains** — merge info disclosure + exploitation into one narrative
2. **Prioritize by chain strength** — submit the chain with highest combined severity first
3. **Chain structure:** Step 1 reveals intelligence → Step 2 uses that intelligence for exploitation → Impact shows combined blast radius
4. **Per-asset grouping** — combine findings on the same asset/subdomain into one chain report
5. **Cross-reference within chain** — show how finding A enables/amplifies finding B (not just "two bugs on same host")

**Example (GoPay, May 2026):**
- Had 6 split reports, 2 rejected (source maps), 2 submissions remaining
- Combined: ArgoCD config disclosure (Medium) + device code flow (High) = one High chain report
- Combined: Debug mode (Medium) + CORS wildcard (Medium) + source map tokens = one High chain report
- Each chain tells a complete attack story with escalating impact

**Re-submitting rejected findings as chain steps:**
- A finding rejected individually (e.g., "source map is informational") can be included as a STEP in a larger chain
- The rejection was for the standalone severity, not for the technique itself
- When embedded in a chain, the rejected finding becomes "Step 1: reconnaissance" that enables higher-impact exploitation
- Frame it as: "source map → token extraction → verified write access" (chain) not "source map exposed" (standalone)
- Include the interactive HTML PoC as an attachment showing the full chain in action
- The PoC demonstrates that individual "informational" findings combine into real exploitation

**Report structure for chains:**
- Title mentions both vulnerabilities and the combined impact
- Description explains the chain logic (A enables B)
- Exploitation shows sequential steps (recon → weaponize → exploit)
- PoC demonstrates the full chain in one script
- Risk section has a "chain summary" table showing step-by-step escalation

**Output delivery:** Write chain reports in sections across multiple messages to avoid truncation. Never dump the full report in one message.

---

## Submission Structure (Platform-Agnostic)

### Required Fields

| Field | Guidance |
|-------|----------|
| Title | Action-oriented, includes asset + impact. "Source Maps Expose Production API Tokens with Verified Write Access" NOT "Information Disclosure" |
| Asset | Must EXACTLY match a program scope entry. If borderline, add scope note |
| Severity | Your assessment (program may adjust). Use CVSS to justify |
| Vulnerability Type | Use platform's taxonomy. Map to closest match |
| Description | 2-3 paragraphs: what, where, why it matters |
| Steps to Reproduce | Numbered, copy-pasteable commands. Triage analyst must reproduce in <5 minutes |
| Impact | Business impact in plain language. "Attacker can..." not "The endpoint is misconfigured" |
| Remediation | Concrete fixes, not generic advice |

### Optional But High-Value Sections

| Section | When to Include |
|---------|----------------|
| Why This Chain Works | Multi-step findings. Explains root cause + how steps connect |
| Attack Scenario | Social engineering vectors. Makes impact tangible |
| Systemic Pattern | When the same vuln affects multiple assets. Justifies higher severity |
| Scope Note | When asset is borderline. Preempts "out of scope" rejection |

---

## Disclosure Policy (CRITICAL)

### Rules (Apply to ALL Programs)

1. **NEVER publish PoCs publicly** before vendor acknowledges AND fixes (or 90-day deadline passes)
2. **NEVER host PoCs on public URLs** (GitHub Pages, Codepen, JSFiddle, personal sites)
3. **PoC code belongs in the report body** — paste it directly in the submission
4. **If hosted PoC is needed** for demonstration (e.g., CORS exploitation requires a page):
   - Use the platform's attachment feature
   - Or describe the PoC with code blocks (triage can create their own local file)
   - Or use a private repo and share access only with the program
5. **Screenshots/recordings** are fine — they don't expose exploit code to the public
6. **90-day disclosure deadline** — most programs allow public disclosure after 90 days IF the vendor hasn't fixed it. Check program-specific policy first.

### What Counts as "Public Disclosure"

| Action | Violation? |
|--------|-----------|
| Push PoC HTML to public GitHub repo | ✅ YES |
| Tweet about the vulnerability (even without details) | ⚠️ Depends on program |
| Blog post after fix + program approval | ❌ No (coordinated disclosure) |
| Share with another researcher privately | ⚠️ Check program rules |
| Include PoC code in report body on platform | ❌ No (private to program) |
| Host PoC on localhost for your own testing | ❌ No |

### Consequences of Violation

- Report marked as "Policy Violation" → no bounty
- Account warning or permanent ban from platform
- Legal liability (some programs have legal safe harbor that's voided by disclosure)
- Reputation damage in bug bounty community

### Recovery If You Accidentally Disclosed

1. **Immediately** remove the public content (delete repo, take down page, delete tweet)
2. **Check if cached** — Google Cache, Wayback Machine, GitHub event log
3. **Disclose in your report** — "PoC was briefly public for X hours, now removed"
4. **Be honest** — programs are more forgiving of honest mistakes than cover-ups
5. **git force-push** to remove from history (commits are still in reflog for 90 days but not publicly browsable)

---

## Scope Boundary Decisions

### Scope Type Interpretation

| Program Lists | What's In Scope | What's NOT |
|--------------|----------------|-----------|
| `example.com` (Web Application) | Only `example.com` and `www.example.com` | `*.example.com` subdomains |
| `*.example.com` (Wildcard) | All subdomains of `example.com` | Parent domain may or may not be included |
| `api.example.com` (API) | That specific API endpoint | Other APIs on same infra |

### Related Infrastructure (Different Domain, Same Company)

When you find a vulnerability on infrastructure that's clearly related but on a different domain:

**Decision Framework:**

| Factor | Submit | Skip |
|--------|--------|------|
| Same company, manages in-scope assets | ✅ | |
| Directly impacts security of in-scope assets | ✅ | |
| Same IP range as in-scope targets | ✅ | |
| Completely separate product/team | | ✅ |
| No connection to in-scope assets | | ✅ |

**Scope Note Pattern (add to Asset field or Description):**

```markdown
**Scope note:** This finding is on `argocd-ui.go-pay.co.id` (note: `go-pay.co.id`, 
not `gopay.co.id`). This is clearly GoPay/GoTo Financial infrastructure managing 
the same Kubernetes cluster that serves `*.gopayapi.com` services. The finding 
directly impacts the security of in-scope assets. If the program considers this 
out of scope, the [specific impact] still demonstrates a critical risk to the 
in-scope `*.gopayapi.com` infrastructure.
```

**Risk/Reward:**
- Best case: accepted at full severity (High/Critical bounty)
- Likely case: accepted at reduced tier ("valid but out of scope" → Medium bounty)
- Worst case: marked N/A with no penalty (you lose time, not reputation)
- Never penalized for submitting borderline findings in good faith

### When to Skip Entirely

- Target is explicitly listed in "Out of Scope" section
- Target belongs to a different company (shared hosting coincidence)
- Finding requires testing targets you're not authorized to touch
- The connection to in-scope assets is speculative, not demonstrable

---

## Multi-Finding Consolidation Strategy

### When to Combine vs Split Findings

**Default: SPLIT into individual findings per endpoint/app.** Each gets its own bounty. Combine only when the chain is the finding (i.e., individual steps aren't reportable alone).

| Scenario | Action | Rationale |
|----------|--------|-----------|
| Same vuln on different apps (e.g., source map on app A and app B) | **Split** | Each app = separate finding = separate bounty |
| Two independent vulns on same asset (e.g., debug mode + CORS) | **Split** | Each is independently fixable and reportable |
| Same vuln class, different assets | **Split** | Each is independently fixable |
| Step A is ONLY useful because of Step B (not reportable alone) | **Combine** | Individual steps have no standalone severity |
| Info disclosure that's only Low alone but enables High exploitation | **Combine** | The chain IS the finding |

**Splitting strategy (GoPay, May 2026):**

Original plan: 3 combined reports. Final submission: 6 individual reports.

| Original | Split Into | Why |
|----------|-----------|-----|
| Source map + token chain (2 apps) | 1A: gopay-web-page, 1B: gwc | Each app is independently exploitable, separate bounties |
| Debug + CORS combined | 2A: debug mode, 2B: CORS wildcard | Each is independently fixable and reportable |
| ArgoCD config + device code | 3A: config disclosure, 3B: device code flow | Config is Medium alone, device code is High alone |

**Key insight:** Programs pay per-finding, not per-chain. Splitting maximizes bounty while each report remains self-contained and independently reproducible. Cross-reference related reports ("when combined with the debug mode finding reported separately, this enables...") to show combined impact without bundling.

**When combining IS better:**
- The individual steps are too weak to report alone (Info + Info = not reportable separately)
- The chain demonstrates a systemic architectural issue that's more impactful as one narrative
- The program explicitly prefers chains (check program policy)

### Combining Rules

1. **Title reflects the chain**, not individual steps: "Source Maps Expose Tokens with Write Access" not "Source Map Found"
2. **Severity = chain severity**, not individual: Info (source map) + Low (token in JS) + Medium (write access) = **High** (full chain)
3. **Steps to Reproduce show the full path** from zero to impact
4. **Each step must be reproducible** — don't combine if one step is theoretical

### Submission Ordering Strategy

Submit in this order:
1. **Strongest finding first** — clear scope, verified exploit, highest severity
2. **Second strongest** — may reference first report
3. **Borderline/scope-adjacent last** — if first reports are accepted, establishes credibility for borderline ones

**Why order matters:**
- First report sets triage analyst's impression of your quality
- Strong first report → analyst gives benefit of doubt on borderline later reports
- Weak first report → analyst scrutinizes everything harder

### Cross-Referencing Between Submissions

```markdown
**Related submission:** This finding is related to report #[ID] (Source Map Exposure). 
The token extracted in this report was discovered through the source map disclosed 
in that report. However, this finding is independently exploitable — the token is 
also present in the minified JavaScript without needing the source map.
```

**Key principle:** Each report must be independently valid. Cross-references add context but the finding must stand alone. If Report B only works because of Report A, they should be combined into one report.

---

## Severity Justification

### CVSS Is Necessary But Not Sufficient

Always include CVSS vector string, but also explain in business terms:

| CVSS Says | You Should Add |
|-----------|---------------|
| C:H (Confidentiality High) | "Attacker reads 45,000 customer records including national IDs" |
| I:L (Integrity Low) | "Attacker can inject fake analytics events, corrupting business metrics" |
| A:N (Availability None) | "No service disruption, but data poisoning affects fraud detection accuracy" |

### Upgrading Severity (When Justified)

| Factor | Justification |
|--------|--------------|
| Financial services target | Regulatory implications (OJK, PCI-DSS) |
| Chain of findings | Combined impact exceeds individual CVSS |
| Systemic pattern | Same vuln on N apps = N× impact |
| Production + write access confirmed | Not theoretical — verified working |
| No rate limiting on exploitable endpoint | Amplification possible |

### Common Triage Pushback and Responses

| Pushback | Response |
|----------|----------|
| "This is informational only" | "The source map alone is informational. Combined with token extraction and verified write access, this is a confirmed exploitation chain." |
| "Clickstream tokens are designed to be client-side" | "Client-side tokens should be scoped (origin validation, rate limiting). This token grants unrestricted write access from any IP with no rate limit." |
| "Debug mode is just information disclosure" | "Combined with CORS *, any website can extract this information cross-origin without user interaction. This is active exploitation, not passive disclosure." |
| "We'll fix it, but severity is Low" | "The CVSS vector accounts for [specific factors]. Happy to discuss, but the write access confirmation elevates this beyond information disclosure." |
| "Out of scope" | "The finding directly impacts in-scope assets [explain how]. Even if the specific host is borderline, the security implication for [in-scope asset] is clear." |
| "Public API key" (excluded) | Reframe: "This isn't about the key being public — it's about the key granting unauthorized write access to production infrastructure. The vulnerability is broken access control on the endpoint, not the key exposure itself." |

---

## Program Exclusion Avoidance

### Reframing Findings to Avoid Exclusion Triggers

Programs exclude certain bug classes (e.g., "public API keys", "rate limiting", "user enumeration", "staging environments"). A finding that TOUCHES an excluded class can still be valid if the IMPACT goes beyond it.

**Reframing strategy:**

| Excluded Class | Your Finding | Reframe As |
|---------------|-------------|-----------|
| Public API keys | Token in JS grants write access | **Broken Access Control** — unauthorized write to production endpoint |
| Information disclosure | Debug mode + CORS chain | **CORS Misconfiguration** — cross-origin data extraction at scale |
| Rate limiting | No rate limit on OTP endpoint | **Authentication Bypass** — brute-force 2FA codes |
| Staging environments | Staging ArgoCD exposed | **Production impact** — staging manages same K8s cluster as prod |
| User enumeration | Login response differentiates users | **Account Takeover prerequisite** — enables targeted credential stuffing |

**Key principle:** The bug type in the submission form determines which exclusion filter the triager applies. Choose the bug type that reflects the IMPACT, not the attack vector.

**Example (GoPay, May 2026):**
- ❌ Rejected as: "Information Disclosure" (source map exposed) — triager applied "public API keys" exclusion
- ✅ Resubmitted as: "Broken Access Control" (unauthorized write to event pipeline) — same token, different framing
- The vulnerability didn't change. The classification did.

### Multi-Domain Chain Limitation

YesWeHack (and most platforms) expect **one primary asset per report**. When your chain spans multiple domains:

1. **Pick the domain where the IMPACT lands** as the primary asset (not where the recon starts)
2. Other domains appear in exploitation steps as "how the attacker got there"
3. The "Vulnerable part" field should be the endpoint with the highest-impact action

**Cross-program chains (CRITICAL):**

When a chain spans assets belonging to DIFFERENT bug bounty programs (even if same company), you CANNOT submit as one report. Each program has its own scope, exclusions, and submission limits.

**Example (GoTo, May 2026):**
- `cms-website.gopay.co.id` → GoTo Financial program
- `gopay-web-raccoon.gojekapi.com` → Gojek program
- These are separate programs on YesWeHack with separate scopes

**Decision:** Split into separate reports per program. Each report must be self-contained within that program's scope. Don't reference assets from another program's scope — the triager only sees their own program.

**Before writing a chain report, verify:**
- [ ] All assets in the chain belong to the SAME program
- [ ] The primary asset matches a scope entry in THAT program
- [ ] No exploitation step requires testing an out-of-scope asset

**Example:**
- Chain: `gopay-web-page.gopayapi.com` (source map) → `gopay-web-raccoon.gojekapi.com` (write access) → `cms-website.gopay.co.id` (debug+CORS)
- ❌ Wrong: submit against source map domain (that's just recon)
- ✅ Right: submit against `gopay-web-raccoon.gojekapi.com` with "Broken Access Control" — that's where unauthorized write happens
- The source map is mentioned in Step 1 of exploitation as "how the token was obtained"

### Resubmission After Rejection

When a finding is rejected and you have limited submissions remaining:

1. **Don't resubmit the same finding with the same framing** — it will be auto-rejected as duplicate
2. **Embed the rejected finding as a STEP in a larger chain** — the rejection was for standalone severity
3. **Change the bug type** — if rejected as "Information Disclosure", resubmit the chain as "Broken Access Control"
4. **Change the primary asset** — if the rejected asset triggers exclusions, lead with a different asset in the chain
5. **Add new exploitation proof** — show that the "informational" finding enables real impact (write access, RCE, data modification)
6. **Never reference the rejected report** — treat the new submission as completely independent

### Replying to Rejection (Rebuttal Strategy)

When a report is rejected with RTFS/"Read The Fine Scope" but you believe the finding is valid beyond the excluded class, reply directly on the existing report thread instead of burning a new submission:

**Rebuttal structure:**
1. **Acknowledge** — "Thank you for the review"
2. **Distinguish** — explain precisely why your finding differs from the excluded class
3. **Evidence table** — side-by-side comparison (excluded class vs your finding)
4. **Proof** — include the specific curl/response showing the non-excluded impact
5. **Attach PoC** — interactive HTML or script demonstrating the full chain
6. **Request** — "I'd appreciate a re-evaluation as [correct bug type]"

**Example rebuttal (GoPay, May 2026):**
- Rejected as: "Disclosed or misconfigured public API keys (e.g. Google Maps, Firebase, analytics tools...)"
- Rebuttal argument: "This is not a read-only analytics key. It grants **write access** to production."
- Evidence: comparison table showing read-only analytics keys vs unauthorized write access
- Proof: `curl -X POST` returning HTTP 200 with `sent_time` (confirmed write)
- Result: forces triager to re-evaluate under "Broken Access Control" instead of "public API keys"

**Key principles:**
- Replying costs NO submission slots — always try rebuttal before burning a new submission
- Keep it concise (under 500 words) — triagers won't read essays
- Lead with the distinction, not the complaint
- Include ONE copy-pasteable command that proves the non-excluded impact
- Attach supporting PoC files (HTML, Python scripts) for visual proof
- If both reports in a split pair got the same rejection, reply to both (same argument applies)

### When NOT to reply:**
- The finding genuinely falls under the exclusion (accept and move on)
- The report was rejected for a different reason (duplicate, out of scope)
- You've already replied once and been rejected again (don't spam)
- The triager's logic is correct and you can't disprove it (e.g., "impact flows backwards" — see below)

### Accepting Valid Rejections Gracefully

Sometimes the triager is RIGHT. Signs you should accept and close:

| Triager Argument | Valid If | Accept When |
|-----------------|---------|-------------|
| "Impact flows backwards" (victim gains control of attacker's account) | You can't prove the action REMOVES something from victim | Email/phone bind without proving unbind from original account |
| "This is by design" | The behavior is documented and intentional | Feature works as specified, no security boundary crossed |
| "Convenience feature, not security" | The bypass doesn't cross an auth boundary | Skipping email verification on YOUR OWN account |
| "No demonstrated impact on other users" | You only proved self-harm | Binding unverified email to your own account |

**Response template for graceful acceptance:**
```
Hi [triager],

Thank you for the detailed explanation. You're right — without proving [specific missing piece], 
the actual security impact is limited to [what it actually is]. I appreciate the clarification. 
Happy to close this one.

Regards.
```

**Why graceful acceptance matters:**
- Preserves reputation with triagers (they remember difficult researchers)
- No reputation point loss on RTFS/Informational closures
- Saves time for findings with real impact
- Triager may be more generous on your next submission

### Pre-Submission Impact Verification (Prevent Invalid Submissions)

Before submitting ANY finding, verify the impact direction:

```
Who is harmed by this vulnerability?
├── Only the ATTACKER (self-harm)
│   └── NOT a valid finding (e.g., binding unverified email to YOUR account)
│
├── The VICTIM (other users)
│   └── VALID — proceed with submission
│   └── Verify: can you PROVE harm to victim with evidence?
│
└── UNCLEAR (could go either way)
    └── Test with 2 accounts before submitting
    └── If you can't prove victim harm → don't submit
```

**Common "impact flows backwards" patterns:**
- Email/phone bind without verification → attacker binds victim's email to ATTACKER's account → victim can now reset ATTACKER's password
- Adding unverified recovery method → weakens YOUR account, not victim's
- Linking external account without verification → gives the external account owner access to YOUR account

**Fix:** Prove the action REMOVES the identifier from the victim's account, or prove you can perform the action on the VICTIM's account (not your own).

### Report Accuracy: Verify Real PoC Values

**CRITICAL:** When writing reports from session history, always verify the exact values used in successful exploitation:

| Field | Common mistake | How to verify |
|-------|---------------|---------------|
| Endpoint path | `/v1/batch` vs `/api/v1/events` | Check session_search for the actual curl that returned 200 |
| Auth scheme | `Bearer` vs `Basic` | Check source code pattern (`Authorization: Basic ${token}`) |
| Token encoding | Raw UUID vs base64-encoded | Check what was actually sent in the working request |
| Response body | Fabricated vs actual | Use the real `{"status":1,"code":1,"sent_time":...}` response |

**Rule:** Never write a PoC from memory. Always pull the exact endpoint, headers, and response from the session where it was tested. One wrong detail (wrong auth scheme, wrong path) makes the entire report non-reproducible during triage.

**GoPay lesson (May 2026):** Report initially used `POST /v1/batch` with `Bearer` token — wrong. Actual working request was `POST /api/v1/events` with `Basic` auth (base64-encoded UUID). Had to patch the report 8 times to fix all occurrences.

---



---

## Finding Splitting Strategy

### When to Split vs Combine

| Scenario | Split (multiple reports) | Combine (one chain) |
|----------|------------------------|-------------------|
| Same vuln, different apps (e.g., source map on app A and app B) | ✅ Split | |
| Step A enables Step B (info disclosure → token → write access) | | ✅ Combine |
| Same root cause, same app, different endpoints | | ✅ Combine |
| Independent vulns on same asset (debug mode + CORS) | ✅ Split | |
| Config disclosure + exploitation of that config (ArgoCD settings + device code) | ✅ Split | |

### Trade-Off Analysis

| Factor | Combined (Chain) | Split (Individual) |
|--------|-----------------|-------------------|
| Severity | Higher (chain > parts) | Lower per-report |
| Bounty count | 1 bounty | Multiple bounties |
| Total payout | Often higher (one High > two Lows) | Sometimes higher (two Mediums > one High) |
| Triage speed | Faster (one review) | Slower (multiple reviews) |
| Rejection risk | Lower (chain is compelling) | Higher (individual parts may seem low-impact) |

### Decision Framework

```
Is finding B ONLY exploitable because of finding A?
├── YES → Combine (B has no independent value)
│   Example: Token extraction only possible because source map reveals the pattern
│
└── NO (B is independently exploitable)
    ├── Does combining them tell a stronger story?
    │   ├── YES → Combine (severity upgrade justifies single bounty)
    │   │   Example: Debug mode (Medium) + CORS * (Low) = cross-origin extraction (Medium-High)
    │   │
    │   └── NO → Split (each stands alone)
    │       Example: Debug mode on CMS + CORS on CMS = two independent misconfigs
    │
    └── Are they on DIFFERENT assets?
        ├── YES → Split (different apps = different reports)
        │   Example: Source map on gopay-web-page vs source map on gwc
        │
        └── NO → Judgment call based on platform norms
```

### Platform Norms

| Platform | Tendency | Notes |
|----------|----------|-------|
| YesWeHack | Prefers chains | Triagers appreciate seeing the full attack path. Higher severity = higher bounty tier |
| HackerOne | Splits for you sometimes | If you submit a chain, triager may split into separate findings and pay for each |
| Bugcrowd | Prefers individual | Each finding gets its own P-rating. Chains can be noted in description |

### Splitting Rules of Thumb

1. **Different apps = always split.** Even if same vuln type. Each app is a separate fix for the vendor.
2. **Same app, independent root causes = split.** Debug mode and CORS wildcard are fixed by different teams/configs.
3. **Same app, dependent chain = combine.** Source map → token → write access is one attack path.
4. **Config disclosure + exploitation of config = split.** ArgoCD settings (info) vs device code flow (auth bypass) have different severities and different fixes.
5. **When in doubt, split.** You can always reference the other report. You can't un-combine after submission.

### Cross-Referencing Between Split Reports

When splitting related findings, add a brief cross-reference in each:

```markdown
**Related finding:** This vulnerability's impact increases when combined with 
[report title / ID] (submitted separately). The debug mode disclosed here enables 
the architecture extraction described in that report. However, each finding is 
independently fixable and independently exploitable.
```

Keep cross-references factual and brief. Don't make one report dependent on the other — each must stand alone.



---

## PoC Resilience (Surviving Triage Delays)

### The Problem

Bug bounty triage can take days to weeks. During that time:
- JS bundles get redeployed (hash changes: `main.be9942c6.js` → `main.a1b2c3d4.js`)
- Tokens get rotated (your curl one-liner returns 401 during triage)
- Endpoints get patched (vendor sees the report and fixes before triage completes)
- Source maps get removed (vendor's security team acts on the finding)

If the triager can't reproduce → "Not Applicable" or "Informational" → no bounty.

### Evidence Caching (MANDATORY)

Save full HTTP responses at time of testing, not just commands:

```bash
# Save the full response (headers + body) as evidence
curl -sk -D- "https://target.com/static/js/main.be9942c6.js.map" \
  -o evidence/sourcemap-response.json \
  > evidence/sourcemap-headers.txt 2>&1

# Save timestamp
echo "Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence/sourcemap-headers.txt

# For write-access verification, save the full exchange
curl -sk -D- -X POST "https://target.com/api/v1/events" \
  -H "Authorization: Basic TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' > evidence/write-access-full-response.txt 2>&1
```

**What to cache:**
- Full HTTP response (headers + body) for every exploitation step
- Screenshots of browser-based PoCs (in case the page changes)
- Source map files themselves (download and keep locally)
- Decoded token values and their verification responses
- Timestamps on everything

### Making PoCs Resilient to Redeployment

**Pattern 1: Dynamic filename discovery**

Instead of hardcoding the JS hash, include a discovery step:

```bash
# Step 0: Find current JS bundle filename
JS_FILE=$(curl -sk "https://target.com/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
echo "Current bundle: $JS_FILE"

# Step 1: Check for source map
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/static/js/${JS_FILE}.map"
```

**Pattern 2: Note the pattern, not just the instance**

In your report, always include:
```markdown
**Note:** The JS bundle filename changes on each deployment. At time of testing, 
the file was `main.be9942c6.js`. The pattern is `/static/js/main.*.js.map` — 
check the page HTML source for the current filename.
```

**Pattern 3: Multiple evidence timestamps**

Test on two different days if possible:
```markdown
**Verified on:**
- 2026-05-22 14:30 UTC — HTTP 200, source map accessible (1,606,974 bytes)
- 2026-05-23 09:15 UTC — HTTP 200, still accessible (same size)
```

This proves persistence, not a momentary misconfiguration.

### Handling "Finding Was Valid But May Not Reproduce Now"

If you suspect the vendor may fix before triage:

1. **Include cached evidence in the report** — attach the saved HTTP response as proof
2. **Add a note:**
   ```markdown
   **Reproduction note:** This finding was verified on [date]. If the source map 
   has been removed since submission, the attached `sourcemap-response.json` 
   (1.6MB) contains the full downloaded source map as evidence. The token 
   write-access was verified with the response shown in Step 4.
   ```
3. **Attach files** — most platforms allow file attachments. Attach:
   - The source map file itself (proves it was accessible)
   - Full HTTP response logs with timestamps
   - Screenshots of browser-based PoCs

### Evidence Checklist (Per Finding)

Before submitting, verify you have:

- [ ] Full HTTP response saved for each exploitation step
- [ ] Timestamps on all evidence
- [ ] Source files downloaded locally (source maps, configs)
- [ ] PoC includes dynamic discovery step (not just hardcoded URLs)
- [ ] Report notes that URLs may change on redeployment
- [ ] Attachments ready for upload (responses, source maps, screenshots)
- [ ] PoC tested from a clean environment (not relying on cached state)



---

## Finding Splitting Strategy

### Default: Split Per Endpoint/App

**User preference:** When in doubt, split findings into individual reports per affected endpoint or application. The operator prefers maximizing bounty count over combined severity. Only combine when findings are truly dependent (Step A is required to exploit Step B). When asked to "finalize reports," default to one finding per submission unless explicitly told to combine.

### When to Submit as One Chain vs Split

| Scenario | Strategy | Rationale |
|----------|----------|-----------|
| Step A enables Step B (causal chain) | **Combine** | Chain severity > individual; one bounty but higher tier |
| Same vuln on 2+ independent apps | **Split** | Each is independently fixable; multiple bounties |
| Same root cause, same app, multiple manifestations | **Combine** | Avoids "duplicate" rejection on second report |
| Info disclosure + exploitation of disclosed info | **Combine** | Disclosure alone is Low; chain is High |
| Two unrelated vulns on same asset | **Split** | Each gets own bounty; no dependency |
| Config issue + its consequence (debug + CORS) | **Split or Combine** | See decision tree below |

### Decision Tree

```
Found multiple related issues?
├── Does Issue B REQUIRE Issue A to exploit?
│   ├── YES → COMBINE (chain)
│   │   Example: source map → token → write access
│   │   (token is useless without knowing the auth pattern from source map)
│   │
│   └── NO (each exploitable independently)
│       ├── Same app, same root cause?
│       │   ├── YES → COMBINE (systemic finding)
│       │   │   Example: debug mode on prod + staging + cms (one .env template)
│       │   │
│       │   └── NO (different apps or different root causes)
│       │       └── SPLIT (separate reports)
│       │           Example: debug mode on cms + CORS on cms API
│       │           (different fixes, different teams may own them)
│       │
│       └── Would splitting reduce each finding below reportable threshold?
│           ├── YES → COMBINE (Info + Info = Medium only works together)
│           └── NO → SPLIT (each stands alone as Medium+)
```

### Trade-offs

| Factor | Combine | Split |
|--------|---------|-------|
| Bounty count | 1 bounty | Multiple bounties |
| Severity per report | Higher (chain) | Lower (individual) |
| Total payout | Often higher per-report but fewer reports | More reports but each may be lower tier |
| Triage complexity | Harder to triage (longer report) | Easier (focused reports) |
| Duplicate risk | None (all in one) | Risk of "duplicate of report #X" |
| Fix tracking | One fix may break the chain | Each fix is independent |

### Platform Norms

| Platform | Tendency |
|----------|----------|
| YesWeHack | Prefers chains — triagers appreciate seeing the full attack path |
| HackerOne | Triagers sometimes split your chain into separate findings (you still get credit) |
| Bugcrowd | Prefers one finding per report — split unless truly dependent |

### Practical Example (GoPay, May 2026)

**Original combined report:** Source maps + tokens + write access (3 apps, 3 tokens)
**Final split:**
- Report 1A: gopay-web-page source map + token + write access (self-contained chain)
- Report 1B: gwc source map + token + write access (same pattern, different app)
- Report 2A: Debug mode (standalone finding)
- Report 2B: CORS wildcard (standalone finding, cross-references 2A)
- Report 3A: ArgoCD config disclosure (standalone)
- Report 3B: ArgoCD device code flow (standalone, cross-references 3A)

**Why this split works:**
- 1A and 1B are independent apps → separate bounties
- 2A and 2B have different fixes → separate reports
- 3A and 3B: config disclosure is Medium alone; device code is High alone — both stand independently
- Cross-references between related reports strengthen each without creating dependency



---

## PoC Resilience & Evidence Caching

### The Problem

Bug bounty PoCs break between testing and triage because:
- JS bundle hashes change on deploy (`main.be9942c6.js` → `main.a1b2c3d4.js`)
- Tokens get rotated (your curl returns 401 during triage)
- Endpoints get patched (team fixes before triager reproduces)
- CDN cache expires (source map was cached, now 404)

### Evidence Caching (Do This During Testing)

**Save HTTP responses, not just commands:**

```bash
# Save full response with headers for every critical step
curl -sk -D- "https://target.com/static/js/main.be9942c6.js.map"   -o evidence/sourcemap-response.json   > evidence/sourcemap-headers.txt 2>&1

# Save timestamp
echo "Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence/sourcemap-headers.txt

# Screenshot equivalent for API responses
curl -sk -w "

--- HTTP %{http_code} | Size: %{size_download} | Time: %{time_total}s ---
"   "https://target.com/api/v1/events"   -H "Authorization: Basic TOKEN"   -H "Content-Type: application/json"   -d '{}' | tee evidence/write-access-proof.txt
```

**Minimum evidence per finding:**
- [ ] Full HTTP response (headers + body) for each exploitation step
- [ ] Timestamp of when the test was performed
- [ ] Source map / JS file saved locally (not just the URL)
- [ ] Token values documented (in case they're rotated)
- [ ] Screenshot of browser DevTools if applicable

### Making PoCs Resilient to Redeployment

**Pattern 1: Dynamic hash discovery (JS bundles)**

Instead of hardcoding `main.be9942c6.js`, include a discovery step:

```bash
# Step 0: Find current JS bundle filename
JS_FILE=$(curl -sk "https://target.com/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
echo "Current bundle: $JS_FILE"

# Step 1: Check for source map
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/static/js/${JS_FILE}.map"
```

**Pattern 2: Note in report**

Always add this note when referencing versioned URLs:

```markdown
> **Note:** The JS bundle filename contains a content hash that changes on each 
> deployment. The current filename at time of testing is `main.be9942c6.js`. 
> After redeployment, find the current filename by viewing page source or:
> `curl -sk "https://target.com/" | grep -oE 'main\.[a-f0-9]+\.js'`
> The source map vulnerability persists regardless of the hash value.
```

**Pattern 3: Resilient PoC script**

```python
#!/usr/bin/env python3
"""Resilient PoC — auto-discovers current bundle hash"""
import requests, re

TARGET = "https://target.com"

# Auto-discover current JS bundle
html = requests.get(TARGET, verify=False).text
js_match = re.search(r'(main\.[a-f0-9]+\.js)', html)
if not js_match:
    print("[!] Could not find JS bundle — page structure may have changed")
    print("    Try: view-source on the target and look for /static/js/main.*.js")
    exit(1)

js_file = js_match.group(1)
print(f"[+] Current bundle: {js_file}")

# Check source map
map_url = f"{TARGET}/static/js/{js_file}.map"
resp = requests.get(map_url, verify=False)
print(f"[+] Source map: {resp.status_code} ({len(resp.content)} bytes)")
```

### Handling "Finding Was Valid But May Not Reproduce Now"

When you suspect the target may have changed between testing and submission:

**In the report, add:**

```markdown
## Reproduction Notes

- **Tested:** 2026-05-23 14:30 UTC
- **Evidence captured:** Full HTTP responses saved (attached)
- **Resilience:** The JS bundle hash changes on deploy. Use the discovery 
  step above to find the current filename. If source maps have been removed 
  since testing, the attached evidence proves they were accessible at the 
  time of testing.
- **If token no longer works:** The token `bf63bf09-...` was confirmed 
  working at test time (HTTP 200 response attached). If rotated since then, 
  this confirms the remediation recommendation was followed — but the 
  underlying issue (token in client JS) persists unless server-side 
  proxying is implemented.
```

**Attach evidence files:**
- `evidence-sourcemap-response.json` (the actual source map content)
- `evidence-write-access.txt` (full HTTP response showing 200)
- `evidence-timestamps.txt` (when each test was performed)

### What Triagers Accept as Proof

| Evidence Type | Accepted? | Notes |
|--------------|-----------|-------|
| Curl command + response (with headers) | ✅ Best | Copy-pasteable, includes status code |
| Screenshot of browser DevTools | ✅ Good | Shows request + response in context |
| Video recording of exploitation | ✅ Good | For complex multi-step chains |
| "I tested this and it worked" (no evidence) | ❌ Never | Always save the response |
| Saved response file (attached) | ✅ Good | Proves state at time of testing |
| Nuclei/tool output | ⚠️ Depends | Some triagers don't trust tool output alone |

## Platform-Specific Formatting

### PoC Resilience (Preventing Stale Evidence)

Bug bounty triage can take days to weeks. Your PoC must still work when the analyst tests it.

**Common staleness causes:**
- JS bundle hash changes on redeploy (`main.be9942c6.js` → `main.a1b2c3d4.js`)
- Tokens get rotated after incident response
- Staging environments get rebuilt
- CDN cache purges change response sizes

**Mitigation strategies:**

1. **Include a discovery step** in your PoC that finds the current filename:
```bash
# Instead of hardcoding the hash:
JS_FILE=$(curl -sk "https://target.com/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
curl -sk "https://target.com/static/js/${JS_FILE}.map" -o sourcemap.json
```

2. **Note the pattern, not just the URL** in your report:
```
Note: The JS filename contains a build hash that changes on deploy.
Current URL: /static/js/main.be9942c6.js.map
Pattern: /static/js/main.*.js.map (check page source for current hash)
```

3. **Cache evidence locally** — save HTTP responses, not just commands:
```bash
# Save full response with headers as evidence
curl -sk -D headers.txt "https://target.com/endpoint" -o response.json
# Screenshot the terminal output
# Save source map files locally (they may be removed)
```

4. **Include timestamps** in your evidence:
```
Tested: 2026-05-24T13:00:00Z
Response saved: ./evidence/response-20260524.json
```

5. **For token findings** — note that the token value proves the vulnerability pattern exists even if rotated:
```
Note: If this specific token has been rotated since testing, the vulnerability 
pattern persists — the build pipeline still embeds CLICKSTREAM_TOKEN in client-side 
JS. Check the current bundle for the replacement token.
```

### YesWeHack

- Markdown supported in all fields
- Code blocks with syntax highlighting (```bash, ```json)
- Tables supported
- File attachments: screenshots, PoC files, videos
- Severity: you propose, program adjusts
- Asset: must match a listed scope entry (dropdown or free text depending on program)

**YWH Form Fields (quick reference):**

| Field | Guidance |
|-------|----------|
| Title | Short, impact-focused. Avoid mentioning excluded classes in title |
| Bug type | Pick the IMPACT class, not the attack vector (e.g., "Broken Access Control" not "Information Disclosure") |
| Vulnerable part | The endpoint where the highest-impact action occurs (e.g., `POST https://target.com/api/write`) |
| Payload | The key input that triggers the vuln. For access control: the auth header. For CORS: `Origin: https://evil.com`. For exposed files: just the path |
| Technical environment | `Browser: Any, OS: Any, No authentication required` for unauthenticated findings |
| HTTP method | GET/POST/PUT matching the vulnerable endpoint |

### HackerOne

- Markdown supported
- "Weakness" field maps to CWE
- "Asset" is a dropdown from program scope
- Severity: CVSS calculator built-in
- Structured fields for impact, steps, remediation
- "Attachments" for PoC files

### Bugcrowd

- Markdown supported
- VRT (Vulnerability Rating Taxonomy) for classification
- Priority (P1-P5) instead of CVSS
- "Target" must match program scope
- Inline image upload

### General Tips (All Platforms)

1. **First paragraph is everything** — triage analysts read 50+ reports/day. Hook them in 2 sentences.
2. **Copy-pasteable reproduction** — `curl` one-liners > "use Burp Suite to..."
3. **Show the response** — include the actual HTTP response proving the exploit works
4. **One finding per report** (unless chain) — don't bundle unrelated issues
5. **Be professional** — no "your security is terrible" commentary. Facts only.
6. **Respond quickly** to triage questions — slow responses = deprioritized report
