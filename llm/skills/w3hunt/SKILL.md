---
name: w3hunt
version: 1.3.0
description: "Web3 bug bounty hunting on Immunefi and similar platforms. Target selection, scope verification, DeFi-specific recon, and attack vector prioritization for hybrid web+contract programs."
tags: [web3, bug-bounty, immunefi, defi, smart-contract, recon]
trigger: "immunefi, web3 hunting, defi bug bounty, smart contract bounty, web3 recon"
argument-hint: "<command: start|recon|scope|targets|status>"
metadata:
  hermes:
    tags: [web3, bug-bounty, immunefi, defi, smart-contract]
    related_skills: [ptest, scode]
---

# Web3 Bug Bounty Hunting Framework

Structured approach for hunting on Immunefi and similar web3 bug bounty platforms. Optimized for hunters with strong web pentest backgrounds targeting DeFi protocol web+contract hybrid programs.

## Strategy

**Core edge:** Most Immunefi hunters are Solidity-focused. Web pentest skills applied to DeFi frontends, APIs, and off-chain components face far less competition.

**CRITICAL WORKFLOW RULE — "15-minute triage before deep-dive":**
Before spending 1+ hour on ANY target, answer these in order (max 15 min):
1. Is the program live? (`curl -sL -o /dev/null -w "%{http_code}"`)
2. Was there a prior C4/Sherlock contest? (GitHub search)
3. Does it have web/app scope? (check scope tab)
4. For SC: do the 3 oracle prerequisites exist? (permissionless trigger + on-chain oracle swap + oracle-derived slippage)
If SC prerequisites FAIL → pivot to web scope on SAME target BEFORE moving to next target. Your web edge is wasted if you only audit Solidity.

**Target selection criteria:**
- BOTH web/app scope AND smart contract scope (hybrid programs)
- Mid-tier payout: $10K-$100K for Critical (avoid over-audited top-tier)
- Protocols with: DeFi frontends, admin panels, APIs, off-chain components
- Active programs on EVM chains (Ethereum, Arbitrum, Optimism, Base, Polygon, BSC)
- Multi-chain deployments preferred (larger attack surface, inconsistency bugs)

**Priority by web pentest edge:**
- HIGH: CeFi/DeFi hybrids, multi-chain aggregators, platforms with complex APIs
- MEDIUM: Trading UIs, yield farming dashboards, DCA/scheduling frontends
- LOWER: Pure contract protocols with minimal web layer
- **NEVER skip web scope** — if a target has web/app in scope ($25K Critical), always assess it even if SC looks more interesting. Web bugs face 10x less competition.

**After first submission — next target selection heuristics:**
1. **Pattern transferability** — pick targets where your PROVEN exploit pattern applies (e.g., found oracle bug on Protocol A → pick Protocol B that uses same oracle architecture)
2. **Payout multiplier** — prioritize 5-10x payout increase over comfort zone (a Medium on $500K program > Critical on $50K program)
3. **Novel mechanisms** — less-audited = more edge cases. Transmuters, fixed-rate lending, time-weighted DCA all have less security research than standard AMM/lending
4. **Don't squeeze blood from stone** — if web layer is hardened and you have one good finding, submit it and move on. A Low-severity finding ($500-$2K) is rarely worth the hours to validate when fresh targets exist
5. **Submit immediately** — sitting on findings risks duplicates. Report is ready → submit → next target
6. **Time-box hard targets** — if after 2-3 hours of source review you haven't found a concrete lead (not "this looks complex" but an actual exploitable pattern), pivot. Mature protocols with 400+ functions, 14+ facets, proper Chainlink validation, and role-based access are unlikely to yield findings without 20+ hours of focused review. Your time is better spent on the next target.
7. **Verify program is live BEFORE recon** — batch-check all shortlisted programs with HTTP status codes. Programs disappear from Immunefi without notice (7/10 from our 2026-05-25 shortlist were gone).
8. **Check prior audit contests BEFORE deep-diving** — search Code4rena (`code-423n4/{year}-{month}-{protocol}-findings`) and Sherlock (`sherlock-audit/{protocol}-judging`) on GitHub. If the protocol had a contest, most low-hanging fruit is already found and classified. Known issues will be rejected on Immunefi. Do this check within the first 30 minutes of recon, not after finding a bug.

**Protocol complexity vs exploitability (learned from experience):**
- **Yield optimizers** (Beefy, Yearn forks): simpler code, fewer audits, oracle/harvest patterns repeat across vaults. HIGH exploitability.
- **Yield-bearing tokens with off-chain harvest** (Origin OUSD/OETH): single-asset vaults, harvesters just transfer (no on-chain swap), all rebalance access-controlled. Oracle bugs exist in code but have no active call path. LOW exploitability — the architecture deliberately avoids on-chain oracle dependency in fund flows.
- **Synthetic dollars / trust-based systems** (Ethena USDe): no on-chain oracle, no AMM, no algorithmic pricing. Contracts are mint/burn/stake wrappers around off-chain strategies. Security = MINTER_ROLE honesty + user signature verification + rate limits. On-chain attack surface is tiny. Only catastrophic bugs (signature bypass, role escalation) qualify for bounty. LOW exploitability unless you find a novel EIP-712 or access control flaw.
- **Perp DEXes** (gTrade, GMX): 400+ function diamonds, multiple audits, proper accounting (realized PnL tracking, reentrancy guards, oracle whitelists, delegation access control). LOW exploitability — expect 10+ hours of source review before finding anything.
- **Lending protocols** (Aave forks, Compound forks): middle ground. Interest rate model edge cases and liquidation logic are the sweet spots.
- **Dual-pricing AMMs** (Origin ARM): dead shares mitigate inflation, crossPrice constraints bound operator manipulation to 20bps, withdrawal queue has liquidity reservation. Well-designed but operator trust assumptions could be attack surface if key is compromised.
- **On-chain asset management** (Enzyme Finance): fund managers execute trades via adapters (owner-only), users deposit/redeem through gated queues. Slippage is user-supplied (not oracle-derived). Oracle used for NAV display only, not swap execution. No permissionless trigger that performs swaps. Attack surface: redemption queue logic bugs, adapter calldata parsing, share price manipulation for throttle bypass. Requires deep source review (10-20h), not pattern matching. No prior C4/Sherlock contests = less picked over.
- **Rule of thumb:** If the protocol has a Diamond proxy with 14+ facets and a TypeScript SDK with comprehensive test coverage, it's been heavily audited. Pivot to web layer ($40K Critical) or move to a softer target unless you have a specific hypothesis to test.

**Pattern transferability prerequisite check (MANDATORY before source review):**
Before spending 2+ hours auditing a target's oracle/harvest code, verify ALL THREE prerequisites exist:
1. ✅ Permissionless trigger function (harvest, compound, rebase callable by anyone)
2. ✅ On-chain oracle-dependent swap (not just transfer to strategist)
3. ✅ Slippage/minAmountOut calculated FROM oracle price (not user-supplied)
If ANY is missing → the oracle→harvest→sandwich pattern does NOT apply. Pivot immediately or switch to a different bug class (access control, share math, queue logic).

## Commands

| Command | Action |
|---------|--------|
| `start` | Initialize new target — verify scope, create working directory |
| `recon` | Phase 1: Subdomain enum, GitHub repos, frontend analysis, API mapping |
| `scope` | Verify program scope on Immunefi (web+contract assets, impacts, rules) |
| `targets` | Research and shortlist suitable programs from Immunefi |
| `status` | Show current target, phase, findings |

## Phase 1: Target Selection & Scope Verification

1. **Browse Immunefi** — filter for programs with "Websites and Applications" scope category
2. **Verify scope tab** — click "Web & App" button on scope page to see web targets
3. **CRITICAL: Save the FULL in-scope asset list** — every contract address listed. These are the ONLY valid "Impacted Assets" for your report. If your finding targets a contract NOT on this list, you must manually enter it (Immunefi allows this) but risk "out of scope" rejection.
4. **Check impacts** — map Critical/High impacts to your skill set
5. **Note rules** — PoC required? Fix suggestion required? Primacy of Rules vs Impact?
6. **Check payout** — flat vs % of impact? Stablecoin/token?
7. **Check severity classification version** — v2.2 or v2.3? (shown on program page under "Rewards by Threat Level")
8. **Create working directory** — `~/PenTest/Hunting/Immunefi/<target>/`
9. **Save scope.txt** — all rules, targets, impacts, payout structure, FULL asset list

**Scope validation rule (HARD GATE — learned from Beefy SC-1 rejection):**
Before spending time on a finding, verify the vulnerable contract IS in the scope list OR directly called by an in-scope contract during normal user/keeper operations. If neither, the finding WILL be rejected — Immunefi triagers enforce asset scope before the project ever sees the report.

**Asset scope verification steps:**
1. Get the exact address of the vulnerable contract on the target chain
2. Check if that address appears in the program's "Assets in Scope" list
3. If NOT listed: trace the call chain — does an in-scope contract call the vulnerable contract? (e.g., in-scope Strategy calls out-of-scope Swapper during harvest)
4. If yes to (3): submit with the IN-SCOPE contract as primary asset, explain the call chain to the vulnerable code
5. If no to both (2) and (3): DO NOT SUBMIT. Either find an in-scope entry point or move on.

**Common trap:** Infrastructure contracts (oracles, swappers, routers, fee managers) are often NOT in scope even though every in-scope vault/strategy depends on them. The scope list is typically frozen at program launch date — newer contracts added later won't be there.

**Key Immunefi web impacts (typical):**
- Critical ($25K): RCE, sensitive data theft, app takedown, wallet drain, subdomain takeover w/ wallet, tx manipulation
- High ($10K): Persistent injection, user data change, PII disclosure, subdomain takeover w/o wallet
- Medium ($4K): Non-sensitive user data changes

## Phase 2: Reconnaissance

Run in parallel (delegate_task with 3 sub-agents):

### 2a. GitHub & SDK Enumeration (DO THIS FIRST — highest ROI)
- Find org repos via GitHub API: `https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated`
- Clone SDK/trading-sdk repos immediately (shallow: `git clone --depth 1`)
- Extract from SDK: contract addresses (`src/contracts/addresses.json`), ABIs (`abi/`), backend URLs (`src/config/constants.ts`), trade construction logic (`src/libs/tx.ts`)
- Identify: frontend repo, API/backend repo, smart contracts repo, subgraph repos
- Note: active vs archived, languages, last update dates
- Look for: beefy-api pattern (separate API repos), yield-server repos, indexer repos
- **SDK repos reveal more attack surface than subdomain scanning** — backend URLs, internal API paths, precision handling, delegation mechanisms all live here

### 2b. Subdomain Enumeration (Passive)
- HackerTarget: `curl -s "https://api.hackertarget.com/hostsearch/?q={domain}"`
- crt.sh: `curl -s "https://crt.sh/?q=%25.{domain}&output=json"`
- DNS lookups on all discovered subdomains (A, CNAME records)
- Identify non-CDN subdomains (potential takeover candidates)
- Flag: beta/staging, legacy, internal APIs, RPC proxies, payment/onramp

### 2c. Frontend Analysis
- Framework detection (React/Vue/Next.js, build tool)
- API endpoint discovery from JS bundles
- Security headers audit (CSP, CORS, HSTS)
- Source map exposure check
- Build info leakage (git commit, timestamps)
- localStorage/state persistence analysis
- Transaction construction flow mapping

### 2d. Backend API Enumeration
DeFi protocols often have Express.js/Node backends that serve trading state. Find URLs from SDK constants, then probe:
```bash
# Common DeFi backend patterns (found in SDK constants.ts):
# https://backend-{chain}.{domain}
# https://api.{domain}/v1/

# Probe endpoints
for path in /health /trading-variables /open-trades /open-trades/{address} /config /admin /graphql /ws /metrics /debug; do
  curl -s -w "\n%{http_code}" "${URL}${path}" | tail -1
done
```
Key findings pattern:
- `/trading-variables` — full protocol state (OI, fees, pairs, collaterals)
- `/open-trades` — all open positions (public, no auth — blockchain data)
- `/open-trades/{address}` — per-user positions
- `/health` — confirms service is alive
- Express.js error pages (`Cannot GET /path`) confirm framework
- These APIs are typically read-only (no auth needed) since they mirror on-chain state
- Attack value: monitor state changes for front-running, find undocumented write endpoints

## Phase 2.5: Web Scope Quick Assessment (30 min — DO THIS if SC prerequisites fail)

When SC oracle/harvest pattern doesn't apply, pivot to web scope IMMEDIATELY. This phase takes 30 minutes max and identifies quick-win web vectors.

**Quick kill checklist (in order):**
1. **CORS on ALL API subdomains** — `curl -sI -H "Origin: https://evil.com" https://api.{domain}/ | grep -i access-control` — if origin reflected + credentials=true → POTENTIAL finding but MUST VALIDATE IMPACT. Test: (a) same query WITHOUT origin/cookies returns same data? → public data, no impact. (b) Find endpoint returning DIFFERENT data with auth → real impact. (c) Web3 wallet-signature auth is NOT vulnerable to CORS (can't steal signatures cross-origin). Only report if authenticated-only data is exposed cross-origin.
2. **GraphQL introspection** — `curl -s https://api.{domain}/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { mutationType { fields { name } } } }"}'` — if mutations exist, test WITHOUT auth. Unauth write = High.
3. **CSP headers** — `curl -sI https://app.{domain}/ | grep -i content-security` — no CSP = XSS potential
4. **Source maps** — check `https://app.{domain}/static/js/*.js.map` or `/_next/static/chunks/*.js.map`
5. **API discovery** — grep JS bundles for `/api/`, `fetch(`, `axios.`, backend URLs
6. **Subdomain takeover** — check CNAME records for dangling entries (S3, Heroku, Vercel)
7. **Wallet interaction flow** — how does the frontend construct transactions? API-sourced addresses?
8. **RPC proxy** — does the protocol run its own RPC? Test for SSRF with internal IPs

**DeFi web Critical ($25K) patterns:**
- XSS on app domain → inject malicious `eth_sendTransaction` → drain connected wallet
- API endpoint that serves contract addresses → poison it → users interact with attacker contract
- Subdomain takeover on domain with wallet-connected users → phishing with legitimate origin
- SSRF via RPC proxy → access internal services / cloud metadata

**Key difference from traditional web pentest:**
- No cookies/sessions to steal — auth is wallet signature
- Impact = "can you make the user sign a malicious transaction?"
- Contract address substitution > credential theft
- Frontend supply chain (npm, CDN integrity) is high-value

## Phase 3: Attack Vector Prioritization (DeFi-Specific)

### Web-First Vectors (your edge)

| Priority | Vector | Impact | Typical Payout |
|----------|--------|--------|----------------|
| P1 | XSS → Wallet Drain | Inject malicious tx signing | Critical $25K |
| P1 | SSRF via RPC Proxy | Internal service access | Critical $25K |
| P1 | API Data Poisoning → Tx Manipulation | Substitute contract addresses | Critical $25K |
| P2 | Unauthenticated API Writes | Poison vault/price data | Critical/High |
| P2 | Subdomain Takeover | Phishing w/ wallet interaction | Critical/High |
| P3 | beta/legacy/staging Environments | Less hardened, debug features | Varies |
| P3 | IDOR on User APIs | Balance/position disclosure | High $10K |
| P3 | Payment Flow Manipulation | Onramp parameter tampering | High $10K |

### DeFi Frontend-Specific Checks

1. **No CSP = XSS goldmine** — DeFi frontends often skip CSP because of wallet injection complexity
2. **CORS * on APIs** — common in DeFi (public data), but check for write endpoints
3. **Transaction construction** — frontend builds calldata client-side, can params be manipulated?
4. **Contract address sourcing** — are addresses hardcoded, from API, or from on-chain registry?
5. **Slippage/deadline injection** — can frontend be tricked into setting 100% slippage?
6. **RPC proxy abuse** — if protocol runs its own RPC, test for SSRF/internal access
7. **Price feed display vs reality** — can displayed APY/TVL be manipulated to mislead users?
8. **Wallet connection flow** — WalletConnect, injected provider, deep link manipulation

### Contract Vectors (use scode framework for full audit, or targeted review below)

- Run `scode start` on cloned contract repo for full pipeline
- Focus on vault/strategy patterns (one bug = hundreds of affected deployments)
- Check cross-chain deployment inconsistencies
- ERC-4626 vault inflation (first depositor attack)
- Zap contract slippage/sandwich vectors

## Phase 4: Smart Contract Targeted Audit

When the web layer is well-hardened, pivot to smart contracts for higher payouts.

### Parallel Audit Strategy (delegate 3 sub-agents)

Batch contracts by risk tier for parallel review:

| Batch | Contracts | Focus |
|-------|-----------|-------|
| 1 | Vault (ERC-4626, share math) | Inflation attack, donation, rounding, reentrancy |
| 2 | Oracle + Swapper | Staleness, negative price, TWAP manipulation, slippage bypass |
| 3 | Strategy base + fee manager | Harvest manipulation, fee bypass, migration safety |

### High-Value Contract Bug Patterns (DeFi-Specific)

**Oracle bugs (often Critical/High):**
- Chainlink `latestAnswer()` without staleness check or negative price validation
- Unsafe `int256` → `uint256` cast (negative becomes astronomical)
- UniswapV2 TWAP first observation using manipulable spot price
- No minimum TWAP period enforcement (1-second TWAP ≈ spot price)
- Missing fallback when oracle reverts (blocks all swaps = DoS)

**Vault/share bugs (often Critical):**
- First depositor inflation (no virtual shares, no minimum deposit)
- Share price manipulation via direct token donation to vault/strategy
- `balance()` using live `balanceOf()` instead of internal accounting
- Missing `nonReentrant` on withdraw (deposit has it, withdraw doesn't)
- `earn()` public with no access control (anyone can force-deposit to strategy)
- No flash loan protection (deposit + withdraw in same tx)

**Strategy/harvest bugs (often High/Medium):**
- `wantHarvested = balanceOfWant()` instead of delta (inflates totalLocked)
- Infinite approvals to routers that persist after swap
- `addWantAsReward()` bypassing `require(_token != want)` safety check
- Harvest/deposit race condition (MEV sandwich around harvest)
- Uninitialized proxy front-running (factory creates clone, attacker front-runs initialize)

### On-Chain Verification

After finding bugs in source, verify deployment:
```bash
# Check contract is deployed and has code
cast code <address> --rpc-url <rpc>

# Verify function selectors match source
cast sig 'functionName(argTypes)'

# Read state to confirm configuration
cast call <address> 'owner()(address)' --rpc-url <rpc>
cast call <address> 'staleness()(uint256)' --rpc-url <rpc>
```

**Free Polygon RPCs that work (2026):**
- `https://polygon-bor-rpc.publicnode.com` (reliable)
- Avoid: polygon-rpc.com (401), ankr (requires key), blastapi (deprecated)

### Foundry PoC for Immunefi

Immunefi requires working PoC for Critical/High. Use Foundry fork tests:
```solidity
// For oracle bugs: mock the feed returning bad data
contract MaliciousFeed {
    int256 public latestAnswer = -1; // or 0
    uint8 public decimals = 8;
}

// For vault bugs: demonstrate inflation attack
function testInflationAttack() public {
    vm.startPrank(attacker);
    vault.deposit(1);  // 1 wei → 1 share
    // donate to strategy to inflate share price
    token.transfer(address(strategy), 10000e18);
    vm.stopPrank();
    // victim deposits, gets 0 shares
    vm.prank(victim);
    vault.deposit(5000e18); // rounds to 0 shares
}
```

## Output Structure

```
~/PenTest/Hunting/Immunefi/<target>/
├── scope.txt              # Program rules, payouts, impacts, targets
├── subdomains.txt         # Subdomain enumeration results
├── frontend-recon.txt     # Framework, APIs, headers, hosting
├── recon-summary.txt      # Consolidated findings + attack vectors
├── github-repos.txt       # Repository enumeration
├── api-endpoints.txt      # Full API endpoint map
├── findings/              # Individual finding write-ups
│   ├── finding-001.txt
│   └── ...
└── poc/                   # PoC scripts for submissions
    ├── poc_001.py
    └── ...
```

## Severity Classification (Immunefi v2.2 — used by most programs)

**BEFORE writing a report, map your finding to the EXACT impact category. Do NOT overclaim.**

### Smart Contracts
| Level | Impact |
|-------|--------|
| Critical ($75K) | Direct theft of user funds (at-rest or in-motion), permanent freezing, protocol insolvency, MEV, governance manipulation, unauthorized NFT minting |
| High ($15K) | Theft of unclaimed yield/royalties, permanent freezing of unclaimed yield, temporary freezing of funds/NFTs |
| Medium ($2K) | Contract unable to operate (DoS), griefing (no profit motive), theft of gas, unbounded gas consumption |
| Low ($500) | Contract fails to deliver promised returns but doesn't lose value |

### Websites and Apps
| Level | Impact |
|-------|--------|
| Critical ($25K) | RCE, sensitive data from server (/etc/shadow, DB passwords, blockchain keys — NOT env vars or open source code), app takedown, state-modifying actions on behalf of users, wallet manipulation (modify tx args, substitute addresses), subdomain takeover w/ wallet, direct fund theft |
| High ($10K) | Persistent injection w/o JS, changing sensitive user details (email/password), disclosing confidential user info (email/phone/address), subdomain takeover w/o wallet |
| Medium ($4K) | Changing non-sensitive user details, redirecting to malicious websites |
| Low ($2K) | Non-state-modifying actions on behalf of users, changing non-sensitive details w/ interaction |

### Severity Validation Checklist (prevent overclaiming AND rejection)

Before assigning severity, answer these honestly:

0. **Is the vulnerable contract IN THE ASSET SCOPE LIST?** If not, can you trace a call chain from an in-scope contract to the vulnerable code? If neither → DO NOT SUBMIT. This is the #1 rejection reason (Beefy SC-1 was rejected purely on this).

1. **Can the attacker TRIGGER the condition themselves?** If it requires external events (Chainlink malfunction, sequencer downtime), the finding may be downgraded or rejected as "requires uncommon external conditions."

2. **Is there DIRECT fund loss?** "Could theoretically lead to loss" ≠ "direct theft." Immunefi wants concrete, demonstrable impact.

3. **Does it require elevated privileges?** If only owner/manager can trigger the vulnerable path, it's centralization risk (usually out of scope or None).

4. **Is it a known/accepted pattern?** First-depositor inflation on a 4-year-old vault = almost certainly known. Check if the team has addressed it operationally.

5. **Does the PoC demonstrate ACTUAL impact?** A mock showing "this code path is reachable" is weaker than "this extracts $X from the protocol."

6. **Web scope: does it affect USERS or just disclose non-sensitive info?** Source maps without secrets = None. Open source code is explicitly excluded from "sensitive data."

### Common Rejection Reasons (ordered by frequency from experience)
1. **"Out of scope asset"** — #1 killer. Contract not in the program's asset list = instant close. Triagers don't check validity. Infrastructure contracts (oracles, swappers, routers) are almost never listed even if every vault depends on them. ALWAYS verify asset scope before writing report.
2. "Requires external conditions outside attacker control" (oracle malfunction, sequencer down)
3. "Known issue / accepted risk" (first-depositor on old vaults)
4. "Centralization risk" (owner-only functions)
5. "Informational / best practice" (missing headers, source maps w/o secrets)
6. "No PoC" (all web/app bugs require working PoC)
7. "Theoretical impact only" (no concrete demonstration of fund loss)

## Reporting (Immunefi Format)

**PRE-SUBMISSION GATE (mandatory):**
1. Open the program's scope page → "Smart Contracts" tab → verify your target contract address is listed
2. If not listed: identify an in-scope contract that CALLS the vulnerable contract (trace the call chain)
3. Use the in-scope contract as "Impacted Asset" in the submission form, explain the full call chain in the report
4. If no in-scope entry point exists: DO NOT SUBMIT — find one or move to next target

### Title Format
Use vulnerability class + impact. After reading the title, the program should understand the basics.
Examples:
- "Missing replay protection and timestamp expiry in updateProfile mutation leads to permanent unauthorized modification of user registration information"
- "Reentrancy in the withdraw function leads to total loss of funds"
- "Lack of access control in uploadMetadata mutation leads to stored XSS and resource abuse"

### Submission Template (Immunefi's actual form structure)

```markdown
## Brief/Intro
One paragraph: what the problem is + consequences if exploited in production.
Keep it concise — triager reads 50+ reports/day.

## Vulnerability Details
Detailed explanation of the vulnerability. Code snippets where helpful.
Must make it obvious you understand the bug AND that it exists.
Include: affected function/endpoint, root cause, why current validation fails.
PoC goes here as a self-contained Python script with actual output in comments.

## Impact Details
Detailed breakdown of possible losses. Map to the program's EXACT impact category.
State the selected impact explicitly: "Selected impact: Taking state-modifying
authenticated actions on behalf of other users without any interaction by that user."
If funds at risk, estimate the amount or describe the loss path.

## References
- Frontend code references (bundle URLs proving scope)
- Relevant EIPs, CWEs, OWASP references
- Documentation links
```

**DO NOT include:** CVSS scores (Immunefi uses their own classification), remediation section (optional, add only if program requires "fix suggestion"), severity label in title (selected via dropdown on form).

### Web/App Severity Decision Tree (Immunefi v2.3)

Use this to select the correct severity BEFORE writing the report:

```
Q1: Can attacker execute system commands or read sensitive server files?
    YES → Critical (RCE / sensitive data retrieval)

Q2: Can attacker take down the application/website?
    YES → Critical (app takedown)

Q3: Can attacker perform STATE-MODIFYING actions on behalf of OTHER users
    WITHOUT any interaction by that user at exploitation time?
    (e.g., change email, make trades, withdraw, vote, comment)
    YES → Critical ("Taking state-modifying authenticated actions...")
    
    Key test: Does the victim need to DO anything for the exploit to work
    RIGHT NOW? If attacker just sends a request and victim's state changes → Critical.
    If victim must click/sign/visit something → downgrade based on interaction level.

Q4: Can attacker interact with victim's ALREADY-CONNECTED wallet?
    (modify tx args, substitute addresses, submit malicious tx)
    YES → Critical (malicious wallet interaction)

Q5: Can attacker inject persistent HTML/XSS through metadata/NFT?
    YES → Critical (injection through NFT/metadata)

Q6: Can attacker steal/modify SENSITIVE user details (email, password)?
    (requires some user interaction like visiting a page)
    YES → High (changing sensitive user details)

Q7: Can attacker disclose confidential user info (email, phone, address)?
    YES → High (PII disclosure)

Q8: Subdomain takeover?
    With wallet interaction → Critical
    Without wallet interaction → High

Q9: Can attacker change NON-SENSITIVE user details?
    YES → Medium

Q10: Redirect users to malicious websites?
    YES → Medium

Q11: Non-state-modifying actions on behalf of users?
    YES → Low
```

**Critical trap to avoid:** "Requires elevated privileges or uncommon user interaction" can DOWNGRADE any finding. Pre-empt this in your report by explaining why the prerequisite is realistic (e.g., cross-protocol signature reuse doesn't require phishing — it's a passive interception).

## Pitfalls

- **Cloudflare blocks automated browsing** — Immunefi uses aggressive bot detection. Manual scope verification may be needed. Use combobox interaction (click dropdown → select option) not button clicks for scope category switching.
- **PoC required for ALL web/app bugs** — don't submit without working PoC. Write PoCs EXCLUSIVELY in Python (`requests` + `eth_account`), NEVER curl. User explicitly said "STOP USE CURL" — this is a hard rule. Single self-contained `#!/usr/bin/env python3` script covering all steps with actual output in comments. Include `Origin` header matching the in-scope app URL. Use the exact mutation/endpoint format the app's frontend uses (with variables, not inline). For recon/probing during hunting, also prefer Python `requests` over curl commands.
- **NEVER claim impact you haven't proven end-to-end** — "no rate limiting" ≠ "brute-forceable". "Config leak" ≠ "access gained". "Token exposed" ≠ "data compromised". You MUST prove the FULL exploitation chain: (1) exploit the vulnerability, (2) demonstrate the ACTUAL impact (account takeover, data access, fund loss). If you can't complete the chain, downgrade severity honestly. Theoretical findings get rejected or closed as Informational. OTP brute-force lesson: without proving a successful login, you only have "missing rate limiting" (Low/Medium), not "authentication bypass" (High).
- **Fully exploit EVERY leaked token/key before dismissing** — Don't say "public by design" without testing ALL API endpoints the token could access. For each leaked credential: (1) identify the service it belongs to, (2) test read access (list/get endpoints), (3) test write access (create/modify/delete), (4) test cross-service reuse, (5) only THEN conclude "no impact" with evidence (specific 401/403 responses). Lazy dismissal = missed findings. Session lesson: DataDog pub tokens, Leanplum dev keys, LaunchDarkly client IDs — all tested exhaustively, all confirmed dead ends with proof.
- **VERIFY EXPLOIT OUTPUT BEFORE WRITING REPORT (HARD RULE)** — Run the FULL exploit chain end-to-end and confirm the output matches your claimed impact. Two StakeWise findings were initially written with inflated severity because verification was skipped: (1) CORS claimed "PII theft" but all data was public — downgraded to Informational. (2) Dojo #51 PoC read from wrong flag location — rejected by triager. **Verification steps:** (a) Run exact PoC curl — does it return claimed data? (b) For "auth data theft" — query WITHOUT auth, if same data returns it's public (no impact). (c) For mutations — verify state actually changed with follow-up query. (d) Use REAL keys/wallets, not placeholders. (e) For Web3 CORS — wallet signatures can't be stolen cross-origin, so CORS on wallet-auth apps has no impact unless cookie-based sessions exist.
- **Fix suggestion required** — many programs reject without remediation advice
- **Primacy of Rules — ASSET SCOPE IS STRICTLY ENFORCED** — if the vulnerable contract is not explicitly listed in the program's "Assets in Scope" section, the report WILL be rejected regardless of impact validity. Immunefi triagers check asset scope BEFORE forwarding to the project. Our Beefy SC-1 (valid zero-price oracle bug with working PoC) was rejected because BeefyOracleChainlink/BeefySwapper weren't in the 2022 asset list. The project never even saw the report. **Pre-submission checklist:** (1) Is the vulnerable contract address in the scope list? (2) If not, is it directly called by an in-scope contract during normal operation? (3) If neither, DO NOT SUBMIT — find an in-scope contract that triggers the same vulnerable code path and use THAT as the primary asset.
- **Immunefi rate limits submissions** — new accounts are limited to 1 report/day. Plan submission order carefully: strongest finding first (sets triager impression), weakest last. If you have 3 findings, that's 3 days of submissions. Don't sit on findings — duplicates can appear while you wait.
- **Don't test on mainnet with real funds** — use fork testing (Foundry `vm.createSelectFork`)
- **Rate limits** — DeFi APIs often have rate limiting (e.g., 100 req/60s). Respect them.
- **Wallet-based auth** — no cookies/sessions to steal, but connected wallet = full access to user's funds via malicious tx
- **Multi-chain = scope confusion** — contracts on chains not listed in scope may be out of scope even if the app supports them
- **Immunefi programs churn fast** — programs get paused/removed without notice. Our 2026-05-25 shortlist of 10 targets had 7 return 404 within days. ALWAYS verify program is live (HTTP 200 on `/bug-bounty/{slug}/`) before starting recon. Batch-check with: `for slug in ...; do curl -sL -o /dev/null -w "%{http_code}" "https://immunefi.com/bug-bounty/${slug}/information/"; done`
- **Cloudflare blocks curl on Immunefi program pages** — use `curl -sL -o /dev/null -w "%{http_code}"` for status checks (works through redirects). Full page content requires browser tool. The `/information/` suffix auto-redirects.
- **SDK repos are the best recon source for DeFi** — contract addresses, backend API URLs, ABI files, and trade construction logic are all in the protocol's SDK/trading-sdk repos on GitHub. Clone these FIRST before subdomain scanning. Pattern: `https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated`
- **Diamond proxy (EIP-2535) enumeration** — call `facetAddresses()` to get all facets, then use the ABI to map 400+ functions. Key permissionless functions to check: `triggerOrder`, `cancelOrderAfterTimeout`, `multicall`, `delegatedTradingAction`. Use `cast call` for on-chain state probing.
- **DeFi frontends are often well-hardened** — no dangerouslySetInnerHTML, no eval, vault addresses bundled at build time (not from API). Don't assume web layer is easy pickings.
- **GraphQL on DeFi = high ROI target** — introspection almost always enabled, mutations often lack auth (devs assume "wallet signature = auth" but forget server-side mutations). Test pattern: introspection → list mutations → call each without auth. Alias batching (`{ a: mut(...) b: mut(...) }`) amplifies any unauth mutation. StakeWise `uploadMetadata` was fully unauth with no rate limit.
- **EIP-191 signature validation on DeFi is often incomplete** — devs implement `ecrecover` correctly (wrong signer rejected) but skip temporal/replay/binding checks. Test pattern: (1) sign with old timestamp → accepted? (no expiry), (2) replay same sig with different params → accepted? (no nonce), (3) is the action parameter (email, amount, etc.) included in the signed message? (no binding). If any of these fail, it's a High — single intercepted signature = permanent unauthorized access. StakeWise `updateProfile` had all three gaps. Compare against EIP-4361 (SIWE) which mandates domain, nonce, expiration, and statement binding.
- **CORS on DeFi APIs — VALIDATE IMPACT BEFORE REPORTING** — CORS origin reflection + `Access-Control-Allow-Credentials: true` is common on DeFi APIs, but the misconfiguration alone is NOT a finding. You MUST prove that cross-origin access exposes data that is OTHERWISE INACCESSIBLE. Validation steps: (1) Query the same endpoint WITHOUT Origin header and WITHOUT cookies — if data returns identically, it's public data and CORS adds zero impact. (2) Find an endpoint that returns DIFFERENT data with vs without auth cookies/tokens. (3) Web3 apps typically use wallet signatures (not cookies) for auth — CORS can't steal wallet signatures cross-origin. (4) `uploadMetadata`-style mutations that are already unauthenticated are separate findings (unauth write), not CORS findings. **StakeWise lesson (2026-05-26):** CORS was technically misconfigured (origin reflection + credentials:true) but ALL data was publicly accessible without any auth. Profile emails returned null. Mutations required wallet signatures. Report would have been rejected as "informational/no impact" if submitted as-is. Always test ALL API subdomains separately (mainnet-api, gnosis-api, etc.) — they often share the same misconfigured Caddy/nginx config.
- **Parallel recon with delegate_task is optimal for web3** — spawn 2-3 sub-agents: (1) scope verification, (2) passive recon (subdomains/headers/GitHub), (3) active testing (GraphQL/CORS/auth). Total wall-clock time ~10 min for full recon + confirmed findings.
- **CORS wildcard on Supabase is NOT a finding by itself** — Supabase sets `Access-Control-Allow-Origin: *` by design because the client-side SDK needs cross-origin access. Security is enforced via RLS policies and API key scoping, not CORS. Only report if: (1) service_role key is leaked (bypasses RLS = Critical), (2) anon key + broken RLS exposes sensitive data, or (3) CORS * is on a CUSTOM backend (not Supabase's hosted endpoints). Don't waste time reporting CORS * on `*.supabase.co` — it will be closed as "by design."
- **API endpoints not listed in scope — reframe via frontend bundle proof** — When Immunefi scope says only `https://app.example.io/` but your findings target the backend API (e.g., `api.example.io/graphql`), you MUST prove the API is the app's backend. Technique: (1) curl the app's JS bundles and grep for the API URL, (2) find the exact mutation/endpoint strings the app calls, (3) reframe report title to reference the in-scope app URL, (4) add a Scope justification section citing bundle filenames, (5) use `Origin: https://app.example.io` in all PoC curls, (6) use the app's exact mutation format (with variables, not inline). Without this reframing, triagers auto-reject as out of scope. StakeWise lesson: all 3 findings targeted `mainnet-api.stakewise.io` but scope was only `app.stakewise.io` — reframed by proving SDK bundle (`sdk-*.js`) hardcodes the API URL and layout bundle (`layout-*.js`) contains the exact mutation strings.
- **Map findings to EXACT Immunefi impact categories** — Each program lists specific impacts (e.g., Loss of user funds, Freezing of unclaimed yield for at least 1 week). Your report MUST map to one of these EXACTLY. Profile takeover or resource abuse wont match any category and gets rejected. Reframe: signature replay to Freezing of unclaimed yield (operator misses exit notification), unauth upload to Loss of user funds (stored XSS then wallet drain). Check the program impact table BEFORE writing the report and build your impact narrative around their exact wording.
- **Avoid phishing-required framing in reports** — Many programs explicitly exclude impacts requiring phishing or social engineering attacks. If your finding requires obtaining a signature/token, frame acquisition as interception from browser storage, network logs, or cross-protocol reuse — NOT phishing. The cross-protocol angle (signature from unrelated dApp reused against target) is particularly strong because it does not require any interaction with the target users.
- **HackenProof programs page is Cloudflare-blocked** — can't access programmatically. Need user to browse manually and share target details. Platform is web3-focused with generally smaller payouts but less competition than Immunefi.
- **"Requires external conditions" is the #1 rejection reason for oracle bugs** — if the attacker can't trigger the Chainlink malfunction themselves, the finding is borderline. Frame as "theft of yield WHEN condition occurs" not "attacker causes condition."
- **Check Code4rena/Sherlock findings BEFORE writing a report** — many Immunefi programs had prior audit contests. If your finding was already reported (even as QA/Low), Immunefi will reject it as "known issue." Search `github.com/code-423n4/{year}-{month}-{protocol}-findings` and `github.com/sherlock-audit/{protocol}-judging`. Ethena's unstake blacklist bypass (valid bug) was already in C4 #707 — would have been wasted effort to submit.
- **"Valid code bug with no impact path" is not submittable** — Origin's OETHOracleRouter has an unsafe uint256() cast (negative price wraps to max), but the oracle is never called in any active fund-flow. A bug that exists in code but has no exploitable path = Informational at best. Don't waste time building PoCs for bugs with no impact.
- **Factory vs non-factory strategy versions** — Beefy (and similar protocols) often have fixed bugs in factory versions while non-factory versions remain vulnerable. The factory fix proves the team acknowledges the bug, but the non-factory may be legacy/deprecated.
- **staleness=0 on oracle means no cache** — every call hits the feed directly, making oracle bugs more impactful (no stale "good" price to fall back on)
- **harvest() is often permissionless** — anyone can call it, making sandwich attacks on harvest swaps a real vector. Check access control on harvest before dismissing MEV findings.
- **Verify harvest SWAPS on-chain before auditing oracle code** — if the harvester just calls `transfer()` to a strategist EOA (Origin, Ethena pattern) instead of swapping via DEX router, the entire oracle→slippage→sandwich attack class is dead. Check: does harvest call a router/swapper? Does it calculate minAmountOut from oracle? If no to either, pivot immediately. Don't spend 2 hours auditing oracle routers that have no active callers.
- **Modern protocols separate harvest from swap** — Origin Protocol pattern: harvester calls collectRewardTokens() → transfers raw reward tokens to strategist address → strategist swaps off-chain. No on-chain swap = no oracle dependency = no sandwich vector. Always verify the FULL harvest flow before assuming oracle→slippage pattern applies.
- **Code bug ≠ exploitable finding** — A valid code defect (e.g., unsafe cast, missing validation) with no active call path that triggers it is Informational at best on Immunefi. Before writing a report, trace the vulnerable function's callers on-chain to confirm it's actually invoked during normal operations. Origin's OETHOracleRouter has an unsafe uint256() cast but the oracle is never called in any fund-flow path (vault is single-asset, harvesters don't swap).
- **Single-asset vaults don't need oracles** — If a vault only holds one asset (e.g., OETH vault holds only WETH), mint/redeem is 1:1 and no price oracle is needed. Multi-asset vaults (old OUSD with DAI/USDC/USDT) need oracles. Check `getAllAssets()` on-chain before assuming oracle is in the critical path.
- **Scope freshness matters for exploitability** — Beefy's 60 in-scope contracts (all from May 2022) are ALL either empty (balance=0) or paused. Even a valid bug on a dead contract has zero impact. Check `paused()` and `balanceOf()` on strategies before investing time in exploit development.
- **Next.js API routes are high-value SSRF targets** — `/api/download-file/`, `/api/company-logo/`, `/api/og-image/`, `/api/proxy/` — these server-side fetch endpoints bypass client-side restrictions (CORS, Cloudflare Access). If the target uses Next.js, enumerate all `/api/` routes from JS bundles and test each with external/internal URLs. Hacken engagement: `/api/download-file/` bypassed Cloudflare Access Zero Trust on their internal portal. Detection: grep JS bundles for `fetch(`, check robots.txt for `/api/` paths, test with external URL first (webhook.site), then internal subdomains.
- **Supabase projects leak via auth CNAME** — `auth.X.domain` often CNAMEs to `<project-ref>.supabase.co`. Once you have the ref, try the anon key from JS chunks (`sb_publishable_*` or `eyJ*`). Then enumerate: `/rest/v1/` (tables), `/auth/v1/settings` (OAuth config), `/storage/v1/bucket`, RPC functions (errors leak other function names via "hint" field). RLS bypass: try INSERT on each table — `42501` error = RLS enforced, `201` = write access without auth.
- **ABP Framework portals expose API maps without auth** — `/AbpServiceProxies/GetAll` returns full JavaScript service proxy (all controllers, endpoints, parameters). `/api/services/app/Session/GetCurrentLoginInformations` returns tenant config without auth. These are standard ABP endpoints that many devs forget to lock down. Combined with SSRF → full internal platform reconnaissance.
- **SSRF + Cloudflare Access = bypass pattern** — When an app behind CF has SSRF, requests from the app server to sibling subdomains bypass CF Access (Zero Trust). CF Access trusts same-zone IPs. The WAF still blocks internal IPs (169.254.x.x, localhost) and sensitive file patterns (.env, .git), but application endpoints on protected subdomains are fully accessible. This is a common architectural flaw.
- **Don't exfiltrate data to prove SSRF impact** — The Session endpoint + API map + tenant config is sufficient proof. Extracting actual user/client/finding data crosses from PoC into data theft and risks report rejection for policy violation. If triager needs more proof, discuss with them first.
- **HackenProof has no submission rate limit** (unlike Immunefi's 1/day). Submit findings as soon as they're ready.

## References

- `references/immunefi-severity-v2.2.md` — Full severity classification with decision tree
- `references/immunefi-severity-v2.3-webapps.md` — v2.3 Websites and Apps classification (Critical includes "state-modifying actions on behalf of users")
- `references/immunefi-targets-research.md` — Target shortlist with strategy notes
- `references/defi-frontend-attack-patterns.md` — DeFi-specific web attack patterns
- `references/foundry-oracle-exploit-poc.md` — Proven Foundry fork test patterns for oracle exploits (vm.mockCall, attack chain verification, working RPCs)
- `references/beefy-engagement-lessons.md` — Full engagement retrospective: what worked, pitfalls, tempo decisions, reusable patterns
- `references/diamond-proxy-recon.md` — EIP-2535 Diamond enumeration, attack patterns, precision tables, Gains Network architecture
- `references/olympus-dao-architecture.md` — Kernel-Module-Policy pattern, security posture, remaining attack surface
- `references/immunefi-targets-v2.md` — Updated target shortlist (2026-05-25): Origin Protocol as top pick, pattern-transferability strategy, confirmed active slugs, lessons from Gains/Olympus dead ends
- `references/immunefi-targets-v3.md` — Post-exploration update: Origin/Ethena/Enzyme eliminated, prerequisite check formalized, Enzyme deep-review and Lombard/DeXe as next picks
- `references/origin-protocol-recon.md` — Full recon: 30 in-scope assets, architecture analysis, why oracle pattern doesn't apply, remaining attack surface
- `references/stakewise-engagement.md` — Successful engagement: signature replay (Critical, submitted 2026-05-26), unauth GraphQL mutation, CORS (downgraded). Recon approach, scope reframing technique, report format, severity selection lessons.
- `references/grab-ovo-engagement.md` — HackerOne Grab/OVO: config.js leak chain, LaunchDarkly flag exposure (35 flags), OVO infrastructure mapping, reusable LD exploitation pattern.
- `references/hacken-engagement.md` — HackenProof engagement: SSRF bypassing Cloudflare Access (CVSS 8.6), Supabase exposure, ABP Framework exploitation patterns, Next.js API route SSRF detection
- `references/hackenproof-platform-notes.md` — HackenProof platform differences from Immunefi, Hacken's own bounty recon (*.hacken.io), Supabase testing methodology
- `references/bug-bounty-platform-comparison.md` — Platform comparison (Immunefi vs HackerOne vs YesWeHack vs Intigriti vs Bugcrowd vs HackenProof) with strategy for n4igme's profile
- `references/grab-engagement.md` — HackerOne Grab/OVO engagement: OTP brute-force (unproven), config leaks (no impact), food.grab.com runtimeConfig, infrastructure map, lessons on hardened targets
