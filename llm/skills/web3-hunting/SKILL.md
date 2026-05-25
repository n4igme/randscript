---
name: web3-hunting
version: 1.2.0
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
1. **CORS on ALL API subdomains** — `curl -sI -H "Origin: https://evil.com" https://api.{domain}/ | grep -i access-control` — if origin reflected + credentials=true → HIGH finding immediately. Test mainnet-api, gnosis-api, etc. separately. (StakeWise: 2x High from this alone)
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

```
Title: [Severity] Short description

## Bug Description
What the vulnerability is, where it exists.

## Impact
What an attacker can achieve. Map to program's "Impacts in Scope" table.

## Risk Breakdown
Difficulty: {Easy/Medium/Hard}
CVSS: {vector string}

## Recommendation
How to fix (REQUIRED by most programs).

## Proof of Concept
Step-by-step reproduction with code/scripts.
```

## Pitfalls

- **Cloudflare blocks automated browsing** — Immunefi uses aggressive bot detection. Manual scope verification may be needed. Use combobox interaction (click dropdown → select option) not button clicks for scope category switching.
- **PoC required for ALL web/app bugs** — don't submit without working PoC
- **Fix suggestion required** — many programs reject without remediation advice
- **Primacy of Rules — ASSET SCOPE IS STRICTLY ENFORCED** — if the vulnerable contract is not explicitly listed in the program's "Assets in Scope" section, the report WILL be rejected regardless of impact validity. Immunefi triagers check asset scope BEFORE forwarding to the project. Our Beefy SC-1 (valid zero-price oracle bug with working PoC) was rejected because BeefyOracleChainlink/BeefySwapper weren't in the 2022 asset list. The project never even saw the report. **Pre-submission checklist:** (1) Is the vulnerable contract address in the scope list? (2) If not, is it directly called by an in-scope contract during normal operation? (3) If neither, DO NOT SUBMIT — find an in-scope contract that triggers the same vulnerable code path and use THAT as the primary asset.
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
- **CORS on DeFi APIs is commonly misconfigured** — devs think "blockchain data is public anyway" so they set permissive CORS. But when combined with `Access-Control-Allow-Credentials: true` + origin reflection, it enables authenticated query theft. The key is finding a query that returns PII (email, phone) or session-specific data. Always test ALL API subdomains separately (mainnet-api, gnosis-api, etc.) — they often share the same misconfigured Caddy/nginx config.
- **Parallel recon with delegate_task is optimal for web3** — spawn 2-3 sub-agents: (1) scope verification, (2) passive recon (subdomains/headers/GitHub), (3) active testing (GraphQL/CORS/auth). Total wall-clock time ~10 min for full recon + confirmed findings.
- **Proxy endpoints (1inch/Kyber/etc) are rarely SSRF-able** — chain validation is strict (whitelist), baseURLs hardcoded, API keys redacted from errors. Test but don't spend hours.
- **"Requires external conditions" is the #1 rejection reason for oracle bugs** — if the attacker can't trigger the Chainlink malfunction themselves, the finding is borderline. Frame as "theft of yield WHEN condition occurs" not "attacker causes condition."
- **Check Code4rena/Sherlock findings BEFORE writing a report** — many Immunefi programs had prior audit contests. If your finding was already reported (even as QA/Low), Immunefi will reject it as "known issue." Search `github.com/code-423n4/{year}-{month}-{protocol}-findings` and `github.com/sherlock-audit/{protocol}-judging`. Ethena's unstake blacklist bypass (valid bug) was already in C4 #707 — would have been wasted effort to submit.
- **"Valid code bug with no impact path" is not submittable** — Origin's OETHOracleRouter has an unsafe uint256() cast (negative price wraps to max), but the oracle is never called in any active fund-flow. A bug that exists in code but has no exploitable path = Informational at best. Don't waste time building PoCs for bugs with no impact.
- **Factory vs non-factory strategy versions** — Beefy (and similar protocols) often have fixed bugs in factory versions while non-factory versions remain vulnerable. The factory fix proves the team acknowledges the bug, but the non-factory may be legacy/deprecated.
- **Factory vs non-factory strategy versions** — Beefy (and similar protocols) often have fixed bugs in factory versions while non-factory versions remain vulnerable. The factory fix proves the team acknowledges the bug, but the non-factory may be legacy/deprecated.
- **staleness=0 on oracle means no cache** — every call hits the feed directly, making oracle bugs more impactful (no stale "good" price to fall back on)
- **harvest() is often permissionless** — anyone can call it, making sandwich attacks on harvest swaps a real vector. Check access control on harvest before dismissing MEV findings.
- **Verify harvest SWAPS on-chain before auditing oracle code** — if the harvester just calls `transfer()` to a strategist EOA (Origin, Ethena pattern) instead of swapping via DEX router, the entire oracle→slippage→sandwich attack class is dead. Check: does harvest call a router/swapper? Does it calculate minAmountOut from oracle? If no to either, pivot immediately. Don't spend 2 hours auditing oracle routers that have no active callers.
- **Modern protocols separate harvest from swap** — Origin Protocol pattern: harvester calls collectRewardTokens() → transfers raw reward tokens to strategist address → strategist swaps off-chain. No on-chain swap = no oracle dependency = no sandwich vector. Always verify the FULL harvest flow before assuming oracle→slippage pattern applies.
- **Code bug ≠ exploitable finding** — A valid code defect (e.g., unsafe cast, missing validation) with no active call path that triggers it is Informational at best on Immunefi. Before writing a report, trace the vulnerable function's callers on-chain to confirm it's actually invoked during normal operations. Origin's OETHOracleRouter has an unsafe uint256() cast but the oracle is never called in any fund-flow path (vault is single-asset, harvesters don't swap).
- **Single-asset vaults don't need oracles** — If a vault only holds one asset (e.g., OETH vault holds only WETH), mint/redeem is 1:1 and no price oracle is needed. Multi-asset vaults (old OUSD with DAI/USDC/USDT) need oracles. Check `getAllAssets()` on-chain before assuming oracle is in the critical path.
- **Scope freshness matters for exploitability** — Beefy's 60 in-scope contracts (all from May 2022) are ALL either empty (balance=0) or paused. Even a valid bug on a dead contract has zero impact. Check `paused()` and `balanceOf()` on strategies before investing time in exploit development.

## References

- `references/immunefi-severity-v2.2.md` — Full severity classification with decision tree
- `references/immunefi-targets-research.md` — Target shortlist with strategy notes
- `references/defi-frontend-attack-patterns.md` — DeFi-specific web attack patterns
- `references/foundry-oracle-exploit-poc.md` — Proven Foundry fork test patterns for oracle exploits (vm.mockCall, attack chain verification, working RPCs)
- `references/beefy-engagement-lessons.md` — Full engagement retrospective: what worked, pitfalls, tempo decisions, reusable patterns
- `references/diamond-proxy-recon.md` — EIP-2535 Diamond enumeration, attack patterns, precision tables, Gains Network architecture
- `references/olympus-dao-architecture.md` — Kernel-Module-Policy pattern, security posture, remaining attack surface
- `references/immunefi-targets-v2.md` — Updated target shortlist (2026-05-25): Origin Protocol as top pick, pattern-transferability strategy, confirmed active slugs, lessons from Gains/Olympus dead ends
- `references/immunefi-targets-v3.md` — Post-exploration update: Origin/Ethena/Enzyme eliminated, prerequisite check formalized, Enzyme deep-review and Lombard/DeXe as next picks
- `references/origin-protocol-recon.md` — Full recon: 30 in-scope assets, architecture analysis, why oracle pattern doesn't apply, remaining attack surface
- `references/stakewise-engagement.md` — Successful engagement: 2x High findings (CORS + unauth GraphQL mutation), recon approach, report format, lessons learned
