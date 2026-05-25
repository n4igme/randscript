# StakeWise Engagement — Successful Patterns (2026-05-25)

## Target
- Program: StakeWise Mainnet (Immunefi)
- Payout: Critical $200K flat, High $50K flat
- Web scope: https://app.stakewise.io/
- 14 smart contracts on Ethereum mainnet

## Findings (3x High confirmed)

### Finding 1: CORS Origin Reflection + Credentials (High — CVSS 8.2)
**Pattern:** GraphQL API reflects arbitrary Origin with `Access-Control-Allow-Credentials: true`
**Endpoints:** mainnet-api.stakewise.io/graphql, gnosis-api.stakewise.io/graphql, hoodi-api.stakewise.io/graphql
**Impact:** Cross-origin authenticated data theft (email PII via `profile(account)` query, vault internal flags, OFAC list, MEV data)
**Detection method:** Simple curl with `-H "Origin: https://evil.com"` checking response headers
**Report:** `FINAL-immunefi-cors.md`

### Finding 2: Unauthenticated GraphQL Mutation (High — CVSS 7.5-8.6)
**Pattern:** `uploadMetadata` mutation requires no auth, no rate limit, supports alias batching (5+ per request)
**Impact:** Arbitrary IPFS upload at StakeWise's cost, malicious content hosting, XSS payload storage, phishing infrastructure
**Detection method:** GraphQL introspection → identify mutations → test without auth headers
**Report:** `FINAL-immunefi-upload.md`

### Finding 3: Signature Replay + No Expiry + Unbound Email (High — CVSS 7.1)
**Pattern:** `updateProfile` mutation validates EIP-191 signature but has three critical gaps:
1. No timestamp expiry — signatures from 2020 still accepted
2. No replay protection — same signature reusable unlimited times
3. Email not bound to signature — one signature can set ANY email
**Impact:** Single intercepted signature = permanent irrevocable profile takeover. Attacker can set any email, unlimited times, forever. Victim cannot revoke access without protocol deploying a fix.
**Detection method:** Tested `updateProfile` with old timestamps (2020) → accepted. Replayed same sig with different email → accepted. Confirmed email not in signed payload.
**Key insight:** The mutation DOES validate crypto signature (wrong signer rejected), but fails on temporal/replay/binding checks. This is a common pattern in DeFi — devs implement EIP-191 verification but skip the session management that makes it secure. Compare against EIP-4361 (SIWE) which mandates domain, nonce, expiration, and statement binding.
**Report:** `FINAL-immunefi-signature.md`

### Signature Validation Testing Checklist (reusable pattern)
When a DeFi mutation requires wallet signature, test these in order:
1. **Expiry:** Sign with timestamp from years ago → does it still work?
2. **Replay:** Use same signature twice with different action params → both succeed?
3. **Binding:** Is the action parameter (email, amount, recipient) included in the signed message? Or is it a separate unbound field?
4. **Format strictness:** Does the message require exact format, or just "contains Timestamp:"?
5. **Future timestamps:** Sign with timestamp far in the future → accepted?
6. **Cross-protocol reuse:** Could a signature from another dApp (that happens to match the loose format) be replayed here?
If ANY of checks 1-3 fail → High severity finding. All three failing together = permanent irrevocable access (victim cannot self-remediate).

## Recon Approach (what worked)

### High-ROI techniques (in order of value):
1. **Subdomain enumeration** → found admin panels, staging envs, direct IPs
2. **CORS header check on ALL API endpoints** → immediate finding
3. **GraphQL introspection** → full schema dump → mutation testing
4. **GitHub org repos** → 41 repos, clean (no secrets) but revealed architecture

### Tech stack indicators:
- Next.js on Vercel + Cloudflare (frontend)
- GraphQL (Strawberry/Python) on Caddy reverse proxy (backend)
- OVH for backend infra (not behind Cloudflare!)
- The Graph subgraphs (publicly accessible)
- Sentry, Grafana, Loki, Prometheus for monitoring

### What the recon revealed that led to findings:
- **8 direct IPs** on OVH (not behind CDN) — Prometheus exporters exposed
- **4 admin panels** (admin, gnosis-admin, hoodi-admin, mainnet-admin) — 403/525
- **Staging environments** (stage, stage-app, prerelease)
- **Weak CSP** — only `frame-ancestors`, no script-src
- **Wide-open CORS** — the actual finding

## Key Lessons

### CORS testing on DeFi APIs is HIGH ROI
- DeFi APIs often have permissive CORS because "the data is public anyway" (blockchain)
- But when combined with `credentials: true`, it enables authenticated query theft
- The profile query exposing email is the key — transforms "public data" into PII theft
- **Always test:** `curl -sI -H "Origin: https://evil.com" <endpoint> | grep access-control`

### GraphQL is a goldmine on DeFi platforms
- Introspection almost always enabled (devs leave it on for "developer experience")
- Mutations are the target — queries are usually public data
- Test mutations without auth FIRST (fastest path to finding)
- Alias batching (`{ a: mutation(...) b: mutation(...) }`) amplifies any unauth mutation
- Array batching (`[{query:...},{query:...}]`) is often disabled but alias batching isn't

### Parallel recon with delegate_task is the right approach
- Task 1: Scope verification (Immunefi program details)
- Task 2: Passive recon (subdomains, headers, tech stack, GitHub)
- Task 3: Active testing (GraphQL, CORS, auth bypass)
- Total time: ~10 minutes wall clock for full recon + confirmed findings

### StakeWise-specific architecture notes
- WalletConnect Project ID: `61433d35f9a6daeedebe9fa03ca41b51`
- Cloudflare Turnstile key: `0x4AAAAAABAmnH4ivAPI-3rL`
- Feature flags reveal emergency disable capabilities
- `updateProfile` requires ETH signature but has no expiry/replay/binding (Finding 3)
- Subscriptions disabled, array batching disabled
- OFAC sanctioned addresses list publicly queryable (88 addresses)

## Report Format Used (Immunefi)
```
Title: [High] CORS Origin Reflection with Credentials on GraphQL APIs

## Bug Description
## Affected Endpoints  
## Impact
## Severity (with CVSS)
## Proof of Concept (curl commands + PoC HTML)
## Remediation
## References
```

## Files
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/findings/FINAL-immunefi-cors.md` — CORS report (CVSS 8.2)
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/findings/FINAL-immunefi-upload.md` — Upload report (CVSS 7.5-8.6)
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/findings/FINAL-immunefi-signature.md` — Signature report (CVSS 7.1)
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/findings/cors-poc.html` — CORS exploitation PoC
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/findings/api-signature-testing.md` — Raw testing notes
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/scope.md`
- `/Users/nb-dk-0552/PenTest/Hunting/Web3/StakeWise/recon/` (full recon data)
