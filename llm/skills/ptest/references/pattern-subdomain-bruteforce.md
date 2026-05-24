# Pattern-Based Subdomain Brute-Force

When passive recon reveals a naming convention, use targeted brute-force to discover additional services that aren't publicly indexed.

## When to Use

Trigger this technique when you observe:
- Multiple subdomains following a pattern (e.g., `bravo-agent`, `bravo-bpm`, `bravo-customer`)
- Environment prefixes (e.g., `*.dev.bravo.bfi.co.id`, `*.sit.bravo.bfi.co.id`)
- Service-oriented naming (e.g., `ms-onboarding`, `ms-master`, `ms-bpm`)

## Methodology

### Step 1: Identify the Pattern

From discovered subdomains, extract the naming convention:
```
bravo-agent.mock.bravo.bfi.co.id
bravo-bpm.mock.bravo.bfi.co.id
bravo-customer.mock.bravo.bfi.co.id
```
Pattern: `bravo-{SERVICE}.mock.bravo.bfi.co.id`

### Step 2: Build a Targeted Wordlist

Sources for service names:

**From the engagement itself:**
- API paths: `/v1/surveyor-*` → `surveyor`
- Actuator health components: `jobExecutor` → `bpm`, `rabbit` → `notification`
- Actuator metrics URI tags: `/v1/operation-*` → `operation`
- K8s service names from leaked redirects: `prod-ms-onboarding` → `onboarding`
- JavaScript bundle names: `bravo-underwriting-console` → `underwriting`

**Common microservice names:**
```
# Financial services specific
account
agreement
agent
application
approval
asset
asset-pricing
audit
auth
billing
branch
bpm
calculation
card
collateral
collection
compliance
credit
customer
disbursement
document
edoc
fee
fraud
gateway
identity
insurance
integration
kyc
lead
lending
loan
master
masterdata
notification
onboarding
operation
partner
payment
payout
product
rating
reconciliation
report
risk
scoring
settlement
sharia
sms
surveyor
treasury
underwriting
user
verification
workflow
```

**Environment variations to test:**
```
# If you found bravo-{service}.mock.bravo.bfi.co.id, also try:
bravo-{service}.dev.bravo.bfi.co.id
bravo-{service}.sit.bravo.bfi.co.id
bravo-{service}.uat.bravo.bfi.co.id
bravo-{service}.prod.bravo.bfi.co.id
{service}.dev.bravo.bfi.co.id
{service}.sit.bravo.bfi.co.id
```

### Step 3: Brute-Force with ffuf

```bash
# Using ffuf for DNS brute-force
ffuf -u "https://bravo-FUZZ.mock.bravo.bfi.co.id" \
  -w wordlist.txt \
  -t 30 \
  -timeout 4 \
  -mc 200,301,302,401,403,500 \
  -o results.json \
  -of json

# Or with a simple bash script
while read -r service; do
  ip=$(dig +short "bravo-${service}.mock.bravo.bfi.co.id" 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://bravo-${service}.mock.bravo.bfi.co.id" --max-time 4 -k 2>/dev/null)
    [ "$code" != "000" ] && echo "[+] bravo-${service}.mock.bravo.bfi.co.id | ${code} | ${ip}"
  fi
done < wordlist.txt
```

### Step 4: Cross-Environment Validation

Once you find services in one environment, check if they exist in others:
```bash
SERVICES="agent agreement bpm branch calculation collateral customer document edoc masterdata notification product"
ENVS="mock.bravo dev.bravo sit.bravo uat.bravo prod.bravo"

for env in $ENVS; do
  echo "=== ${env}.bfi.co.id ==="
  for svc in $SERVICES; do
    ip=$(dig +short "bravo-${svc}.${env}.bfi.co.id" 2>/dev/null | head -1)
    [ -n "$ip" ] && echo "  [+] bravo-${svc}.${env}.bfi.co.id → ${ip}"
  done
done
```

## Why Passive Recon Misses These

| Source | What it finds | What it misses |
|--------|--------------|----------------|
| subfinder | Subdomains in public databases | Internal services never publicly indexed |
| crt.sh | Subdomains with SSL certificates | Services using wildcard certs (`*.mock.bravo.bfi.co.id`) |
| amass | Aggregated OSINT sources | Services with no public footprint |
| DNS brute-force | Anything that resolves | Nothing (if wordlist is good) |

**Key insight:** When an organization uses wildcard DNS (`*.mock.bravo.bfi.co.id → 34.101.125.217`), ALL subdomains under that pattern resolve — even ones that were never publicly referenced. Only brute-force discovers them.

## Real-World Example (BFI)

**What passive recon found:** 6 mock services (from subfinder/crt.sh)
**What pattern brute-force found:** 10+ additional services (collateral, notification, calculation, etc.)
**What we missed by not doing this:** Services with exposed actuators that revealed the complete architecture

## Environment Prefix Mutation (MANDATORY)

**Why this matters:** Passive recon often finds `service.dev.domain.com` or `service.staging.domain.com` but misses the production equivalent `service.domain.com` (no env prefix). This is the #1 cause of missed subdomains in real engagements.

**Real-world example (BFI Finance, May 2026):**
- Passive recon found: `e-pmo2.dev.bfi.co.id` → 172.22.32.94 (from crt.sh)
- Never tested: `e-pmo2.bfi.co.id` (production — no env prefix)
- Result: Production asset missed entirely from initial scope
- **Later confirmed (2026-05-22):** `e-pmo2.bfi.co.id` → 34.111.225.150 (GCP), live Apache2 with forgotten PHP app at `/rapi/` (RAPI — "Report All Project Implementation"). Classic SQLi in `build/login.php` line 11 (`mysqli->query()` with string concatenation). Error-based extraction via EXTRACTVALUE revealed **21 databases** on shared GCP Cloud SQL instance: `mysql`, `information_schema`, `performance_schema`, `sys`, `pmotools`, `room`, `vms`, `resep`, `briliance`, `momo`, `dfr`, `absen`, `dfr_new`, `pdc`, `kboard`, `core`, `actionlog`, `projo`, `boarding`, `rapi`, `pmotools2`. Includes employee PII (KTP, NPWP, bank accounts in `boarding`), employee passwords (`absen`), and customer financial data (`pmotools` — Sharia finance, loan collections). CVSS 10.0.
- **Root cause:** env-prefix mutation was not performed during Phase 1/2 — the bare domain was never tested. The quick-win check (strip `dev.` prefix, resolve bare domain) would have caught this in seconds.
- **Lesson:** This is now the canonical example of why the Env-Prefix Quick-Win Check is MANDATORY at end of Phase 1. A 5-second `dig +short e-pmo2.bfi.co.id` would have revealed the production asset.

### Mutation Rules

For EVERY subdomain discovered with an environment indicator, generate and test these mutations:

```bash
# Input: discovered subdomain with env prefix/suffix
# e-pmo2.dev.bfi.co.id → extract: service=e-pmo2, env=dev, base=bfi.co.id

# Rule 1: Strip environment prefix entirely (dev/staging/sit/uat/mock/sandbox)
# e-pmo2.dev.bfi.co.id → e-pmo2.bfi.co.id
# api.staging.example.com → api.example.com

# Rule 2: Swap environment for other environments
# e-pmo2.dev.bfi.co.id → e-pmo2.sit.bfi.co.id, e-pmo2.uat.bfi.co.id, e-pmo2.prod.bfi.co.id

# Rule 3: Strip nested env patterns
# bravo-agent.mock.bravo.bfi.co.id → bravo-agent.bfi.co.id, bravo-agent.bravo.bfi.co.id

# Rule 4: Add common prod indicators
# e-pmo2.dev.bfi.co.id → e-pmo2.prod.bfi.co.id, e-pmo2.live.bfi.co.id
```

### Automated Mutation Script

```bash
#!/bin/bash
# subdomain-mutate.sh — Generate prod equivalents from discovered subdomains
# Usage: ./subdomain-mutate.sh subdomains-merged.txt > mutations.txt

ENV_INDICATORS="dev|staging|stg|sit|uat|mock|sandbox|test|qa|preprod|pre-prod|nonprod|non-prod|demo|lab|experiment"

while read -r subdomain; do
  # Skip if no env indicator found
  echo "$subdomain" | grep -qiE "\.(${ENV_INDICATORS})\." || continue
  
  base_domain=$(echo "$subdomain" | rev | cut -d. -f1-2 | rev)  # e.g., bfi.co.id → adjust for TLD
  
  # Rule 1: Strip env segment
  stripped=$(echo "$subdomain" | sed -E "s/\.(${ENV_INDICATORS})\././" | sed -E "s/\.(${ENV_INDICATORS})\././")
  echo "$stripped"
  
  # Rule 2: Swap env for each alternative
  for env in dev sit uat prod staging mock preprod live; do
    swapped=$(echo "$subdomain" | sed -E "s/\.(${ENV_INDICATORS})\./.${env}./")
    [ "$swapped" != "$subdomain" ] && echo "$swapped"
  done
done < "$1" | sort -u
```

### Using altdns / gotator for Permutation

```bash
# Install
go install github.com/infosec-au/altdns@latest
pip3 install py-altdns
go install github.com/Josue87/gotator@latest

# altdns — permutation-based subdomain discovery
# Uses a words file to generate permutations of known subdomains
altdns -i subdomains-merged.txt -o permutations.txt -w /opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsx -l permutations.txt -silent -o resolved-permutations.txt

# gotator — more intelligent permutation (prefix, suffix, split-join)
gotator -sub subdomains-merged.txt -perm /opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -depth 1 -numbers 3 -md | \
  dnsx -silent -o gotator-resolved.txt

# Custom env-stripping wordlist (create this per engagement)
cat > env-mutations.txt << 'EOF'
prod
live
app
www
api
internal
private
public
EOF
```

### Validation Script

```bash
#!/bin/bash
# validate-mutations.sh — Resolve and HTTP-probe mutated subdomains
# Usage: ./validate-mutations.sh mutations.txt

while read -r domain; do
  ip=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]' | head -1)
  if [ -n "$ip" ]; then
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://${domain}" --max-time 5 2>/dev/null)
    echo "[+] ${domain} → ${ip} [HTTP ${code}]"
  fi
done < "$1"
```

### Phase 2 Integration (MANDATORY)

This technique is **MANDATORY** in Phase 2 (Active DNS Expansion). The checklist item is:

```
- [ ] Active DNS Expansion — Pattern Permutation (MANDATORY)
  - [ ] Extract all env-prefixed subdomains from Phase 1 results
  - [ ] Generate mutations (strip env, swap env, add prod indicators)
  - [ ] Resolve all mutations with dnsx
  - [ ] HTTP-probe resolved mutations
  - [ ] Add new discoveries to master subdomain list
  - [ ] Run altdns/gotator for broader permutation coverage
```

**Exit criteria:** Cannot pass Phase 2 gateway without documenting that environment prefix mutation was performed on ALL discovered subdomains containing env indicators.

---

## Integration with Other Techniques

After discovering new services via brute-force:
1. **Immediately run bulk actuator scan** on all new hosts
2. **Check for JS files** and scan for secrets
3. **Test API endpoints** for auth bypass
4. **Add to attack surface inventory** with priority scoring

## Lesson Learned

> "Passive recon finds what's been publicly exposed. Pattern brute-force finds what
> the organization thought was hidden. When you see a naming convention, exploit it —
> the organization likely has 3x more services than what's publicly indexed."

> "If you find `service.dev.domain.com`, ALWAYS test `service.domain.com`. The dev
> instance got a certificate (showing up in CT logs), but production uses a wildcard
> cert and was never publicly indexed. This is the most common blind spot in subdomain
> enumeration."
