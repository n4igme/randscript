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
