# Dynatrace Managed Cluster Probing

Systematic approach for assessing internet-facing Dynatrace Managed instances.

## Identification

- `dynatrace-response-source: Cluster` header (vs `Server` for SaaS)
- `dynatrace-response-id: XXXXXXXXXX` header (request ID, NOT environment ID)
- Login page title: "Login - Dynatrace" or "Error Unsupported browser"
- Self-signed cert: CN=Dynatrace, O=Dynatrace, OU=Dynatrace

## Probe Sequence

### 1. Login Page — SAML Information Extraction

```bash
# Extract SAML request from login page
curl -sk "https://target/login" | grep -o 'name="SAMLRequest" value="[^"]*"' | cut -d'"' -f4 | base64 -d
```

**What leaks from SAML AuthnRequest:**
- `AssertionConsumerServiceURL` — confirms the service URL
- `Destination` — IdP URL with customer ID (e.g., `idpid=C02tekxn2`)
- `Issuer` — SP entity ID (the Dynatrace URL)
- `X509Certificate` — signing cert (CN, O, OU, validity dates)
- `SignatureMethod` — crypto algorithm used

### 2. CMC (Cluster Management Console)

```bash
curl -sk "https://target/cmc/" -w "%{http_code}"
# 302 → /login = CMC exists, auth required
# 404 = CMC disabled or not exposed
# 200 = CMC accessible (critical finding!)
```

CMC API endpoints (all require auth):
```
/cmc/api/v1.0/onpremise/cluster
/cmc/rest/v1/cluster/configuration
```

### 3. Environment ID Discovery

Environment IDs are needed to access per-environment APIs. Discovery methods:

```bash
# Error pages may leak env ID in "Ref. ID: JS-2-{ENV_ID}" format
curl -sk "https://target/e/test123/" | grep -i "ref"

# Try known env IDs from other findings
curl -sk "https://target/e/{KNOWN_ID}/api/v1/time"

# Response codes:
# 200 (login page) = env ID format accepted (doesn't confirm it exists)
# 404 "failed to resolve tenant" = env ID doesn't exist on this cluster
```

**Note:** The `dynatrace-response-id` header is a REQUEST ID, not an environment ID. Don't confuse them.

### 4. API Endpoints (per-environment)

```bash
# These require env ID + API token
/e/{ENV_ID}/api/v2/entities          # All monitored entities
/e/{ENV_ID}/api/v2/securityProblems  # Security vulnerabilities
/e/{ENV_ID}/api/v1/time             # Server time (auth check)
/e/{ENV_ID}/rest/v2/entities        # Alternative API path
```

Without env ID, try cluster-level:
```bash
/rest/v2/entities        # Returns "failed to resolve tenant <monitoring>"
/rest/v2/version         # May return version without auth
/api/v1/time            # Same tenant resolution error
```

### 5. SSO Metadata

```bash
curl -sk "https://target/sso/saml2/metadata"
# Usually redirects to login (no unauthenticated metadata)
```

### 6. Port Scan

Dynatrace Managed typically only exposes 80/443. Additional ports to check:
- 8021 (ActiveGate communication)
- 8443 (alternative HTTPS)
- 9999 (cluster communication)
- 9090 (metrics)

## Findings Classification

| Finding | Severity | Condition |
|---------|----------|-----------|
| CMC accessible without auth | Critical | /cmc/ returns 200 with data |
| API accessible without token | High | /e/{id}/api/v2/entities returns data |
| Login page exposed without IAP | Medium | Internet-facing, only SAML protects it |
| SAML info disclosure | Low | IdP ID, cert details, issuer leaked |
| Cluster exists (headers only) | Info | dynatrace-response-source: Cluster |

## Defense-in-Depth Assessment

Compare Dynatrace protection vs other internal tools:

| Protection Layer | Expected | Finding |
|-----------------|----------|---------|
| Cloudflare proxy | Yes/No | Check cf-proxied tag |
| Google IAP | Yes | If missing = gap (other tools have it) |
| SAML SSO | Yes | Minimum auth layer |
| API token | Yes | For programmatic access |

**Key finding pattern:** When data platform tools (airflow, grafana, argocd) are IAP-protected but monitoring (Dynatrace) is NOT, this is a defense-in-depth gap. A compromised Google Workspace account bypasses the only auth layer on Dynatrace, while IAP-protected tools would still block unauthorized access.

## Real-World Example (Bank Jago)

- `monitoring.jago.com` (34.49.98.168) — Dynatrace Managed, NO IAP
- All `*-data.jago.com` hosts — IAP-protected (GCP project 1022863786872)
- SAML IdP: Google Workspace (idpid=C02tekxn2)
- CMC exists at `/cmc/` (redirects to login)
- Environment ID unknown — `AP9AYQB1TNV5` (from other instance) doesn't resolve here
- Finding: Medium — internet-facing without IAP, defense-in-depth gap vs data platform tools
