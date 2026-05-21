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

### 7. Cluster Management API (Dynatrace Managed specific)

```bash
# Cluster-level API (no environment ID needed)
curl -sk "https://target/api/cluster/v2/environments"
# 401 "Missing authorization parameter" → API exists, needs cluster token
# 404 → not exposed or not Dynatrace Managed

# With token format test
curl -sk -H "Authorization: Api-Token test" "https://target/api/cluster/v2/environments"
# 401 "Token Authentication failed" → confirms token format accepted, validates tokens
# This is DIFFERENT from "Missing authorization parameter" — proves the auth pipeline works

# Other cluster endpoints to probe
/api/cluster/v2/environments    # List all environments (401 = exists)
/api/cluster/v2/nodes           # Cluster nodes
/api/cluster/v2/users           # User management
/api/cluster/v1/installer       # Agent installer management
```

**Key insight:** The cluster API uses a DIFFERENT auth token than per-environment APIs. A cluster API token grants god-mode access to ALL environments on the cluster. Sources for cluster tokens:
- CI/CD pipelines (Terraform, Ansible provisioning Dynatrace)
- Heapdumps of services that auto-register with Dynatrace
- Environment variables in container orchestrators
- `.dynatrace/` config files in developer machines

### 8. Health Endpoints (Unauthenticated)

```bash
# These typically work without auth on Dynatrace Managed
curl -sk "https://target/rest/health"           # → "RUNNING"
curl -sk "https://target/e/{ENV_ID}/rest/health" # → "RUNNING" (confirms env ID valid)
```

Use `/e/{ENV_ID}/rest/health` to validate discovered environment IDs without needing a token.

## Real-World Example (Bank Jago)

- `monitoring.jago.com` — Dynatrace Managed, NO IAP, Google-managed cert (WR3)
- All `*-data.jago.com` hosts — IAP-protected (GCP project 1022863786872)
- SAML IdP: Google Workspace (idpid=C02tekxn2)
- CMC exists at `/cmc/` (redirects to login)
- Environment ID: `AP9AYQB1TNV5` (confirmed via `/e/AP9AYQB1TNV5/rest/health` → "RUNNING")
- Cluster API: `/api/cluster/v2/environments` returns 401 "Missing authorization parameter" (exposed!)
- With token: "Token Authentication failed" (validates token format, confirms auth pipeline)
- Response headers: `dynatrace-response-source: Cluster`, `dynatrace-response-id: R5RNQ4NWKIQ9`
- Finding: HIGH — cluster management API internet-facing, only token auth protects full cluster control
