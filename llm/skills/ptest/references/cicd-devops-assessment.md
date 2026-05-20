# CI/CD & DevOps Tool Assessment Reference

## Priority Scoring System

| Priority | Condition | Score |
|----------|-----------|-------|
| P0 - Critical | Exposed without authentication | 10 |
| P1 - High | Exposed with default/weak credentials | 8 |
| P2 - Medium | Exposed with auth but has known CVEs | 6 |
| P3 - Low | Behind IAP/VPN but misconfigured | 4 |
| P4 - Info | Behind IAP/VPN, properly configured | 2 |
| P5 - Unreachable | Cannot connect (Aiven/private network) | 1 |

---

## Discovery Checklist

### Common Subdomains to Enumerate

```
argocd.{domain}, argo.{domain}, cd.{domain}
atlantis.{domain}, deploy.{domain}
airflow.{domain}, dag.{domain}, workflow.{domain}
n8n.{domain}, automation.{domain}, workflow.{domain}
jenkins.{domain}, ci.{domain}, build.{domain}
gitlab.{domain}, git.{domain}, code.{domain}
vault.{domain}, secrets.{domain}
consul.{domain}, service.{domain}
grafana.{domain}, monitoring.{domain}, dashboard.{domain}
prometheus.{domain}, metrics.{domain}, prom.{domain}
```

### Default Ports & Key Paths

#### ArgoCD
- **Ports:** 443 (HTTPS), 8080 (API server), 8083 (metrics)
- **Key Paths:**
  - `/` — Web UI login
  - `/api/v1/session` — Auth endpoint
  - `/api/v1/applications` — List apps (requires auth)
  - `/api/v1/clusters` — Cluster info
  - `/api/v1/repositories` — Repo connections
  - `/api/version` — Version disclosure (often unauth)
  - `/metrics` — Prometheus metrics (may leak info)

#### Atlantis
- **Ports:** 4141 (default)
- **Key Paths:**
  - `/` — Web UI (shows plan/apply history)
  - `/events` — Webhook receiver
  - `/healthz` — Health check
  - `/locks` — Active locks on repos
  - `/jobs/{id}` — Job output (may contain secrets)

#### Airflow
- **Ports:** 8080 (webserver), 5555 (Flower/Celery), 8793 (worker logs)
- **Key Paths:**
  - `/` — Web UI
  - `/api/v1/dags` — List DAGs
  - `/api/v1/connections` — Connection strings (secrets!)
  - `/api/v1/variables` — Variables (may contain secrets)
  - `/api/v1/config` — Airflow config
  - `/admin/` — Legacy admin interface
  - `/health` — Health endpoint

#### n8n
- **Ports:** 5678 (default)
- **Key Paths:**
  - `/` — Web UI / Editor
  - `/healthz` — Health check (often unauth)
  - `/rest/workflows` — List workflows
  - `/rest/credentials` — Stored credentials
  - `/rest/executions` — Execution history
  - `/rest/settings` — Instance settings
  - `/webhook/` — Webhook triggers (user-defined)
  - `/webhook-test/` — Test webhook endpoints

#### Jenkins
- **Ports:** 8080 (HTTP), 8443 (HTTPS), 50000 (agent)
- **Key Paths:**
  - `/` — Dashboard
  - `/script` — Script Console (Groovy RCE)
  - `/api/json` — API root
  - `/credentials/` — Credential store
  - `/env` — Environment variables
  - `/systemInfo` — System information
  - `/asynchPeople/` — User enumeration
  - `/occ/` — Overall/Read without auth check (older versions)

#### GitLab
- **Ports:** 80/443 (web), 22 (SSH), 5050 (registry)
- **Key Paths:**
  - `/explore` — Public projects
  - `/api/v4/projects` — Project listing
  - `/api/v4/users` — User enumeration
  - `/-/graphql-explorer` — GraphQL explorer
  - `/admin` — Admin panel
  - `/-/health` — Health check
  - `/-/readiness` — Readiness probe
  - `/users/sign_in` — Login page (version in source)

#### Vault
- **Ports:** 8200 (HTTP/HTTPS)
- **Key Paths:**
  - `/v1/sys/health` — Health (unauth, reveals init/seal status)
  - `/v1/sys/seal-status` — Seal status
  - `/v1/sys/init` — Init status
  - `/v1/secret/` — KV secrets engine
  - `/v1/auth/token/lookup-self` — Token info
  - `/ui/` — Web UI

#### Consul
- **Ports:** 8500 (HTTP), 8501 (HTTPS), 8600 (DNS)
- **Key Paths:**
  - `/v1/catalog/services` — All services (often unauth)
  - `/v1/catalog/nodes` — All nodes
  - `/v1/kv/` — Key-value store (may contain secrets)
  - `/v1/agent/members` — Cluster members
  - `/v1/acl/tokens` — ACL tokens (if no ACL)
  - `/ui/` — Web UI

#### Grafana
- **Ports:** 3000 (default), 443 (reverse proxy)
- **Key Paths:**
  - `/login` — Login page
  - `/api/datasources` — Data source configs (creds!)
  - `/api/dashboards/search` — Dashboard listing
  - `/api/org` — Organization info
  - `/api/admin/stats` — Admin stats
  - `/api/snapshots` — Public snapshots
  - `/public/dashboards/` — Public dashboards
  - `/metrics` — Internal metrics

#### Prometheus
- **Ports:** 9090 (default), 9093 (Alertmanager)
- **Key Paths:**
  - `/` — Expression browser
  - `/api/v1/targets` — Scrape targets (infra map!)
  - `/api/v1/label/__name__/values` — All metric names
  - `/api/v1/status/config` — Running config
  - `/api/v1/status/flags` — CLI flags
  - `/api/v1/alerts` — Active alerts
  - `/-/healthy` — Health check
  - `/config` — Config (may show secrets in scrape configs)

---

## Per-Tool Assessment

### ArgoCD

**Default Credentials:**
- `admin` / auto-generated (stored in `argocd-initial-admin-secret` k8s secret)
- Older versions: `admin` / `password`

**Unauthenticated Endpoints:**
- `/api/version` — Version info disclosure
- `/metrics` — Prometheus metrics (if not restricted)
- OIDC/Dex endpoints may leak config

**RCE Vectors:**
- CVE-2022-24348: Path traversal → read Helm values from other apps
- CVE-2024-31989: Unprivileged pod → Redis → admin token
- Malicious Helm charts with hooks
- ApplicationSet template injection
- Git repo poisoning (if repo access compromised)

**Secret Extraction:**
- `/api/v1/repositories` — Repo credentials
- `/api/v1/clusters` — Cluster service account tokens
- `/api/v1/gpgkeys` — GPG keys
- Kubernetes secrets in argocd namespace
- Redis cache may contain decrypted secrets

---

### Atlantis

**Default Credentials:**
- No default auth (relies on network restriction or basic auth)
- Webhook secret in config

**Unauthenticated Endpoints:**
- `/` — Full web UI if no auth configured
- `/locks` — Shows active repos/workspaces
- `/jobs/{id}` — Plan/apply output (contains secrets in TF state)

**RCE Vectors:**
- Terraform plan with external data source → command execution
- Malicious PR with custom `atlantis.yaml` → override server-side config
- `pre_workflow_hooks` / `post_workflow_hooks` injection
- Provider plugin execution during plan

**Secret Extraction:**
- Job output contains terraform plan (state secrets)
- Environment variables (cloud credentials)
- `.terraform/` directory contents
- Atlantis server config (repo allowlist, tokens)

---

### Airflow

**Default Credentials:**
- `airflow` / `airflow` (default in docker-compose setup)
- `admin` / `admin` (some deployments)

**Unauthenticated Endpoints:**
- `/health` — Health status
- `/api/v1/` — API may be unauth if `auth_backend = airflow.api.auth.backend.default`
- Flower UI on :5555 (Celery monitoring, often unauth)

**RCE Vectors:**
- DAG file injection (if DAG folder writable)
- Variable/Connection injection → DAG reads and executes
- CVE-2022-40127: Example DAGs enabled → RCE via `example_bash_operator`
- CVE-2020-11978: Example DAG command injection
- Celery broker (Redis/RabbitMQ) message injection

**Secret Extraction:**
- `/api/v1/connections` — Database passwords, API keys
- `/api/v1/variables` — Stored variables
- `/api/v1/config` — Full config including `fernet_key`
- With `fernet_key` → decrypt all connection passwords
- Worker logs may contain secrets from task execution

---

### n8n

**Default Credentials:**
- Owner account created on first setup (no hardcoded default)
- If `N8N_BASIC_AUTH_ACTIVE=true`: check for `n8n` / `n8n`

**Unauthenticated Endpoints:**
- `/healthz` — Health check (always accessible)
- `/webhook/*` — User-defined webhook triggers (by design)
- `/webhook-test/*` — Test webhooks (active during editing)
- `/rest/settings` — May expose version and config

**RCE Vectors:**
- Code node (JavaScript/Python execution by design)
- Execute Command node
- SSH node
- Webhook → trigger workflow with command execution nodes
- SSRF via HTTP Request node (internal network scanning)

**Secret Extraction:**
- `/rest/credentials` — All stored credentials (encrypted)
- Workflow definitions contain hardcoded secrets
- Execution data contains API responses with tokens
- Database contains encryption key and all creds
- Environment variables via Code node

---

### Jenkins

**Default Credentials:**
- Initial admin password in `/var/jenkins_home/secrets/initialAdminPassword`
- `admin` / `admin` (lazy setups)
- Anonymous read access (common misconfiguration)

**Unauthenticated Endpoints:**
- `/api/json` — If anonymous access enabled
- `/asynchPeople/` — User enumeration
- `/occ/` — Overall read (CVE-2018-1000861)
- `/securityRealm/user/admin/search/index?q=` — User search

**RCE Vectors:**
- `/script` — Groovy Script Console (instant RCE)
  ```groovy
  "whoami".execute().text
  ```
- Pipeline SCM with malicious Jenkinsfile
- CVE-2024-23897: Arbitrary file read via CLI
- CVE-2019-1003000: Sandbox bypass in Pipeline
- Build parameter injection
- Shared library poisoning

**Secret Extraction:**
- `/credentials/` — Credential store (masked but extractable)
- Script console: `com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(...)`
- `/env` — Environment variables
- Build logs contain secrets
- `credentials.xml` and `secrets/` directory

---

### GitLab

**Default Credentials:**
- `root` / auto-generated (shown on first login)
- Registration often open by default

**Unauthenticated Endpoints:**
- `/explore` — Public projects/snippets/groups
- `/api/v4/projects?visibility=public` — Public project API
- `/-/health`, `/-/readiness`, `/-/liveness` — Health checks
- `/users/sign_in` — Version in page source

**RCE Vectors:**
- CVE-2021-22205: Exiftool RCE (unauthenticated!)
- CVE-2023-7028: Password reset account takeover
- CI/CD pipeline with malicious `.gitlab-ci.yml`
- Import project from URL → SSRF
- Webhook SSRF to internal services

**Secret Extraction:**
- CI/CD variables (project/group/instance level)
- Runner tokens
- Personal access tokens in user settings
- Repository secrets in commit history
- Container registry credentials

---

### Vault

**Default Credentials:**
- Root token generated at init (no default)
- Dev mode: root token is `root` or specified at startup

**Unauthenticated Endpoints:**
- `/v1/sys/health` — Init/seal/standby status
- `/v1/sys/seal-status` — Seal status details
- `/v1/sys/init` — Whether vault is initialized
- `/v1/sys/leader` — Leader info in HA setup

**RCE Vectors:**
- Not directly applicable (secrets engine, not compute)
- SSH secrets engine → signed keys for target hosts
- PKI engine → forge certificates
- Database engine → generate DB credentials
- Compromised token → lateral movement everywhere

**Secret Extraction:**
- `/v1/secret/data/*` — KV secrets (with valid token)
- `/v1/sys/raw/` — Raw storage access (root only)
- Transit engine → decrypt data
- Token with broad policy → enumerate all secrets
- Audit log may contain request/response bodies

---

### Consul

**Default Credentials:**
- No auth by default (ACL disabled)
- Bootstrap token if ACL enabled

**Unauthenticated Endpoints (ACL disabled):**
- `/v1/catalog/services` — All registered services
- `/v1/catalog/nodes` — All nodes with IPs
- `/v1/kv/?recurse` — Entire KV store
- `/v1/agent/members` — Cluster membership
- `/v1/agent/self` — Agent config (may have tokens)
- `/v1/connect/ca/roots` — CA certificates

**RCE Vectors:**
- Service registration → DNS poisoning
- Exec API (if enabled): `/v1/agent/exec`
- Script checks (if `enable_script_checks = true`)
- Connect/Envoy sidecar injection
- KV store poisoning (if apps read config from Consul)

**Secret Extraction:**
- `/v1/kv/` — Application secrets stored in KV
- `/v1/acl/tokens` — All ACL tokens (if no ACL)
- `/v1/agent/self` — Agent token in config
- Connect CA private keys
- Prepared queries may contain tokens

---

### Grafana

**Default Credentials:**
- `admin` / `admin` (prompts change on first login, often skipped)
- Viewer accounts with weak passwords

**Unauthenticated Endpoints:**
- `/api/snapshots` — Public snapshots
- `/public/dashboards/{uid}` — Public dashboards
- `/login` — Version disclosure
- `/metrics` — Internal metrics (if exposed)

**RCE Vectors:**
- CVE-2021-43798: Path traversal (read arbitrary files)
- CVE-2024-9264: SQL Expressions RCE (if DuckDB enabled)
- Data source proxy SSRF → internal services
- Alert notification channels → webhook SSRF
- Plugin installation (admin) → arbitrary code

**Secret Extraction:**
- `/api/datasources` — Data source credentials (admin)
- `/api/datasources/proxy/` — Proxy requests as data source
- Path traversal → `/etc/grafana/grafana.ini` (DB creds, secret key)
- Database contains encrypted data source passwords
- With `secret_key` from config → decrypt all passwords

---

### Prometheus

**Default Credentials:**
- No authentication by default
- Often completely open

**Unauthenticated Endpoints:**
- `/api/v1/targets` — All scrape targets (full infra map)
- `/api/v1/status/config` — Running configuration
- `/api/v1/status/flags` — Command-line flags
- `/api/v1/label/__name__/values` — All metric names
- `/api/v1/query?query=` — Arbitrary PromQL queries
- `/config` — Configuration file contents

**RCE Vectors:**
- No direct RCE (read-only by design)
- SSRF via federation or remote_write targets
- If `--web.enable-admin-api`: delete/snapshot data
- If `--web.enable-lifecycle`: reload config → point to malicious targets
- Information gathered enables attacks on discovered targets

**Secret Extraction:**
- `/api/v1/status/config` — May contain basic_auth passwords for scrape targets
- Metric labels may contain sensitive info (URLs, IPs, usernames)
- `/api/v1/targets` — Internal service discovery
- Alert rules may reference internal endpoints
- Remote write/read configs may contain auth tokens

---

## Bank Jago Context — Current Findings

### n8n — Priority: P1 (High)
- **Status:** Service responding, database broken (503 on main, `/healthz` returns 200)
- **Assessment:**
  - DB connection failure means auth may be bypassed or error-prone
  - Test `/rest/settings` for version/config leak
  - Enumerate `/webhook/*` paths (active webhooks still fire without DB)
  - Check if `/rest/credentials` returns data from cache
  - Broken DB state may expose debug info or stack traces
  - **Action:** Fuzz webhook paths, check error responses for info disclosure

### Airflow — Priority: P3 (Low)
- **Status:** Behind Google IAP
- **Assessment:**
  - IAP bypass techniques: check for `X-Goog-Iap-Jwt-Assertion` header manipulation
  - Look for service account tokens that have IAP access
  - Check if Flower (port 5555) or worker logs (port 8793) are also behind IAP
  - Test direct IP access bypassing IAP
  - **Action:** Enumerate alternative ports, test IAP bypass vectors

### ArgoCD — Priority: P3 (Low)
- **Status:** Behind Google IAP
- **Assessment:**
  - Same IAP bypass vectors as Airflow
  - Check if metrics endpoint (8083) is separately exposed
  - Look for ArgoCD CLI access that might bypass web IAP
  - gRPC endpoint may have different auth path
  - **Action:** Test metrics port, gRPC endpoint, IAP bypass

### Atlantis — Priority: P2 (Medium)
- **Status:** Returns 403 (IP-restricted)
- **Assessment:**
  - 403 means the service IS reachable, just IP-filtered
  - Test with different source IPs (cloud metadata, SSRF from other services)
  - Check if webhook endpoint `/events` has different IP rules
  - X-Forwarded-For / X-Real-IP header injection
  - If accessible from compromised internal service → full RCE via Terraform
  - **Action:** Test header injection for IP bypass, use SSRF from n8n if possible

### Grafana (Aiven) — Priority: P5 (Info)
- **Status:** Unreachable (hosted on Aiven managed platform)
- **Assessment:**
  - Aiven-hosted means network-isolated to their VPC
  - Check if Aiven API keys are exposed elsewhere
  - Look for Grafana snapshots shared publicly
  - May be accessible from within cloud VPC
  - **Action:** Low priority, check for public snapshots/dashboards only

---

## Attack Chains

### n8n DB Failure → Exploitation
```
1. Enumerate active webhooks (still functional without DB)
2. Check if auth middleware fails-open on DB error
3. Trigger workflows via webhook → Code/Command nodes execute
4. Use HTTP Request node for SSRF to internal services
5. Pivot to Atlantis (bypass IP restriction from internal)
```

### Atlantis IP Bypass → Infrastructure Compromise
```
1. Find SSRF in accessible service (n8n webhook)
2. Route request through internal network to Atlantis
3. Craft malicious Terraform plan via webhook
4. Extract cloud credentials from Terraform state
5. Pivot to cloud infrastructure (GCP/AWS)
```

### IAP Bypass → CI/CD Pipeline Compromise
```
1. Find service account with IAP-secured Web App User role
2. Generate OIDC token for that service account
3. Access Airflow/ArgoCD behind IAP
4. Inject malicious DAG or Application manifest
5. Execute code in cluster context
```

---

## Quick Reference Commands

```bash
# Subdomain enumeration for CI/CD tools
subfinder -d target.com -silent | httpx -silent -mc 200,401,403

# Port scan for common CI/CD ports
nmap -sV -p 4141,5555,5678,8080,8200,8500,3000,9090 target

# Check n8n health and webhooks
curl -s https://n8n.target.com/healthz
curl -s https://n8n.target.com/rest/settings

# Test Atlantis IP bypass
curl -H "X-Forwarded-For: 10.0.0.1" https://atlantis.target.com/
curl -H "X-Real-IP: 127.0.0.1" https://atlantis.target.com/

# Consul full dump (if no ACL)
curl -s http://consul.target.com:8500/v1/kv/?recurse | jq

# Prometheus infrastructure mapping
curl -s http://prom.target.com:9090/api/v1/targets | jq '.data.activeTargets[].labels'

# Jenkins script console RCE
curl -d 'script=println+"whoami".execute().text' https://jenkins.target.com/script

# Vault status check
curl -s https://vault.target.com:8200/v1/sys/health | jq
```

---

*Last updated: 2026-05-21*
*Context: Bank Jago penetration test engagement*
