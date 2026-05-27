# Findaya / GoTo Financial — Engagement Intelligence

**Last Updated:** 2026-05-24
**Program:** YesWeHack — GoTo Financial Public Bounty Program

## findaya.co.id Infrastructure

- **Registrar:** PT Digital Registra Indonesia (same as gobiz.co.id)
- **DNS:** Alibaba Cloud (vip7/vip8.alidns.com)
- **Cloud:** Alibaba Cloud Jakarta (8.215.x.x, 147.139.x.x)
- **Email:** Google Workspace (aspmx.l.google.com)
- **SPF:** Google + Mailgun + Salesforce
- **Atlassian:** atlassian-domain-verification present (Jira/Confluence)
- **Legal entity:** PT Mapan Global Reksa (from financial reports on website)

### IP Clusters

| IP | Role | Ports Open | Notes |
|----|------|-----------|-------|
| 8.215.152.172 | Main API/App ingress (NLB) | 80,443,2379,2380,3000,4443,5432,5601,6379,8080,8443,8888,9090,9200,9300,10250,10255 | Public-facing, actuator exposed, KYC vuln here |
| 8.215.43.91 | Web cluster (al-mg-id-p) | 443 | www, sentry, lender-dashboard, funding, payment |
| 8.215.194.107 | Secondary cluster (al-mg-id-s) | 80,443 | Istio RBAC on everything |
| 8.215.87.224 | MLflow | 443 | Istio RBAC blocked |
| 147.139.202.38 | Teleport proxy | 443 | Teleport Enterprise v17.7.21 |

### Key Services

| Service | URL | Status |
|---------|-----|--------|
| Main API | api.findaya.co.id | 401 (Spring Boot, actuator exposed) |
| Cashloans App | app.cashloans.findaya.co.id | 200 (Next.js) |
| GoPay Pinjam Modal | app.gopaypinjammodal.findaya.co.id | 200 (Next.js) |
| Modal Toko | app.modaltoko.findaya.co.id | 200 (React) |
| Toko Kapital | app.tokokapital.findaya.co.id | 200 (React) |
| Findaya Portal | app.findaya.co.id | 200 (React SPA) |
| Sentry | sentry.findaya.co.id | 302→login (self-hosted, Istio) |
| Teleport | teleport-proxy.apps.findaya.co.id | 302→/web (Enterprise v17.7.21) |
| Cashloans Gateway | api-gateway.cashloans.findaya.co.id | 405 (Alibaba WAF/Tengine) |

### Authentication Patterns

- **Main API:** JWT-based (`"User is not logged in"` error, `acw_tc` Alibaba WAF cookie)
- **OTP flow:** POST /v1/otp → {phoneNumber, countryCode:"+62"} → returns otpToken (720s expiry)
- **Login:** POST /v2/login → {otpToken, otp} → JWT
- **SSO:** /v1/login/sso/gopay, /v1/login/sso/gobiz, /v1/login/gma (GoPay Merchant App)
- **Integration callbacks:** /integration/gopay/kyc/v1/{id}/callback — NO AUTH (by design, but exploitable)
- **KYC docs:** /legalEntityKYC/v1/onboarding-doc — NO AUTH (CRITICAL BUG)

### Findings (2026-05-24)

| ID | Title | Severity | Asset |
|----|-------|----------|-------|
| F-1 | Unauthenticated Spring Boot Actuator | High (7.5) | api.findaya.co.id |
| F-2 | Teleport Enterprise config disclosure | Medium (5.3) | teleport-proxy.apps.findaya.co.id |
| F-3 | Self-hosted Sentry exposed | Low (3.7) | sentry.findaya.co.id |
| F-4 | Unauthenticated KYC document access | Critical (9.1) | api.findaya.co.id |
| F-5 | Internal service discovery via error | Medium (5.3) | api.findaya.co.id |

### OTP Behavior (program excludes rate limit + user enum)

- Valid format: `{"phoneNumber":"812345678901","countryCode":"+62"}` → success (otpToken)
- Invalid/unregistered: `OTP_GENERATE_BAD_REQUEST` (E7)
- No rate limiting observed (multiple tokens generated for same number)
- OTP brute-force: wrong OTP returns `OTP_BAD_REQUEST` (E6), no lockout after 3 attempts
- 720-second window + 6-digit OTP + no lockout = theoretically brute-forceable

### Internal Architecture (from error messages + metrics)

- **K8s services:** kyc-service (internal), findaya-api (host tag)
- **Internal domains:** api.kyc.loanplatform.findaya.com
- **GCP project:** ojk-compliant-launch (KYC docs storage)
- **GCS bucket:** prod_legal_entity_kyc_docs
- **Service account:** stg-kyc-docs-owner@ojk-compliant-launch.iam.gserviceaccount.com
- **Team tag:** gofin-loan-platform
- **Stack:** Spring Boot, Java 11, PostgreSQL, Kafka, HikariCP, Istio/Envoy
- **Monitoring:** Grafana Faro (katulampa.gopay.sh), New Relic (accountID 1986505)

## go-pay.co.id Infrastructure

- **DNS:** Alibaba Cloud (ns1/ns2.alidns.com)
- **Main IP:** 34.96.114.176 (GCP) — not responding to HTTP
- **ArgoCD prod:** argocd-ui.go-pay.co.id → 149.129.250.140 (v2.14.13)
- **ArgoCD stg:** argocd-ui-stg.go-pay.co.id → 149.129.243.113 (v3.0.2)
- **Global portal:** global-portal.go-pay.co.id → 8.215.48.67 (Istio RBAC)
- Most subdomains: internal IPs or non-resolving

### ArgoCD Finding (F-9 on main GoPay engagement)

- Both prod + stg exposed to internet
- Unauthenticated: /api/v1/settings, /api/version, /api/dex/keys, OIDC discovery
- Device code flow works on both (social engineering vector)
- execEnabled: true, kustomize LoadRestrictionsNone
- Manages: Elasticsearch, Kafka (Strimzi), Velero, cert-manager, ClusterRoleBindings
- Auth: Google SSO via Dex (userLoginsDisabled: true)

## gofin.io — Decommissioned

- 73 subdomains discovered, almost none resolve externally
- Live IPs (13.214.67.72, 18.141.102.62) don't respond on any port
- AWS NLB (staging) also unresponsive
- Not worth further testing
