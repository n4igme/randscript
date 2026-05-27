# Alibaba Cloud Infrastructure Patterns

Reference for testing targets hosted on Alibaba Cloud (Aliyun). Common in Southeast Asian fintech (GoTo, Gojek, GoPay, Findaya).

## Detection Signals

| Signal | Indicator |
|--------|-----------|
| DNS | `*.alidns.com` (vip7/vip8 for premium), `*.aliyuncsslbintl.com` (NLB) |
| WAF | `server: Tengine`, `acw_tc` cookie (30min TTL), 405 page with Chinese/English text referencing `errors.aliyun.com` |
| CDN | `*.cdn.gtflabs.io` (GoTo Financial CDN on Alibaba) |
| Object Storage | `*.oss-ap-southeast-5.aliyuncs.com` (Jakarta region) |
| IP ranges | `8.215.x.x`, `147.139.x.x` (Alibaba Cloud Indonesia/Singapore) |
| NLB hostname | `nlb-*.ap-southeast-5.nlb.aliyuncsslbintl.com` |

## WAF Behavior (Alibaba Cloud WAF / Tengine)

### Block Response Pattern
```
HTTP/2 405
server: Tengine
content-type: text/html; charset=utf-8

<!doctypehtml><html lang="zh-cn">...<title>405</title>...
"Sorry, your request has been blocked as it may cause potential threats to the server's security."
```

Contains `traceid` in a hidden textarea: `{"traceid":"...","lang":"en"}`

### WAF Cookie
```
set-cookie: acw_tc=<hex>;path=/;HttpOnly;Max-Age=1800
```
This is Alibaba Cloud WAF's session tracking cookie. Present on all WAF-fronted services.

### WAF vs Istio RBAC (Differentiation)
- **Alibaba WAF block:** 405 + Tengine + Chinese/English HTML page (2657 bytes)
- **Istio RBAC block:** 403 + `server: istio-envoy` + `RBAC: access denied` (19 bytes)
- **Both can coexist:** WAF at edge, Istio inside the mesh

## Kubernetes Cluster Naming Convention (GoTo/Findaya)

Pattern: `al-mg-id-{p|s}` = Alibaba Managed - Indonesia - {Production|Staging}

| Prefix | Meaning |
|--------|---------|
| `al-mg-id-p` | Alibaba Managed K8s, Indonesia, Production |
| `al-mg-id-s` | Alibaba Managed K8s, Indonesia, Staging |
| `al-mg-id-s-waf-lb` | Staging cluster WAF load balancer |
| `p-*-k8s-lb` | Production K8s load balancer |
| `s-*-k8s-lb` | Staging K8s load balancer |
| `p-*-k8s-waf-lb` | Production K8s WAF load balancer |

### Subdomain Routing Pattern
```
{service}.{product}.{cluster}.findaya.co.id
  api.cashloans.al-mg-id-p.findaya.co.id  → prod cluster
  api.cashloans.al-mg-id-s.findaya.co.id  → staging cluster
  api.cashloans.findaya.co.id             → main ingress (NLB)
```

**Key insight:** The `al-mg-id-p`/`al-mg-id-s` direct cluster gateways enforce Istio RBAC strictly. The main ingress (without cluster prefix) may have DIFFERENT auth policies — this is where misconfigurations are found (e.g., actuator exposed on main ingress but blocked on direct cluster gateway).

## Port Exposure Pattern

Alibaba Cloud security groups sometimes allow TCP handshake on internal service ports but the services don't respond to external application-layer traffic (bound to internal interfaces).

**Observed on 8.215.152.172 (Findaya, May 2026):**
- Ports open (TCP SYN-ACK): 80, 443, 2379, 2380, 3000, 4443, 5432, 5601, 6379, 8080, 8443, 8888, 9090, 9200, 9300, 10250, 10255
- Ports responding to HTTP: only 80, 443 (via correct hostname/SNI)
- All other ports: TCP open but application-layer filtered

**Implication:** Document as "defense-in-depth failure" (security group too permissive) but note it's not directly exploitable from external. The real attack surface is the HTTP/HTTPS ingress.

## Spring Boot on Alibaba Cloud

### Actuator Discovery via Metrics Tags

When `/actuator/metrics/http.server.requests` is accessible, the `uri` tag reveals ALL API routes:

```bash
curl -sk "https://target/actuator/metrics/http.server.requests" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(v) for t in d.get('availableTags',[]) if t['tag']=='uri' for v in t['values']]"
```

This is MORE valuable than directory brute-force — it shows the exact routes the application serves, including:
- Internal callback endpoints (often unauthenticated)
- Integration endpoints (server-to-server, may lack auth)
- Admin/actuator paths
- Versioned API routes

### Additional Metric Tags to Extract

| Tag | Intelligence Value |
|-----|-------------------|
| `uri` | Complete API route map |
| `host` | Internal hostname |
| `team` | Owning team name |
| `env` | Environment confirmation (production/staging) |
| `exception` | Error types (reveals framework internals) |
| `status` | Which HTTP codes are returned (429 = rate limiting exists) |
| `method` | Which HTTP methods are accepted |
| `outcome` | Success/error ratios |

## Integration/Callback Endpoint Pattern (HIGH VALUE)

Server-to-server integration endpoints often LACK authentication because they're designed to be called by trusted internal services or partner APIs.

### Detection
- Path contains: `/integration/`, `/callback`, `/webhook`, `/notify`, `/hook`
- Discovered via actuator metrics tags (e.g., `/integration/gopay/kyc/v1/{gopay_account_id}/callback`)
- Returns 405 (Method Not Allowed) on GET instead of 401 (Unauthorized) — indicates no auth middleware

### Testing
```bash
# If GET returns 405 (not 401), try POST — callbacks are typically POST
curl -sk -X POST "https://target/integration/partner/callback" \
  -H "Content-Type: application/json" -d '{}'

# Common responses:
# 500 + verbose error → internal service discovery (service names, internal domains)
# 200 + data → unauthenticated data access (CRITICAL)
# 400 + field validation → reveals expected payload structure
# 401 → auth IS enforced (safe)
```

### Real-World Case Study: Findaya KYC (May 2026)

**Discovery path:**
1. `/actuator/metrics/http.server.requests` exposed route: `/integration/gopay/kyc/v1/{gopay_account_id}/callback`
2. GET returned 405 (not 401) → no auth on this path
3. POST returned 500 with internal service name: `"api.kyc.loanplatform.findaya.com: Name or service not known executing POST http://kyc-service/..."`
4. Tested adjacent endpoint: `/legalEntityKYC/v1/onboarding-doc`
5. POST with empty body `{}` returned **signed GCS URLs to production KYC documents** (Critical!)

**Key lesson:** When actuator reveals integration/callback routes, ALWAYS test them with POST. They frequently lack auth because the original design assumed only internal services would call them. The API gateway may not enforce auth on `/integration/*` paths.

**Severity escalation:** A 500 error disclosing internal service names is Medium. But testing ADJACENT endpoints on the same path prefix (`/legalEntityKYC/v1/`) revealed a Critical data leak. Don't stop at the first error — enumerate the entire path namespace.
