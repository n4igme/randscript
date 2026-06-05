# Alibaba Cloud / Ant Group Infrastructure Patterns

## Fingerprinting

| Header/Indicator | Meaning |
|-----------------|---------|
| `server: Tengine` | Alibaba's nginx fork (CDN/edge) |
| `server: Spanner` | Ant Group internal proxy/load balancer |
| `server: ESA` | Edge Security Acceleration (Alibaba CDN) |
| `server: nginx/1.6.2` | Legacy nginx behind Spanner (Ant Group backend) |
| `x-oss-request-id` | Alibaba Object Storage Service |
| `x-oss-cdn-auth: success` | OSS with CDN auth enabled |
| `x-fc-request-id` | Alibaba Function Compute (serverless) |
| `via: ispanner-internet-*` | Spanner internal routing (leaks region/node) |
| `via: ens-cache*` | Alibaba CDN edge cache nodes |
| CNAME `*.w.cdngslb.com` | Alibaba CDN Global SLB |
| CNAME `*.spanner.alipaydns.com` | Alipay/Ant DNS infrastructure |

## Ant Group SPA Framework (Tern)

Ant Group SPAs use a `tern-site-config` JSON blob in the HTML `<script type="tern-site-config">`:

```json
{
  "authType": "antbuservice",
  "mode": "cloud",
  "yuyanId": "180020010201248959",
  "name": "antom-workbench-site",
  "iframeImplantEnable": true,
  "metadata": { "links": [{"href": "https://dashboard-apiv2.antom.com", "rel": "dns-prefetch"}] }
}
```

Key fields:
- `yuyanId` — uniquely identifies the micro-app; JS bundles hosted at `render-intl.alipayobjects.com/p/yuyan/{yuyanId}/`
- `name` — internal app identifier
- `metadata.links` with `crossOrigin: "use-credentials"` — reveals backend API hosts

## Referer-Based Access Control Bypass

Ant Group APIs commonly enforce Referer checks instead of (or before) token auth. Known working Referers:

| Referer | Bypasses |
|---------|----------|
| `https://dashboard.antom.com/` | PROD dashboard-apiv2 endpoints |
| `https://global-testpre.alipay.com/` | PRE env endpoints + some PROD endpoints (broader) |
| `https://render-intl.alipay.com/` | CDN-origin paths |

**Pattern:** Different Referers work for different endpoint groups. Test each separately. Some endpoints (like `getPubKey.json`) need NO Referer at all on certain hosts.

## Cloud Metadata

Alibaba Cloud uses `100.100.100.200` (NOT `169.254.169.254`) for instance metadata:
```bash
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

## OSS Bucket Patterns

```bash
# Format: {bucket}.{region}.aliyuncs.com
# Common regions: oss-ap-southeast-1, oss-cn-hangzhou, oss-cn-shanghai
curl -s 'https://{name}.oss-ap-southeast-1.aliyuncs.com/'
# Check via CNAME too (may have different ACL)
curl -s 'https://subdomain.target.com/'  # if CNAME → bucket
```

OSS POST returns XML `MethodNotAllowed` with `webapp-origin.marmot-cloud.com` as HostId — confirms static CDN bucket (dead end for API testing).

## Session Cookies

Ant Group dashboard sets cookies on `.antom.com` (broad domain scope):
- `ALIPAYINTLJSESSIONID` — session token, Domain=.antom.com, NO HttpOnly
- `ctoken` — CSRF-like token, Domain=.antom.com, NO HttpOnly  
- `spanner` — routing cookie, Secure only, NO HttpOnly
- `JSESSIONID` — backend session, HttpOnly (this one is protected)

## API Error Patterns

| Error | Meaning |
|-------|---------|
| `{"stat":"fail","msg":"RefererCheckFailed"}` | Wrong/missing Referer header |
| `{"redirectURL":"https://global.alipay.com/ilogin/..."}` | Needs authenticated session |
| `{"resultCode":"IPAY_RS_510000400","resultMessage":"..."}` | Processed without auth but validation failed |
| `{"success":true,"data":{...}}` | Fully processed, no auth needed |
| `{"errormsg":"security error!","success":"false"}` | Security check failed (different from Referer) |

Key insight: `IPAY_RS_510000400` means the endpoint PROCESSES without authentication — it reached business logic validation. The auth layer was skipped entirely.

## Function Compute (FC) Probing

js.antom.com exposes Alibaba FC. Fingerprints:
- `x-fc-request-id` header on responses
- GET requests return OSS XML (`NoSuchKey`) — FC fronted by OSS
- POST `/invoke` returns FC internal errors (HTTP 599):
  ```
  unhandled error(13485,13477)@<internal>: PackInfoNotInitError: pack info not init
  ```
- Adding `X-Fc-Invocation-Type: Sync` header triggers same error

FC is not exploitable for SSRF or code exec from external — the function is broken/uninitialized. Document as info-level (internal error disclosure).

## Dead-End Classification (Fast Triage)

Use these fingerprints to quickly dismiss hosts during Phase 3 enumeration:

| Fingerprint | Classification | Action |
|-------------|---------------|--------|
| POST → XML `<Error><Code>MethodNotAllowed` + `webapp-origin.marmot-cloud.com` | CDN/OSS bucket | Dead end |
| HTTP 204, size 0, `server: ESA` on all paths | Tracking beacon | Dead end |
| Body = "success" (7 bytes), all paths identical | Health/proxy stub | Dead end |
| 302 → /platform or /index.html, body = "index page" | Empty OSS app | Dead end |
| All paths return same size + `server: Spanner` + 302→/error | SPA catch-all (no backend paths exposed) | Extract tern-site-config, skip path fuzzing |
| `x-oss-cdn-auth: success` + `x-oss-request-id` | CDN-authenticated OSS | No listing, no write |

## Multi-Host Same-Backend Detection

Ant Group apps often have multiple hostnames pointing to the same backend:
- `dashboard-apiv2.antom.com` = `dashboard-api.antom.com` = `dashboard-apiv2-pre.antom.com` (same API surface)
- All SPAs (`dashboard`, `2c2p-portal`, `demo`) proxy to `dashboard-apiv2` backend

Verify by testing one endpoint on both. Report all affected hosts but don't duplicate enumeration effort. Same tern-site-config `yuyanId` = same JS bundles = same frontend.

## CORS Classification (4 tiers across Ant Group hosts)

Ant Group subdomains have inconsistent CORS policies. Always test each host individually:

| Tier | Behavior | Hosts (Antom example) | Severity |
|------|----------|----------------------|----------|
| 1: Arbitrary origin | Reflects ANY external origin + `credentials: true` | navigator.antom.com, js.antom.com | High (if data endpoint exists) |
| 2: Null origin | Reflects `Origin: null` + credentials | navigator.antom.com | High (iframe sandbox exploit) |
| 3: Subdomain pattern | Reflects `*.antom.com` only + credentials | docs.antom.com, 2c2p-portal.antom.com | Medium (needs XSS on sibling subdomain) |
| 4: No CORS | No ACAO header returned | dashboard-apiv2.antom.com | N/A |

**nuclei false-positive (CRITICAL):** nuclei CORS templates report Tier 3 (subdomain-pattern) as `[cors-misconfig:arbitrary-origin]` because they test with a generated subdomain like `https://dlnot.antom.com`. This looks like arbitrary origin in nuclei output but is actually subdomain-only reflection. ALWAYS manually verify with a fully external origin (`https://evil.attacker.com`) before reporting. In Antom testing (June 2026): nuclei flagged 4 hosts, only 2 were truly arbitrary-origin (Tier 1).

**Exploitation note:** Tier 1 hosts (navigator, js) return 405 on all paths — no data-returning endpoint found. Tier 3 hosts (docs) have `/api` backend (403). The `.antom.com` cookie scope (ALIPAYINTLJSESSIONID without HttpOnly) means a Tier 1 CORS + any future API endpoint on that host = instant session theft.

## Antom v2 Payment API (/ams/api/v1/)

`open-sectest-sg.antom.com` hosts the Antom v2 payment gateway alongside the legacy `gateway.do` (RSA2 signed). The v2 API uses `client-id` header authentication instead of request-body RSA signatures:

```bash
# Discover live endpoints (return 200 with JSON errors, not 404)
for path in payments/pay payments/inquiryPayment payments/cancel payments/refund payments/capture authorizations/consult customs/declare; do
  curl -sk -X POST "https://open-sectest-sg.antom.com/ams/api/v1/$path" \
    -H 'Content-Type: application/json' -H 'client-id: test' -d '{}' -m 5
done
```

Error progression:
- No `client-id` header: `"client-id not found: null"`
- Invalid `client-id`: `"client-id not found: test"` (PARAM_ILLEGAL)
- Valid `client-id` + no signature: would get signature error (not reached)

**Key insight:** The endpoint looks up client-id in a database. Format is unknown (not in JS bundles). Sandbox IDs (e.g., `SANDBOX_5Y...`) don't work on this host. If a valid client-id is ever leaked (GitHub, JS, API response), the payment API becomes directly accessible for testing.

Required headers for full request:
```
client-id: <merchant_client_id>
request-time: 2026-06-03T12:00:00+08:00
signature: algorithm=RSA256,keyVersion=1,signature=<base64>
```

## TLS Configuration

Ant Group wildcard certs (*.antom.com via DigiCert) commonly support TLS 1.0/1.1 across all hosts. This is infrastructure-level — unlikely accepted as a bounty finding but worth documenting for internal pentests.
