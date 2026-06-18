# Intigriti Bug Bounty Recon — Capital.com Engagement Notes

## Target Selection Criteria (Wildcard + Bounty)

Best targets combine: wildcard scope, high max bounty, financial industry (user's expertise).

Recommended from June 2026 enumeration:
1. **Capital.com** (€15k, 4 wildcards) — fintech trading platform
2. **Monzo** (£12.5k, *.monzo.com Tier 1) — neobank
3. **Dropbox** ($15k, 10 wildcards) — widest attack surface

## Capital.com Architecture (June 2026)

### Domains
- `capital.com` — Cloudflare DNS, Imperva WAF (45.60.76/85.121)
- `backend-capital.com` — AWS Route53, direct IPs (no WAF on most)
- `itcapital.io` — AWS Route53, internal (198.18.x.x VPN-gated)

### Key Infrastructure
- Company entity: expcapital (from Java packages)
- AWS eu-west-1 (Ireland) primary region
- Spring Boot microservices (callback-service)
- Kafka for event streaming
- Sumsub for KYC, AppsFlyer for attribution
- Simpplr for internal intranet (mycapital.capital.com)

### Attack Surface (no WAF)
- demo-api-capital.backend-capital.com (Trading API, swagger)
- callback.backend-capital.com (PROD webhooks)
- test-callback.backend-capital.com (TEST webhooks + Prometheus)

### Key Finding: Webhook Signature Bypass
- All /callback/sumsub/cc/v2/* endpoints accept forged POST without HMAC
- Content-Type validation (415), body validation (400), route specificity (500)
- BUT invalid X-Payload-Digest → 200 (signature NOT verified)
- Multi-jurisdiction: cc works (200), cx/cy/bel/au/mena/uk error (500)

### API Auth Flow
- X-CAP-API-KEY header → POST /session → CST + X-SECURITY-TOKEN
- Password encryption: RSA PKCS1 (key from /session/encryptionKey)
- Session timeout: 10 minutes
- Rate limit: 1 req/sec on /session (inconsistent enforcement ~27%)

### GitHub (capital-com-sv org)
- open-api-examples, capital-api-postman, api-java-samples, capital-mcp
- Postman collection has demo + live environment files

### httpx (ProjectDiscovery) vs httpx (Python)
On this macOS system, `/opt/homebrew/bin/httpx` is Python httpx (HTTP client library CLI), NOT ProjectDiscovery's httpx scanner. For batch HTTP probing, use Python concurrent.futures with curl subprocess instead.
