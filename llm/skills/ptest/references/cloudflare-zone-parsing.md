# Cloudflare Zone Export Parsing for Pentest

## When to Load
- Phase 1, after receiving a Cloudflare zone file export (BIND or CSV format)
- Internal engagements where the DNS team provides zone data

## What It Gives You
A CF zone export contains intelligence that no passive tool can match:
1. **Proxy status** (`cf-proxied:true/false`) — identifies which hosts bypass CF WAF
2. **CF tags** — custom tags like `iap`, `partner`, `brevo`, `staging`, `domain-validation`
3. **Comments** — internal notes revealing purpose (e.g., "For Phishing Campaign", "used for apache guacamole", Jira ticket refs)
4. **True origin IPs** — the real backend IPs behind CF proxying

## Extraction Commands

### Non-Proxied Hosts (direct attack surface, NO WAF)
```bash
grep "cf-proxied:false" zone-export.txt | grep "IN	A" | awk '{print $1, $5}' | sed 's/\.$//' | sort
```
These are TOP PRIORITY for Phase 2 scanning — no CF protection.

### IAP-Tagged Hosts (Google Identity-Aware Proxy)
```bash
grep "cf_tags=.*iap" zone-export.txt | grep "IN	A" | awk '{print $1, $5}' | sed 's/\.$//'
```
IAP hosts redirect to Google OAuth. Useful for: OAuth flow analysis, IAP client ID extraction.

### Partner-Tagged Hosts
```bash
grep "cf_tags=.*partner" zone-export.txt | grep "IN	A" | awk '{print $1, $5}' | sed 's/\.$//'
```
Partner integrations often share a single LB IP — test for path-based routing bypass.

### Extract Internal Comments (intel)
```bash
grep -E ";\s+\S" zone-export.txt | grep "IN	A" | sed 's/.*;\s*//' | sort -u
```
Comments reveal: service purpose, Jira tickets (bankjago.atlassian.net), tool names (Guacamole, thriveDX).

### CNAME Records (subdomain takeover + third-party services)
```bash
grep "IN	CNAME" zone-export.txt | awk '{print $1, $5}' | sed 's/\.$//'
```
Check for dangling CNAMEs (target resolves to NXDOMAIN) and map third-party services.

### AWS Transfer SFTP (CNAME pattern)
```bash
grep "server.transfer.*amazonaws.com" zone-export.txt
```
AWS Transfer Family endpoints — SFTP-only, won't respond on port 22 via direct connection.

## Priority Classification from Zone Export

| cf-proxied | IAP tag | Priority | Rationale |
|------------|---------|----------|-----------|
| false | no | HIGHEST | Direct-to-origin, no WAF, no IAP |
| false | yes | MEDIUM | Direct IP but Google OAuth required |
| true | no | MEDIUM | CF WAF active, test for bypass |
| true | yes | LOW | Double-protected |

## Key Observations (Bank Jago, June 2026)
- 40 non-proxied hosts out of ~150 A records = 27% direct attack surface
- Data platform hosts (*-data.jago.com) were ALL non-proxied — a cluster of GCP services behind only IAP
- SFTP hosts (AWS Transfer) don't respond on port 22 — they're API-driven, not traditional SSH
- GCP LB IPs (34.x.x.x) with 250+ Shodan ports are Global LB false positives
- Zone comments referenced Jira project "ITSC" — useful for social engineering wordlists
- `datahub.jago.com` had explicit comment: "Proxy status set to DNS only due to issues" — intentionally exposed
