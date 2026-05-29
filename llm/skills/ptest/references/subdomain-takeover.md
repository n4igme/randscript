# Subdomain Takeover Assessment

## What Is Subdomain Takeover

A subdomain takeover occurs when a subdomain's DNS record (usually CNAME) points to an external service that has been removed or unclaimed. An attacker can register that resource on the external platform and serve arbitrary content on the victim's subdomain.

**Impact:** Cookie theft, phishing, credential harvesting, bypassing CSP/CORS policies tied to the parent domain.

---

## Vulnerable CNAME Targets

| Provider | CNAME Pattern | Fingerprint (Error Page) |
|----------|--------------|--------------------------|
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |
| Heroku | `*.herokuapp.com` | "No such app" |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Azure | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net` | "404 Web Site not found" |
| CloudFront | `*.cloudfront.net` | "Bad Request" / ERROR: The request could not be satisfied |
| Shopify | `shops.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Ghost | `*.ghost.io` | "The thing you were looking for is no longer here" |
| Pantheon | `*.pantheonsite.io` | "404 unknown site" |
| Tumblr | `*.tumblr.com` | "There's nothing here" |
| WordPress.com | `*.wordpress.com` | "Do you want to register" |
| Surge.sh | `*.surge.sh` | "project not found" |
| Unbounce | `unbouncepages.com` | "The requested URL was not found" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Bitbucket | `*.bitbucket.io` | "Repository not found" |
| Cargo | `*.cargocollective.com` | "404 Not Found" |
| Fly.io | `*.fly.dev` | "404 Not Found" |
| Aiven | `*.aivencloud.com` | DNS NXDOMAIN (service deleted) |
| short.io | `cname.short.io` | 302 redirect (active) or 404 (deleted link) |

---

## How to Check

### 1. Enumerate Subdomains

```bash
# Passive enumeration
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com -o subs.txt

# Combine and deduplicate
sort -u subs.txt -o subs.txt
```

### 2. Resolve CNAME Records

```bash
# Single check
dig CNAME sub.target.com +short

# Bulk resolve
cat subs.txt | while read sub; do
  cname=$(dig CNAME "$sub" +short)
  [ -n "$cname" ] && echo "$sub -> $cname"
done | tee cname-results.txt
```

### 3. Identify Dangling CNAMEs

```bash
# Check if CNAME target resolves (NXDOMAIN = likely takeover)
cat cname-results.txt | while IFS=' -> ' read sub cname; do
  dig "$cname" +short | grep -q "." || echo "DANGLING: $sub -> $cname"
done
```

### 4. HTTP Probe for Error Fingerprints

```bash
# Probe with httpx and look for takeover fingerprints
cat subs.txt | httpx -status-code -title -web-server -o httpx-out.txt

# Grep for known error signatures
grep -iE "NoSuchBucket|No such app|github pages|currently unavailable|unknown domain|not found" httpx-out.txt
```

---

## Automated Tools

### subjack

```bash
# Install
go install github.com/haccer/subjack@latest

# Run against subdomain list
subjack -w subs.txt -t 100 -timeout 30 -o takeover-results.txt -ssl

# With custom fingerprints
subjack -w subs.txt -t 100 -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v
```

### nuclei (takeover templates)

```bash
# Run takeover-specific templates
nuclei -l subs.txt -t takeovers/ -o nuclei-takeover.txt

# With rate limiting for stealth
nuclei -l subs.txt -t takeovers/ -rl 50 -o nuclei-takeover.txt
```

### can-i-take-over-xyz (reference)

GitHub repo: `https://github.com/EdOverflow/can-i-take-over-xyz`

Use as a reference to confirm whether a specific service is currently vulnerable to takeover. Services change their behavior over time.

### dnsx + httpx pipeline

```bash
# Full pipeline: enumerate -> resolve -> probe -> detect
subfinder -d target.com -silent | \
  dnsx -cname -resp -silent | \
  grep -v "target.com" | \
  awk '{print $1}' | \
  httpx -silent -status-code -title | \
  grep -iE "NoSuchBucket|No such app|github pages|unavailable|unknown domain"
```

---

## When to Report

**Confirmed Vulnerable (Report):**
- CNAME points to external service AND the resource is unclaimed/deleted
- DNS returns NXDOMAIN for the CNAME target
- HTTP response shows a platform-specific "not found" error page
- You can demonstrate claim-ability (do NOT actually claim it)
- **Check all environment variants:** When one dangling CNAME is found (e.g., `grafana-dev`), immediately check `grafana-stg`, `grafana-qa`, `grafana-pt`, `grafana-prod` — organizations often have parallel CNAMEs across environments and may decommission them inconsistently

**Not Vulnerable (Do Not Report):**
- CNAME resolves to an active, configured service
- Service returns legitimate content
- CNAME points to an internal resource that resolves

**Severity Guidelines:**
- **High:** Dangling CNAME to a service where anyone can register the resource (S3, Heroku, GitHub Pages)
- **Medium:** Dangling CNAME to a service requiring org-level access to claim
- **Low/Info:** Stale DNS records pointing to decommissioned IPs (no service takeover possible)

---

## Quick One-Liner

```bash
# End-to-end subdomain takeover check
subfinder -d target.com -silent | dnsx -cname -resp-only -silent | sort -u | httpx -silent -title -status-code | grep -iE "NoSuchBucket|No such app|github pages|unavailable|unknown domain|not found|Fastly error"
```

---

## Notes

- Always check `can-i-take-over-xyz` for current service status before reporting
- Some services (CloudFront, Azure) require specific conditions beyond a dangling CNAME
- Never actually register/claim the resource during a pentest without explicit written authorization
- Screenshot the error page and DNS records as evidence
- **Aiven (aivencloud.com):** Services are named per-project (e.g., `public-dev-o11y-grafana-prj-aiven-non-prod`). If the CNAME target returns NXDOMAIN, the Aiven service was deleted. Takeover requires creating a new Aiven service with the exact same name in the same cloud region. Verify claimability by checking if the service name is available in Aiven's console — do NOT actually create it without authorization. **Multi-environment pattern:** When one Aiven CNAME is dangling, check ALL environment variants (dev/stg/qa/pt/prod) — organizations often decommission services across environments at different times, so multiple may be vulnerable simultaneously. Aiven is NOT listed in `can-i-take-over-xyz` as of May 2026 — this doesn't mean it's safe, just untested publicly. Aiven has no wildcard DNS (non-existent services = NXDOMAIN, not a default page), so NXDOMAIN is a reliable signal. Service names appear user-chosen (not UUID/random), which suggests takeover is likely possible but needs practical verification via Aiven account creation.
- **short.io:** Active links return 302 redirects. If a short.io CNAME returns 404 or the short.io dashboard shows the link as unclaimed, it may be takeable. However, short.io links that redirect to the parent domain (e.g., `jadi.jago.com → jago.com`) are active and NOT vulnerable.
