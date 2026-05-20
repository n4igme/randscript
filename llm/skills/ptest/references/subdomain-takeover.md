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
