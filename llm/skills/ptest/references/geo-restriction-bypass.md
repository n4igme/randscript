# Geo-Restriction Detection & Bypass

When targets return consistent empty responses (502, 403) across all endpoints, geo-blocking may be in effect. Detect early to avoid wasting time.

## Detection Heuristics

Signs that a target is geo-restricted (not just broken):

1. **Empty 502 with zero content-length** — gateway drops request before routing
2. **All paths return same status** — `/`, `/api`, `/healthz`, `/robots.txt` all 502
3. **DNS resolves to regional IPs** — target IPs in `ap-southeast-1`, `ap-south-1` etc. but you're outside that region
4. **Other subdomains on same infra work** — e.g., `api.target.com` returns 502 but `www.target.com` works (CDN vs direct)
5. **Headers reveal regional CDN** — `X-Served-By: cache-sin` (Singapore), `X-Cache: HIT from Jakarta`
6. **Mobile app works in-region only** — app store listing restricted to specific countries

**Quick test:**
```bash
# Compare your IP geo vs target IP geo
curl -s https://ipinfo.io/json | jq '.country,.city'
dig +short target.com | head -1 | xargs -I{} curl -s https://ipinfo.io/{}/json | jq '.country,.city,.org'

# If target is in SG/ID/MY and you're not — likely geo-blocked
```

**False positive check:** A truly dead service returns connection timeouts or DNS NXDOMAIN, not clean 502s with proper TLS handshake.

## Bypass Techniques

### 1. Regional Cloud VPS (Recommended for sustained testing)

Spin up a cheap VPS in the target's region:

```bash
# DigitalOcean (Singapore)
doctl compute droplet create pentest-sg \
  --region sgp1 --size s-1vcpu-1gb --image ubuntu-22-04-x64

# AWS (ap-southeast-1)
aws ec2 run-instances --region ap-southeast-1 \
  --instance-type t3.micro --image-id ami-0c55b159cbfafe1f0

# Vultr, Linode, Hetzner also have SG/ID regions
```

Then SSH tunnel all traffic:
```bash
# SOCKS proxy via VPS
ssh -D 1080 -N user@vps-ip

# Use with curl
curl --socks5 localhost:1080 https://target.com/api/endpoint

# Use with Burp: Settings → Network → SOCKS Proxy → localhost:1080
```

### 2. SSH Dynamic Port Forwarding (Quick setup)

```bash
# If you already have a VPS in the right region:
ssh -D 9050 -f -N user@regional-vps

# Route all tools through it
export ALL_PROXY=socks5://localhost:9050
export HTTP_PROXY=socks5://localhost:9050
export HTTPS_PROXY=socks5://localhost:9050

# Or per-command:
proxychains4 curl https://target.com/api/
proxychains4 nuclei -u https://target.com
```

### 3. Residential Proxies (For WAF evasion + geo)

When target blocks datacenter IPs (common with CloudFront/Akamai):

- **BrightData** — residential IPs in 195 countries, pay per GB
- **Oxylabs** — good for SEA region coverage
- **SmartProxy** — cheaper, decent ID/SG/MY coverage
- **IPRoyal** — budget option

```bash
# BrightData example
curl -x http://user:pass@brd.superproxy.io:22225 \
  --proxy-header "X-Luminati-Country: sg" \
  https://target.com/api/

# With specific city
curl -x http://user:pass@brd.superproxy.io:22225 \
  --proxy-header "X-Luminati-Country: id" \
  --proxy-header "X-Luminati-City: jakarta" \
  https://target.com/api/
```

### 4. Free/Quick Options

```bash
# Cloudflare WARP (changes your IP, sometimes bypasses geo)
warp-cli connect

# Tailscale exit node (if you have a node in the right region)
tailscale up --exit-node=<regional-node>

# Public SOCKS proxies (unreliable, last resort)
# Check: https://www.socks-proxy.net/
```

### 5. Browser-Based (For manual exploration)

```bash
# Playwright with proxy (for JS-heavy apps)
# In your test script:
browser = playwright.chromium.launch(proxy={
    "server": "socks5://localhost:1080"
})
```

## Decision Tree

```
Target returns 502/403 on all paths
  ├── DNS resolves? YES
  │   ├── TLS handshake succeeds? YES
  │   │   ├── Same status on ALL paths? YES
  │   │   │   ├── Target IPs in different region? YES
  │   │   │   │   → LIKELY GEO-BLOCKED → Use regional VPS
  │   │   │   └── Same region as you? 
  │   │   │       → Likely WAF/IP block → Try residential proxy
  │   │   └── Some paths work, others don't?
  │   │       → Not geo-block, it's path-based routing/auth
  │   └── TLS fails?
  │       → Target is down or IP-allowlisted
  └── DNS fails?
      → Target decommissioned, skip it
```

## Integration with ptest Phases

- **Phase 2 (Active Recon):** If initial probes return empty 502s, run geo-detection before investing more time. Document in `phase2-active/geo-check.md`.
- **Phase 3 (Enumeration):** If geo-blocked, set up regional proxy BEFORE running enumeration tools.
- **Phase 6 (Exploitation):** Ensure exploit PoCs route through the same regional proxy.

## Cost Estimates

| Method | Cost | Speed | Reliability |
|--------|------|-------|-------------|
| DigitalOcean VPS (SG) | $6/mo | Setup: 2 min | High |
| AWS t3.micro (SG) | ~$8/mo | Setup: 5 min | High |
| BrightData residential | $0.50-1/GB | Instant | High |
| Cloudflare WARP | Free | Instant | Low (limited geo) |
| Public SOCKS | Free | Instant | Very low |

## Pitfalls

- **Don't waste hours on 502s** — if 3+ endpoints all return empty 502, check geo immediately
- **CloudFront 403 ≠ always geo** — could be WAF rule, missing Host header, or bot detection
- **Some targets block ALL non-app traffic** — even from the right region, they may require specific User-Agent, app signatures, or client certificates
- **VPS IPs may also be blocked** — some targets block known cloud provider ranges. Residential proxies are the fallback.
- **Document the bypass** — note in engagement.md which proxy/VPS you used, so PoCs are reproducible
