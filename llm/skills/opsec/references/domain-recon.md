# Domain Recon — opsec

## Purpose

Assess your organization's or personal domain exposure from a defensive perspective.
Identify what an attacker would find during passive reconnaissance.

## Techniques

### DNS Enumeration (what's publicly visible)

```bash
# Subdomain discovery
dig +short NS example.com
dig +short MX example.com
dig +short TXT example.com

# Check for zone transfer (should fail if secure)
dig @ns1.example.com example.com AXFR

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value' | sort -u
```

### WHOIS Exposure

- Registrant name, email, phone visible?
- Organization address exposed?
- Registration/expiration dates (social engineering vector)
- Check privacy protection status

### DNS Record Hygiene

| Record Type | Risk if Exposed | Remediation |
|-------------|-----------------|-------------|
| TXT (SPF) | Reveals mail infrastructure | Necessary — verify correctness |
| TXT (DKIM) | Normal | Ensure key rotation |
| MX | Reveals mail provider | Necessary — verify no legacy |
| A/AAAA (internal) | Exposes internal IPs | Remove stale records |
| CNAME (dangling) | Subdomain takeover | Remove or reclaim |

### Subdomain Takeover Risk

- Check CNAME targets that return NXDOMAIN
- Verify cloud service claims (S3, Azure, Heroku, GitHub Pages)
- Check for expired/unclaimed service endpoints

## Output

- `phase2/domain-audit.md` — full domain exposure report
- Flag any findings for immediate remediation in `phase5/`
