# Breach Correlation — opsec

## Purpose

Check if your accounts, credentials, or personal data appear in known breaches.
Defensive assessment to identify compromised credentials before attackers use them.

## Data Sources

| Source | Type | Access |
|--------|------|--------|
| Have I Been Pwned (HIBP) | Email breach lookup | Free API (rate-limited) |
| DeHashed | Email/username/password lookup | Paid API |
| IntelX | Paste/breach search | Freemium |
| LeakCheck | Credential lookup | Paid |
| Snusbase | Breach database | Paid |

## Methodology

### 1. Email Breach Check

```bash
# HIBP API (free, k-anonymity for passwords)
curl -s -H "hibp-api-key: $HIBP_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com"
```

### 2. Password Exposure (k-anonymity)

```bash
# Check if password hash appears in breaches (safe — only sends first 5 chars of SHA1)
echo -n "password" | sha1sum | cut -c1-5 | tr '[:lower:]' '[:upper:]'
# Query: https://api.pwnedpasswords.com/range/{first5}
```

### 3. Correlation Analysis

- Same password across multiple breaches → immediate rotation priority
- Email + password pair in breach → check all services using that email
- Username patterns across platforms → map full account surface

## Risk Scoring

| Scenario | Risk | Action |
|----------|------|--------|
| Email in breach, password unknown | Low | Monitor, enable 2FA |
| Email + password pair exposed | Critical | Immediate rotation everywhere |
| Old breach (>3 years), password since changed | Info | Verify rotation happened |
| Username pattern exposed | Medium | Assess linked accounts |

## Output

- `phase4/breach-correlation.md` — which accounts are compromised
- Remediation priority list in `phase5/`
- Cross-reference with `domain-recon.md` for organizational exposure
