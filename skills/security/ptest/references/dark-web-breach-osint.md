# Dark Web & Breach Data OSINT

Phase 1 reference. Methodology for discovering leaked credentials, exposed data, and threat intelligence from dark web sources and breach databases.

---

## When to Use

- **Every engagement** — breach data check is mandatory in Phase 1 OSINT
- **Financial sector** — higher priority (credential leaks → fraud, regulatory violation)
- **Internal pentest** — check if employee credentials are in known breaches
- **Bug bounty** — leaked API keys, internal URLs, staging credentials

## Authorization Note

> Discovering credentials in breach databases is a finding in itself. **Testing** those credentials against production requires explicit authorization (see ptest SKILL.md CTI-Sourced Credentials guardrail). Document the exposure without logging in unless authorized.

---

## Methodology (Priority Order)

### 1. Breach Database Search (Highest ROI)

Check if target domain emails/credentials appear in known breaches.

| Service | Type | Access | Best For |
|---------|------|--------|----------|
| [DeHashed](https://dehashed.com) | Paid API | API key ($) | Email, username, password, hash, IP lookup |
| [IntelX](https://intelx.io) | Freemium | API key (free tier) | Paste sites, dark web, breach data, documents |
| [LeakCheck](https://leakcheck.io) | Paid | API key ($) | Email/username → plaintext/hash passwords |
| [HaveIBeenPwned](https://haveibeenpwned.com) | Free/Paid API | API key | Domain-wide breach notification (no passwords) |
| [Snusbase](https://snusbase.com) | Paid | Web/API | Email, username, IP, name, phone lookup |
| [BreachDirectory](https://breachdirectory.org) | Free | Web | Quick check, partial hash reveal |

**Procedure:**

```bash
# 1. HIBP domain search (free, shows which breaches affected the org)
curl -s -H "hibp-api-key: $HIBP_KEY" \
  "https://haveibeenpwned.com/api/v3/breaches" | \
  jq '.[] | select(.Domain) | {Name, BreachDate, DataClasses}'

# 2. DeHashed API (paid — returns actual credentials)
curl -s -H "Authorization: Basic $DEHASHED_KEY" \
  "https://api.dehashed.com/search?query=domain:target.com&size=100" | \
  jq '.entries[] | {email, password, hashed_password, database_name}'

# 3. IntelX search (free tier — 10 searches/day)
# Search for domain, email patterns, internal hostnames
curl -s -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_KEY" \
  -H "Content-Type: application/json" \
  -d '{"term":"target.com","maxresults":100,"media":0,"sort":2,"terminate":[]}'

# 4. Manual HIBP check for key employees (CEO, CTO, admins)
curl -s -H "hibp-api-key: $HIBP_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/admin@target.com"
```

**What to document:**
- Number of breached accounts found
- Which breaches (date, data types exposed)
- Whether passwords are plaintext, hashed, or cracked
- Pattern analysis (password reuse indicators, common patterns)
- Whether MFA would mitigate the risk

### 2. Paste Site & Code Leak Search

Search for accidentally leaked credentials, configs, and internal data.

| Source | URL | What to Find |
|--------|-----|--------------|
| IntelX Paste Search | intelx.io | Paste dumps containing target domain |
| Google Dorking | google.com | `site:pastebin.com "target.com"` |
| GitHub Code Search | github.com/search | Leaked secrets, internal URLs, API keys |
| GitLab Snippets | gitlab.com | Public snippets with target references |
| Postman Public | postman.com/search | API collections with hardcoded tokens |

```bash
# Google dorks for paste/leak sites
"target.com" site:pastebin.com
"target.com" site:paste.ee
"target.com" site:ghostbin.com
"target.com" site:justpaste.it
"@target.com" password OR passwd OR pwd
"target.com" site:trello.com
"target.com" site:notion.so

# GitHub search (via gh CLI or web)
gh search code "target.com" --language=yaml
gh search code "target.com" --language=json
gh search code "target.com password"
gh search code "target.com api_key OR apikey OR secret"
```

### 3. Dark Web Search Engines (Clearnet Gateways)

Search for target mentions on dark web without requiring Tor:

| Engine | URL | Notes |
|--------|-----|-------|
| Ahmia | https://ahmia.fi | Most reliable clearnet gateway to .onion search |
| IACA Dark Web Tools | https://iaca-darkweb-tools.com | Investigation-focused, curated |
| IntelX | https://intelx.io | Indexes dark web content (pastes, forums, markets) |
| DarkSearch | https://darksearch.io | API available, indexes .onion sites |

```bash
# Ahmia search (clearnet, no Tor needed)
curl -s "https://ahmia.fi/search/?q=target.com" | \
  grep -oP 'href="[^"]*"' | grep -i "redirect"

# IntelX dark web search (includes Tor content)
# Use the same API as step 1 but filter for darknet media type
curl -s -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_KEY" \
  -H "Content-Type: application/json" \
  -d '{"term":"target.com","maxresults":50,"media":24,"sort":2}'
# media:24 = darknet/tor content specifically
```

### 4. Threat Intelligence Feeds

Monitor for active threats, leaked data, and mentions in criminal forums.

| Source | URL | Type |
|--------|-----|------|
| DeepDarkCTI | https://github.com/fastfire/deepdarkCTI | Curated threat intel from dark web (free) |
| RansomWatch | https://ransomwatch.telemetry.ltd | Ransomware group leak site monitoring |
| Ransomware.live | https://www.ransomware.live | Real-time ransomware victim tracking |
| eCrime.ch | https://ecrime.ch | Threat intel feeds |
| AlienVault OTX | https://otx.alienvault.com | Open threat exchange (IOCs) |

```bash
# Check if target appears on ransomware leak sites
curl -s "https://api.ransomware.live/victims" | \
  jq '.[] | select(.post_title | test("target"; "i")) | {group_name, post_title, discovered, post_url}'

# DeepDarkCTI — clone and grep for target
git clone https://github.com/fastfire/deepdarkCTI.git /tmp/deepdarkCTI
grep -ri "target.com\|target bank\|PT Target" /tmp/deepdarkCTI/
```

### 5. Tor-Based OSINT (When Authorized)

Only when engagement scope explicitly includes dark web investigation:

**Tools (viable, maintained):**

| Tool | Purpose | Status |
|------|---------|--------|
| [OnionSearch](https://github.com/megadose/OnionSearch) | Search multiple .onion engines | Python, pip install |
| [TorBot](https://github.com/DedSecInside/TorBot) | Crawl .onion sites | Python, active |
| [OnionScan](https://github.com/s-rah/onionscan) | Scan .onion for misconfigs | Go, unmaintained but functional |

```bash
# Requires Tor running (port 9050)
# Install: brew install tor && tor &

# OnionSearch — search across multiple dark web engines
pip install onionsearch
onionsearch --query "target.com" --engines ahmia duckduckgo

# TorBot — crawl specific .onion if found
pip install torbot
torbot -u http://DISCOVERED_ONION.onion --depth 2

# Manual Tor proxy for curl
curl --socks5-hostname 127.0.0.1:9050 "http://ONION_ADDRESS.onion/"
```

---

## What Constitutes a Finding

| Discovery | Severity | Condition |
|-----------|----------|-----------|
| Employee credentials in breach DB | **High** | Plaintext/cracked passwords + no MFA on external services |
| Employee credentials in breach DB | **Medium** | Hashed only, or MFA confirmed on all external services |
| Company mentioned on ransomware leak site | **Critical** | Active listing with data samples |
| Internal URLs/configs on paste sites | **Medium** | Contains valid endpoints, API keys, or architecture details |
| API keys/tokens in public repos | **High–Critical** | Depending on key scope (read vs admin) |
| Company data on dark web markets | **High** | Customer PII, financial data being sold |
| Employee email pattern exposed | **Info** | Useful for phishing simulation, not a vuln alone |

---

## Reporting Template

```markdown
## [FINDING-X] Leaked Credentials in Breach Database

**Severity:** High
**CVSS 3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Affected Asset:** Employee accounts (N accounts across M breaches)
**Phase Discovered:** 1 — Passive Reconnaissance

### Description
{N} employee email addresses from @target.com were found in {M} known data breaches
dating from {earliest_date} to {latest_date}. Of these, {X} have associated plaintext
or cracked passwords. No multi-factor authentication was observed on the following
external-facing services: {list}.

### Evidence
- DeHashed query: `domain:target.com` returned {N} results
- Breaches: {breach_names with dates}
- Sample (redacted): admin@target.com found in {breach_name} ({date})
  - Password hash type: {bcrypt/MD5/SHA1/plaintext}
  - Password status: {cracked/uncracked}

### Impact
- Credential stuffing against external services (VPN, email, SSO)
- Password pattern analysis enables targeted brute-force
- Combined with employee enumeration → targeted phishing

### Remediation
1. **Immediate:** Force password reset for all affected accounts
2. **Short-term:** Enforce MFA on all external-facing services
3. **Medium-term:** Implement credential monitoring service (e.g., HIBP domain search)
4. **Long-term:** Deploy password policy that checks against known breaches (NIST 800-63B)
```

---

## Financial Sector Considerations (Bank Jago / OJK)

- **Regulatory:** OJK POJK 11/2022 requires banks to monitor for credential leaks as part of IT risk management
- **Higher severity:** Leaked banking employee credentials are more impactful than typical corporate leaks (access to core banking, customer data, transaction systems)
- **Credential reuse:** Check if leaked passwords match patterns that could work on internal systems (AD, VPN, email)
- **Third-party risk:** Check if vendor/partner domains also have breaches (supply chain credential exposure)
- **Reporting obligation:** If customer data is found on dark web, bank may have regulatory reporting obligation to OJK

---

## Tools Summary (Recommended Stack)

**Minimum viable (free):**
1. HaveIBeenPwned (domain search) — confirms breach exposure
2. IntelX (free tier) — paste sites + dark web content
3. GitHub code search — leaked secrets
4. Ahmia.fi — dark web search without Tor
5. DeepDarkCTI repo — threat intel feeds

**Full capability (paid):**
1. DeHashed API — actual credentials with passwords
2. IntelX Pro — unlimited searches, full content access
3. LeakCheck/Snusbase — additional breach databases
4. RansomWatch API — ransomware monitoring
5. Tor + OnionSearch — direct dark web enumeration
