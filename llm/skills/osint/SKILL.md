---
name: osint
description: "Offensive person/organization OSINT reconnaissance — handle correlation, email discovery, platform enumeration, breach checks, and cross-reference chain mapping."
version: 1.0.0
author: n4igme
license: MIT
argument-hint: "<command: start|handles|emails|platforms|domains|social|breaches|chain|report>"
metadata:
  hermes:
    tags: [osint, reconnaissance, intelligence, security, offensive]
    related_skills: [ptest, opsec]
---

# OSINT Reconnaissance Framework

Structured person/organization open-source intelligence gathering with progressive discovery.

## Architecture

`Seed (Initial Data)` → `Expansion (Discovery)` → `Correlation (Linking)` → `Report (Findings)`

## Commands

$ARGUMENTS

| Command | Action |
|---------|--------|
| `start` | Initialize OSINT engagement — collect seed data (name, handle, email, domain, location) |
| `preflight` | Verify tool availability (curl, dig, whois, python3, sherlock/maigret if installed) |
| `status` | Show current progress — seeds collected, platforms checked, findings count |
| `resume` | Resume interrupted engagement — reload state and continue from last checkpoint |
| `handles` | Username/handle enumeration across platforms |
| `emails` | Email discovery from git commits, WHOIS, public profiles, breach data |
| `platforms` | Platform presence check (GitHub, HackerOne, Bugcrowd, TryHackMe, HTB, CTFtime, etc.) |
| `domains` | Domain recon — WHOIS, DNS, MX, SPF, subdomains, hosting |
| `social` | Social media profiling (LinkedIn, X/Twitter, Instagram, TikTok, Facebook, YouTube) |
| `breaches` | Breach database lookups and paste site checks |
| `chain` | Build cross-reference chain map showing how identities link |
| `report` | Compile full OSINT report with findings |
| `cleanup` | Archive engagement output, remove temporary files |

## Phase 1: Seed Collection

Gather initial data points. Minimum 1 required, more = better results.

**Seed types:**
- Real name (full or partial)
- Username/handle
- Email address
- Phone number
- Domain/website
- Company/organization
- Location (city, country)
- Profile URL

## Phase 2: Handle Correlation

### Technique: Direct Platform Enumeration

Check target handle across platforms:

```
GitHub:      https://github.com/{handle}
GitHub API:  https://api.github.com/users/{handle}
HackerOne:   https://hackerone.com/{handle}
Bugcrowd:    https://bugcrowd.com/{handle}
TryHackMe:   https://tryhackme.com/r/p/{handle}
HTB:         https://app.hackthebox.com/users/{handle} (requires auth)
CTFtime:     https://ctftime.org/team/list/?q={handle}
LinkedIn:    https://linkedin.com/in/{handle}
X/Twitter:   https://x.com/{handle}
Instagram:   https://instagram.com/{handle}
TikTok:      https://tiktok.com/@{handle}
YouTube:     https://youtube.com/@{handle}
Medium:      https://medium.com/@{handle}
Reddit:      https://reddit.com/user/{handle}
Telegram:    https://t.me/{handle}
Keybase:     https://keybase.io/{handle}
```

### Technique: GitHub Profile Cross-Links

GitHub profiles often expose linked accounts:
- Check profile sidebar for X, LinkedIn, Instagram, website links
- Check `.keys` endpoint: `https://github.com/{handle}.keys`
- Check `.gpg` endpoint: `https://github.com/{handle}.gpg`

### Technique: Username Variations

Generate variations from known handle:
- Prefix/suffix: `{handle}123`, `{handle}_`, `the{handle}`
- Separators: `{first}.{last}`, `{first}_{last}`, `{first}-{last}`
- Abbreviations: first initial + last name, first name + last initial
- Leet speak: common substitutions (a→4, e→3, i→1, o→0)

## Phase 3: Email Discovery

### Technique: Git Commit Mining

```bash
# From GitHub API — check multiple repos
curl -s "https://api.github.com/users/{user}/repos?per_page=100&sort=updated" | \
  python3 -c "import json,sys; [print(r['name']) for r in json.load(sys.stdin) if not r.get('fork')]"

# Extract emails from commits
curl -s "https://api.github.com/repos/{user}/{repo}/commits?per_page=100" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
emails = set()
for commit in data:
    c = commit.get('commit', {})
    for field in ['author', 'committer']:
        info = c.get(field, {})
        email = info.get('email', '')
        name = info.get('name', '')
        if email and 'noreply' not in email:
            emails.add(f'{name} <{email}>')
for e in sorted(emails):
    print(e)
"
```

### Technique: Public Events API

```bash
curl -s "https://api.github.com/users/{user}/events/public" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
emails = set()
for event in data:
    payload = event.get('payload', {})
    for commit in payload.get('commits', []):
        author = commit.get('author', {})
        if author.get('email'):
            emails.add(f\"{author['name']} <{author['email']}>\")
for e in sorted(emails):
    print(e)
"
```

### Technique: Domain Email Patterns

If domain known:
- Check MX records: `dig +short {domain} MX`
- Check SPF: `dig +short {domain} TXT`
- Common patterns: `{first}@`, `{first}.{last}@`, `{f}{last}@`, `{first}{l}@`

## Phase 3.5: Wayback Machine & Archived Content

**Critical source — deleted content persists in archives.**

### Technique: CDX API Search

```bash
# Find all archived URLs for a domain
curl -s "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50"

# Check specific page history
curl -s "https://web.archive.org/cdx/search/cdx?url={url}&output=json"
```

### Technique: Retrieve Archived Pages

```bash
# Get archived version of a page (use timestamp from CDX results)
curl -s "https://web.archive.org/web/{timestamp}/{url}"

# Extract text content from archived HTML
curl -s "https://web.archive.org/web/{timestamp}/{url}" | python3 -c "
import sys, re
html = sys.stdin.read()
html = re.sub(r'<script[^>]*>[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
html = re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html, flags=re.IGNORECASE)
html = re.sub(r'<[^>]+>', ' ', html)
lines = [l.strip() for l in html.split('\n') if l.strip() and len(l.strip()) > 20]
for line in lines:
    if not any(x in line for x in ['function(', 'var ', '{', '}', 'margin', 'padding']):
        print(line)
"
```

### What to look for:
- Old "About Us" / team pages with real names, photos, roles
- Contact pages with emails, phone numbers, addresses
- Blog posts with personal details
- Removed repos/pages that once had sensitive content
- Old company websites linked to the target

## Phase 3.6: Timezone & Activity Pattern Analysis

### Technique: Commit Timestamp Analysis

```bash
# Extract commit timestamps from a repo
curl -s "https://api.github.com/repos/{user}/{repo}/commits?per_page=100" | python3 -c "
import json, sys
from datetime import datetime, timedelta
data = json.load(sys.stdin)
hours = []
for commit in data:
    date_str = commit['commit']['author']['date']
    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    # Adjust for suspected timezone (e.g., UTC+7 for WIB)
    local = dt + timedelta(hours=7)
    hours.append(local.hour)
from collections import Counter
print('Hour distribution (UTC+7):')
for h, c in sorted(Counter(hours).items()):
    print(f'  {h:02d}:00 | {\"█\" * c} ({c})')
"
```

### What this reveals:
- Timezone (narrows location to region)
- Work schedule (9-5 vs freelancer vs night owl)
- Weekend vs weekday patterns (employment indicator)

## Phase 3.7: Certificate Transparency

```bash
# Find all certificates issued for a domain
curl -s "https://crt.sh/?q=%25.{domain}&output=json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
seen = set()
for cert in data:
    name = cert.get('name_value', '')
    not_before = cert.get('not_before', '')
    if name not in seen:
        seen.add(name)
        print(f'{name} | issued: {not_before}')
"
```

### What this reveals:
- Subdomains (staging, dev, internal tools)
- Domain ownership timeline (when certs were first/last issued)
- Whether domain is still actively maintained

## Phase 4: Domain Recon

```bash
# DNS records
dig +short {domain} A
dig +short {domain} MX
dig +short {domain} TXT
dig +short {domain} NS

# WHOIS
whois {domain}

# Certificate transparency
curl -s "https://crt.sh/?q=%25.{domain}&output=json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for cert in data:
    names.add(cert.get('name_value', ''))
for n in sorted(names):
    print(n)
"
```

## Phase 5: Social Media Profiling

### Platform-Specific Techniques

**LinkedIn** (requires auth for full data):
- Public profile: `linkedin.com/in/{slug}`
- Directory: `linkedin.com/pub/dir/{First}/{Last}`
- Auth wall vs "not found" = existence confirmation

**YouTube:**
- Channel about page reveals join date, subscriber count, linked sites
- Video content reveals interests, voice, face, location clues

**Instagram/TikTok:**
- Bio, follower/following counts, linked accounts
- Post content for location/activity patterns

## Phase 6: Breach & Paste Checks

```bash
# HaveIBeenPwned (requires API key)
curl -s -H "hibp-api-key: {key}" "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

# DeHashed, IntelX, etc. (paid services)
# Check manually: haveibeenpwned.com, dehashed.com
```

## Phase 7: Cross-Reference Chain

Build a graph showing how identities connect:

```
{Handle A} ──[platform link]──→ {Handle B}
     │                              │
     └──[git commit]──→ {Email}     └──[profile bio]──→ {Real Name}
                           │
                           └──[breach data]──→ {Password pattern}
```

**Chain strength ratings:**
- 🔴 Direct link (profile cross-reference, same page)
- 🟠 Strong inference (same unique email across platforms)
- 🟡 Moderate inference (similar username pattern + same location)
- 🟢 Weak inference (common name, needs additional confirmation)

## Report Template

```markdown
# OSINT Report: {Target Identifier}

## Seeds Used
- [list initial data points]

## Identity Summary
- Real name:
- Known aliases:
- Location:
- Occupation:
- Employer:

## Accounts Discovered
| Platform | Handle/URL | Confidence | Notes |
|----------|-----------|------------|-------|

## Emails Discovered
| Email | Source | Associated Names |
|-------|--------|-----------------|

## Cross-Reference Chain
[diagram showing linkages]

## Key Findings
[notable discoveries, ranked by significance]

## Recommendations
[for offensive: next steps / for defensive: exposure risks]
```

## Principles

### Data Source Separation

**Critical:** Always distinguish between:
- **Publicly derived** — found through OSINT techniques from public sources
- **Prior knowledge** — information you already knew (from conversations, internal docs, etc.)
- **Inferred** — logical deductions that aren't confirmed

Mark each finding with its source. Contaminating a report with prior knowledge makes it unreliable for assessing what an actual adversary could discover.

### Search Engine Reality (2024+)

Automated search is largely dead for OSINT:
- Google, Bing, DuckDuckGo, Brave, Startpage — all CAPTCHA-block headless browsers
- Nitter instances are dead (X/Twitter proxy)
- Most useful data comes from **direct platform APIs** and **archived content**

**Effective sources that still work without auth:**
- GitHub API (60 req/hr unauthenticated)
- Wayback Machine CDX API (unlimited)
- crt.sh (certificate transparency, unlimited)
- DNS/WHOIS (direct queries)
- YouTube (public channel data)
- TikTok (public profiles)
- HackerOne/Bugcrowd (public profiles)

## Pitfalls

1. **Rate limiting** — GitHub API: 60 req/hr unauthenticated, search engines block automated queries
2. **False positives** — common names/handles match multiple people; always verify with 2+ data points
3. **Auth walls** — LinkedIn, X/Twitter, Facebook require login for full data
4. **CAPTCHA** — Google, DuckDuckGo, Bing, Brave, Startpage all block headless browsers — don't waste time
5. **Nitter/proxies** — most Nitter instances are dead as of 2024+
6. **Legal** — stay within scope, don't access private data, respect platform ToS for authorized engagements
7. **Temporal** — profiles get deleted, usernames get recycled; timestamp all findings
8. **Wayback persistence** — deleted content lives forever in archives; always check web.archive.org
9. **Prior knowledge contamination** — if you already know things about the target, separate that from what you discovered through OSINT
10. **Reverse image search** — profile photos can link accounts; check if target uses same photo across platforms
8. **Common names** — "M. Habib Indonesia" returns thousands of results. Always demand at least one unique identifier (handle, email, domain, specific location) before starting.

## What Actually Works (Browser Automation)

Platforms that DON'T block headless browsers:
- **GitHub** (API + web) — best source for developers. Commits, profiles, repos, orgs all accessible.
- **YouTube** — channel pages, about info, video listings all render fine.
- **TikTok** — public profiles render with follower counts and display names.
- **HackerOne** — public profiles accessible without auth.
- **Bugcrowd** — returns 404 for non-existent, loads for existing (even if empty).
- **Wayback Machine** — CDX API + archived pages work perfectly.
- **crt.sh** — certificate transparency JSON API, no blocks.
- **Instagram** — shows page title with display name even without login (e.g., "name (@handle) • Instagram photos and videos"), but full content requires auth.

Platforms that BLOCK:
- All search engines (Google, Bing, DuckDuckGo, Brave, Startpage)
- LinkedIn (auth wall, but "not found" vs redirect distinguishes existence)
- X/Twitter (login required for search/profiles)
- Medium (Cloudflare challenge)
- Facebook (login required)

## Effective Workflow Order

1. Start with GitHub API (richest unauthenticated data source for tech targets)
2. Mine git commits for emails/names across ALL repos
3. Check Wayback Machine for archived versions of discovered domains/sites
4. Enumerate handles on bot-friendly platforms (TikTok, YouTube, HackerOne, TryHackMe)
5. Use crt.sh + DNS for domain intelligence
6. LinkedIn/X existence check via redirect behavior (can't see content but confirms existence)
7. Save search engine queries for manual follow-up by the user

## Tools (if available)

- `sherlock` / `maigret` — username enumeration across hundreds of sites
- `holehe` — check if email is registered on various services
- `ghunt` — Google account OSINT
- `theHarvester` — email/subdomain/name harvesting (pip3.11)
- `cloud_enum` — cloud resource enumeration (pip3.11)
