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
| `handles` | Username/handle enumeration across platforms |
| `emails` | Email discovery from git commits, WHOIS, public profiles, breach data |
| `platforms` | Platform presence check (GitHub, HackerOne, Bugcrowd, TryHackMe, HTB, CTFtime, etc.) |
| `domains` | Domain recon — WHOIS, DNS, MX, SPF, subdomains, hosting |
| `social` | Social media profiling (LinkedIn, X/Twitter, Instagram, TikTok, Facebook, YouTube) |
| `breaches` | Breach database lookups and paste site checks |
| `chain` | Build cross-reference chain map showing how identities link |
| `report` | Compile full OSINT report with findings |

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

## Pitfalls

1. **Rate limiting** — GitHub API: 60 req/hr unauthenticated, search engines block automated queries
2. **False positives** — common names/handles match multiple people; always verify with 2+ data points
3. **Auth walls** — LinkedIn, X/Twitter, Facebook require login for full data
4. **CAPTCHA** — Google, DuckDuckGo, Bing, Brave, Startpage all block headless browsers
5. **Nitter/proxies** — most Nitter instances are dead as of 2024+
6. **Legal** — stay within scope, don't access private data, respect platform ToS for authorized engagements
7. **Temporal** — profiles get deleted, usernames get recycled; timestamp all findings

## Tools (if available)

- `sherlock` / `maigret` — username enumeration across hundreds of sites
- `holehe` — check if email is registered on various services
- `ghunt` — Google account OSINT
- `theHarvester` — email/subdomain/name harvesting (pip3.11)
- `cloud_enum` — cloud resource enumeration (pip3.11)
