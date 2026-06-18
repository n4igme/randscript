# Phase 2: Exposure Assessment

## 2.1 Git Commit Email Audit

**This is the #1 source of identity leaks for developers.**

```bash
# List all emails across all repos
for repo in $(curl -s "https://api.github.com/users/{USER}/repos?per_page=100" | \
  python3 -c "import json,sys; [print(r['name']) for r in json.load(sys.stdin)]"); do
  curl -s "https://api.github.com/repos/{USER}/$repo/commits?per_page=100" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    for c in data:
        commit = c.get('commit', {})
        for field in ['author', 'committer']:
            info = commit.get(field, {})
            email = info.get('email', '')
            name = info.get('name', '')
            if email and 'noreply' not in email:
                print(f'{name} <{email}>')
" 2>/dev/null
done | sort -u
```

**What to look for:**
- Work emails (`@company.local`, `@corp.domain`)
- Personal emails linking alias → real name
- Multiple names used with same email (alias correlation)
- Internal domain names revealing employer

## 2.2 Profile Cross-Link Audit

Check each platform profile for links to other profiles:

| Platform | What to check |
|----------|--------------|
| GitHub | Sidebar: X, LinkedIn, website, email |
| LinkedIn | Experience, education, connections, endorsements |
| X/Twitter | Bio links, display name, location |
| Personal site | About page, contact info, social links |
| YouTube | About tab, channel description, linked accounts |

**Key question:** If someone finds Profile A, can they reach Profile B in one click?

## 2.3 Public Repository Content Audit

Check repos for accidentally committed sensitive data:

- Wedding/personal sites with real names, addresses, bank accounts
- Config files with API keys or internal URLs
- README files with personal info
- `.env` files (even if deleted — check git history)
- Internal domain references in code

## 2.4 Wayback Machine & Archived Exposure

**Deleted content persists in archives. This is a separate risk category.**

```bash
curl -s "https://web.archive.org/cdx/search/cdx?url={your-domain}/*&output=json&limit=50"
```

**What to check:**
- Old versions of personal sites with more info than current version
- Removed pages (wedding invites, resumes, portfolios) that are still cached
- Former company websites that reveal your role/name
- Old blog posts with personal details you later deleted

**Key insight:** Making a repo private or deleting a page does NOT remove it from Wayback Machine. You must explicitly request removal via: https://web.archive.org/web/removals

## 2.5 Breach Exposure Check

Check all known emails against:
- haveibeenpwned.com
- dehashed.com
- IntelX

## 2.6 Search Engine Presence

Search for:
- `"{real name}" {employer}`
- `"{handle}" site:github.com`
- `"{email}" -site:github.com`
- `"{real name}" {city/region}`

## 2.7 Domain & WHOIS Audit

```bash
whois {your-domain}
dig +short {domain} MX    # Email provider
dig +short {domain} TXT   # SPF, verification records
dig +short {domain} A     # Hosting provider
```

## 2.8 Timezone & Activity Fingerprinting

```bash
# Analyze your own commit timestamps
for repo in $(curl -s "https://api.github.com/users/{USER}/repos?per_page=100" | \
  python3 -c "import json,sys; [print(r['name']) for r in json.load(sys.stdin) if not r.get('fork')]"); do
  curl -s "https://api.github.com/repos/{USER}/$repo/commits?per_page=50" 2>/dev/null
done | python3 -c "
import json, sys, re
from datetime import datetime, timedelta
from collections import Counter
hours = []
for line in sys.stdin:
    dates = re.findall(r'\"date\":\"([^\"]+)\"', line)
    for d in dates:
        try:
            dt = datetime.fromisoformat(d.replace('Z', '+00:00'))
            local = dt + timedelta(hours=7)  # adjust to your TZ
            hours.append(local.hour)
        except: pass
print('Hour distribution:')
for h, c in sorted(Counter(hours).items()):
    print(f'  {h:02d}:00 | {chr(9608) * c} ({c})')
"
```

**What this reveals about you:**
- Confirms your timezone (narrows location)
- Shows work schedule vs personal time
- Late-night commits reveal habits an adversary could exploit (e.g., phishing at 2am when you're tired)

## 2.9 Employer Derivability Check

**Can an adversary figure out where you work from public data?**

Check for:
- Internal domain names in git commits (e.g., `@company.local`, `@corp.internal`)
- Company-specific tool names in repos
- LinkedIn profile (if visible to logged-in users)
- Conference talks or blog posts mentioning employer
- "dk" in "dksec" → is the abbreviation guessable?

**Test:** Give the commit email to someone with no context. Can they Google their way to your employer? If `{prefix}sec.local` maps to a known company, it's a leak.
