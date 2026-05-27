# Person OSINT Methodology

## When to Use
User asks to research a specific person (security researcher, colleague, target employee, CTF player, bug bounty hunter). Different from infrastructure OSINT — requires identity anchors, not domain names.

## Critical: Seed Data Requirements

Person OSINT on common names (especially "Muhammad", "Habib", "Ahmad" in Indonesia/MENA) is nearly impossible without at least ONE additional identifier:
- Username or handle
- Email address
- Company/organization
- Phone number
- City (not just country)
- Platform where they were seen (conference, CTF, bug bounty)
- Profile photo or avatar

**If the user only provides a common name + country, ASK for more identifiers before spending time searching.** Explain why: "That name has thousands of matches in Indonesia — I need at least one more anchor point."

## Platform Access (Browserbase Limitations)

### Works WITHOUT auth (use these first):
- **GitHub user search** — `github.com/search?q=<name>+location:<country>&type=users`
- **HackerOne profiles** — `hackerone.com/<username>` (direct URL, no search)
- **Bugcrowd profiles** — `bugcrowd.com/<username>` (direct URL, no search)
- **GitHub profile pages** — `github.com/<username>` (bio, repos, orgs, location)
- **YouTube search** — `youtube.com/results?search_query=<name>+<keywords>` — works reliably, no CAPTCHA. Channel "About" dialog shows join date, subscriber count, total views, and linked URLs. Excellent for finding content creators in niche communities.
- **YouTube channel pages** — `youtube.com/@<handle>/about` — shows linked socials, description
- **TikTok profiles** — `tiktok.com/@<username>` — shows follower/following counts and bio WITHOUT auth
- **TryHackMe** — `tryhackme.com/r/p/<username>` — page title shows "TryHackMe | <username>" if profile exists (content may not render in headless browser, but title confirms existence)
- **Keybase** — `keybase.io/<username>`
- **CTFtime** — team search at `ctftime.org/team/list/` (type name in search box, click "Show team profile")

### Partially works (existence confirmation without full content):
- **Instagram** — `instagram.com/<username>/` — page title shows "name (@handle) • Instagram photos and videos" if profile exists; requires login for actual content
- **LinkedIn** — `linkedin.com/in/<slug>` — if it redirects to auth wall (sign-up page), profile likely exists. If it shows "Profile Not Found" page, it doesn't exist. Useful signal even without login.

### Requires auth (cannot use via Browserbase):
- LinkedIn (full profile content)
- X/Twitter (redirects to login)
- Facebook (shows "content isn't available" without login)

### Blocked by CAPTCHA (Browserbase detected as bot):
- Google Search
- Bing (intermittent — sometimes works, then triggers Cloudflare)
- DuckDuckGo
- Brave Search
- Startpage

## Workarounds for Search Engine Blocking

1. **Use platform-specific searches directly** — skip Google, go straight to GitHub/HackerOne/CTFtime
2. **Ask user to search manually** on LinkedIn/Twitter (they're logged in) and share findings
3. **Username enumeration tools** (if we have a candidate username):
   - Check same username across platforms manually: github.com, hackerone.com, bugcrowd.com, keybase.io, ctftime.org
4. **Google cache/cached pages** — sometimes accessible when search isn't
5. **Archive.org** — `web.archive.org/web/*/twitter.com/<username>` can show deleted profiles

## Person OSINT Workflow

### Step 1: Gather Seeds
Ask user for ALL known identifiers. Don't start searching with just a name.

### Step 2: Platform Sweep (no-auth platforms)
For each candidate username/name:
- GitHub: profile, repos, contributions, orgs
- HackerOne/Bugcrowd: profile, activity, reputation
- CTFtime: team membership, writeups
- Personal blog/portfolio (if URL known)
- YouTube: channel search (often reveals full legal names)

### Step 3: Git Commit Email Extraction (HIGH VALUE)
Once a GitHub account is found, extract ALL emails from commit history:
```bash
# List repos
curl -s "https://api.github.com/users/<username>/repos?per_page=100&sort=updated" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for repo in data:
    if not repo.get('fork', False):
        print(repo['name'])"

# Extract emails from each repo's commits
curl -s "https://api.github.com/repos/<username>/<repo>/commits?per_page=10" | python3 -c "
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
    print(e)"
```

This often reveals:
- **Real names** used in git config (people forget to anonymize)
- **Work emails** with employer domains (e.g., `user@company.local`, `user@corp.com`)
- **Multiple personal emails** (Gmail, custom domains)
- **Aliases** — different display names used at different times
- **Side project domains** — custom email domains reveal other ventures

Also check: `https://github.com/<username>.keys` for SSH public keys (fingerprinting).

### Step 4: Cross-Reference & Expand
- Each discovered email/alias → probe as username on other platforms
- Work domain → identify employer, team
- Custom domains → WHOIS, DNS (MX records reveal Google Workspace, etc.)
- `dig +short <domain> MX` / `dig +short <domain> TXT` / `dig +short <domain> NS`

### Step 5: Personal Repos Deep Dive
Look for repos that leak personal info:
- **Wedding/invitation sites** — expose full names, family, addresses, bank accounts
- **Portfolio/resume repos** — education, work history
- **Config repos** (dotfiles) — may contain hostnames, paths, internal references
- **Personal blogs** (GitHub Pages) — about pages, bio, linked socials

### Step 6: Report Findings
Present structured: name, usernames, platforms, location, skills, affiliations, activity level.

## OPSEC Exposure Assessment (Full)

When user requests a complete OPSEC assessment on a target (or themselves):

### Structure the report by severity:
1. **🔴 CRITICAL** — PII exposure (real name, address, bank accounts, family members)
2. **🔴 CRITICAL** — Identity chain (single hop from anonymous handle to real identity)
3. **🟠 HIGH** — Cross-platform linking (handles publicly connected)
4. **🟡 MEDIUM** — Professional exposure (employer, skills, tools visible)
5. **🟢 LOW** — Aliases discovered (additional handles/names found)

### Include attack scenarios:
- Targeted phishing (using discovered personal details)
- Social engineering (employer/colleague impersonation)
- Physical targeting (if address exposed)
- Financial fraud (if bank details exposed)
- Credential stuffing (known emails against breach databases)

### Provide actionable recommendations:
- **Immediate** — remove/privatize critical exposures
- **Short-term** — fix git config, remove cross-links
- **Long-term** — persona separation strategy, ongoing monitoring

## Indonesian Cybersecurity Community Specifics

Common platforms for Indonesian security researchers:
- **IDSECCONF** — Indonesia Security Conference (speakers list)
- **Cyber Jawara** — Indonesian CTF competition
- **HackerOne/Bugcrowd** — many Indonesian hunters active
- **Exploit.id** — Indonesian security community
- **GitHub** — check orgs like `nicehash-id`, `tokopedia`, `gojek`, `bukalapak`
- **LinkedIn** — primary professional platform (requires manual search by user)

## Name Variation Strategy

When the user provides an abbreviated or uncertain name (e.g., "M. Habib"):
1. **Ask what "M." stands for** — don't assume "Muhammad" (could be Mabrur, Mochammad, Muhamad, etc.)
2. **Try geographic narrowing** — "Sumut" = Sumatera Utara, use `location:"sumatera utara"` on GitHub
3. **YouTube is gold for niche communities** — small cybersecurity content creators often use their full legal name as channel name, revealing the complete identity
4. **Username pattern consistency** — once you find one handle (e.g., `mabrurhabib`), probe the same handle across all platforms
5. **Full name discovery** — YouTube/LinkedIn often reveal full names (e.g., "Muhammad Mabrur Al Mutaqi") that the user didn't know, which unlocks further searches

## Pitfalls
- Don't waste time on search engines via Browserbase — they ALL block with CAPTCHAs
- Common Indonesian names (Muhammad, Ahmad, Habib, Rizky) need extra identifiers
- HackerOne/Bugcrowd username guessing is low-yield without a known handle
- GitHub `location:indonesia` filter works but returns many results for common names
- Bing sometimes renders results about the letter itself when using quoted searches with single letters like "M"
- YouTube search works but results mix unrelated channels — look for cybersecurity keywords in video titles/descriptions to filter
- TikTok/Instagram with `<firstname><lastname>` pattern (no separator) is a common Indonesian username convention — try both `mabrurhabib` and `mabrur.habib` and `mabrur_habib`
- `delegate_task` subagents do NOT have web search tools — don't waste time delegating OSINT searches to them
- When a target's GitHub profile cross-links multiple platforms (X, LinkedIn, website), that's the single biggest OPSEC failure — document it prominently in findings
- Git commit history is PERMANENT — even if user changes config today, old commits retain the original author/email. This makes it the most reliable OSINT source on GitHub.
- Check BOTH original repos AND forked repos — forks may have commits with different email configs than the main account
- `github.com/<username>.keys` returns SSH public keys (useful for fingerprinting across systems)
- Wedding/invitation repos are goldmines — people forget these are public and include full family names, addresses, bank accounts, dates
