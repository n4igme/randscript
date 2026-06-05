# Social Media Profiling — Deep Methodology

## Platform-Specific Extraction

### LinkedIn (Auth-Walled)

**Without login:**
- Google dork: `site:linkedin.com/in/ "{name}" "{company}"`
- Company employees: `site:linkedin.com/in/ "{company}" "{role}"`
- Page title reveals: name, headline, location (even without login)
- Public company page: `/company/{slug}` → employee count, recent posts

**With login (personal account):**
- Employee list via company page → People tab
- Shared connections reveal network graph
- Activity feed leaks internal project names, tool choices
- Endorsements reveal tech stack proficiency
- "People also viewed" sidebar reveals colleagues

**Data points:** Job title, employer, location, education, certifications, tech skills, career timeline

### GitHub (Richest Unauthenticated Source)

```bash
# Profile metadata
curl -s "https://api.github.com/users/{handle}" | jq '{name, company, location, blog, bio, email, twitter_username, created_at}'

# All repos (reveals internal tool names, side projects)
curl -s "https://api.github.com/users/{handle}/repos?per_page=100&sort=updated" | \
  jq '.[] | {name, description, language, fork, created_at}'

# Starred repos reveal interests/tech stack
curl -s "https://api.github.com/users/{handle}/starred?per_page=100" | jq '.[].full_name'

# Organizations (reveals employers, side projects)
curl -s "https://api.github.com/users/{handle}/orgs" | jq '.[].login'

# SSH keys (fingerprint can be cross-referenced)
curl -s "https://github.com/{handle}.keys"

# GPG keys (may contain email, name)
curl -s "https://github.com/{handle}.gpg"

# Contribution graph timing → timezone detection
# Gist search for secrets/notes
curl -s "https://api.github.com/users/{handle}/gists" | jq '.[].files|keys[]'
```

### X/Twitter

**Without login (limited):**
- Google cache: `site:twitter.com/{handle}`
- Nitter instances: `https://nitter.net/{handle}` (may be down)
- Wayback: `https://web.archive.org/web/*/twitter.com/{handle}`

**Data points:** Bio links, location, join date, following/followers ratio, tweet frequency, topics

### Instagram

**Without login:**
- `https://www.instagram.com/{handle}/?__a=1&__d=dis` (may require headers)
- Page source contains: biography, external_url, follower count, is_verified
- Story highlights visible from profile (thumbnails without login)
- Tagged location from posts reveals frequent places

**Google dork:** `site:instagram.com "{name}"` or `"{handle}"`

### Telegram

```bash
# Check if handle resolves
curl -s "https://t.me/{handle}" | grep -o 'tgme_page_title.*' 

# Public channel/group member lists (if group is public)
# Bot API for group member enumeration (requires bot in group)
```

**Indicators:** Phone number proximity (if shared in group), join date, bio, linked channels

### Discord

- Public server invite links from other profiles/bios
- Discord ID lookup: `https://discord.id/` services
- Server member lists if you join public servers
- Message history in public channels reveals timezone, interests, alt accounts

### Reddit

```bash
# Full comment/post history (reveals interests, location hints, employer mentions)
curl -s "https://www.reddit.com/user/{handle}/comments.json?limit=100" | \
  jq '.data.children[].data | {subreddit, body, created_utc}'

# Subreddit participation reveals: location (r/city), employer (r/company), hobbies
```

### Domain WHOIS (Historical)

```bash
# Current WHOIS (usually privacy-protected now)
whois {domain}

# Historical WHOIS (pre-privacy era records)
# Services: DomainTools, WhoisXMLAPI, SecurityTrails
# Reveals: real name, email, phone, address from original registration
```

## Cross-Platform Correlation Techniques

### Handle Reuse Detection
1. Same handle across platforms → likely same person
2. Similar handle with number suffix (handle → handle123) → likely same
3. Same bio text or profile photo → confirm with reverse image search

### Timezone Triangulation
- GitHub commit hours → UTC offset
- Tweet/post timestamps → active hours
- Time-based greetings ("good morning" + timestamp) → timezone
- Multiple sources agreeing on timezone narrows to region

### Photo Cross-Reference
```bash
# Reverse image search profile photos
# Google Images, Yandex (better for faces), TinEye
# PimEyes for facial recognition (paid, controversial)
```

### Email → Handle Correlation
- Gravatar: `https://gravatar.com/{md5_of_email}` → linked profiles
- GitHub: search commits by email across all public repos
- Keybase: `https://keybase.io/_/api/1.0/user/lookup.json?emails={email}`

## Operational Notes

- **Rate limiting:** GitHub API = 60 req/hr unauthenticated, 5000/hr with token
- **Auth walls:** LinkedIn, Instagram, Facebook aggressively block scrapers. Use Google dorks as proxy.
- **Ephemeral content:** Stories, tweets get deleted. Screenshot immediately on discovery.
- **Username recycling:** Verify account creation date matches expected timeline. Old handles get recycled.
- **Legal boundaries:** Public information only. No credential stuffing, no accessing private content with leaked creds.

## Output Format

```markdown
## Social Profile: {handle/name}

### Platform Presence
| Platform | Handle/URL | Verified | Last Active | Confidence |

### Identity Indicators
- Timezone: {UTC offset} (source: {commit patterns/post times})
- Location: {city/country} (source: {profile/posts/geotags})
- Employer: {company} (source: {LinkedIn/GitHub org/bio})
- Tech Stack: {languages/tools} (source: {repos/endorsements})

### Network Graph
- Connected to: {other handles/people} via {platform/interaction}

### Timeline
| Date | Event | Source |
```
