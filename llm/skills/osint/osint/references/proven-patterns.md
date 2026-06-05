# Proven OSINT Patterns

Techniques that have produced confirmed identity correlations in past engagements.

## Handle Correlation

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| GitHub profile sidebar | Target has GitHub account | Check linked X/LinkedIn/website in profile sidebar | Direct cross-platform link |
| Git commit email mining | Target has public repos | Fetch commits via API, extract author/committer emails | Real email (often personal) |
| GitHub .keys endpoint | Need SSH key fingerprint | `https://github.com/{user}.keys` — compare across platforms | Identity confirmation |
| Username reuse | One confirmed handle | Test same handle on 12+ bot-friendly platforms | 3-5 additional accounts |
| Handle variation sweep | Base handle known | Try {handle}123, the{handle}, {handle}_, {first}{last} | Alt accounts |

## Email Discovery

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| Public events API | GitHub user active | `/users/{user}/events/public` → commit emails in push events | Emails not on profile |
| Multi-repo mining | User has 10+ repos | Iterate all repos, collect unique author emails | Work + personal emails |
| Domain MX + pattern | Company domain known | dig MX, try {first}@, {first}.{last}@, {f}{last}@ | Corporate email |
| crt.sh subdomain → email | Domain known | Certificate transparency → find mail.*, webmail.* | Email infrastructure |
| Wayback contact pages | Personal site existed | Archive.org snapshots of /contact, /about pages | Historical emails/phones |

## Location & Timezone

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| Commit hour histogram | Active GitHub user | Plot commit hours → peak reveals local timezone | City-level location |
| Language in commits | Multilingual dev | Commit messages in non-English → narrow to country | Country |
| Conference talks | Public speaker | YouTube/SlideShare → event location + dates | City + employer |
| Reddit timezone slip | Active redditor | "just woke up" / "heading to bed" posts with timestamps | Timezone confirmation |

## Organization Recon

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| GitHub org members | Org name known | `/orgs/{org}/members` (if public) → all employee handles | Employee list |
| LinkedIn company dork | Company name | `site:linkedin.com/in/ "{company}"` | Employee names + roles |
| DNS SOA/TXT records | Domain known | SPF includes reveal email providers, infra vendors | Infrastructure map |
| WHOIS history | Domain known | Historical WHOIS → pre-privacy registrant details | Real name + address |
| Job postings | Company known | Tech stack from requirements, team size, internal tools | Attack surface intel |

## Breach Correlation

| Pattern | Trigger | Technique | Yield |
|---------|---------|-----------|-------|
| HIBP email check | Email discovered | haveibeenpwned.com API → breach list | Password patterns |
| Cross-breach pivot | One breach found | Same password hash in multiple breaches → linked accounts | Alt email discovery |
| Paste search | Handle/email known | HIBP paste search → leaked configs, credential dumps | Plaintext creds |
| Domain-wide breach | Company domain | HIBP domain search → all breached employee emails | Full employee exposure |

## Anti-Patterns (False Positive Traps)

- Common handles (john_doe, admin, test) match thousands — require 2+ correlation points
- Recycled usernames — verify account creation date matches expected timeline
- Namesakes — same name ≠ same person, especially for common names
- Cached/stale data — Google snippets may show deleted content that's months old
- Bot accounts — auto-generated profiles reuse handles across platforms (not real people)
- VPN/proxy IPs in breaches — don't attribute shared infrastructure to individuals
