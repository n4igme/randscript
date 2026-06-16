---
name: osint
description: "Offensive person/organization OSINT reconnaissance — handle correlation, email discovery, platform enumeration, breach checks, and cross-reference chain mapping."
version: 1.0.2
author: n4igme
license: MIT
trigger: "osint, recon person, find handles, email discovery, platform enumeration, breach check, identity correlation, dox"
argument-hint: "<command: start|status|resume|next|handles|emails|platforms|domains|social|breaches|chain|report|abort|cleanup>"
notes:
  - "v1.1.0: Added Quick Reference, state.yaml schema, gates, command procedures, output path, staleness check"
metadata:
  hermes:
    tags: [osint, reconnaissance, intelligence, security, offensive]
    related_skills: [ptest, opsec, w3hunt, atest, ctest]
---

# OSINT Reconnaissance Framework

Structured person/organization open-source intelligence gathering with progressive discovery.

## Quick Reference

```
Phases:  1.Seed → 2.Handles → 3.Emails → 4.Domains → 5.Social → 6.Breaches → 7.Chain+Report
Flow:    Seed collection → Expansion (discover) → Correlation (link) → Report
Commands: start | handles | emails | platforms | domains | social | breaches | chain | report
Lifecycle: status | resume | next | abort | cleanup

Key rules:
  • Minimum 1 unique seed required (handle, email, domain) — common names alone are insufficient
  • Always distinguish: publicly derived vs prior knowledge vs inferred
  • Timestamp all findings (profiles get deleted, usernames recycled)
  • 2+ data points required before confirming identity match
  • GitHub API is the richest unauthenticated source for tech targets
  • Search engines are dead for automation (CAPTCHA) — use direct APIs
```

## Architecture

`Seed (Initial Data)` → `Expansion (Discovery)` → `Correlation (Linking)` → `Report (Findings)`

## Commands

| Command | Action |
|---------|--------|
| **Lifecycle** | |
| `start` | Initialize engagement — collect seed data |
| `status` | Show progress: seeds, platforms checked, findings |
| `resume` | Resume interrupted engagement |
| `next` | Advance to next phase (check gate) |
| `abort` | Terminate engagement — target out of scope or legal concern |
| `cleanup` | Archive output, remove temp files |
| **Phase Execution** | |
| `handles` | Phase 2: Username enumeration across platforms |
| `emails` | Phase 3: Email discovery (git, WHOIS, profiles, breaches) |
| `platforms` | Platform presence check (GitHub, HackerOne, Bugcrowd, etc.) |
| `domains` | Phase 4: Domain recon (WHOIS, DNS, MX, SPF, subdomains, crt.sh) |
| `social` | Phase 5: Social media profiling |
| `breaches` | Phase 6: Breach database lookups |
| `chain` | Phase 7: Build cross-reference chain map |
| `report` | Compile full OSINT report |

### Command Procedures

**`start`:**
1. Collect seed data (minimum 1 unique identifier): name, handle, email, phone, domain, company, location, profile URL.
2. Create output directory: `./osint-output/`
3. Initialize `state.yaml`.
4. Write seeds to `seeds.md`.
5. Advance to Phase 2.

**`status`:** Output current phase, seeds collected, platforms checked, findings count, chain links discovered. If no engagement, suggest `start`.

**`resume`:**
1. Read `state.yaml`.
2. **Staleness:** >7 days → re-check key profiles (may be deleted/changed). >30 days → re-verify all findings (usernames get recycled, profiles deleted).
3. Report status and suggest next action.

**`next`:**
1. Verify current phase gate is satisfied.
2. If NOT met: list what's missing.
3. If met: update state.yaml, advance.
4. Override allowed with justification.

**`abort`:** Record reason, mark remaining phases ABORTED, run cleanup.

**`cleanup`:** Archive `./osint-output/` to `osint-output-{target}-{date}.tar.gz`. Print summary.

---

## State Tracking

Output path: `./osint-output/`

```yaml
engagement:
  target: ""          # Primary identifier
  started: ""
  status: "active"    # active|completed|aborted

current_phase: 1

gateways:
  1_seed: OPEN
  2_handles: LOCKED
  3_emails: LOCKED
  4_domains: LOCKED
  5_social: LOCKED
  6_breaches: LOCKED
  7_chain_report: LOCKED

seeds:
  names: []
  handles: []
  emails: []
  domains: []
  phones: []
  locations: []

findings_count: 0
platforms_checked: 0
chain_links: 0
notes: ""
```

## Output Structure

```
./osint-output/
├── state.yaml
├── seeds.md              # Initial data points
├── handles.md            # Phase 2: discovered handles
├── emails.md             # Phase 3: discovered emails
├── domains.md            # Phase 4: domain intelligence
├── social.md             # Phase 5: social media findings
├── breaches.md           # Phase 6: breach data
├── chain-map.md          # Phase 7: cross-reference chain
└── report.md             # Final compiled report
```

---

## Phase Routing

| Phase | Gate | Command |
|-------|------|---------|
| 1 Seed Collection | At least 1 unique identifier collected | `start` |
| 2 Handle Correlation | At least 3 platforms checked, variations tested | `handles` / `platforms` |
| 3 Email Discovery | Git commits mined, domain patterns checked | `emails` |
| 4 Domain Recon | DNS/WHOIS/crt.sh completed for all known domains | `domains` |
| 5 Social Media | All bot-friendly platforms checked | `social` |
| 6 Breach Checks | HIBP or equivalent checked for all discovered emails | `breaches` |
| 7 Chain + Report | Cross-reference map built, report generated | `chain` / `report` |

---

## Phase 2: Handle Correlation

### Direct Platform Enumeration

Check target handle across platforms (bot-friendly — no CAPTCHA):

```
GitHub:      https://github.com/{handle}
GitHub API:  https://api.github.com/users/{handle}
HackerOne:   https://hackerone.com/{handle}
Bugcrowd:    https://bugcrowd.com/{handle}
TryHackMe:   https://tryhackme.com/r/p/{handle}
CTFtime:     https://ctftime.org/team/list/?q={handle}
YouTube:     https://youtube.com/@{handle}
TikTok:      https://tiktok.com/@{handle}
Medium:      https://medium.com/@{handle}
Reddit:      https://reddit.com/user/{handle}
Telegram:    https://t.me/{handle}
Keybase:     https://keybase.io/{handle}
```

**Auth-walled (existence check only):** LinkedIn (`/in/{handle}`), X/Twitter, Instagram, Facebook.

### GitHub Profile Cross-Links
- Profile sidebar: X, LinkedIn, Instagram, website links
- `.keys` endpoint: `https://github.com/{handle}.keys`
- `.gpg` endpoint: `https://github.com/{handle}.gpg`

### Username Variations
- Prefix/suffix: `{handle}123`, `the{handle}`, `{handle}_`
- Separators: `{first}.{last}`, `{first}_{last}`
- Abbreviations: first initial + last, first + last initial

---

## Phase 3: Email Discovery

### Git Commit Mining
```bash
curl -s "https://api.github.com/repos/{user}/{repo}/commits?per_page=100" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
emails = set()
for commit in data:
    c = commit.get('commit', {})
    for field in ['author', 'committer']:
        email = c.get(field, {}).get('email', '')
        name = c.get(field, {}).get('name', '')
        if email and 'noreply' not in email:
            emails.add(f'{name} <{email}>')
for e in sorted(emails): print(e)
"
```

### Public Events API
```bash
curl -s "https://api.github.com/users/{user}/events/public" | \
  python3 -c "
import json, sys
emails = set()
for event in json.load(sys.stdin):
    for commit in event.get('payload', {}).get('commits', []):
        author = commit.get('author', {})
        if author.get('email'):
            emails.add(f\"{author['name']} <{author['email']}>\")
for e in sorted(emails): print(e)
"
```

### Domain Email Patterns
- MX records: `dig +short {domain} MX`
- SPF: `dig +short {domain} TXT`
- Common patterns: `{first}@`, `{first}.{last}@`, `{f}{last}@`

### Wayback Machine (deleted content persists)
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50"
```
Look for: old team pages, contact pages, blog posts with personal details.

### Timezone from Commit Patterns
Commit hour distribution reveals timezone → narrows location.

### Certificate Transparency
```bash
curl -s "https://crt.sh/?q=%25.{domain}&output=json" | python3 -c "
import json, sys
for cert in json.load(sys.stdin):
    print(cert.get('name_value', ''))
" | sort -u
```

---

## Phase 4: Domain Recon

**Full methodology:** `skill_view(name='osint', file_path='references/domain-recon.md')`

### Corporate OSINT (organizations)

**Full methodology:** `skill_view(name='osint', file_path='references/corporate-osint-patterns.md')`

Covers: employee enumeration (LinkedIn dorks, GitHub org mining), email pattern discovery, ASN/IP range mapping, cloud asset discovery, acquisition/subsidiary mapping, tech stack fingerprinting from job posts, supply chain (npm/PyPI/Docker).

Quick checklist:
1. DNS full record pull (A, AAAA, MX, TXT, NS, SOA, DMARC)
2. ASN lookup → CIDR range mapping → reverse DNS on entire range
3. Subdomain enumeration: crt.sh + subfinder + amass passive, then active brute
4. Cloud asset discovery (S3, GCP buckets, Azure blobs with company name permutations)
5. HTTP probe all discovered hosts (httpx with tech detection)
6. Historical data: Wayback Machine for deleted pages, old endpoints, exposed files
7. Correlation triggers → feed findings to ptest/ctest/scode

---

## Phase 5: Social Media Profiling

**Full methodology:** `skill_view(name='osint', file_path='references/social-media-profiling.md')`

Quick checklist:
1. GitHub (richest source): profile metadata, repos, orgs, stars, SSH/GPG keys, gists, commit emails
2. LinkedIn via Google dorks: `site:linkedin.com/in/ "{name}" "{company}"`
3. Reddit comment history: subreddit participation reveals location, employer, interests
4. Telegram/Discord: public group membership, channel ownership
5. Cross-platform correlation: handle reuse, timezone triangulation, photo reverse search
6. Network graph: who they interact with, shared connections across platforms

---

## Phase 6: Breach & Paste Checks

**Full methodology:** `skill_view(name='osint', file_path='references/breach-correlation.md')`

Quick checklist:
1. HIBP: email → breaches list + paste search
2. HIBP domain search: all breached emails for target domain
3. DeHashed/IntelX/Snusbase: full credential lookup (if authorized)
4. Password pattern analysis: identify base words, rotation schemes, reuse risk
5. Cross-breach correlation: trace alternate emails, phone numbers, IP addresses
6. Feed actionable intel: valid creds → ctest, API keys → atest, internal URLs → ptest

---

## Phase 7: Cross-Reference Chain

Build a graph showing how identities connect:

```
{Handle A} ──[platform link]──→ {Handle B}
     │                              │
     └──[git commit]──→ {Email}     └──[profile bio]──→ {Real Name}
                           │
                           └──[breach data]──→ {Password pattern}
```

**Chain strength:** 🔴 Direct link | 🟠 Strong inference | 🟡 Moderate | 🟢 Weak (needs confirmation)

---

## Report Template

```markdown
# OSINT Report: {Target Identifier}

## Seeds Used
## Identity Summary
- Real name / Known aliases / Location / Occupation / Employer

## Accounts Discovered
| Platform | Handle/URL | Confidence | Notes |

## Emails Discovered
| Email | Source | Associated Names |

## Cross-Reference Chain
[diagram]

## Key Findings
## Recommendations
```

---

## Cross-Skill Triggers

**Into osint (from other skills):**
- ptest Phase 1 needs target intel (employee names, tech stack, email patterns) → invoke osint
- opsec needs offensive validation of own exposure → invoke osint against own handles
- w3hunt needs team/developer enumeration for a DeFi protocol → invoke osint

**Out of osint (to other skills):**
- Domain/infra discovered → hand to ptest Phase 1 (add to attack surface)
- Cloud assets found (S3 buckets, GCP projects) → hand to ctest Phase 1
- Source code repos discovered → hand to scode
- Credentials found in breaches → hand to ptest Phase 6 (credential stuffing)
- API keys/tokens discovered → hand to atest or ctest (validate scope)
- Identity chain complete for self → hand to opsec (defensive assessment)

| osint Finding | Triggers | Action |
|---------------|----------|--------|
| Subdomains + live hosts | ptest | Add to scope, begin Phase 2 active recon |
| Leaked AWS/GCP creds in breach | ctest | IAM access analysis |
| GitHub repos with source | scode | Code review for vulns |
| Employee emails enumerated | ptest | Phishing surface, credential stuffing |
| Personal handle → real identity chain | opsec | Defensive remediation |

---

## Operational Rules

### Data Source Separation
Always distinguish: **Publicly derived** vs **Prior knowledge** vs **Inferred**. Mark each finding with its source.

### What Works (2024+)
**Bot-friendly:** GitHub API, Wayback Machine, crt.sh, DNS/WHOIS, YouTube, TikTok, HackerOne, Bugcrowd.
**Blocked:** All search engines, LinkedIn (content), X/Twitter, Medium, Facebook.

### Pitfalls
1. Rate limiting — GitHub: 60 req/hr unauthenticated
2. False positives — common names match multiple people; verify with 2+ data points
3. Common names — demand at least one unique identifier before starting
4. Auth walls — LinkedIn, X, Facebook require login for full data
5. Temporal — profiles get deleted, usernames recycled; timestamp everything
6. Legal — stay within scope, respect platform ToS
7. Prior knowledge contamination — separate what you knew from what you discovered

### Time Budgets & Abandon Heuristics

| Target Type | Total Budget | Expansion | Correlation | Report |
|-------------|-------------|-----------|-------------|--------|
| Person (unique handle) | 2-3 hr | 1.5 hr | 30 min | 30 min |
| Person (common name) | 3-4 hr | 2 hr | 1 hr | 30 min |
| Organization | 4-6 hr | 3 hr | 1.5 hr | 1 hr |

**Abandon triggers:**
- No unique handle/email found after 30 min → demand better seed data from requester
- No new findings after 45 min of expansion → stop expanding, move to correlation
- Common name + no unique identifier → abort unless requester provides additional context
- All platforms return 404 for handle → try variations for 15 min max, then move to email-based discovery
- GitHub has no public repos/commits → skip git mining, focus on other platforms
- Target appears to have strong OPSEC (no public presence) → document absence as finding, report in 30 min

### Tools (if available)
`sherlock`/`maigret` (username enum), `holehe` (email registration check), `theHarvester` (email/subdomain harvesting)

### Script Invocation

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/osint/scripts"))
import state_manager, handle_check
from gate_check import check_gate, print_gate_status

# Initialize
state_manager.init_state(".", target="handle", handles=["n4igme"], emails=["x@y.com"])

# Check handle across platforms
results = handle_check.check("n4igme")

# Lifecycle
state_manager.status(".")
state_manager.advance_phase(".")
state_manager.add_finding(".", "GitHub", "handle1", source="public", confidence="high")
state_manager.add_chain_link(".", "handle1", "real@email.com", "git commit", "strong")
state_manager.increment_platforms(".", count=5)
state_manager.abandon(".", "No unique identifier available")

# Gate check before advancing
result = check_gate(".", phase=None)
print_gate_status(result)
```
