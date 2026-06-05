---
name: opsec
description: "Defensive OPSEC self-assessment framework — exposure scoring, identity compartmentalization, remediation playbook, and periodic audit methodology."
version: 1.0.1
author: n4igme
license: MIT
trigger: "opsec, operational security, exposure check, identity compartment, privacy audit, digital footprint"
argument-hint: "<command: start|status|resume|next|assess|score|chain|remediate|audit|report|abort|cleanup>"
metadata:
  hermes:
    tags: [opsec, privacy, defensive, security, exposure, compartmentalization]
    related_skills: [osint, ptest]
---

# OPSEC Self-Assessment Framework

Structured methodology for assessing and reducing your own digital exposure. Think of it as pentesting yourself — finding leaks in your personal digital footprint before adversaries do.

## Quick Reference

```
Phases:  1.Inventory → 2.Exposure → 3.Scoring → 4.Chain → 5.Remediation → 6.Audit
Flow:    What exists → What's exposed → How bad → How linked → Fix it → Maintain
Commands: start | assess | score | chain | remediate | audit | report
Lifecycle: status | resume | next | abort | cleanup

Key rules:
  • Git commit history is the #1 source of identity leaks for developers
  • Deleted content persists in Wayback Machine — request explicit removal
  • 3+ hops between public persona and real identity = good compartmentalization
  • Quarterly audits catch new exposure before adversaries do
  • Don't overreact — focus on what enables real attacks, not theoretical exposure
```

## Architecture

`Inventory (What exists)` → `Assessment (What's exposed)` → `Scoring (How bad)` → `Remediation (Fix it)`

## Commands

| Command | Action |
|---------|--------|
| **Lifecycle** | |
| `start` | Initialize self-assessment — collect all known identifiers |
| `status` | Show progress: phases completed, findings by severity |
| `resume` | Resume interrupted assessment |
| `next` | Advance to next phase (check gate) |
| `abort` | Terminate assessment |
| `cleanup` | Archive output, sanitize sensitive data |
| **Phase Execution** | |
| `assess` | Phase 2: Run full exposure assessment |
| `score` | Phase 3: Rate findings by severity |
| `chain` | Phase 4: Map identity cross-reference chains |
| `remediate` | Phase 5: Generate remediation plan |
| `audit` | Phase 6: Periodic audit checklist |
| `report` | Compile full OPSEC assessment report |

### Command Procedures

**`start`:** Collect ALL identifiers → create `./opsec-output/` → write `state.yaml` + `inventory.md` → advance to Phase 2.

**`status`:** Current phase, findings by severity (🔴🟠🟡🟢), chain hops to real identity, remediation items pending.

**`resume`:** Read state.yaml. Staleness: >30 days → re-run Phase 2 (new breaches). >90 days → fresh assessment.

**`next`:** Verify gate (inventory complete / all checks run / findings scored / chain mapped / remediation written). If unmet, list gaps.

**`abort`:** Record reason, mark remaining ABORTED, cleanup.

**`cleanup`:** Archive `./opsec-output/` → `opsec-output-{date}.tar.gz`. Remove discovered credentials (document first).

### Output: `./opsec-output/`

```
state.yaml | inventory.md | exposure.md | scoring.md | chain-map.md | remediation-plan.md | audit-checklist.md | report.md
```
## Phase 1: Identity Inventory

Collect ALL known identifiers (be honest — adversaries will find them anyway):

```markdown
## My Identifiers
- Real name:
- Aliases/nicknames:
- Handles (list all):
- Email addresses (list all):
- Phone numbers:
- Domains owned:
- Employer/org:
- Location (city/region):
- Profiles (list URLs):
```

## Phase 2: Exposure Assessment

### 2.1 Git Commit Email Audit

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

### 2.2 Profile Cross-Link Audit

Check each platform profile for links to other profiles:

| Platform | What to check |
|----------|--------------|
| GitHub | Sidebar: X, LinkedIn, website, email |
| LinkedIn | Experience, education, connections, endorsements |
| X/Twitter | Bio links, display name, location |
| Personal site | About page, contact info, social links |
| YouTube | About tab, channel description, linked accounts |

**Key question:** If someone finds Profile A, can they reach Profile B in one click?

### 2.3 Public Repository Content Audit

Check repos for accidentally committed sensitive data:

- Wedding/personal sites with real names, addresses, bank accounts
- Config files with API keys or internal URLs
- README files with personal info
- `.env` files (even if deleted — check git history)
- Internal domain references in code

### 2.4 Wayback Machine & Archived Exposure

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

### 2.5 Breach Exposure Check

Check all known emails against:
- haveibeenpwned.com
- dehashed.com
- IntelX

### 2.6 Search Engine Presence

Search for:
- `"{real name}" {employer}`
- `"{handle}" site:github.com`
- `"{email}" -site:github.com`
- `"{real name}" {city/region}`

### 2.7 Domain & WHOIS Audit

```bash
whois {your-domain}
dig +short {domain} MX    # Email provider
dig +short {domain} TXT   # SPF, verification records
dig +short {domain} A     # Hosting provider
```

### 2.8 Timezone & Activity Fingerprinting

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
    print(f'  {h:02d}:00 | {\"█\" * c} ({c})')
"
```

**What this reveals about you:**
- Confirms your timezone (narrows location)
- Shows work schedule vs personal time
- Late-night commits reveal habits an adversary could exploit (e.g., phishing at 2am when you're tired)

### 2.9 Employer Derivability Check

**Can an adversary figure out where you work from public data?**

Check for:
- Internal domain names in git commits (e.g., `@company.local`, `@corp.internal`)
- Company-specific tool names in repos
- LinkedIn profile (if visible to logged-in users)
- Conference talks or blog posts mentioning employer
- "dk" in "dksec" → is the abbreviation guessable?

**Test:** Give the commit email to someone with no context. Can they Google their way to your employer? If `{prefix}sec.local` maps to a known company, it's a leak.

## Phase 3: Severity Scoring

### 🔴 CRITICAL
- Real name + home address publicly linked
- Bank account numbers exposed
- Work credentials or internal domains in public repos
- Single profile that chains to full real identity in 1 hop
- Family member names + relationship exposed

### 🟠 HIGH
- Real name linked to security handle (targeted attack risk)
- Employer clearly identifiable from public data
- Multiple emails exposed enabling credential stuffing
- Cross-links between professional and personal personas on profile pages

### 🟡 MEDIUM
- Handle exists on platform but minimal info exposed
- Location narrowed to city/region level
- Professional role/skills visible (enables targeted phishing)
- Secondary/old accounts still active

### 🟢 LOW
- Alias-only presence with no real identity link
- Generic bio/about info
- Inactive accounts with no content
- Public SSH keys (low risk unless combined with other data)

## Phase 4: Cross-Reference Chain Analysis

Map how identities connect and identify **single points of failure**:

```
[Handle A] ──direct link──→ [Handle B] ──git commit──→ [Real Name + Email]
                                                              │
                                                    [Wedding Site] ──→ [Address, Family, Bank]
```

**Metrics:**
- **Chain length:** How many hops from anonymous handle to real identity?
- **Single points of failure:** Which ONE link, if removed, breaks the chain?
- **Redundant paths:** Can the chain be rebuilt via alternate routes?

**Ideal state:** Minimum 3+ hops between public security persona and real identity, with no single point of failure.

## Phase 5: Remediation Playbook

### Priority 1: Stop the Bleeding

| Issue | Fix |
|-------|-----|
| Sensitive data in public repo | Make repo private OR remove sensitive content + force push |
| Bank accounts/addresses exposed | Remove immediately, consider the data burned |
| Cross-links on profiles | Remove X/LinkedIn/website links from GitHub sidebar |
| Work email in git commits | Can't undo history easily — see git-filter-repo below |

### Priority 2: Rewrite History

**Remove emails from git history:**
```bash
# Install git-filter-repo
pip install git-filter-repo

# Replace old email with noreply
git filter-repo --email-callback '
    if email == b"real@email.com":
        return b"user@users.noreply.github.com"
    return email
'

# Force push (destructive — backup first)
git push --force --all
```

**Note:** GitHub caches commits. Even after rewriting, old commits may be accessible via SHA for some time.

### Priority 3: Compartmentalize

**Persona separation strategy:**

| Persona | Purpose | Handles | Email |
|---------|---------|---------|-------|
| Professional | Bug bounty, CTF, security work | unique-handle | handle@proton.me |
| Personal | Social, family, non-security | different-handle | personal@gmail.com |
| Work | Employer-related | work-handle | name@company.com |

**Rules:**
- Never cross-link personas on profile pages
- Use different emails per persona
- Use GitHub noreply for all commits: `{id}+{user}@users.noreply.github.com`
- Different profile photos per persona (reverse image search links them)

### Priority 4: Ongoing Hygiene

```bash
# Set git to always use noreply
git config --global user.email "{id}+{user}@users.noreply.github.com"
git config --global user.name "{handle}"

# Verify before committing
git config user.email  # Should show noreply
```

### Priority 5: Domain Expiry Monitoring

**If you own domains linked to your identity, they MUST NOT lapse.**

- Set calendar reminders 60 days before expiry
- Enable auto-renewal on all domains
- If you no longer need a domain, keep it registered anyway (prevent impersonation)
- Monitor with: `whois {domain} | grep -i expir`

A lapsed domain can be re-registered by an adversary who then:
- Receives your old emails (if MX records are restored)
- Impersonates your former company
- Hosts phishing pages under your brand

### Priority 6: Wayback Machine Removal

If archived content contains sensitive data:
- Request removal: https://web.archive.org/web/removals
- Note: only works if you control the domain or can prove ownership
- For GitHub Pages: making repo private does NOT auto-remove from Wayback

## Phase 6: Periodic Audit Checklist

Run quarterly:

- [ ] Search own handles on Google/Bing — any new exposure?
- [ ] Check git commits on recent repos — any email leaks?
- [ ] Review GitHub profile links — still compartmentalized?
- [ ] Check haveibeenpwned for new breaches on known emails
- [ ] Review any new public repos for sensitive content
- [ ] Google own real name + location — what comes up?
- [ ] Check if any old accounts resurfaced or got compromised
- [ ] Verify domain WHOIS privacy still active
- [ ] Review social media privacy settings (LinkedIn visibility, etc.)
- [ ] Check Wayback Machine for new snapshots of your sites
- [ ] Verify domain expiry dates — nothing lapsing soon?
- [ ] Run crt.sh check on owned domains — any unexpected certs?
- [ ] Review commit timestamps — timezone still consistent with cover story?
- [ ] Check if employer is derivable from any new public data
- [ ] Verify archived content hasn't resurfaced (Wayback, Google cache)

## Report Template

```markdown
# OPSEC Self-Assessment Report

**Date:** {date}
**Subject:** {handle/identity}

## Identity Inventory
[list all known identifiers]

## Findings

### 🔴 Critical
[findings with immediate action needed]

### 🟠 High
[findings requiring short-term fixes]

### 🟡 Medium
[findings to address when possible]

### 🟢 Low
[acceptable risks / informational]

## Cross-Reference Chain
[diagram showing identity linkages]

## Attack Scenarios
[what an adversary could do with discovered info]

## Remediation Plan
| Priority | Action | Effort | Impact |
|----------|--------|--------|--------|
| 1 | ... | ... | ... |

## Comparison to Last Audit
[what improved, what's new, what regressed]
```

## Pitfalls

1. **Git history is forever** — even after rewriting, cached commits and forks preserve old data
2. **Wayback Machine** — archived versions of profiles/sites may preserve removed info; request explicit removal
3. **Google cache** — removed pages may still appear in search results for weeks
4. **Social graph** — even if YOUR profile is clean, others may tag/mention you
5. **Metadata** — photos contain EXIF (GPS, device), PDFs contain author names
6. **Timing correlation** — commit timestamps reveal timezone, work hours
7. **Writing style** — stylometry can link anonymous accounts to known authors
8. **Don't overreact** — some exposure is acceptable/unavoidable; focus on what enables real attacks
9. **Prior knowledge contamination** — when assessing yourself, separate what you know internally from what's publicly discoverable. Test by asking: "Could a stranger find this?"
10. **Domain lapse risk** — expired domains can be weaponized for impersonation and email interception
11. **Certificate transparency is permanent** — crt.sh logs are append-only; subdomains you created are visible forever
12. **Employer derivability** — internal domain prefixes in commits (e.g., `dksec.local`) may be guessable if the company abbreviation is common

## Time Budgets

| Assessment Type | Total | Inventory | Exposure | Scoring | Chain | Remediation |
|----------------|-------|-----------|----------|---------|-------|-------------|
| First full assessment | 3-4 hr | 30 min | 1.5-2 hr | 30 min | 30 min | 30 min |
| Quarterly audit | 1 hr | skip | 30 min | 15 min | skip | 15 min |
| Post-incident (breach/dox) | 2 hr | 15 min | 1 hr | 15 min | 15 min | 15 min |

**Abandon triggers:**
- No new exposure found after 1 hour of Phase 2 → your OPSEC is good, move to scoring
- All findings are 🟢 Low → skip remediation, schedule next quarterly audit
- Assessment reveals 🔴 Critical → stop assessment, remediate immediately, then resume

## Cross-Skill Integration

- **Validate your own exposure:** Run `osint` skill against your handles — `handle_check.py` from osint scripts checks 12+ platforms in one call
- **After remediation:** Re-run osint to verify fixes worked (profile removed, email no longer discoverable)
- **For team assessments:** Use osint on team members (with authorization) to find org-wide patterns
- **Domain recon overlap:** osint `references/domain-recon.md` has DNS/WHOIS/crt.sh methodology — use it in Phase 2 for your own domains
- **Breach correlation:** osint `references/breach-correlation.md` covers HIBP/DeHashed techniques — use in Phase 2.5
- **Proven patterns:** osint `references/proven-patterns.md` has handle/email discovery patterns — reverse them to find YOUR leaks

## Gate Enforcement (MANDATORY before `next`)

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/opsec/scripts"))
from gate_check import check_gate, print_gate_status

result = check_gate(".", phase=None)
print_gate_status(result)
# Only advance if result["passed"] is True
```

## Script Invocation

**state_manager.py — assessment lifecycle:**
```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/opsec/scripts"))
import state_manager

workdir = "."
state_manager.init_state(workdir, "n4igme",
    handles=["n4igme", "maurha"], emails=["test@proton.me"],
    domains=["example.com"])

state_manager.status(workdir)
state_manager.advance_phase(workdir)
state_manager.add_finding(workdir, "high", "Work email in git commits", source="github")
state_manager.set_chain_hops(workdir, 2)
state_manager.add_remediation(workdir, 1, "Remove cross-links from GitHub sidebar")
```
