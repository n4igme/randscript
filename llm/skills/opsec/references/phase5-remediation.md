# Phase 5: Remediation Playbook

## Priority 1: Stop the Bleeding

| Issue | Fix |
|-------|-----|
| Sensitive data in public repo | Make repo private OR remove sensitive content + force push |
| Bank accounts/addresses exposed | Remove immediately, consider the data burned |
| Cross-links on profiles | Remove X/LinkedIn/website links from GitHub sidebar |
| Work email in git commits | Can't undo history easily — see git-filter-repo below |

## Priority 2: Rewrite History

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

## Priority 3: Compartmentalize

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

## Priority 4: Ongoing Hygiene

```bash
# Set git to always use noreply
git config --global user.email "{id}+{user}@users.noreply.github.com"
git config --global user.name "{handle}"

# Verify before committing
git config user.email  # Should show noreply
```

## Priority 5: Domain Expiry Monitoring

**If you own domains linked to your identity, they MUST NOT lapse.**

- Set calendar reminders 60 days before expiry
- Enable auto-renewal on all domains
- If you no longer need a domain, keep it registered anyway (prevent impersonation)
- Monitor with: `whois {domain} | grep -i expir`

A lapsed domain can be re-registered by an adversary who then:
- Receives your old emails (if MX records are restored)
- Impersonates your former company
- Hosts phishing pages under your brand

## Priority 6: Wayback Machine Removal

If archived content contains sensitive data:
- Request removal: https://web.archive.org/web/removals
- Note: only works if you control the domain or can prove ownership
- For GitHub Pages: making repo private does NOT auto-remove from Wayback
