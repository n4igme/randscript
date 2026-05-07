---
name: recon-passive
description: Passive reconnaissance — gather intelligence without touching the target directly.
version: 2.0.0
metadata:
  category: reconnaissance
  phase: 1
  requires_toolsets: [read, bash]
---

# Skill: Passive Reconnaissance

## When to Use
- First phase of any engagement.
- When you need to map the attack surface without alerting the target.

## Techniques
1. **OSINT Gathering:** Search public sources (WHOIS, DNS records, certificate transparency logs, social media, job postings).
2. **Subdomain Enumeration:** Passive sources (crt.sh, SecurityTrails, Wayback Machine, Google dorks).
3. **Technology Fingerprinting:** Identify tech stack from public-facing assets (Wappalyzer, BuiltWith, HTTP headers).
4. **Email/Credential Harvesting:** Search breach databases, paste sites, GitHub leaks.
5. **Network Mapping:** ASN lookup, IP range identification, BGP data.

## Output
Document findings in `recon-passive-results.md`:
- Target domains and subdomains
- IP ranges and ASNs
- Technology stack
- Potential usernames/emails
- Exposed services or data

## Exit Criteria
- [ ] Attack surface is mapped (domains, IPs, subdomains).
- [ ] Technology stack identified.
- [ ] Potential entry points listed.
- [ ] No direct contact with target systems was made.
