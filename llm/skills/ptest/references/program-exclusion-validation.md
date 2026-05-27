# Program Exclusion Validation (Bug Bounty)

## Lesson Learned

In the Dropbox engagement (May 2026), we spent significant effort testing vectors that were explicitly listed as out-of-scope in the paid bounty program:
- **Username/email enumeration** — found 16,100 users, 78 employees → OOS
- **Tokens leaked to third parties** — found 2 valid Dropbox OAuth tokens on GitHub → OOS
- **HTTP Request smuggling without proven impact** — tested, no finding → OOS even if found
- **Host header injection without proven impact** — tested → OOS
- **Bypassing rate-limits or non-existence of rate-limits** — tested → OOS
- **Email spoofing, SPF, DMARC, DKIM** — checked → OOS
- **Banner grabbing/Version disclosure** — found nginx version → OOS

Total wasted effort: ~2 hours of testing + report writing for 0 valid findings.

## Mandatory Pre-Testing Step

**BEFORE running any technique**, parse the program's exclusion list and create an exclusion filter.

### Procedure

1. **Navigate to the program page** (Intigriti/HackerOne/Bugcrowd/YesWeHack)
2. **Extract the full "Out of Scope" section** — copy it verbatim
3. **Save to `ptest-output/program-exclusions.md`**
4. **Create a quick-reference exclusion checklist** mapping common test categories to OOS items:

```markdown
# Program Exclusions — Quick Reference

## DO NOT TEST (explicitly excluded)
- [ ] Username/email enumeration
- [ ] Rate limiting / brute force
- [ ] Token leaks to third parties
- [ ] SPF/DMARC/DKIM issues
- [ ] Missing security headers
- [ ] Missing cookie flags
- [ ] Clickjacking without proven impact
- [ ] HTTP request smuggling without proven impact
- [ ] Host header injection without proven impact
- [ ] Banner grabbing / version disclosure
- [ ] ...

## CONDITIONAL (only with proven impact)
- [ ] SSRF (must hit private IPs or internal servers, not just pingback)
- [ ] CSRF (must have real impact, not just low-impact state change)
- [ ] ...

## VALID TARGETS (not excluded)
- [ ] RCE
- [ ] SQLi
- [ ] XSS (except self-XSS, except on specific domains)
- [ ] IDOR / access control bypass
- [ ] Authentication bypass
- [ ] ...
```

5. **Cross-reference BEFORE each test phase** — before running a technique, check if the finding category is excluded

### Common Exclusion Patterns by Program

| Exclusion | Programs That Use It | What It Blocks |
|-----------|---------------------|----------------|
| "Username/email enumeration" | Dropbox, most mature programs | User enum via login/forgot/API |
| "Tokens leaked to third parties" | Dropbox | GitHub credential scanning |
| "Rate limiting" | Dropbox, many programs | Brute force, OTP bypass |
| "Missing security headers" | Almost all programs | HSTS, X-Frame-Options, CSP reports |
| "Reports from automated tools" | Dropbox, many programs | Raw nuclei/nikto output |
| "Blind SSRF without proven business impact" | Dropbox, HackerOne programs | OOB pingbacks alone |
| "HTTP Request smuggling without proven impact" | Dropbox | Theoretical smuggling |
| "Self-XSS" | Almost all programs | XSS requiring victim to paste payload |
| "Subdomain takeover without taking over" | Dropbox | Dangling CNAME without actual takeover |

### Integration with ptest Workflow

This check belongs in the `start` command, immediately after scope definition:

```
1. Define scope (targets, authorization)
2. >>> PARSE PROGRAM EXCLUSIONS <<<
3. Save exclusions to ptest-output/program-exclusions.md
4. Generate DO-NOT-TEST checklist
5. Proceed to preflight/recon
```

At each phase transition, the agent should verify:
- "Is the technique I'm about to run likely to produce a finding in an excluded category?"
- If yes → skip and document as "SKIPPED (OOS per program rules)"

### Red Flags (Stop and Check Exclusions)

Before investing time in any of these, verify they're not OOS:
- User enumeration (login, forgot password, registration, API)
- Credential leaks on third-party platforms (GitHub, Pastebin)
- Rate limiting tests
- DMARC/SPF/DKIM checks
- Missing headers/cookies
- Clickjacking
- CSRF on low-impact actions
- Subdomain takeover (without actual takeover proof)
- Open redirect (many programs exclude or rate as Info)
