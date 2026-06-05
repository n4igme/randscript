# Phase 10: Reporting

### Gate: All findings documented, severity validated, report generated

**Steps:**

1. Compile findings with:
   - Title and severity (Critical/High/Medium/Low/Info)
   - Affected component (client/server/both)
   - Platform (Android/iOS/both)
   - Steps to reproduce (with screenshots/video)
   - Impact statement
   - Remediation recommendation
   - OWASP Mobile Top 10 mapping

2. Generate report.md with:
   - Executive summary
   - Scope and methodology
   - Findings table (sorted by severity)
   - Detailed findings
   - Attack chain diagram (how findings combine)
   - Remediation roadmap (prioritized)
   - Appendix: tool versions, device info, test dates

3. Generate exploitation-walkthrough.md (CTF/lab contexts, or when client requests):
   - Step-by-step reproduction from APK to full exploitation
   - Include all commands, scripts, and code needed to reproduce
   - Structure: identify target → reverse logic → build exploit → execute → verify
   - Include cracking scripts (Python) for any brute-forced secrets
   - Include PoC code (malicious app, Frida script, or adb commands)
   - Target audience: someone who has never seen the app before

---

## Finding Template

```markdown
# MTEST-XXX: [Title]

**Severity:** Critical|High|Medium|Low|Info
**Confidence:** Confirmed|Probable|Theoretical
**Platform:** Android|iOS|Both
**Component:** Client|Server|Both
**OWASP Mobile:** M1-M10 mapping
**MASVS v2:** MASVS-STORAGE|MASVS-CRYPTO|MASVS-AUTH|MASVS-NETWORK|MASVS-PLATFORM|MASVS-CODE|MASVS-RESILIENCE|MASVS-PRIVACY
**Feature:** [Which feature from attack surface map]

## Description
[What the vulnerability is]

## Confidence Justification
[Why this confidence level — what was verified vs assumed]

## Steps to Reproduce
1. ...
2. ...
3. ...

## Evidence
[Screenshots, request/response, Frida output]

## Impact
[What an attacker can achieve]

## Remediation
[How to fix it]
```

## Finding Confidence Levels

| Level | Meaning | Bug Bounty Expectation |
|-------|---------|----------------------|
| **Confirmed** | Exploited dynamically on production build (non-rooted, logged-in user) | Full payout, Critical/High accepted |
| **Probable** | Code path proven + partial dynamic evidence (e.g., intent accepted, activity launched) but full chain not demonstrated | Reduced payout, may be downgraded |
| **Theoretical** | Code path exists in decompiled source but blocked by runtime condition (feature flag, server config, auth gate) that couldn't be verified | Often Informational/Won't Fix unless code evidence is compelling |

**Rules:**
- Never rate a finding Critical with Theoretical confidence
- Probable + Critical code path = submit as High
- Theoretical findings must explicitly state what runtime condition blocks exploitation
- If you can't distinguish Confirmed from Theoretical (e.g., can't test on non-rooted device), state that limitation

## Severity Guidelines (Mobile-specific)

| Severity | Examples |
|----------|----------|
| Critical | Hardcoded credentials with server access, RCE via WebView, auth bypass exposing all accounts |
| High | SSL pinning absent on banking app, plaintext token storage, BOLA on financial endpoints |
| Medium | Missing root detection, exported activities with sensitive data, weak crypto |
| Low | Missing screenshot protection, clipboard exposure, verbose logs |
| Info | Missing obfuscation, outdated SDK versions, unused permissions |
