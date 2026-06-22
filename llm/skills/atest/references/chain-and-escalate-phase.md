# Chain & Escalate Phase — atest

## Purpose

After initial vulnerability discovery, attempt to chain findings for higher impact.
This phase bridges individual findings into attack narratives.

## Checklist

- [ ] Review all findings for chainable pairs
- [ ] Test privilege escalation paths (horizontal → vertical)
- [ ] Attempt data exfiltration via confirmed access
- [ ] Check if BOLA findings chain with auth bypass
- [ ] Test if information disclosure enables further attacks
- [ ] Verify SSRF reach (internal services, cloud metadata)
- [ ] Document full attack path with evidence at each step

## Common Chains

1. **Info Leak → BOLA**: Disclosed IDs enable direct object access
2. **Auth Bypass → Data Exfil**: Unauthenticated access to sensitive endpoints
3. **SSRF → Cloud Creds**: Internal metadata to full account compromise
4. **Mass Assignment → Privilege Escalation**: Role injection to admin access
5. **Rate Limit Bypass → Account Takeover**: Brute force OTP/password

## Cross-Skill Triggers

| Finding | Trigger Skill | Action |
|---------|---------------|--------|
| Cloud credentials via SSRF | ctest | Start ctest Phase 2 with extracted creds |
| Source code via path traversal | scode | Run code review on extracted source |
| Internal web app discovered | ptest | Start ptest against internal target |

## Output

- `findings/chain-{N}.md` — documented attack chain with full evidence
- Update `findings.jsonl` with chain metadata and cross-references
