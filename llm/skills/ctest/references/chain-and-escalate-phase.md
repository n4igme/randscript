# Chain & Escalate Phase — ctest

## Purpose

After discovering cloud/container misconfigurations, chain findings for maximum impact demonstration.

## Checklist

- [ ] Test if discovered credentials grant cross-service access
- [ ] Check if container escape leads to host/cluster access
- [ ] Verify if IAM role chaining enables privilege escalation
- [ ] Test lateral movement between cloud services
- [ ] Check if discovered secrets unlock additional resources
- [ ] Document full attack path from initial access to impact

## Common Chains

1. **S3 Misconfiguration → Credential Harvest → Account Takeover**
2. **SSRF → IMDS → IAM Role → Cross-Account Access**
3. **Container Escape → Node Access → Cluster Admin**
4. **Exposed Secrets → CI/CD Pipeline → Code Execution**
5. **Overprivileged Lambda → IAM Escalation → Admin**

## Cross-Skill Triggers

| Finding | Trigger Skill | Action |
|---------|---------------|--------|
| Web app in container | ptest | Test web vulnerabilities |
| API keys in config | atest | Test API with extracted keys |
| Source code in bucket | scode | Review for hardcoded secrets |
| AD credentials found | adtest | Attempt domain escalation |

## Output

- `findings/chain-{N}.md` — full attack chain documentation
- Update `findings.jsonl` with chain metadata
