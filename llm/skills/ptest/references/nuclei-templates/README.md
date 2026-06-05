# Custom Nuclei Templates

Proven attack patterns encoded as nuclei templates. Run during Phase 1 exit as background recon.

## Usage

```bash
# Run all custom templates against target
nuclei -t ~/.hermes/skills/security/ptest/references/nuclei-templates/ -u https://target.com

# Run specific template
nuclei -t ~/.hermes/skills/security/ptest/references/nuclei-templates/cors-credentials.yaml -l urls.txt

# Run with rate limiting (avoid WAF)
nuclei -t ~/.hermes/skills/security/ptest/references/nuclei-templates/ -rl 10 -u https://target.com
```

## Templates

| Template | Severity | What it finds |
|----------|----------|---------------|
| prerequisite-skip.yaml | High | Consent/approval endpoints accepting without prerequisites |
| otp-oracle.yaml | Medium | Differential responses on OTP endpoints (brute-force viable) |
| cors-credentials.yaml | High | Origin reflection + credentials = cross-origin data theft |
| api-version-downgrade.yaml | High | Older API versions lacking auth enforcement |

## Adding New Templates

After finding a new generalizable pattern:
1. Write template in this directory
2. Add entry to attack-recipes.md with trigger + technique
3. Test on known-vulnerable target to confirm detection
