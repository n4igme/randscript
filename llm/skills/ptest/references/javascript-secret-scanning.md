# JavaScript Secret Scanning

Mandatory Phase 3 technique. Collect all JavaScript files from live hosts and scan for hardcoded secrets, API keys, tokens, and credentials.

## Why This Is Mandatory

In the BFI engagement, we missed:
- Multiple Google API keys reused across dev/SIT/UAT/prod
- Hardcoded secrets (`Secret:"G4nsI81QagRMUchH8jEG"`)
- JWT tokens from third-party integrations
- CI/CD path leaks revealing GitHub Actions usage
- Pub tokens for marketing platforms (Insider)
- Hardcoded password patterns

These were found across 163 JS files from 285 hosts — a bulk scan that takes minutes but reveals high-value findings.

## Methodology

### Step 1: Collect JS Files

```bash
#!/bin/bash
# collect-js-files.sh
# Crawl all live hosts and extract JS file URLs

INPUT="${1:-live-subs.txt}"
OUTPUT="js-files.txt"
TOTAL=$(wc -l < "$INPUT" | tr -d ' ')
COUNT=0

echo "[*] Collecting JS files from ${TOTAL} hosts..."
> "$OUTPUT"

while IFS='|' read -r sub rest; do
  sub=$(echo "$sub" | tr -d ' ')
  [ -z "$sub" ] && continue
  COUNT=$((COUNT + 1))
  [ $((COUNT % 50)) -eq 0 ] && echo "[*] Progress: ${COUNT}/${TOTAL}"
  
  # Fetch page and extract JS URLs
  curl -s "https://${sub}" --max-time 10 -k 2>/dev/null | \
    grep -oE '(src|href)="[^"]*\.js[^"]*"' | \
    grep -oE '"[^"]*"' | tr -d '"' | \
    while read -r jsurl; do
      # Resolve relative URLs
      case "$jsurl" in
        http*) echo "$jsurl" ;;
        //*) echo "https:${jsurl}" ;;
        /*) echo "https://${sub}${jsurl}" ;;
        *) echo "https://${sub}/${jsurl}" ;;
      esac
    done >> "$OUTPUT"
done < "$INPUT"

sort -u "$OUTPUT" -o "$OUTPUT"
FOUND=$(wc -l < "$OUTPUT" | tr -d ' ')
echo "[*] Found ${FOUND} unique JS files"
```

### Step 2: Scan for Secrets

```bash
#!/bin/bash
# scan-js-secrets.sh
# Download and scan JS files for hardcoded secrets

INPUT="${1:-js-files.txt}"
OUTPUT="js-secrets.txt"
TMPDIR=$(mktemp -d)
TOTAL=$(wc -l < "$INPUT" | tr -d ' ')
COUNT=0

echo "[*] Scanning ${TOTAL} JS files for secrets..."
> "$OUTPUT"

while read -r url; do
  COUNT=$((COUNT + 1))
  [ $((COUNT % 25)) -eq 0 ] && echo "[*] Progress: ${COUNT}/${TOTAL}"
  
  content=$(curl -s "$url" --max-time 10 -k 2>/dev/null)
  [ -z "$content" ] && continue
  
  # Scan with regex patterns
  echo "$content" | grep -oEn "$PATTERNS" | while read -r match; do
    echo "[!] SECRET found in: $url"
    echo "    Match: $match"
    echo ""
  done >> "$OUTPUT"
done < "$INPUT"

FOUND=$(grep -c "^\[!\]" "$OUTPUT" 2>/dev/null || echo 0)
echo "[*] Done. ${FOUND} potential secrets found."
rm -rf "$TMPDIR"
```

## Regex Patterns

### High-Confidence (likely real secrets)

```bash
# API Keys
AIza[0-9A-Za-z_-]{35}                          # Google API Key
AKIA[0-9A-Z]{16}                                # AWS Access Key
sk-[a-zA-Z0-9]{20,}                             # OpenAI / Stripe Secret Key
ghp_[a-zA-Z0-9]{36}                             # GitHub Personal Access Token
glpat-[a-zA-Z0-9_-]{20,}                        # GitLab Personal Access Token

# AI/ML API Keys
sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}    # Anthropic API Key
sk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}  # OpenAI Project Key
sess-[A-Za-z0-9]{40}                             # OpenAI User Session
hf_[A-Za-z0-9]{30,}                              # HuggingFace Token

# Infrastructure & Cloud
dop_v1_[a-f0-9]{64}                              # DigitalOcean Token
SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}      # SendGrid API Key
SK[0-9a-fA-F]{32}                                # Twilio API Key
AC[a-f0-9]{32}                                   # Twilio Account SID

# Package Registries
npm_[A-Za-z0-9]{36}                              # npm Token
pypi-AgENdGV[A-Za-z0-9_\-]+                      # PyPI Token
dckr_pat_[A-Za-z0-9_\-]{27,}                     # Docker Hub PAT

# SaaS & Observability
ATATT3xFfGF0[A-Za-z0-9_\-]{180,}                 # Atlassian API Token
lin_api_[A-Za-z0-9]{40}                          # Linear API Key
https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+  # Slack Webhook URL

# Bot Tokens
[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}       # Discord Bot Token
\d{8,10}:[A-Za-z0-9_\-]{35}                      # Telegram Bot Token

# Cloudflare
(?i)cf[_\-]?api[_\-]?key['": ]+([a-f0-9]{37})   # Cloudflare Global API Key

# Tokens
eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*  # JWT Token
xox[baprs]-[0-9a-zA-Z-]{10,}                    # Slack Token

# Secrets in assignments
["\']?[Ss]ecret["\']?\s*[:=]\s*["\'][^"\']{8,}  # Secret = "value"
["\']?[Pp]assword["\']?\s*[:=]\s*["\'][^"\']{4,} # Password = "value"
["\']?[Tt]oken["\']?\s*[:=]\s*["\'][^"\']{8,}   # Token = "value"
["\']?[Aa]pi[_-]?[Kk]ey["\']?\s*[:=]\s*["\'][^"\']{8,}  # ApiKey = "value"
["\']?[Aa]ccess[_-]?[Tt]oken["\']?\s*[:=]\s*["\'][^"\']{8,}  # AccessToken = "value"

# Private keys
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----

# Connection strings
(postgres|mysql|mongodb|redis|amqp):\/\/[^\s"']+  # Database URLs with credentials
```

### Medium-Confidence (may be false positives)

```bash
# Generic hex/base64 secrets (high false positive rate)
["\']?[Kk]ey["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{20,}
PWD[:=]["\'][^"\']+                              # PWD:"path" (may be CI/CD path)
["\']?[Cc]lient[_-]?[Ss]ecret["\']?\s*[:=]\s*["\'][^"\']{8,}
```

## Classification

After scanning, classify each finding:

| Type | Severity | Action |
|------|----------|--------|
| AWS Access Key (AKIA...) | CRITICAL | Verify if active, report immediately |
| Private Key | CRITICAL | Report immediately |
| Database connection string with password | CRITICAL | Report immediately |
| Google API Key (AIza...) | MEDIUM-HIGH | Check API restrictions, test for billing abuse |
| JWT Token | MEDIUM | Check if expired, decode payload for info |
| Hardcoded secret/password | HIGH | Verify if it's a real credential vs placeholder |
| CI/CD path leak | LOW | Information disclosure (reveals build system) |
| Marketing/analytics token (pub...) | LOW | Usually public by design |
| `PASSWORD="Password"` pattern | LOW-MEDIUM | May be placeholder or default |

## False Positive Filtering

Common false positives to filter out:

```bash
# Ignore these patterns
PASSWORD="Password"          # UI label, not a real password (but document anyway)
token="+_e.refreshToken      # Code logic, not a hardcoded token
Token:"revalidate_token_error"  # Error string, not a token value
Password:"/forgot-password"  # URL path, not a password
```

**Rule:** When in doubt, include it in the report as "Unverified" rather than filtering it out. Let the client determine if it's a real secret.

## Tools (alternatives to manual scripting)

| Tool | Install | Notes |
|------|---------|-------|
| trufflehog | `brew install trufflehog` | Best for git repos, also works on files |
| gitleaks | `brew install gitleaks` | Fast regex-based scanner |
| nuclei (exposure templates) | `nuclei -t exposures/` | Includes JS secret detection |
| LinkFinder | `pip3 install linkfinder` | Finds endpoints in JS (not secrets) |
| SecretFinder | `pip3 install secretfinder` | Purpose-built for JS secret scanning |
| mantra | `go install github.com/MrEmpy/mantra@latest` | Fast JS secret hunter |

## Reporting

```markdown
## [FINDING-N] Hardcoded Secrets in JavaScript Files ({count} secrets across {hosts} hosts)

**Severity:** {based on highest-severity secret found}
**Affected Assets:** {list hosts where secrets were found}
**Environment:** {dev/sit/uat/prod — note if same secret appears in multiple envs}

### Secrets Found

| # | Type | Value (redacted) | Source URL | Environment |
|---|------|-----------------|-----------|-------------|
| 1 | Google API Key | AIzaSy...48Ek | pinjaman.bfi.co.id/main.js | prod |
| 2 | Hardcoded Secret | G4nsI8...12a | ca.sit.bravo.bfi.co.id/app.js | SIT |
| 3 | JWT Token | eyJhbG...Rcvr | useinsider.com/ins.js | UAT |

### Key Observations
- {Note if same key appears across multiple environments}
- {Note if keys are restricted or unrestricted}
- {Note CI/CD paths or build system info leaked}

### Remediation
1. Rotate all exposed secrets immediately
2. Implement server-side proxy for API keys (never embed in client JS)
3. Use environment variables, not hardcoded values
4. Add pre-commit hooks to detect secrets before deployment
5. Scan JS bundles in CI/CD pipeline before release
```

## Integration with Other Phases

- **Phase 5 (Vuln Assessment):** Test discovered API keys for validity and scope
- **Phase 6 (Exploitation):** Use valid keys/tokens for authenticated access
- **Phase 7 (Post-Exploitation):** Document what access the secrets provide

## Lesson Learned

> "JavaScript files are the #1 source of accidentally exposed secrets in web applications.
> A 5-minute bulk scan across all hosts finds what hours of manual testing misses.
> Never skip this step — it's low effort, high reward."
