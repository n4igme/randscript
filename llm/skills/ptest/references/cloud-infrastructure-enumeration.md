## Cloud Infrastructure Enumeration (GCP / AWS / Azure)

Reference for discovering and mapping cloud infrastructure during external penetration tests. Techniques focus on passive and semi-passive enumeration from an external perspective.

---

## GCP Project Discovery

### IAP Client ID Extraction

When targets use Google Identity-Aware Proxy (IAP), the OAuth client_id in redirect URLs leaks the GCP project number.

```bash
# Trigger IAP auth flow and extract client_id from redirect
curl -sI https://target.example.com/ | grep -i location

# Client ID format: PROJECT_NUMBER-RANDOM.apps.googleusercontent.com
# Example: 369001918367-abc123def456.apps.googleusercontent.com
#          ^^^^^^^^^^^^^^^-- GCP project number
```

```bash
# Extract from HTML meta tags or JS bundles
curl -s https://target.example.com/ | grep -oP '\d{12}-[a-z0-9]+\.apps\.googleusercontent\.com'

# Bulk extract across subdomains
cat subdomains.txt | while read sub; do
  cid=$(curl -sk -o /dev/null -w '%{redirect_url}' "https://$sub/" | grep -oP '\d{12}-[a-z0-9]+\.apps\.googleusercontent\.com')
  [ -n "$cid" ] && echo "$sub -> $cid"
done
```

### Mapping Project Numbers to Projects

```bash
# If you have any GCP access token, resolve project number to project ID
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects?filter=projectNumber%3D369001918367"

# Using gcloud
gcloud projects list --filter="projectNumber=369001918367"
```

### Org Structure Mapping from Multiple IAP Endpoints

Real-world example (Bank Jago engagement):

- `banking.jago.com` → client_id prefix `369001918367` → Banking platform project
- `data.jago.com` → client_id prefix `1022863786872` → Data platform project

Different project numbers under the same org reveal team/product segmentation:

| Project Number | Inferred Purpose | Discovery Source |
|---|---|---|
| 369001918367 | Banking / core platform | IAP on banking subdomain |
| 1022863786872 | Data platform / analytics | IAP on data subdomain |

### GCP Service Account Discovery

```bash
# Service accounts leak in error messages, headers, metadata
# Common format: NAME@PROJECT_ID.iam.gserviceaccount.com

# Check for metadata endpoint (from compromised instance)
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/

# Enumerate default SA naming patterns
# Default compute: PROJECT_NUMBER-compute@developer.gserviceaccount.com
# Default App Engine: PROJECT_ID@appspot.gserviceaccount.com
# Custom: CUSTOM_NAME@PROJECT_ID.iam.gserviceaccount.com
```

```bash
# Check if SA exists (returns 200 if valid)
curl -s -o /dev/null -w '%{http_code}' \
  "https://iam.googleapis.com/v1/projects/TARGET_PROJECT/serviceAccounts/sa-name@TARGET_PROJECT.iam.gserviceaccount.com"
```

### GCS Bucket Enumeration

```bash
# Common naming patterns to bruteforce
# {company}-{env} | {company}-{service} | {project_id}-{purpose}

# Check bucket existence (no auth needed)
curl -s -o /dev/null -w '%{http_code}' https://storage.googleapis.com/BUCKET_NAME

# 200 = public listing, 403 = exists but private, 404 = doesn't exist

# Bulk check with wordlist
cat bucket_wordlist.txt | while read bucket; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://storage.googleapis.com/$bucket")
  echo "$bucket: $code"
done
```

```bash
# Tools for GCS enumeration
# GCPBucketBrute
python3 gcpbucketbrute.py -k target-company -s

# cloud_enum
python3 cloud_enum.py -k jago -k bankjago --disable-azure --disable-aws

# Common patterns to try
# jago-backup, jago-prod, jago-staging, bankjago-data, jago-analytics
# PROJECT_ID-assets, PROJECT_ID-tfstate, PROJECT_ID-logs
```

```bash
# List public bucket contents
gsutil ls gs://BUCKET_NAME/
curl -s "https://storage.googleapis.com/BUCKET_NAME?list-type=2"

# Check for sensitive files in public buckets
gsutil ls gs://BUCKET_NAME/**/*.{json,env,key,pem,sql,bak}
```

---

## AWS Resource Discovery

### DNS-Based Discovery

```bash
# CNAME records pointing to AWS services
dig +short CNAME sftp.target.com
# Example: s-abc123def456.server.transfer.us-east-1.amazonaws.com
#          ^-- AWS Transfer Family SFTP server

# Common AWS CNAME patterns
# ELB: NAME-123456789.REGION.elb.amazonaws.com
# CloudFront: d1234abcdef.cloudfront.net
# S3: BUCKET.s3.amazonaws.com / BUCKET.s3.REGION.amazonaws.com
# API Gateway: abc123.execute-api.REGION.amazonaws.com
# Transfer Family: s-SERVERID.server.transfer.REGION.amazonaws.com
```

Real-world example (Bank Jago engagement):
```bash
$ dig +short CNAME sftp.bankjago.co.id
s-abc123def456.server.transfer.ap-southeast-1.amazonaws.com
# Reveals: AWS Transfer Family SFTP in ap-southeast-1
# Implies: File transfer workflow, possibly partner integrations
```

### Header-Based Discovery

```bash
# Identify AWS services from response headers
curl -sI https://target.com/ | grep -iE '(x-amz|x-amzn|server|via)'

# Key headers:
# x-amz-cf-id / x-amz-cf-pop → CloudFront
# x-amzn-requestid → API Gateway / Lambda
# x-amz-request-id + x-amz-id-2 → S3
# server: AmazonS3 → S3 direct
# x-amzn-trace-id → X-Ray enabled (ELB/Lambda)
```

```bash
# Extract AWS account ID from public resources
# S3 bucket policy (if readable)
aws s3api get-bucket-policy --bucket TARGET_BUCKET --no-sign-request 2>/dev/null | jq .

# From IAM error messages during enumeration
aws sts get-caller-identity  # (if you obtain any AWS creds)
```

### AWS S3 Bucket Enumeration

```bash
# Check bucket existence
aws s3 ls s3://BUCKET_NAME --no-sign-request 2>&1

# Bulk enumeration
cat aws_buckets.txt | while read b; do
  result=$(aws s3 ls "s3://$b" --no-sign-request 2>&1)
  if echo "$result" | grep -qv "NoSuchBucket"; then
    echo "[EXISTS] $b"
  fi
done

# Tools
# cloud_enum, S3Scanner, lazys3
python3 cloud_enum.py -k bankjago -k jago --disable-gcp --disable-azure
```

### AWS Service Enumeration from DNS

```bash
# Comprehensive subdomain → AWS service mapping
cat subdomains.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if echo "$cname" | grep -q "amazonaws.com"; then
    echo "$sub -> $cname"
  fi
done

# Parse service type from CNAME
# .elb.amazonaws.com → Load Balancer (check for HTTP smuggling)
# .s3.amazonaws.com → S3 (check for public access)
# .cloudfront.net → CDN (check for origin bypass)
# .transfer.REGION.amazonaws.com → SFTP (check for weak auth)
# .execute-api.REGION.amazonaws.com → API GW (check for auth bypass)
# .rds.amazonaws.com → RDS (should not be public)
# .es.amazonaws.com → Elasticsearch (check for open access)
```

---

## Azure Resource Discovery

### DNS-Based Discovery

```bash
# Azure CNAME patterns
dig +short CNAME target.com

# Common Azure DNS patterns:
# *.azurewebsites.net → App Service
# *.blob.core.windows.net → Blob Storage
# *.database.windows.net → SQL Database
# *.vault.azure.net → Key Vault
# *.azurefd.net → Front Door
# *.trafficmanager.net → Traffic Manager
# *.azure-api.net → API Management
# *.azureedge.net → CDN
# *.servicebus.windows.net → Service Bus
```

```bash
# Enumerate Azure subdomains
cat subdomains.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if echo "$cname" | grep -qE "(azure|windows\.net|microsoft)"; then
    echo "$sub -> $cname"
  fi
done
```

### Azure Blob Storage Enumeration

```bash
# Check if storage account exists
curl -s -o /dev/null -w '%{http_code}' \
  "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# 200 = public listing, 403 = exists/private, 404 = doesn't exist

# Common container names to check
for container in backup data files uploads assets logs; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    "https://TARGET.blob.core.windows.net/$container?restype=container&comp=list")
  echo "$container: $code"
done
```

```bash
# Tools for Azure enumeration
# MicroBurst
Invoke-EnumerateAzureBlobs -Base "target"

# cloud_enum
python3 cloud_enum.py -k target --disable-gcp --disable-aws
```

### Azure Tenant Discovery

```bash
# Get tenant ID from domain
curl -s "https://login.microsoftonline.com/TARGET.COM/.well-known/openid-configuration" | jq -r .token_endpoint

# Check if domain uses Azure AD
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@TARGET.COM&json=1" | jq .

# Enumerate tenant info
curl -s "https://login.microsoftonline.com/TARGET.COM/v2.0/.well-known/openid-configuration" | jq .
```

---

## Cross-Cloud Enumeration Workflow

### Step 1: DNS Reconnaissance

```bash
# Collect all CNAMEs for subdomains
subfinder -d target.com -silent | dnsx -cname -silent -o cnames.txt

# Categorize by cloud provider
grep "amazonaws\|aws" cnames.txt > aws_services.txt
grep "google\|gcp\|googleapis" cnames.txt > gcp_services.txt
grep "azure\|windows\.net\|microsoft" cnames.txt > azure_services.txt
```

### Step 2: Header Analysis

```bash
# Bulk header grab
cat subdomains.txt | httpx -silent -H "Host: {}" -status-code -title -tech-detect -o headers_out.txt
```

### Step 3: Storage Enumeration

```bash
# All-in-one with cloud_enum
python3 cloud_enum.py -k target-company -k targetcompany -k target

# Or targeted
python3 cloud_enum.py -kf keywords.txt -l results.txt
```

## Quick Reference: Cloud Service Indicators

- **GCP IAP**: `accounts.google.com/o/oauth2` in redirects, `client_id` with 12-digit prefix
- **GCP GCE**: `Server: Google Frontend` header
- **GCP Cloud Run**: `*.run.app` domains
- **AWS CloudFront**: `x-amz-cf-id` header, `*.cloudfront.net` CNAME
- **AWS ALB/ELB**: `*.elb.amazonaws.com` CNAME, `x-amzn-trace-id` header
- **AWS S3**: `x-amz-request-id` header, `*.s3.amazonaws.com` CNAME
- **AWS Transfer**: `*.server.transfer.REGION.amazonaws.com` CNAME
- **Azure App Service**: `*.azurewebsites.net` CNAME
- **Azure Blob**: `*.blob.core.windows.net` CNAME
- **Azure Front Door**: `*.azurefd.net` CNAME, `x-azure-ref` header

## Tools Summary

- **cloud_enum**: Multi-cloud storage/service enumeration
- **GCPBucketBrute**: GCP bucket brute-forcing with permission checks
- **S3Scanner**: AWS S3 bucket discovery and permission testing
- **MicroBurst**: Azure enumeration toolkit (PowerShell)
- **subfinder + dnsx**: Subdomain discovery with DNS resolution
- **httpx**: Bulk HTTP probing with tech detection
- **gcloud / aws-cli / az**: Native CLI tools for authenticated enumeration
