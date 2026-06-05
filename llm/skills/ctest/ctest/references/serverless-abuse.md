# Serverless Abuse

## Lambda / Cloud Functions / Azure Functions

### Environment Variable Extraction
```bash
# AWS Lambda — if you can invoke or read config
aws lambda get-function --function-name <name> --query 'Configuration.Environment.Variables'
# GCP Cloud Functions
gcloud functions describe <name> --format='value(environmentVariables)'
# Azure Functions
az functionapp config appsettings list --name <app> --resource-group <rg>
```

### Event Injection

**S3 Trigger Poisoning (AWS):**
```bash
# If you can write to the trigger bucket, upload a crafted file
# Lambda processes it — potential for: command injection in filename, SSRF via file content, deserialization
aws s3 cp malicious.json s3://<trigger-bucket>/input/
```

**SNS/SQS Injection:**
```bash
# If topic/queue allows publish from your identity
aws sns publish --topic-arn <arn> --message '{"exploit": "payload"}'
aws sqs send-message --queue-url <url> --message-body '{"cmd": "id"}'
```

**API Gateway → Lambda:**
```bash
# Direct invocation bypassing API Gateway auth
aws lambda invoke --function-name <name> --payload '{"path":"/admin","httpMethod":"GET"}' output.json
```

### Layer/Dependency Poisoning

**AWS Lambda Layers:**
```bash
# If you can publish layers or modify function config
aws lambda publish-layer-version --layer-name <name> --zip-file fileb://malicious-layer.zip
aws lambda update-function-configuration --function-name <name> --layers <malicious-layer-arn>
```

**Dependency Confusion:**
- Internal package names discoverable from error messages or source
- Publish malicious package to public registry with same name + higher version
- Lambda/Function pulls malicious version on next cold start

### Cold Start Credential Caching
- Lambda reuses execution environments for ~15 minutes
- Credentials from `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars
- Session token valid for function's role duration (up to 12 hours)
- Stolen creds work from any IP (no IP restriction on Lambda role by default)

### Timeout/Resource Abuse
- Set timeout to maximum (15 min Lambda, 9 min Cloud Functions)
- Use for: crypto mining, outbound scanning, data exfiltration relay
- Cost: ~$0.0001/invocation but scales to thousands

## Step Functions / Workflows

### State Machine Injection
```bash
# If you can start executions
aws stepfunctions start-execution --state-machine-arn <arn> --input '{"target":"attacker-controlled"}'
# If state machine passes input to Lambda/ECS without sanitization → injection
```

### Workflow Bypass
- Skip approval states by directly invoking downstream Lambdas
- Modify execution input to bypass conditional branches
- Race condition: start execution before IAM policy propagates

## API Gateway Abuse

### Authorization Bypass
```bash
# Missing authorizer on specific methods
curl -X POST https://<api-id>.execute-api.<region>.amazonaws.com/prod/admin
# Custom authorizer bypass — send request without token (authorizer may return allow-all on error)
curl https://<api-id>.execute-api.<region>.amazonaws.com/prod/resource
# WAF bypass via direct Lambda invocation (if you have lambda:InvokeFunction)
```

### Resource Policy Misconfiguration
```bash
# Check if API allows access from any AWS account
aws apigateway get-rest-api --rest-api-id <id> --query 'policy'
# Look for: "AWS": "*" or missing condition keys
```

## Serverless-Specific Findings

| Finding | Severity | Impact |
|---------|----------|--------|
| Secrets in environment variables (not Secrets Manager) | High | Credential exposure via function config read |
| Function URL with AuthType=NONE | Medium-High | Unauthenticated invocation |
| Overly permissive execution role (`*:*`) | High | Full account compromise from any code execution |
| No VPC attachment (internet-facing) | Medium | Outbound data exfiltration unrestricted |
| Event source without input validation | Medium | Injection via crafted events |
| Shared execution role across functions | Medium | Lateral movement between functions |
| No dead letter queue (silent failures) | Low | Missed security events |
| Timeout set to maximum without justification | Low | Resource abuse potential |

## Tools

| Tool | Purpose |
|------|---------|
| Pacu (Lambda modules) | AWS Lambda enumeration and exploitation |
| ServerlessGoat | Intentionally vulnerable serverless app (practice) |
| sls-dev-tools | Serverless debugging and monitoring |
| Prowler | Serverless security checks |
