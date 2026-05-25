# AWS Attack Paths

## Initial Access Vectors

### Leaked Credentials
- GitHub/GitLab commit history (`AKIA*`, `ASIA*` prefixes)
- `.env` files in public repos or exposed web roots
- Terraform state files in public S3 buckets
- CI/CD logs with environment variables
- Docker images with baked-in credentials (`docker history --no-trunc`)
- Client-side JS bundles (Cognito pool IDs, API keys)

### Unauthenticated Access
- Public S3 buckets: `aws s3 ls s3://<bucket> --no-sign-request`
- Public SNS topics: `aws sns list-subscriptions-by-topic`
- Public SQS queues: `aws sqs receive-message --queue-url <url>`
- Public ECR repositories
- Cognito identity pools with unauthenticated role
- API Gateway without authorization

### SSRF to Metadata
```bash
# IMDSv1 (no token required)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# IMDSv2 (token required — blocked by most SSRF)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

## Privilege Escalation

### IAM Policy Abuse
| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| Create policy version | `iam:CreatePolicyVersion` | Attach `*:*` to self |
| Attach user policy | `iam:AttachUserPolicy` | Attach AdministratorAccess |
| Put user policy | `iam:PutUserPolicy` | Inline admin policy |
| Create access key | `iam:CreateAccessKey` | Keys for any user |
| Update login profile | `iam:UpdateLoginProfile` | Reset any user's password |
| PassRole + Lambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Execute as privileged role |
| PassRole + EC2 | `iam:PassRole` + `ec2:RunInstances` | Launch instance with admin role |
| PassRole + CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` | Deploy as admin role |
| AssumeRole chain | `sts:AssumeRole` | Pivot across accounts |
| Update assume role policy | `iam:UpdateAssumeRolePolicy` | Allow self to assume any role |

### Cross-Account Pivoting
```bash
# Enumerate roles that trust external accounts
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]]'
# Assume role in target account
aws sts assume-role --role-arn arn:aws:iam::<target>:role/<name> --role-session-name pentest
```

### Service-Specific Escalation
- **SSM**: `ssm:SendCommand` on managed instances = RCE
- **Lambda**: environment variables contain secrets, layers can be poisoned
- **ECS/EKS**: task role credentials via metadata, node IAM role
- **Glue**: job execution with attached role
- **SageMaker**: notebook instance with admin role
- **CodeBuild**: build project environment variables

## Data Exfiltration Paths

### S3
```bash
# List all buckets
aws s3api list-buckets
# Recursive download
aws s3 sync s3://<bucket> ./exfil/ --no-sign-request
# Check bucket policy for cross-account access
aws s3api get-bucket-policy --bucket <name>
# Check for versioning (recover deleted secrets)
aws s3api list-object-versions --bucket <name> --prefix <key>
```

### Secrets Manager / Parameter Store
```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name>
aws ssm get-parameters-by-path --path / --recursive --with-decryption
```

### RDS Snapshots
```bash
# Public snapshots from target account
aws rds describe-db-snapshots --snapshot-type public --query 'DBSnapshots[?DBSnapshotIdentifier.contains(@,`target`)]'
# Copy and restore
aws rds copy-db-snapshot --source-db-snapshot-identifier <arn> --target-db-snapshot-identifier pentest-copy
```

## Persistence Techniques (Document Only)

- IAM user with programmatic access
- Lambda function triggered by CloudWatch Events
- EC2 instance in unused region
- Cross-account role trust
- SSM document with scheduled execution
- EventBridge rule triggering attacker Lambda
- Backdoored AMI/container image

## Detection Evasion Indicators

Document these for the blue team:
- CloudTrail: which API calls are logged vs not
- GuardDuty: which findings would trigger
- Config Rules: which violations are monitored
- VPC Flow Logs: what network activity is visible

## Tools

| Tool | Purpose |
|------|---------|
| Pacu | AWS exploitation framework |
| ScoutSuite | Multi-cloud security auditing |
| Prowler | AWS CIS benchmark + security checks |
| CloudFox | AWS situational awareness |
| enumerate-iam | Brute-force IAM permissions |
| Cartography | Infrastructure graph |
| Steampipe | SQL queries against cloud APIs |
| trufflehog | Credential scanning |
