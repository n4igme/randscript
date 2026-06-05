# Alibaba Cloud Attack Paths

Techniques for testing Alibaba Cloud (Aliyun) infrastructure. Common in SEA targets (GoPay, Grab, Gojek, Tokopedia, OVO).

## Metadata Service

- Endpoint: `http://100.100.100.200/latest/meta-data/`
- NO special headers required (unlike GCP/Azure)
- RAM credentials: `/latest/meta-data/ram/security-credentials/`
- Instance ID: `/latest/meta-data/instance-id`
- Region: `/latest/meta-data/region-id`

```bash
# Full metadata dump
curl -s http://100.100.100.200/latest/meta-data/
curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/
# Get role name first, then fetch creds:
ROLE=$(curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/)
curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/$ROLE
```

## OSS (Object Storage Service)

**Bucket URL formats:**
- Path style: `https://oss-{region}.aliyuncs.com/{bucket}`
- Virtual-hosted: `https://{bucket}.oss-{region}.aliyuncs.com`
- CNAME: custom domain → bucket (different ACLs possible)

**Common regions:** oss-ap-southeast-1 (Singapore), oss-cn-hangzhou, oss-cn-shanghai, oss-cn-beijing

**Testing:**
```bash
# Existence check
curl -sk "https://{bucket}.oss-ap-southeast-1.aliyuncs.com/" -o /dev/null -w "%{http_code}"
# 404=doesn't exist, 403=exists+ACL'd, 200=public listing

# List objects (if public)
curl -sk "https://{bucket}.oss-ap-southeast-1.aliyuncs.com/?list-type=2&max-keys=100"

# Test via CNAME (may have different ACL)
curl -sk "https://assets.target.com/" -o /dev/null -w "%{http_code}"

# Write test (PUT)
curl -sk -X PUT "https://{bucket}.oss-ap-southeast-1.aliyuncs.com/pentest-probe.txt" \
  -d "PENTEST-PROBE" -o /dev/null -w "%{http_code}"
```

**Pitfall:** POST to OSS returns XML `MethodNotAllowed` with HostId (e.g., `webapp-origin.marmot-cloud.com`) — confirms static bucket but not writable.

## RAM (Resource Access Management)

Alibaba's IAM equivalent. Key escalation paths:

| Permission | Technique | Severity |
|-----------|-----------|----------|
| ram:CreatePolicy | Create admin policy, attach to self | Critical |
| ram:AttachPolicyToUser | Attach AdministratorAccess | Critical |
| ram:CreateAccessKey | Create key for any user | High |
| sts:AssumeRole | Cross-account pivot | High |
| ecs:RunCommand | Execute on ECS instances | High |
| fc:InvokeFunction | Invoke Function Compute | Medium |

```bash
# Identity check
aliyun sts GetCallerIdentity

# List policies
aliyun ram ListPoliciesForUser --UserName $USER
aliyun ram GetPolicy --PolicyName AdministratorAccess --PolicyType System
```

## Function Compute (FC)

Serverless platform. Look for `x-fc-request-id` header in responses.

```bash
# List services/functions (if creds available)
aliyun fc GET /services
aliyun fc GET /services/{service}/functions

# Invoke (if permissions allow)
aliyun fc POST /services/{service}/functions/{func}/invocations -b '{}'
```

## ECS (Elastic Compute Service)

```bash
# List instances
aliyun ecs DescribeInstances --RegionId ap-southeast-1

# Check security groups (firewall rules)
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxx --RegionId ap-southeast-1

# Run command on instance (if permitted)
aliyun ecs RunCommand --Type RunShellScript --CommandContent "id" --InstanceId i-xxx
```

## Fingerprinting

| Signal | Confirms |
|--------|----------|
| `x-fc-request-id` header | Function Compute |
| `x-oss-request-id` header | OSS |
| Server: `Tengine` | Alibaba CDN edge |
| Server: `Spanner` | Alibaba internal LB |
| `aliyuncs.com` in DNS | Alibaba Cloud hosting |
| `*.oss-*.aliyuncs.com` CNAME | OSS bucket |

## Geo-Blocking

SEA companies commonly geo-restrict API gateways. Symptoms:
- All API paths return 502 from outside region
- Static assets (CDN/OSS) remain globally accessible
- Fix: test from regional VPN (Singapore, Jakarta) before concluding service is down

## Cross-Skill Triggers

| Finding | Action |
|---------|--------|
| OSS bucket with listing | Enumerate for .tfstate, backups, configs |
| RAM creds from metadata | Run `iam_enum.py` adapted for Alibaba |
| Function Compute exposed | Test for SSRF to metadata endpoint |
| ECS instance with role | Pivot via metadata → RAM creds |
