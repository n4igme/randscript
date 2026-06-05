# IAM Escalation Patterns

## AWS IAM Escalation

### Direct Escalation (Single Permission)

| # | Permission | Technique |
|---|-----------|-----------|
| 1 | `iam:CreatePolicyVersion` | Create new policy version with `*:*`, set as default |
| 2 | `iam:SetDefaultPolicyVersion` | Activate an older permissive policy version |
| 3 | `iam:AttachUserPolicy` | Attach `arn:aws:iam::aws:policy/AdministratorAccess` to self |
| 4 | `iam:AttachGroupPolicy` | Attach admin policy to a group you're in |
| 5 | `iam:AttachRolePolicy` | Attach admin policy to a role you can assume |
| 6 | `iam:PutUserPolicy` | Add inline admin policy to self |
| 7 | `iam:PutGroupPolicy` | Add inline admin policy to your group |
| 8 | `iam:PutRolePolicy` | Add inline admin policy to assumable role |
| 9 | `iam:CreateAccessKey` | Create access key for any user |
| 10 | `iam:CreateLoginProfile` | Create console password for any user |
| 11 | `iam:UpdateLoginProfile` | Reset any user's console password |
| 12 | `iam:UpdateAssumeRolePolicy` | Modify role trust to allow self to assume it |

### Indirect Escalation (Permission Combinations)

| # | Permissions | Technique |
|---|------------|-----------|
| 13 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin role, invoke it |
| 14 | `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin instance profile |
| 15 | `iam:PassRole` + `cloudformation:CreateStack` | Deploy stack with admin role |
| 16 | `iam:PassRole` + `glue:CreateJob` | Create Glue job with admin role |
| 17 | `iam:PassRole` + `ecs:RunTask` | Run ECS task with admin task role |
| 18 | `iam:PassRole` + `codebuild:CreateProject` | Build project with admin service role |
| 19 | `lambda:UpdateFunctionCode` | Modify existing Lambda (inherits its role) |
| 20 | `ec2:CreateInstanceProfile` + `ec2:AssociateIamInstanceProfile` | Attach role to running instance |
| 21 | `sts:AssumeRole` (cross-account) | Pivot to more permissive account |
| 22 | `ssm:SendCommand` | Execute commands on managed instances (inherits instance role) |

### Enumeration Commands
```bash
# What can I do?
aws iam get-user
aws iam list-user-policies --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>
# For each group:
aws iam list-group-policies --group-name <group>
aws iam list-attached-group-policies --group-name <group>
# Simulate permissions
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names s3:GetObject iam:CreateUser
```

## GCP IAM Escalation

### Direct Escalation

| # | Permission | Technique |
|---|-----------|-----------|
| 1 | `resourcemanager.projects.setIamPolicy` | Grant self Owner role |
| 2 | `iam.serviceAccounts.actAs` + compute/functions | Deploy workload as privileged SA |
| 3 | `iam.serviceAccountKeys.create` | Create key for any SA |
| 4 | `iam.serviceAccounts.getAccessToken` | Generate access token for SA |
| 5 | `iam.serviceAccounts.signBlob` | Sign arbitrary payloads as SA |
| 6 | `iam.serviceAccounts.signJwt` | Create signed JWTs as SA |
| 7 | `iam.serviceAccounts.implicitDelegation` | Chain through SAs |
| 8 | `deploymentmanager.deployments.create` | Deploy resources as project SA |
| 9 | `cloudfunctions.functions.create` + `actAs` | Execute as SA |
| 10 | `run.services.create` + `actAs` | Cloud Run as SA |
| 11 | `composer.environments.create` + `actAs` | Airflow as SA |
| 12 | `orgpolicy.policy.set` | Disable security constraints |

### SA Impersonation Chain
```bash
# Direct impersonation
gcloud auth print-access-token --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com
# Chain: SA-A can impersonate SA-B which has Owner
gcloud auth print-access-token --impersonate-service-account=<sa-b>@<project>.iam.gserviceaccount.com \
  --impersonate-service-account=<sa-a>@<project>.iam.gserviceaccount.com
```

## Azure IAM Escalation

### Entra ID (Azure AD)

| # | Permission/Role | Technique |
|---|----------------|-----------|
| 1 | Application Administrator | Add credentials to any app registration |
| 2 | Cloud Application Administrator | Same as above for enterprise apps |
| 3 | Privileged Role Administrator | Activate/assign any PIM role |
| 4 | User Administrator | Reset passwords for non-admin users |
| 5 | Groups Administrator | Add self to privileged groups |
| 6 | `AppRoleAssignment.ReadWrite.All` | Grant app permissions without consent |
| 7 | `RoleManagement.ReadWrite.Directory` | Assign Global Admin to self |
| 8 | Conditional Access Administrator | Disable MFA policies |

### Azure RBAC

| # | Permission | Technique |
|---|-----------|-----------|
| 1 | `Microsoft.Authorization/roleAssignments/write` | Assign Owner to self |
| 2 | `Microsoft.Authorization/roleDefinitions/write` | Create custom role with `*` |
| 3 | `Microsoft.Compute/virtualMachines/runCommand/action` | RCE on VMs |
| 4 | `Microsoft.Automation/automationAccounts/runbooks/draft/write` | Execute as RunAs account |
| 5 | `Microsoft.Web/sites/publish/action` | Deploy code to Function App |
| 6 | `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Read all secrets |

## Detection & Logging

### What Gets Logged

| Provider | Service | Logged Actions |
|----------|---------|---------------|
| AWS | CloudTrail | All IAM API calls (management events) |
| AWS | GuardDuty | Anomalous API calls, credential use from unusual IPs |
| GCP | Cloud Audit Logs | Admin Activity (always), Data Access (if enabled) |
| Azure | Azure AD Audit Logs | Sign-ins, role changes, app registrations |
| Azure | Activity Log | RBAC changes, resource modifications |

### Evasion Considerations (Document for Blue Team)
- AWS: CloudTrail can be disabled per-region, S3 data events often not logged
- GCP: Data Access logs disabled by default (expensive)
- Azure: Diagnostic settings must be configured per-resource
