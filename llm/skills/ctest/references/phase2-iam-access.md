## Phase 2: IAM & Access Analysis

### Gate: identity enumeration complete, privilege level assessed, escalation paths identified

**Techniques:**

1. **Identity Enumeration:**
   ```bash
   # AWS — who am I?
   aws sts get-caller-identity
   aws iam list-users
   aws iam list-roles
   aws iam list-attached-user-policies --user-name <user>

   # GCP
   gcloud auth list
   gcloud projects get-iam-policy <project>
   gcloud iam service-accounts list

   # Azure
   az account show
   az ad user list
   az role assignment list
   ```

2. **Policy Analysis:**
   - Overly permissive policies (`*:*`, `s3:*`, `iam:PassRole`)
   - Cross-account trust relationships
   - Service-linked roles with excessive permissions
   - Conditional policies that can be bypassed

3. **Privilege Escalation Paths:**
   - AWS: `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PassRole` + `lambda:CreateFunction`, `sts:AssumeRole` chains
   - GCP: `setIamPolicy`, `actAs` on service accounts, `deployments.create`
   - Azure: `Microsoft.Authorization/roleAssignments/write`, custom role abuse

4. **Federation & SSO:**
   - SAML provider misconfigurations
   - OIDC trust with overly broad conditions
   - Cross-account role assumption without external ID
   - Workload identity federation abuse

5. **Automated Enumeration:**
   ```bash
   # AWS
   enumerate-iam  # or pacu
   python3 pacu.py
   # GCP
   gcp_enum.sh  # custom or gcpbucketbrute
   # Azure
   azurehound  # or ROADtools
   roadrecon gather
   ```

**Prioritization by access level:**
- **Leaked keys (AKIA/ASIA):** Identity Enumeration (#1) → Policy Analysis (#2) → Escalation (#3). Determine what the key can do before trying to escalate.
- **Compromised user:** Federation & SSO (#4) first (can you pivot to other accounts?) → then Policy Analysis (#2) → Escalation (#3).
- **Service account:** Skip user enumeration. Go straight to Policy Analysis (#2) → check what services the SA can access → Escalation (#3).

**Reference:** `references/iam-escalation-patterns.md`

**Cross-reference:** ptest `references/cloud-privilege-escalation.md` for post-compromise escalation.

---
