# Camunda BPM Assessment (Black-Box)

When Spring Boot Actuator `/health` reveals Camunda (jobExecutor component), the target runs a Business Process Management engine. This is high-value — BPM systems contain business workflow definitions, task assignments, and often connect to core business databases.

## Detection

Camunda presence confirmed by any of:
- `/actuator/health` shows `jobExecutor` component with `SpringJobExecutor`
- `/camunda/app/welcome/` returns 200 (web UI)
- `/camunda/api/engine/engine` returns engine list
- Prometheus metrics contain `camunda_` prefixed metrics

## Testing Checklist (10 minutes max)

### 1. Web Interface Access

```bash
# Check if Camunda Webapp is accessible
curl -s -o /dev/null -w "%{http_code}" "${TARGET}/camunda/app/welcome/default/"
# 200 = login page accessible
# 404 = webapp not deployed
# 302 = redirect to auth
```

### 2. Engine List (often unauthenticated)

```bash
curl -s "${TARGET}/camunda/api/engine/engine"
# [{"name":"default"}] = engine exposed without auth
# Empty/401 = auth required
```

This endpoint frequently works without auth even when all other REST endpoints require it.

### 3. Default Credentials

```bash
# Camunda ships with demo/demo in development
for creds in "demo:demo" "admin:admin" "camunda:camunda"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${TARGET}/camunda/api/engine/engine/default/user" -u "${creds}")
  echo "${creds} → HTTP $code"
done

# Also try the login form
curl -s -X POST "${TARGET}/camunda/api/admin/auth/user/default/login/welcome" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo"
```

### 4. REST API Data Endpoints (if auth works or not required)

```bash
BASE="${TARGET}/camunda/api/engine/engine/default"

# Users (PII)
curl -s "${BASE}/user"

# Process definitions (business logic)
curl -s "${BASE}/process-definition"

# Running process instances
curl -s "${BASE}/process-instance?maxResults=10"

# Tasks (active work items with assignees)
curl -s "${BASE}/task?maxResults=10"

# Deployments (BPMN files — full workflow definitions)
curl -s "${BASE}/deployment"

# Process variables (may contain sensitive business data)
curl -s "${BASE}/variable-instance?maxResults=10"

# History (completed processes)
curl -s "${BASE}/history/process-instance?maxResults=10"
```

### 5. BPMN File Download (if deployments accessible)

```bash
# Get deployment ID from /deployment response
DEPLOY_ID="<id-from-above>"
# List resources in deployment
curl -s "${BASE}/deployment/${DEPLOY_ID}/resources"
# Download BPMN XML (full workflow definition)
curl -s "${BASE}/deployment/${DEPLOY_ID}/resources/<resource-id>/data"
```

## What Camunda Exposure Reveals

| Endpoint | Data | Severity |
|----------|------|----------|
| /engine | Engine exists | Info |
| /user | Employee names, emails | High |
| /process-definition | Business workflow names and versions | Medium |
| /process-instance | Active business processes with IDs | High |
| /task | Active tasks with assignee names | High |
| /deployment + resources | Full BPMN XML (complete business logic) | Critical |
| /variable-instance | Process variables (may contain PII, amounts, decisions) | Critical |
| /history | Completed processes (audit trail) | High |

## Security Implications for Financial Services

Camunda in a financial institution typically manages:
- Loan approval workflows (credit decisions)
- KYC/onboarding processes
- Surveyor assignments and document verification
- Insurance approval flows
- Payment disbursement workflows

Exposure of process definitions reveals the exact business rules, approval thresholds, and decision points — similar impact to the credit scoring rules exposure (enables fraud by understanding the system).

## Common Misconfigurations

1. **Engine list without auth** — `/camunda/api/engine/engine` often bypasses auth filters because it's not under the `/engine/default/` path pattern
2. **Demo user left enabled** — `demo:demo` credentials work in non-production environments
3. **REST API auth separate from webapp auth** — webapp may require login but REST API may not
4. **Actuator exposes Camunda internals** — health endpoint shows job executor details, lock owners, process engine names

## Reporting

If Camunda is accessible without auth:
- Severity: High (minimum) — Critical if process variables or BPMN files are downloadable
- Environment tag: note if mock/SIT/prod
- Document: engine name, number of process definitions, any user data visible
- Remediation: enable Camunda REST API authentication (`camunda.bpm.authorization.enabled=true`)
