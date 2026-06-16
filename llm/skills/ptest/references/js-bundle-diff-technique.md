# JS Bundle Diff Technique (Multi-Environment Targets)

## When to Use
- Phase 3 (Enumeration) when target has multiple environments (dev/staging/prod)
- When you've extracted endpoints from one environment's JS bundle
- Anytime you see different JS build hashes across environments

## Why This Matters
Development and production environments often deploy different builds. Prod may have:
- Additional endpoints not present in dev (feature flags, admin routes)
- Endpoints with different auth requirements (dev requires auth, prod doesn't)
- Different API versions or deprecated routes still active

## Procedure

### 1. Identify JS bundles per environment
```bash
# Get main JS file from each env's login page
curl -sk "https://dev-target.com/login" | grep -oE 'src="[^"]*app-[^"]*\.js"'
curl -sk "https://target.com/login" | grep -oE 'src="[^"]*app-[^"]*\.js"'
```

### 2. Extract endpoints from each
```bash
# Dev
curl -sk "https://dev-target.com/build/assets/app-DEVHASH.js" | \
  grep -oE '"/api/[a-zA-Z0-9_/-]{2,80}"' | sort -u | tr -d '"' > dev-endpoints.txt

# Prod
curl -sk "https://target.com/build/assets/app-PRODHASH.js" | \
  grep -oE '"/api/[a-zA-Z0-9_/-]{2,80}"' | sort -u | tr -d '"' > prod-endpoints.txt
```

### 3. Diff
```bash
# Endpoints in PROD but NOT in dev (high priority!)
comm -23 prod-endpoints.txt dev-endpoints.txt

# Endpoints in dev but NOT in prod
comm -13 prod-endpoints.txt dev-endpoints.txt
```

### 4. Test prod-only endpoints for unauth access
Any endpoint that exists only in prod is likely a newer feature or admin function — test immediately for missing authentication.

## Example (BlueSpider, June 2026)
```
Dev bundle:  app-50814d1f.js → 83 endpoints
Prod bundle: app-6750147a.js → 84 endpoints

Diff: /api/load-user (PROD ONLY)

Result: /api/load-user returned 166 users with full emails UNAUTHENTICATED
        → enabled mass ATO of 69 production accounts
```

## Key Lesson
The single endpoint difference between dev and prod was the key to the entire production compromise. Always diff. Never assume dev and prod have identical attack surfaces.
