# Cloudflare API Shield Bypass Patterns

## Overview

CF API Shield enforces API token requirements on specific paths. Misconfigurations create path-based bypasses where some endpoints reach the backend without the CF token.

## Detection

When a host returns different error formats for different paths:
- CF-blocked: `{"message":"Rejected by Cloudflare! {"error":{"message":"MISSING_API_TOKEN"}}"}` (401, ~102B)
- Backend-reached: Different error format from the actual backend (e.g., Tyk: `{"error": "Authorization field missing"}` 401, 46B)

The second response means CF passed the request through without checking the API token.

## Exploitation Methodology

1. **Identify bypass paths:** Test known application paths (from source code, JS analysis, API docs) against the CF-protected host. Compare response format/size to identify which reach the backend.

2. **Test all HTTP methods:** A path blocked on GET may accept POST (Tyk often restricts by method separately from CF).

3. **Cross-host testing (CRITICAL):** If a bypass exists on one host, test ALL hosts sharing the same CF zone/config:
   - api.example.com → dev-api, stg-api, pt-api
   - mobile.example.com → dev-mobile, stg-mobile
   - bisnis.example.com, partner.example.com, etc.

4. **Confirm backend identity:** Look for `x-generator` header (e.g., `x-generator: tyk.io`) to confirm requests reach the actual API gateway.

## Bank Jago Pattern (May 2026)

- `/ginpay/*` paths bypassed CF API Shield on 10 hosts
- `/configuration/graphql` bypassed on api.jago.com and pt-api.jago.com
- `/partner-webview/` served static Flutter app (GCS bucket) without CF token
- `/hello` (Tyk health) exposed on 2 hosts where CF didn't cover it

## Key Lesson

CF API Shield rules are path-based. When developers add new API paths, they may forget to add corresponding CF rules. Always test newly discovered paths against CF-protected hosts — the shield may not cover them.

## Severity Assessment

- If backend also enforces auth: Medium (defense-in-depth failure)
- If backend has no auth on bypassed paths: High/Critical (direct data access)
- Combined with source code leak revealing auth patterns: increases exploitability
