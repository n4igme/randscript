# K8s / Istio Internal Target Enumeration

## When to Use
- Target is behind K8s ingress with Istio/Envoy service mesh
- VPN-gated internal staging/prod environment
- Single ingress IP serving multiple services via path routing

## Key Behaviors

### Istio Ingress Routing
- Strict vhost routing: unknown Host headers → 404:0
- Path-based routing: services share one ingress (/app-name/service-name/)
- 400 "Bad Request" (11 bytes, text/plain, server: istio-envoy) = service ALIVE but needs valid auth token
- x-envoy-upstream-service-time header confirms request reached backend

### Service Discovery Priority
1. **Prometheus URI extraction** (best technique for Spring Boot behind Istio):
   ```bash
   curl -sk /actuator/prometheus | grep -oE 'uri="[^"]+"' | sort -u
   ```
   Reveals ALL registered routes including internal-only endpoints invisible to fuzzing.

2. **Path-prefix brute-force** (second priority):
   ```bash
   for svc in loan-service gateway notification scoring kyc; do
     curl -sk "https://target/app-prefix/${svc}/" -w "%{http_code}"
   done
   ```

3. **Swagger/OpenAPI discovery** (third):
   Test /swagger-resources, /v2/api-docs?group=X at each service prefix.

4. **VHost enum** (low value for K8s):
   Usually all 404 — K8s uses path routing not vhost routing.

### VPN DNS Brute-Force
Even though domain is internal-only, the VPN pushes DNS (169.254.169.254):
```bash
# Works from VPN — test env prefixes
for prefix in stg- dev- uat- prod-; do
  for svc in api admin auth gateway loan; do
    dig +short "${prefix}${svc}.domain.io"
  done
done
```

### Reverse DNS on K8s Internal IPs
K8s internal DNS rarely has PTR hostnames (returns self-referencing IPs).
Still worth checking adjacent IPs in known /24 ranges for services.

## OpenAPI Batch Unauth Testing (MANDATORY)

When Swagger spec found, batch-test ALL endpoints:
```python
import json, requests
with open('swagger.json') as f:
    spec = json.load(f)
base = 'https://target/app-prefix/service'
for path, methods in spec['paths'].items():
    for method in methods:
        if method in ('get','post','put','delete','patch'):
            url = base + path.replace('{param}','test')
            r = requests.request(method, url, json={}, verify=False, timeout=5)
            if r.status_code != 401 and r.status_code != 404:
                print(f'[+] {method.upper()} {path} -> {r.status_code}')
```

## Findings Pattern (LoanPlatform, June 2026)
- Prometheus exposed → full route map + Kafka topics + domain classes
- Swagger unauth → 77 endpoints documented, batch test found 28 unauth
- User profile endpoint → PII for all 33 users without auth
- Task approval WRITE endpoints → approve/reject without auth
- Source maps → full client source code (PBKDF2 auth implementation)
- No account lockout → brute-force feasible with known usernames

## Pitfalls
- loan-service 400 is NOT broken — it's Istio requiring auth token header
- Don't skip VPN DNS brute-force just because "internal domain"
- env-prefix check (strip stg-/dev- → test bare domain) is mandatory
- SPA catch-all on frontend (200:fixed-size) but backend has proper 404s
