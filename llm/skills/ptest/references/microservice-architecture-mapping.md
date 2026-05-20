# Microservice Architecture Mapping (Black-Box)

Technique for inferring internal microservice architecture, K8s pod structure, and network topology from external reconnaissance data — without authenticated access.

## Data Sources

| Source | What it reveals |
|--------|----------------|
| DNS subdomain enumeration | Service names, environments, cluster groupings |
| Internal IP leaks via DNS | Network subnets, cluster boundaries |
| K8s service name leaks (302 redirects) | Pod naming convention, namespace structure |
| API path structure (`/service/v1/*`) | Individual microservice boundaries |
| Kiali/Istio dashboard subdomains | Service mesh presence, observability stack |
| Infrastructure subdomains (airflow, temporal, rmq) | Supporting services, message queues, orchestrators |
| Error messages (Spring Boot, Django) | Framework per service, internal routing |

## K8s Naming Convention Inference

When a redirect leaks an internal service URL like:
```
Location: http://prod-ms-onboarding.prod.svc.cluster.local/onboarding/
```

The pattern is:
```
{env}-ms-{service}.{env}.svc.cluster.local
```

From this single leak, you can predict other service names:
- `prod-ms-master.prod.svc.cluster.local`
- `prod-ms-bpm.prod.svc.cluster.local`
- etc.

## Network Topology from DNS

Internal IPs leaked via DNS records reveal subnet boundaries:
```
172.22.x.x — nonprod / legacy cluster
172.23.x.x — main cluster (dev/sit/uat/prod)
172.28.x.x — core-system cluster
```

Private IPs (`-private` suffix subdomains) vs public IPs reveal which services have external ingress vs internal-only access.

## Environment Matrix

Map services across environments to understand deployment patterns:
```
{service}.dev.{cluster}.bfi.co.id    → development
{service}.sit.{cluster}.bfi.co.id    → system integration testing
{service}.uat.{cluster}.bfi.co.id    → user acceptance testing
{service}.prod.{cluster}.bfi.co.id   → production
{service}.{env}-sharia.{cluster}...  → sharia-compliant variant
```

Services that exist in dev/sit/uat but NOT prod may be upcoming features. Services only in prod may be legacy.

## Istio/Service Mesh Assessment

Indicators of Istio service mesh:
- `kiali*.{domain}` subdomains (Istio observability dashboard)
- `kiali-private` (internal-only mesh dashboard)
- Consistent mTLS indicators in response headers

If Kiali is accessible, it reveals:
- Full service-to-service communication graph
- mTLS enforcement status (if disabled, internal traffic is sniffable)
- Traffic flow volumes and error rates
- Istio AuthorizationPolicy coverage

Default Kiali port: **20001** (also check 8080, 8443, 3000)

## Security Implications

| Finding | Impact |
|---------|--------|
| Auth delegated to individual services (not mesh-level) | Single misconfigured service = full data exposure |
| Flat internal network (same /24 subnet) | Lateral movement trivial once inside any pod |
| Single Keycloak instance for all services | Compromise Keycloak = access everything |
| No namespace-level AuthorizationPolicy | Any pod can talk to any other pod |
| Infrastructure tools on same network (pgadmin, airflow) | Privilege escalation paths from any foothold |

## Google IAP Fingerprinting (Passive Recon)

When targets use Google IAP, the OAuth redirect leaks useful info:
- **GCP Project Number** — the `client_id` prefix (e.g., `1022863786872-xxx`) is the GCP project number, shared across all IAP-protected services in that project
- **Per-service client IDs** — each IAP-protected service has a unique suffix, confirming they're separate backends
- **Single project = single blast radius** — if one service's IAP is misconfigured, the project-level IAM may grant access to others

Extract from redirect:
```
location: https://accounts.google.com/o/oauth2/v2/auth?client_id=PROJECT_NUMBER-UNIQUE_SUFFIX.apps.googleusercontent.com&...&redirect_uri=https://iap.googleapis.com/v1/oauth/clientIds/PROJECT_NUMBER-UNIQUE_SUFFIX.apps.googleusercontent.com:handleRedirect
```

## Reporting Template

When documenting microservice architecture in a pentest report:

1. **Total services identified** (confirmed vs inferred)
2. **Cluster topology** (how many clusters, what environments)
3. **Network segmentation** (subnets, private vs public)
4. **Auth architecture** (centralized vs per-service, mesh-level vs app-level)
5. **Supporting infrastructure** (databases, queues, orchestrators, monitoring)
6. **Attack paths** (which service compromise leads to what lateral movement)
