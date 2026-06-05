# Istio/Service Mesh Assessment (External)

When Istio is detected (via Kiali subdomains, `x-envoy-upstream-service-time` headers), document:

## Confirmation Indicators

| Indicator | Source |
|-----------|--------|
| `x-envoy-upstream-service-time` header | Any HTTP response |
| `kiali*.domain` subdomains | DNS enumeration |
| `kiali-private*.domain` (internal IP) | DNS — confirms internal-only dashboard |
| Consistent CORS headers across services | Mesh-level CORS policy |
| `x-datadog-*` / `Traceparent` in allowed headers | Distributed tracing integration |

## What You CAN Assess Externally

- Envoy sidecar presence (confirmed by header)
- Whether auth is mesh-level vs app-level (if one service lacks auth, it's app-level)
- Tracing/APM stack (from CORS allowed headers)
- Whether Kiali is externally accessible (try ports 20001, 8080, 8443, 3000)

## What You CANNOT Assess Externally

- mTLS enforcement between pods
- AuthorizationPolicy coverage
- VirtualService/DestinationRule configs
- Service-to-service communication graph
- Namespace isolation

## Security Implications to Report

If auth is app-level (not mesh-level), document that:
- A single misconfigured service = full data exposure (as demonstrated)
- Istio AuthorizationPolicy SHOULD enforce JWT at namespace level
- Recommendation: `RequestAuthentication` + `AuthorizationPolicy` requiring valid JWT for all inbound traffic
