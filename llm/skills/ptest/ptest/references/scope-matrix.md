# Scope-Aware Checklist Matrix

When generating phase checklists during `start`, filter techniques by scope type. Techniques that don't apply to the engagement's scope type should be pre-marked as `N/A (scope: {type})` instead of `PENDING`.

| Phase | Technique | web | network | cloud | mobile | mixed |
|-------|-----------|-----|---------|-------|--------|-------|
| 1 | OSINT Gathering | Y | Y | Y | Y | Y |
| 1 | JS Bundle Analysis & Staging Domain Discovery | Y | N | Y | Y | Y |
| 1 | Subdomain Enumeration | Y | Y | Y | N | Y |
| 1 | Internal Asset Inventory Request | Y | Y | Y | N | Y |
| 1 | Knowledge Base / Support Site Scraping | Y | Y | Y | N | Y |
| 1 | Pattern-Based Subdomain Brute-Force | Y | Y | Y | N | Y |
| 1 | Technology Fingerprinting | Y | N | Y | Y | Y |
| 1 | Email & Username Discovery | Y | Y | Y | N | Y |
| 1 | Network Mapping | N | Y | Y | N | Y |
| 1 | Asset Validation | Y | Y | Y | N | Y |
| 2 | Port Scanning (MANDATORY) | Y | Y | Y | Y | Y |
| 2 | Active DNS Expansion — Pattern Permutation (MANDATORY) | Y | Y | Y | N | Y |
| 2 | Active DNS Expansion — DNS-Level Brute-Force (MANDATORY) | Y | Y | Y | N | Y |
| 2 | Active DNS Expansion — Reverse DNS on IP Ranges | N | Y | Y | N | Y |
| 2 | Active DNS Expansion — Virtual Host Enumeration | Y | N | Y | N | Y |
| 2 | Active DNS Expansion — Zone Transfer Attempt | Y | Y | Y | N | Y |
| 2 | Service Detection & Banner Grabbing | Y | Y | Y | Y | Y |
| 2 | OS Fingerprinting | N | Y | N | N | Y |
| 2 | Network Topology Mapping | N | Y | Y | N | Y |
| 3 | Directory & File Brute-Force (MANDATORY) | Y | N | N | N | Y |
| 3 | HTTP Method Testing on Unauth Endpoints (MANDATORY) | Y | N | Y | N | Y |
| 3 | API Endpoint Discovery (MANDATORY) | Y | N | Y | Y | Y |
| 3 | Parameter Discovery | Y | N | N | Y | Y |
| 3 | Virtual Host Enumeration | Y | N | N | N | Y |
| 3 | CMS-Specific Enumeration | Y | N | N | N | Y |
| 3 | JavaScript Analysis | Y | N | N | Y | Y |
| 3 | JavaScript Secret Scanning (MANDATORY) | Y | N | N | Y | Y |
| 3 | Source Map Sweep (MANDATORY when web apps found) | Y | N | N | N | Y |
| 3 | Authentication Endpoint Mapping | Y | N | Y | Y | Y |
| 3 | Bulk Actuator/Admin Scan (MANDATORY) | Y | N | Y | N | Y |
| 5 | Threat Modeling | Y | Y | Y | Y | Y |
| 5 | Nuclei Scan (MANDATORY) | Y | N | Y | N | Y |
| 5 | CORS Origin Reflection Testing (MANDATORY) | Y | N | Y | N | Y |
| 5 | OAuth/OIDC redirect_uri Validation (MANDATORY) | Y | N | Y | N | Y |
| 5 | Nikto Scan | Y | N | N | N | Y |
| 5 | SSL/TLS Assessment | Y | Y | Y | N | Y |
| 5 | CVE Mapping | Y | Y | Y | Y | Y |
| 5 | Manual Verification | Y | Y | Y | Y | Y |
| 5 | Prioritized Vector List | Y | Y | Y | Y | Y |
| 6 | Known CVE Exploitation | Y | Y | Y | Y | Y |
| 6 | Web Application Attacks | Y | N | Y | N | Y |
| 6 | Authentication Bypass | Y | Y | Y | Y | Y |
| 6 | Injection Attacks | Y | N | Y | Y | Y |
| 6 | Logic Flaws | Y | N | Y | Y | Y |
| 6 | Client-Side Attacks | Y | N | N | Y | Y |
| 7 | Privilege Escalation | Y | Y | Y | Y | Y |
| 7 | Lateral Movement | N | Y | Y | N | Y |
| 7 | Persistence (Document Only) | N | Y | Y | N | Y |
| 7 | Data Access | Y | Y | Y | Y | Y |
| 7 | Credential Harvesting | Y | Y | Y | Y | Y |

When scope type is `mixed`, all techniques are `PENDING`. For other scope types, mark `N` entries as `N/A (scope: {type})`.
