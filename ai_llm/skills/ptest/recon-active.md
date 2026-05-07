---
name: recon-active
description: Active reconnaissance and enumeration — directly probe targets to identify services and vulnerabilities.
version: 2.0.0
metadata:
  category: enumeration
  phase: 2
  requires_toolsets: [read, bash]
---

# Skill: Active Reconnaissance & Enumeration

## When to Use
- After passive recon is complete (Gateway 1 passed).
- When you need to identify live services, versions, and potential attack vectors.

## Techniques
1. **Port Scanning:** Identify open ports and services (TCP/UDP).
2. **Service Enumeration:** Banner grabbing, version detection.
3. **Web Enumeration:** Directory brute-forcing, virtual host discovery, API endpoint mapping.
4. **Vulnerability Scanning:** Automated scanners for known CVEs.
5. **Authentication Probing:** Default credentials, login page discovery, auth mechanism analysis.
6. **SSL/TLS Analysis:** Certificate inspection, cipher suite evaluation, protocol version checks.

## Output
Document findings in `recon-active-results.md`:
- Open ports and services per host
- Software versions identified
- Potential vulnerability vectors
- Authentication mechanisms found
- Misconfigurations detected

## Exit Criteria
- [ ] All in-scope hosts port-scanned.
- [ ] Service versions fingerprinted.
- [ ] Web applications enumerated (directories, endpoints).
- [ ] Potential attack vectors prioritized.
