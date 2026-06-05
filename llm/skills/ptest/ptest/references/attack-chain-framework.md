# Attack Chain Documentation Framework

## Overview

Individual findings tell the client "you have a bug." Attack chains tell the client "here's how an attacker destroys your business." Chains demonstrate compound impact — where the combined severity exceeds the sum of individual findings.

This framework provides structure for identifying, documenting, and presenting attack chains in the final report.

## What Is an Attack Chain?

An attack chain is a sequence of 2+ findings that, when combined, achieve greater impact than any single finding alone.

**Example:**
- FINDING-1: Heapdump accessible without auth (Critical — info disclosure)
- FINDING-2: Extracted token valid on SIT Keycloak (High — cross-env access)
- FINDING-3: Same gateway proxies prod Keycloak (Medium — architecture weakness)
- FINDING-4: CTI credentials valid on prod (Critical — production compromise)

**Individual max severity:** Critical
**Chain impact:** Full production compromise from unauthenticated internet access — worse than any single finding suggests.

## When to Document a Chain

Document an attack chain when:
- Two or more findings are causally linked (A enables B)
- Combined impact is higher than individual severities suggest
- The chain demonstrates a realistic attack path an adversary would follow
- Removing any single link would break the chain (shows defense-in-depth failure)

Do NOT force chains:
- Unrelated findings on the same host aren't a chain
- Two findings that independently achieve the same result aren't a chain
- A finding that's already Critical on its own doesn't need a chain to justify severity

## Chain Identification Process

### During Exploitation (Phase 6)

After each successful exploitation:

```
1. What did this finding ENABLE that wasn't possible before?
   → If it enabled another finding → chain candidate

2. What PREREQUISITE did this finding require?
   → If another finding was the prerequisite → chain candidate

3. Could an attacker reach this finding WITHOUT the previous step?
   → NO → mandatory chain link
   → YES → parallel path (document both, but not as a chain)
```

### Post-Exploitation (Phase 7)

After all exploitation is complete:

```
1. Map all findings on a graph:
   - Nodes = findings
   - Edges = "enables" relationships
   
2. Find the longest path (deepest chain)
3. Find paths that reach Critical impact
4. Find paths that cross environment boundaries
5. Document each unique path as a chain
```

## Chain Documentation Template

Location: `./ptest-output/exploit/attack-chains.md`

```markdown
# Attack Chains

## Chain Summary

| ID | Name | Entry Point | Final Impact | Links | Severity |
|----|------|-------------|-------------|-------|----------|
| AC-1 | {name} | {first finding} | {ultimate impact} | {count} | {chain severity} |
| AC-2 | {name} | {first finding} | {ultimate impact} | {count} | {chain severity} |

---

## AC-1: {Descriptive Name}

### Chain Severity: {Critical/High/Medium}

**Justification:** {Why the chain severity differs from individual findings}

### Visual Flow

```
[FINDING-1: Heapdump Accessible]
    │ Enables: credential extraction
    ▼
[FINDING-2: SA Token Valid on SIT]
    │ Enables: environment pivot
    ▼
[FINDING-3: Gateway Proxies Prod Keycloak]
    │ Enables: production token acquisition
    ▼
[FINDING-4: Prod Access Achieved]
    │ Enables: data exfiltration
    ▼
[IMPACT: Full production API access — 8 microservices, customer data]
```

### Narrative

{2-3 paragraphs telling the story of this attack chain as an attacker would execute it. Written for executive audience — no jargon, focus on business impact.}

### Links

| Step | Finding | Individual Severity | Role in Chain |
|------|---------|--------------------|--------------| 
| 1 | FINDING-1 | Critical | Entry point — provides initial access |
| 2 | FINDING-2 | High | Pivot — converts data into access |
| 3 | FINDING-3 | Medium | Enabler — provides path to production |
| 4 | FINDING-4 | Critical | Impact — demonstrates production compromise |

### Defense-in-Depth Analysis

Which controls, if present, would have broken this chain?

| Break Point | Missing Control | Recommendation |
|-------------|----------------|----------------|
| Between Step 1-2 | Actuator endpoint authentication | Require auth for all actuator endpoints |
| Between Step 2-3 | Environment credential isolation | Unique service accounts per environment |
| Between Step 3-4 | Network segmentation | Prod Keycloak not accessible from same gateway |
| At any point | Credential rotation | Rotate SA tokens every 90 days |

### Assumptions & Limitations

- {What would an attacker need that you didn't test? E.g., "Assumes attacker has time to analyze heapdump with Eclipse MAT"}
- {What scope limitations prevented full chain execution? E.g., "CTI credential testing required explicit authorization"}
- {What's theoretical vs confirmed? E.g., "Steps 1-3 confirmed. Step 4 confirmed with authorization. Full data exfiltration not attempted."}

---
```

## Chain Severity Scoring

Individual CVSS doesn't capture chain impact. Use this supplemental scoring:

### Severity Upgrade Rules

| Condition | Upgrade |
|-----------|---------|
| Chain crosses environment boundary (nonprod → prod) | +1 severity tier |
| Chain achieves access to >100 user records | Minimum High |
| Chain enables persistent access (not just one-time) | +1 severity tier |
| Chain requires zero authentication at entry point | +1 severity tier |
| Chain is fully automatable (no manual steps) | +1 severity tier |
| Chain affects financial transactions or credit decisions | Minimum Critical |

### Severity Cap

- Maximum chain severity: **Critical**
- Minimum chain severity: One tier above the lowest individual finding in the chain
- If all individual findings are already Critical: Chain adds **urgency** not severity — emphasize in narrative

## Chain Patterns (Common in Financial Services)

### Pattern 1: Credential Cascade

```
Info Disclosure → Credential Extraction → Cross-Env Pivot → Production Access
```
**Typical findings:** Heapdump/actuator exposure → token/password extraction → environment boundary failure → authenticated prod access

### Pattern 2: Authentication Bypass Ladder

```
Public Client Discovery → Token Acquisition → Privilege Escalation → Admin Access
```
**Typical findings:** Keycloak public client → low-privilege token → IDOR/role manipulation → admin-level data access

### Pattern 3: Reconnaissance to Exploitation

```
Subdomain Discovery → Service Enumeration → Misconfiguration → Data Exposure
```
**Typical findings:** Pattern-based subdomain brute-force → actuator/swagger discovery → unauthenticated endpoint → sensitive data download

### Pattern 4: Supply Chain Pivot

```
CI/CD Token Discovery → Dependency Database Access → Vulnerability Roadmap → Targeted Exploitation
```
**Typical findings:** Snyk/GitHub token in heapdump → full org vulnerability data → identify unpatched CVE → exploit specific service

### Pattern 5: WAF Bypass to Impact

```
WAF Rule Evasion → Endpoint Access → Authentication Bypass → Data Access
```
**Typical findings:** Case variation bypass → actuator/admin reachable → default creds or token reuse → sensitive data

## Presenting Chains in the Report

### In Executive Summary

One paragraph per chain, no technical details:
> "We demonstrated that an unauthenticated attacker on the internet could, through a series of four steps, gain full access to production customer data across 8 microservices. This chain exploits the combination of exposed debugging endpoints, shared credentials between environments, and insufficient network segmentation."

### In Attack Narrative (Section 6)

Full story-form walkthrough with technical details, written chronologically as the engagement progressed. Include decision points ("We noticed X, which led us to test Y").

### In Remediation Roadmap (Section 7)

Map chain break-points to remediation items. Highlight that fixing ANY single link breaks the chain — but recommend fixing ALL links for defense-in-depth.

### In Risk Matrix (Section 10)

Present the worst-case chain as the "realistic worst case" scenario. Individual findings are the "isolated incident" scenario. The gap between them demonstrates why defense-in-depth matters.

## Integration with Other Frameworks

### Credential Inventory → Chains

Every credential that enables a pivot is a chain link. The credential inventory's "Chain Potential" checkboxes feed directly into chain identification.

### Phase 7 (Post-Exploitation) → Chains

Post-exploitation extends chains. If Phase 6 achieves access and Phase 7 demonstrates lateral movement or privilege escalation, the chain grows.

### Report Template → Chains

The report template's "Attack Narrative" section (Section 6) IS the chain documentation, reformatted for client consumption.

## Pitfalls

- **Don't over-chain.** Not every pair of findings is a chain. If finding B is exploitable without finding A, they're parallel findings, not a chain.
- **Don't inflate severity artificially.** A chain of three Low findings doesn't become Critical just because there are three of them. The IMPACT must genuinely escalate.
- **Document theoretical vs confirmed links.** If you proved steps 1-3 but step 4 is theoretical ("if an attacker also had X, they could Y"), mark it clearly.
- **Chains need a story.** A list of findings isn't a chain. The narrative must explain WHY each step enables the next and what an attacker gains at each stage.
- **One chain per path.** If finding A enables both B and C independently, that's two chains (A→B and A→C), not one chain (A→B→C) unless B also enables C.
- **Update chains when new findings emerge.** A chain documented in Phase 6 might extend in Phase 7. Keep the chain document living until the report is finalized.
