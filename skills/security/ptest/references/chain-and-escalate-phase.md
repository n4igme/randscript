# Chain & Escalate Phase (Phase 5.5)

Run this micro-phase AFTER vulnerability assessment (Phase 5) and BEFORE exploitation (Phase 6).

## Purpose

Revisit all findings (including Info/Low) and systematically attempt to chain or escalate them into higher-severity impacts. This is where Low findings become Medium+ through creative combination.

## When to Trigger

- After Phase 5 completes with findings of any severity
- Especially when you have 3+ Info/Low findings (chain potential increases with quantity)
- When unauth testing is exhausted and you need to maximize value before pivoting to auth

## Protocol

### Step 1: Inventory All Findings

List every finding regardless of severity. Include:
- Info disclosures (headers, error messages, version leaks)
- Exposed endpoints (health, metrics, config)
- Open storage (buckets, registries)
- Authentication details (mechanisms, policies, error verbosity)

### Step 2: Cross-Reference Matrix

For each finding, ask:
| Question | Example |
|----------|---------|
| Does this leak credentials/keys? | CSP header → Sentry DSN → event injection |
| Does this expose internal tools? | Open bucket → internal binary → RE for vulns |
| Does this reveal endpoints to attack? | OpenAPI spec → authenticated attack surface map |
| Can I use data from A to attack B? | Version disclosure → CVE lookup → exploit |
| Does this weaken a trust boundary? | Config leak → password policy = 0 → brute force viable |

### Step 3: Escalation Techniques

#### Information Leak → Active Exploitation
- **CSP/headers → third-party key extraction** (Sentry DSN, analytics tokens, API keys)
- **Error messages → library identification** → known CVE lookup
- **Version disclosure → changelog diff** → find security fixes you can reverse
- **Config endpoints → policy weaknesses** (no rate limit, weak passwords, hidden features)

#### Storage Exposure → Intelligence Gathering
- **Open buckets → non-public binaries** (internal agents, tools not on GitHub)
- **Open buckets → install scripts** (supply chain context, infrastructure mapping)
- **Open buckets → GPG keys/configs** (aids targeted attacks)
- **Binary analysis → internal endpoints** (metadata URLs, API paths, auth mechanisms)

#### Endpoint Discovery → Attack Surface Expansion
- **OpenAPI/Swagger specs → full API map** for authenticated testing
- **Health/metrics endpoints → infrastructure details** (versions, dependencies)
- **Staging/dev environments → weaker security controls**

### Step 4: Prove the Chain

For each escalation:
1. Document the full chain: A → B → C
2. Prove each step with evidence (curl commands, responses)
3. Assess combined impact (not individual finding severity)
4. Write the narrative: "An attacker who discovers X can leverage it to achieve Y"

### Step 5: Re-assess Severity

| Original | Escalated To | Chain Example |
|----------|-------------|---------------|
| Info (CSP leak) | Medium | CSP → Sentry DSN → event injection |
| Low (bucket listing) | Low-Medium | Bucket → internal binary exposure → offline RE |
| Info (error verbosity) | Low-Medium | JWT library leak → targeted attack research |
| Low (no rate limit) | Medium | No rate limit + weak password policy → brute force |
| Info (config disclosure) | Low | Hidden login form still active at API level |

## Exit Criteria

- [ ] All findings cross-referenced against each other
- [ ] Third-party keys/tokens extracted from headers tested for abuse
- [ ] Exposed binaries/files checked for non-public internal tools
- [ ] At least one escalation attempt documented per Info/Low finding
- [ ] Escalated findings re-assessed with updated severity
