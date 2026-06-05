# Data Classification Framework (Post-Exploitation)

When data is exfiltrated during exploitation, systematically classify it to accurately assess business impact. This is critical for Phase 7 (Post-Exploitation) and the final report.

## Classification Process

### Step 1: Identify Data Categories

For each exfiltrated dataset, categorize records into:

| Category | Examples | Base Sensitivity |
|----------|----------|-----------------|
| PII (Personally Identifiable Information) | Names, KTP/ID numbers, addresses, phone numbers, email | HIGH |
| Financial Records | Account numbers, balances, transactions, loan details | CRITICAL |
| Credentials | Passwords, API keys, tokens, certificates | CRITICAL |
| Business Logic | Scoring rules, approval thresholds, workflow configs | HIGH (financial) / MEDIUM (other) |
| Reference Data | Country codes, status enums, category lists | LOW |
| Infrastructure | Service names, IPs, configs, environment variables | MEDIUM |
| Metadata | Timestamps, version numbers, record counts | LOW |

### Step 2: Count and Measure

For each category, document:
```markdown
| Category | Record Count | Data Size | Sensitivity |
|----------|-------------|-----------|-------------|
| Credit scoring rules | 80+ | ~200KB | HIGH |
| Bank integration details | 200+ | ~300KB | MEDIUM |
| Reference data | 5000+ | ~400KB | LOW |
```

### Step 3: Assess Business Impact

For each HIGH/CRITICAL category, answer:

1. **Can this enable fraud?** (e.g., gaming credit scoring)
2. **Can this enable social engineering?** (e.g., knowing approval hierarchy)
3. **Does this violate regulations?** (e.g., PII exposure → GDPR/OJK violation)
4. **Can this be used for further attacks?** (e.g., infrastructure details → targeted exploitation)
5. **Is this data available elsewhere?** (e.g., public reference data = low impact)

### Step 4: Determine Severity Upgrade

| Condition | Severity Adjustment |
|-----------|-------------------|
| Data enables systematic fraud | Upgrade to Critical |
| Data contains credentials | Upgrade to Critical |
| Data violates financial regulations | Upgrade one tier |
| Data volume > 1000 sensitive records | Upgrade one tier |
| Data is publicly available elsewhere | Downgrade one tier |
| Data requires additional context to exploit | No change |

## Industry-Specific Classification

### Financial Services (Banks, Multi-Finance, Insurance)

**CRITICAL exposure:**
- Credit scoring algorithms/thresholds
- Approval authority matrices with limits
- Risk assessment rules
- Customer financial records
- Payment routing details (SWIFT, clearing codes)

**HIGH exposure:**
- Internal role hierarchies
- Business process workflows
- Document requirements per product
- Bank integration configurations

**Why business logic > PII for financial targets:**
- PII theft = individual identity fraud (detectable, limited scale)
- Business logic theft = systematic approval fraud (harder to detect, scalable)
- An attacker who knows the exact DSR threshold, LTV limit, and approval hierarchy can submit hundreds of fraudulent applications designed to pass automated checks

### Healthcare

**CRITICAL:** Patient records (PHI), treatment protocols, drug databases
**HIGH:** Staff credentials, system configurations, billing codes

### Technology / SaaS

**CRITICAL:** Source code, API keys, customer databases
**HIGH:** Infrastructure configs, deployment secrets, internal documentation

## Reporting Template

Use this in Phase 7 documentation:

```markdown
## Data Access Summary

### Data Successfully Exfiltrated (Unauthenticated)

| Endpoint | Records | Data Type | Sensitivity | Business Impact |
|----------|---------|-----------|-------------|-----------------|
| /api/v1/data | 5600+ | Credit rules, bank data | HIGH | Fraud enablement |

### Data Categories Breakdown

| Category | Count | Sensitivity | Impact |
|----------|-------|-------------|--------|
| {category} | {n} | {level} | {description} |

### Data NOT Accessed (blocked by auth)

- Customer PII
- Financial transactions
- Employee records
- Authentication credentials

### Impact Assessment

An attacker with this data can:
1. {specific attack scenario}
2. {specific attack scenario}
3. {specific attack scenario}

### Regulatory Implications

| Regulation | Violation | Potential Penalty |
|-----------|-----------|-------------------|
| {regulation} | {what's violated} | {penalty range} |
```

## Comparison: What Was Accessed vs What's Protected

Always document BOTH what was exposed AND what was properly protected. This gives the client a balanced view:

**Exposed (findings):**
- Business logic data (credit rules, approval matrices)
- Infrastructure details (K8s service names, network topology)

**Protected (strengths):**
- Customer PII (behind auth)
- Financial transactions (behind auth)
- Credentials (not in API responses)
- Admin functionality (auth + WAF)

This framing helps the client understand their security posture isn't completely broken — specific gaps need fixing while other controls are working.
