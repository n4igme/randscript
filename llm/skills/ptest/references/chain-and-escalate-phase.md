# Chain & Escalate Phase (Mandatory Between Phase 6 and Phase 8)

After exploitation and before reporting, cross-reference ALL findings for combinatorial impact. Individual findings often undersell the real risk — chains demonstrate realistic attack scenarios.

## When to Run

- After Phase 6 (Exploitation) completes
- Before Phase 8 (Reporting) begins
- Can also run mid-Phase-6 when 3+ findings exist

## Process

### Step 1: Build the Finding Matrix

List all confirmed findings in a table:

| ID | Type | Asset | Requires Auth | Gives Attacker |
|----|------|-------|---------------|----------------|
| F1 | Access bypass | api.target.com | No | Bypasses origin check |
| F2 | User enum | api.target.com | No | Confirms registered emails |
| F3 | Actuator | dev.target.com | No | Internal architecture |

### Step 2: Chain Discovery

For each pair (A, B), ask:
1. Does A's output feed B's input?
2. Does A remove a prerequisite that B needs?
3. Do A+B together affect a larger population than either alone?
4. Does A provide targeting info that makes B more dangerous?

**Common chain patterns:**

| Chain Type | Example | Impact Upgrade |
|-----------|---------|----------------|
| Bypass + Enum | Referer bypass + user enum = unauthenticated mass enumeration | Low+Medium → High |
| Enum + Credential | User enum + no rate limit = credential stuffing at scale | Medium+Low → High |
| Info Leak + Targeted Attack | Actuator (internal IPs) + SSRF = internal network access | Medium+Medium → Critical |
| Auth Bypass + Data Access | Token leak + IDOR = full account takeover | Medium+High → Critical |
| Config Leak + Privilege Esc | Exposed env vars + default creds = admin access | Low+Medium → Critical |

### Step 3: Write Chain Narratives

For each viable chain, write the attack scenario as a story:

```
CHAIN: F1 + F6 → Unauthenticated Merchant Reconnaissance

STEP 1: Attacker adds Referer: https://global.alipay.com/ (F1 bypass)
STEP 2: Attacker calls /checkLoginId with empty captcha object (F6 no-captcha)
STEP 3: Differential response confirms registered merchants
STEP 4: Attacker builds verified target list at scale (no rate limit)
STEP 5: Credential stuffing / spear phishing against confirmed accounts

RESULT: Unauthenticated attacker can identify all registered payment merchants
         then launch targeted attacks knowing accounts definitely exist.
SEVERITY UPGRADE: F1 alone = Medium, F6 alone = Medium, Chain = High
```

### Step 4: Decide Submission Strategy

| Situation | Strategy |
|-----------|----------|
| Chain is tight (A directly enables B) | Submit as single finding, reference both |
| Chain is loose (A provides context for B) | Submit separately, mention chain in Impact |
| Chain hits different assets | Submit separately per asset, cross-reference |
| One finding is Low but chain is High | Lead with the chain, Low finding is supporting evidence |

## Checklist Before Reporting

- [ ] Every finding pair has been evaluated for chain potential
- [ ] Each chain has a step-by-step attack narrative
- [ ] Severity is rated for the CHAIN, not individual findings
- [ ] Submission strategy decided (single vs separate reports)
- [ ] PoC script demonstrates the full chain end-to-end (not just individual steps)

## Mandatory Chain PoC Scripts (AntGroup lesson, June 2026)

**Every chain MUST have a dedicated PoC script** (`exploit/chain-{letter}-{name}.py`) that runs the full attack end-to-end in one execution. The user WILL ask "do these chains have real exploitation PoCs?" — diagrams alone are insufficient.

**Chain PoC structure:**
```python
#!/usr/bin/env python3
"""CHAIN X PoC: {title} ({severity})
Steps: step1 → step2 → step3 → impact
"""
def main():
    print('[*] CHAIN X: {title}')
    print('[STEP 1] ...')  # Execute and show real output
    print('[STEP 2] ...')  # Each step uses prior step's output
    print('[CHAIN COMPLETE]')
    print('[IMPACT] ...')
```

Each step must produce REAL server responses (not mocked). If a step is blocked (e.g., rate limited), document it as "PROVEN: {evidence}" with reference to logs.

## Anti-Patterns

- **Reporting findings individually when a chain exists** — you leave severity on the table
- **Claiming a chain without proving prerequisites** — "if attacker has X" without demonstrating X
- **Over-chaining** — 5-step chains with speculative steps get rejected. Keep it to 2-3 proven steps
- **Ignoring Info/Low findings** — these are often the glue that upgrades a Medium to High
- **Writing chain diagrams without PoC scripts** — the user demands executable proof, not ASCII art

## Real-World Example: AntGroup (June 2026)

Individual findings:
- F1: Referer bypass on dashboard API (Medium)
- F6: User enumeration with captcha bypass (Medium)

Chain: F1 removes origin restriction → F6 confirms merchants at scale → attacker builds target list → credential stuffing/phishing against confirmed payment merchants

Result: Chain severity = High (unauthenticated mass reconnaissance of financial accounts)
