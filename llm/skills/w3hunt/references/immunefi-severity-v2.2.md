# Immunefi Vulnerability Severity Classification System v2.2

Used by most Immunefi programs (including Beefy Finance). 5-level scale: Critical, High, Medium, Low, None.

Key principle: "if the exploit requires elevated privileges or uncommon user interaction, the level may be downgraded or rejected."

## Smart Contracts

| Level | Impact |
|-------|--------|
| Critical | Direct theft of user funds (at-rest/in-motion, excl. unclaimed yield), permanent freezing of funds/NFTs, protocol insolvency, governance voting manipulation, MEV, unauthorized NFT minting, manipulable RNG, unintended NFT alteration |
| High | Theft of unclaimed yield/royalties, permanent freezing of unclaimed yield/royalties, temporary freezing of funds/NFTs |
| Medium | Contract unable to operate due to lack of token funds, block stuffing for profit, griefing (no profit motive), theft of gas, unbounded gas consumption |
| Low | Contract fails to deliver promised returns but doesn't lose value |
| None | Best practices |

## Websites and Apps

| Level | Impact |
|-------|--------|
| Critical | RCE, retrieve sensitive data/files (/etc/shadow, DB passwords, blockchain keys — NOT non-sensitive env vars, open source code, or usernames), app/website takedown, state-modifying authenticated actions on behalf of users (trades, withdrawals, etc.), subdomain takeover w/ connected wallet, direct theft of user funds, malicious wallet interactions (modify tx args, substitute contract addresses, submit malicious tx), injection of malicious HTML/XSS through NFT metadata |
| High | Injecting/modifying static content w/o JS (persistent HTML injection, arbitrary file uploads), changing sensitive user details (email/password) w/ up to 1 click, improperly disclosing confidential user info (email/phone/address), subdomain takeover w/o connected wallet |
| Medium | Redirecting users to malicious websites (open redirect) |
| Low | Changing non-sensitive details of other users, taking non-state-modifying authenticated actions on behalf of users |
| None | Best practices |

## Key Exclusions (common rejection triggers)

- "Non-sensitive environment variables, open source code, or usernames" are NOT sensitive data (Critical web)
- Source maps without secrets = open source code = None
- Missing security headers without demonstrated exploit = best practices = None
- Centralization risks (owner-only functions) = usually out of scope
- Bugs requiring external conditions attacker can't control (oracle malfunction, sequencer down) = may be downgraded or rejected
- Known/accepted patterns on long-running contracts (first-depositor on 4-year vault) = likely duplicate

## Practical Severity Decision Tree

```
Can attacker trigger it themselves without external events?
├── NO → Likely downgraded or rejected (unless impact is Critical-level)
└── YES
    ├── Does it cause DIRECT fund loss?
    │   ├── YES → Critical (theft) or High (yield only)
    │   └── NO
    │       ├── Does it freeze funds?
    │       │   ├── Permanently → Critical
    │       │   └── Temporarily → High
    │       └── Does it grief/DoS without profit?
    │           ├── YES → Medium
    │           └── NO → Low or None
    └── Does it require elevated privileges (owner/admin)?
        └── YES → Usually out of scope (centralization risk)
```
