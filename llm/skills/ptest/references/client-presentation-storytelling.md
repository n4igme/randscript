# Client Presentation Storytelling

## Overview

This reference covers how to **verbally present** pentest/red-team findings to clients — particularly non-technical stakeholders. Written reports explain "what"; presentations explain "why it matters" through narrative structure.

Key lesson (BFI Kill Chain, June 2026): jumping straight to findings without explaining the background concept makes the presentation fail. The audience needs to understand the mechanism before they can grasp the impact.

---

## Core Principle: Educate → Contextualize → Present → Impact

Every finding slide needs four layers when presented verbally:

| Layer | Purpose | Example (CTI/Leak DBs) |
|-------|---------|------------------------|
| **Background** | What is this concept? Assume zero knowledge | "What is Cyber Threat Intelligence? Where do leak databases come from?" |
| **Mechanism** | How does it work technically? Keep it accessible | "Infostealer malware on employee laptops harvests browser passwords. These get sold in bulk on Telegram." |
| **Finding** | What did we find specifically? | "We queried these databases for *.bfi.co.id and got 79,411 records. 59 worked on production." |
| **Impact** | Why should the client care? Frame as business risk | "Any attacker with Telegram access has this today. Zero detection surface." |

**NEVER skip Background and Mechanism.** Technical audiences may not need them — executive audiences always do.

---

## Storytelling Structure Per Kill Chain Step

### Opening Hook (1 sentence)
Frame from the attacker's perspective. Make it visceral.

- ✅ "Before we even touched your infrastructure, we already had credentials."
- ✅ "We didn't need to hack anything — the data was already public."
- ❌ "We found 59 credentials in leak databases." (no narrative, just a fact)

### Background Block (explain the concept)
Educate the audience on the attack class. Use analogies if needed.

**Pattern:**
1. Name the concept plainly
2. Explain where it comes from (source/origin)
3. Explain why it exists (attacker economics)
4. Make it tangible ("this is freely accessible to anyone")

**Example — CTI/Leak Databases:**
> "Cyber Threat Intelligence — CTI — includes information about threats that already exist. In this case: credential leak databases. Massive collections of stolen usernames and passwords circulating on Telegram, dark web forums, and paste sites.
>
> Where do they come from?
> - Infostealer malware — an employee visits a compromised site or installs a cracked app. Malware silently harvests every saved browser password, including work credentials. These get bundled and sold in bulk.
> - Third-party breaches — a service your employees registered on (using work email) gets hacked. Those credentials leak.
> - Phishing campaigns — credentials entered on fake pages get aggregated.
>
> None of this requires targeting your company directly. Your employees' credentials are collateral damage."

### Finding Block (present the evidence)
Now that the audience understands the mechanism, present what you found.

**Pattern:**
1. What you did (method — keep it one sentence)
2. What came back (numbers — let them land)
3. Validation (prove it's real, not theoretical)

**Example:**
> "We queried these same public databases — the exact ones any attacker can access for free — filtering for your domains. 79,411 records came back. We validated 59 credential pairs against your live production systems. They worked."

### Impact Block (business risk framing)
Translate technical finding into business language.

**Pattern:**
1. Who else has this (threat actor accessibility)
2. Detection gap (can you see it happening?)
3. What it enables (next step in the chain)

**Example:**
> "This means:
> - The barrier to entry is zero — a script kiddie with Telegram has this
> - You cannot detect this step — no logs, no alerts, no traffic on your side
> - Credential reuse bridges personal device compromise to production access
>
> This is Step 01 because everything that follows starts here."

### Transition (bridge to next slide)
One sentence connecting this step to the next.

> "So what did we do with those 59 working credentials? That's Step 02..."

---

## Common Concept Explanations (reusable background blocks)

### CTI / Leak Databases
See example above. Key points: infostealer malware, third-party breaches, phishing aggregation, Telegram channels, zero targeting required.

### Credential Stuffing / Reuse
"People reuse passwords. When a password leaks from one service, attackers try it everywhere else. If your employee uses the same password for Netflix and your VPN — one Netflix breach means VPN access."

### Lateral Movement
"Once inside one system, attackers don't stop. They move sideways — from a low-privilege account to admin, from one server to the database. Like a burglar who enters through the garage but walks to the safe."

### Privilege Escalation
"Starting as a regular user and ending as an administrator. The system has paths — sometimes intentional, sometimes accidental — that let a low-level account gain full control."

### Supply Chain / Third-Party Risk
"Your security is only as strong as your weakest vendor. If a partner's system is compromised, and they have a trusted connection to yours, the attacker rides that trust."

---

## Delivery Tips

### For Executive Audiences
- Lead with business impact, then explain the how
- Use "any attacker can do this today" framing — urgency without fear-mongering
- Pause after big numbers (79,411 records) — let them land
- Avoid jargon: "leak databases" not "CTI feeds", "stolen passwords" not "credential dumps"
- Connect every finding to: money, reputation, or regulatory exposure

### For Technical Audiences
- Can abbreviate the Background block (they know what CTI is)
- Focus on: what you validated, what's still exposed, what detection gaps exist
- Include tool names and methodology if asked
- They'll ask "how did you validate?" — have the answer ready

### For Mixed Audiences
- Present Background for executives, then signal "for the technical team: [detail]"
- Use the slide as anchor, verbal delivery as the narrative
- Offer "happy to go deeper on methodology in the technical appendix"

### General Rules
- Never show live credentials on-screen in group meetings with non-security staff
- Always frame as "here's what an attacker sees" not "here's what's wrong with you"
- End each step with forward motion ("and that leads us to...")
- If showing a kill chain: each step should feel like inevitable escalation

---

## Anti-Patterns (what NOT to do)

| Bad | Why | Fix |
|-----|-----|-----|
| Jump straight to findings | Audience doesn't understand the mechanism | Add Background + Mechanism first |
| List bullet points without narrative | Feels like a report reading, not a presentation | Use opening hook + story arc |
| Say "we found X vulnerability" | Technical label means nothing to executives | Say "we could do X to your business" |
| Show all creds on-screen | Unnecessary risk in group settings | Say "samples available in detailed report" |
| Use only technical severity (CVSS 9.1) | Executives don't think in CVSS | Translate: "anyone on the internet can..." |
| Present findings in isolation | Misses the chain/escalation narrative | Connect each step to the next |

---

## Slide Design Alignment (Kill Chain format)

When the presentation uses the Kill Chain visual format (as in BFI Red Team):
- Each slide = one step in the chain
- Left side = evidence card (facts, numbers, domains)
- Right side = "Why It Matters" panel (interpretation, risk)
- Verbal delivery fills the gaps between what's on the slide

The slide shows WHAT. Your voice explains WHY and HOW.
