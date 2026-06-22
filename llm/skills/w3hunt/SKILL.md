---
name: w3hunt
version: 2.3.0
description: "Web3 bug bounty hunting on Immunefi and similar platforms. Target selection, scope verification, DeFi-specific recon, and attack vector prioritization for hybrid web+contract programs."
tags: [web3, bug-bounty, immunefi, defi, smart-contract, recon]
trigger: "immunefi, web3 hunting, defi bug bounty, smart contract bounty, web3 recon"
argument-hint: "<command: start|next|recon|scope|targets|status|resume|report|abort|cleanup>"
notes:
  - "v2.2.0: Deduplicated Gate Enforcement (3x→1x) and Postmortem (2x→1x). Consolidated command procedures. Added Phase Entry Protocol, findings.jsonl procedure. Aligned with skill family patterns."
  - "v2.1.0: Hub model — SKILL.md is routing + strategy + framework. Phase content in references/phase*.md"
  - "NEVER rewrite full SKILL.md in one tool call — use strReplace/patch for edits. Large write_file calls hit output token limits and get truncated."
metadata:
  hermes:
    tags: [web3, bug-bounty, immunefi, defi, smart-contract]
    related_skills: [ptest, scode, atest]
---

# Web3 Bug Bounty Hunting Framework

Optimized for hunters with strong web pentest backgrounds targeting DeFi protocol web+contract hybrid programs.

## Quick Reference

```
Phases:  1.Triage(15m) → 2.Recon(1h) → 3.Web(30m-2h) → 4.SC(2-3h,conditional) → 5.Exploit+Submit(30m)
Default: WEB-FIRST (Phase 3 always runs, Phase 4 only if web is dead)
Budget:  4-8 hours per target. No High+ by hour 6 → move on.

Key rules:
  • 15-min triage BEFORE deep-dive (verify live, check C4/Sherlock, check scope)
  • NEVER claim impact you haven't proven end-to-end
  • Verify exploit output BEFORE writing report
  • Asset scope is STRICTLY enforced — check before submitting
  • PoC in Python only (requests + eth_account), NEVER curl
  • Submit immediately — sitting on findings risks duplicates

Oracle prerequisite check (all 3 required — see Strategy section):
  If ANY fails → pivot to web scope or different bug class
```

## When to Use / When NOT to Use

**Use when:**
- Bug bounty program has both web/app AND smart contract scope
- Target is DeFi protocol on EVM chain (Ethereum, Arbitrum, Optimism, Base, Polygon, BSC)
- You have web pentest skills applying to frontend + off-chain components

**Avoid when:**
- No web + smart contract hybrid scope (pure SC → scode only)
- Program is paused or out of scope
- Prior contest exhausted high-value bugs
- Time budget < 4 hours (minimum viable engagement is 4-8h)

## Retry / Timeout Patterns

| Operation | Timeout | Retry | Backoff |
|-----------|---------|-------|---------|
| HTTP requests | 30s | 3x | 5s linear |
| Blockchain RPC | 10s | 3x | 5s |
| Subsquid/GraphQL | 30s | 2x | 10s |

**Rules:**
- On timeout: retry once. If persistent, document as blocker.
- On 429/503: exponential backoff, max 3 attempts.
- On partial output: save what you have, note the gap, continue.
- Long-running scans: use background terminal with `notify_on_complete=true`.

## Commands


## Findings (findings.jsonl)

**Format:** JSONL, one JSON object per line.

**Required fields:** `finding_id`, `title`, `severity`, `category`, `target`, `confidence` (0.0-1.0), `timestamp`

**Example:**
```json
{"finding_id": "RETOOLS-001", "title": "Hardcoded API key", "severity": "High", "category": "secrets", "target": "app.apk", "confidence": 0.95, "timestamp": "2026-06-22T10:00:00Z"}
```


## Error Handling

### Post-Submission Protocol

| Response | Action |
|----------|--------|
| "Needs more info" | Respond within 24hr with exact evidence |
| "Not reproducible" | Re-run PoC, provide updated output with timestamps |
| "Duplicate" | Accept gracefully. Move on. |
| "Out of scope" | Check if reframeable (frontend bundle proof). If not, lesson learned. |
| "Accepted" | 🎉 Note pattern. Look for same bug class on similar targets. |

## Concurrent Execution Safety

**Parallel recon:**
- Subdomain enum + GitHub clone + API mapping can run in parallel
- Save intermediate results to files — do not rely on in-memory state
- Nuclei scan: rate-limit to 150 req/s to avoid IP block

**State safety:**
- `state.yaml` is single-writer — only parent agent advances phases
- Findings file `findings.jsonl` is append-only — safe for concurrent writers
- PoC scripts in `poc/` use unique filenames (finding-id + timestamp)

**Subagent handoff:**
- Document target slug + scope before spawning
- Child agents read-only on `scope.txt` — do not modify
- Parent validates findings.jsonl additions before marking phase PASSED

### Abandon Decision

**Triggers:** hour 6 with no High+, OR Phase 3 yields nothing and SC prerequisites fail.

1. `state_manager.abandon(workdir, reason)`
2. Document in `recon-summary.txt`: what was tested, why it's hardened/dead
3. Move to Next Target Decision Tree (fresh target criteria: payout × novelty × recency × hybrid)

### Severity Mapping

Cross-skill severity normalization: `../references/severity-mapping.md`

## Pitfalls

> Full pitfalls and operational rules: `references/operational-rules.md`

**Engagement file naming:** ALWAYS prefix target-specific references with `engagement-` (e.g., `engagement-ens.md`, `engagement-grab-ovo.md`). These patterns are gitignored from public backup repos via `llm/skills/**/engagement-*` and the template in `../references/engagement-gitignore-template`. Files without the prefix trigger GitHub secret scanning alerts when they contain contract addresses, API keys, or wallet details found during testing.

**Top 5 instant-rejection rules:**
1. **NEVER claim impact you haven't proven end-to-end** — theoretical = rejected
2. **VERIFY EXPLOIT OUTPUT BEFORE WRITING REPORT** — run full chain, confirm output matches claim
3. **Asset scope is STRICTLY enforced** — verify address in scope list before submitting
4. **Submit immediately** — sitting on findings risks duplicates
5. **PoC in Python only** — never curl. Include `Origin` header matching in-scope app URL

### References

- `references/sc-audit-patterns.md` — DeFi SC audit patterns
- `references/platform-operational-notes.md` — Platform-specific notes
- `references/immunefi-severity-v2.2.md` — Severity tables
- `references/immunefi-report-template.md` — Report format

### Evidence Standards

All findings must follow `../references/evidence-standards.md` for required/optional evidence capture and redaction rules.
- `references/operational-rules.md` — Full operational rules
- `references/immunefi-targets-v3.md` — Target shortlist
- `references/engagement-stakewise.md` — Signature replay (Critical)
- `references/engagement-ens.md` — CSP bypass via stale PostHog (Critical)
- `references/engagement-hacken.md` — SSRF bypassing Cloudflare Access
- `references/engagement-beefy-lessons.md` — Scope rejection lesson
