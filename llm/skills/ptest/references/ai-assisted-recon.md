# AI-Assisted Recon (Phase 1 Technique)

Use AI search tools (Perplexity, ChatGPT Search, Claude web) as a structured Phase 1 technique. Fills gaps that traditional dorking and passive tools miss by aggregating scattered public information into actionable leads.

## When to Use

- Early Phase 1 alongside passive OSINT (after DNS/CT/Shodan, before marking OSINT complete)
- Targets with large public footprints (docs, blogs, changelogs, job postings, developer forums)
- Unfamiliar target industries where you lack domain knowledge
- Scope viability assessment — quick signal on whether a target is hardened or has exposed surface

## What AI Search Finds That Dorking Misses

- Aggregated tech stack info from multiple sources in one query
- Acquisitions/subsidiaries not visible in DNS (investor pages, press releases, LinkedIn)
- Deprecated API versions mentioned in old forum posts / Stack Overflow / developer docs
- Internal tool names leaked in job postings (Lever, Greenhouse, LinkedIn jobs)
- Third-party integrations (payment providers, analytics, auth SDKs, monitoring)
- Historical incidents/breaches/CVEs compiled from scattered reports
- Developer blog posts revealing architecture decisions
- Conference talks/slides mentioning internal infrastructure

## Prompt Templates

Adapt per target. Use follow-up questions to drill deeper.

### Asset Discovery
- "What subdomains, acquisitions, and sister companies does [target] own?"
- "List all domains and web properties operated by [target company]"
- "Has [target] acquired any companies in the last 5 years? What domains do they use?"

### Tech Stack
- "What technology stack does [target.com] use? Include CDN, backend framework, database, auth provider, hosting"
- "What CI/CD and deployment tools does [target] use based on job postings and blog posts?"
- "What monitoring/observability tools does [target] use?"

### API & Endpoint Discovery
- "List all known API endpoints for [target] with documentation links"
- "Does [target] have a public API? Show me docs, SDKs, or developer portal URLs"
- "What webhook or callback URLs does [target] document for integrations?"

### Vulnerability History
- "Any disclosed vulnerabilities, bug bounty reports, or security incidents for [target]?"
- "Show me HackerOne or Bugcrowd disclosed reports for [target]"
- "What CVEs affect [target]'s known tech stack?"

### Third-Party Integrations
- "What third-party SaaS integrations does [target] use?" (payment, monitoring, CI/CD, auth)
- "What SDKs does [target]'s mobile app include?"

### People & OSINT
- "Show me [target] engineering team GitHub profiles or tech blog posts"
- "What security tools or practices does [target] mention in job postings?"

## Verification Rule (MANDATORY)

AI search results are LEADS, not findings. Every claim must be verified with actual tooling before entering the checklist as DONE:

| AI claim | Verification |
|----------|-------------|
| Subdomain exists | `dig`, `curl`, httpx probe |
| Uses technology X | Response headers, Wappalyzer, JS analysis |
| API endpoint at /path | Actually request it |
| Acquired company Y | WHOIS, DNS, confirm shared infra |
| Past breach/CVE | Find original advisory/disclosure |

Never add unverified AI output to findings-log.md or attack-surface inventory.

## Pitfalls

1. **Hallucinated subdomains/endpoints** — AI confidently generates plausible-looking domains that don't exist. Always resolve before probing.
2. **Outdated info presented as current** — tech stacks change. Verify with live fingerprinting.
3. **OPSEC** — do NOT paste target secrets, tokens, or internal data into AI tools. Treat prompts as potentially logged/trained-on.
4. **Confirmation bias** — don't anchor on AI's first answer. Cross-check with traditional tools.
5. **Rate limiting** — Perplexity Pro has limits. Batch your questions, don't query one-at-a-time.

## Integration with Phase 1 Checklist

Add as optional technique in `phase1-passive-recon.md`:

```
- [ ] AI-assisted recon (Perplexity/ChatGPT Search) — tech stack, acquisitions, API docs, vulnerability history
```

Position: after DNS/CT/Shodan/GitHub, before OSINT completeness check. Results feed into:
- `attack-surface/` inventory (verified assets)
- `recon-passive/tech-stack.md` (confirmed technologies)
- `scope-expansion` candidates (discovered subsidiaries/acquisitions)

## Tool Comparison

| Tool | Strength | Weakness |
|------|----------|----------|
| Perplexity | Real-time web, cites sources, follow-up context | Rate limited on free tier |
| ChatGPT Search | Broad coverage, good at synthesis | Sometimes shallow on technical detail |
| Claude web | Good reasoning about findings | Slower, less real-time indexing |
| Google Dorking | Precise, repeatable | One query at a time, manual aggregation |

Use AI search for breadth/synthesis, traditional dorking for precision/depth. They complement, not replace.
