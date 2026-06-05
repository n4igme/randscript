# Phase 6: Per-Host Coverage Template

Copy this table into `exploit/checklist.md` under "## Per-Host Coverage" and fill it during exploitation.

## Template

```markdown
## Per-Host Coverage

| Host | Techniques Applied | Surface Type | Result |
|------|--------------------|-------------|--------|
| example.com | 6.3,6.4,6.7,6.8,6.9,6.10,6.12 | WordPress X.Y + Elementor | FINDING-N / No vuln |
| www.example.com | N/A | 301→example.com | No separate surface |
| api.example.com | 6.2,6.4,6.5,6.6,6.8,6.9 | REST API (Spring Boot) | FINDING-N |
| staging.example.com | 6.2,6.5 (earlier) | Same as prod | Timed out in Phase 6 |
| cdn.example.com | 6.12 | Static CDN (S3/CF) | No vuln |
| mkt.example.com | 6.4 | 3rd-party SaaS (Pardot) | Auth-gated |
```

## Column Guidelines

| Column | What to write |
|--------|--------------|
| **Host** | Full subdomain. Include ALL hosts from `domains-live.md` + any discovered during exploitation |
| **Techniques Applied** | List technique numbers actually executed. Use "N/A" for redirects/no-surface. Use "attempted" for timeouts |
| **Surface Type** | Brief tech description: WP version, API framework, SaaS name, "SPA catch-all (NNN bytes)", "301→target" |
| **Result** | "FINDING-N (short name)", "No vuln", "Auth-gated", "Timed out (tested earlier)", "SPA catch-all" |

## Justified Skips (valid reasons for not testing a host)

| Reason | How to document |
|--------|----------------|
| 301/302 redirect to another in-scope host | "301→{target} — no separate surface" |
| SPA catch-all (all paths return identical response) | "SPA catch-all ({size} bytes) — no real endpoints" |
| 3rd-party SaaS with only auth-gated API | "{Platform} — auth-gated (err code)" |
| Host timed out / became unreachable | "Timed out in Phase 6 (tested in Phase {N} earlier)" |
| Identical to another host (same backend confirmed) | "Same as {host} (verified: same response + headers)" |

## Coverage Gate

Before requesting Phase 6 sign-off:
1. Count rows in per-host table
2. Count hosts in `domains-live.md` + discovered hosts
3. If table rows < total hosts → phase is NOT complete
4. Every host must have at least one technique applied OR a justified skip with evidence

## Unreachable Hosts Section

Add below the per-host table when hosts timeout:

```markdown
## Unreachable Hosts

| Host | Last Working | Techniques Before Timeout | Retry Result |
|------|-------------|--------------------------|--------------|
| alpha.example.com | 2026-06-02 22:00 UTC | 6.2, 6.5 (GraphQL tested) | Still timeout after 30min |
| staging.example.com | Never in Phase 6 | None (tested Phase 3 only) | Timeout — coverage gap |
```
