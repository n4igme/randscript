# Engagement ROI Metrics

Track hours spent vs outcomes to sharpen target selection. Updated by `postmortem` command.

## Completed Engagements

| Target | Platform | Type | Hours | Phase Found | Outcome | Payout | $/hr | Date |
|--------|----------|------|-------|-------------|---------|--------|------|------|
| StakeWise | Immunefi | DeFi hybrid | 6 | 3 (Web) | dead (API OOS) | $0 | $0 | 2026-05 |
| Beefy | Immunefi | DeFi vault | 4 | 4 (SC) | abandoned (oracle pattern N/A) | $0 | $0 | 2026-05 |
| ENS (web) | Immunefi | Infra/naming | 3 | 3 (Web) | submitted (CSP bypass, Critical) | pending | pending | 2026-05 |
| ENS (SC) | Immunefi | Infra/naming | 5 | 4 (SC) | confirmed (role persistence, High) | pending | pending | 2026-05 |
| Origin Protocol | Immunefi | DeFi vault | 2 | 2 (Recon) | abandoned (oracle prereqs fail) | $0 | $0 | 2026-05 |
| Grab/OVO | HackerOne | Consumer fintech | 3 | 3 (Web) | submitted (config.js leak) | pending | pending | 2026-05 |
| Hacken | HackenProof | Security co | 4 | 3 (Web) | submitted (SSRF, CVSS 8.6) | pending | pending | 2026-05 |
| TikTok | HackerOne | Consumer app | 2 | 3 (Web) | submitted (email bind, High) | pending | pending | 2026-05 |

## Derived Insights (update after each postmortem)

**Success rate by phase:**
- Phase 3 (Web): 5/6 engagements produced findings (83%)
- Phase 4 (SC): 1/3 engagements produced findings (33%)
- Phase 2 (Recon): 0 direct findings, but enables Phase 3

**Success rate by target type:**
- Consumer app/fintech: 2/2 submitted (100%)
- Security company: 1/1 submitted (100%)
- DeFi hybrid (web scope): 1/2 submitted (50% — StakeWise was dead)
- DeFi vault (SC-only): 1/3 submitted (33% — oracle pattern rarely applies)
- Infra/naming: 2/2 submitted (100%)

**Average time-to-finding:** ~2.5h (for successful engagements)

**Dead-end patterns (avoid or time-cap hard):**
- Pure yield vaults with no web scope → 0% hit rate
- Oracle prerequisite check saves ~3h per dead target
- Programs with API returning 403/OOS → verify liveness BEFORE deep-dive

**High-ROI patterns (prioritize):**
- Web scope on DeFi protocols → low competition, high payout
- CSP gaps on wallet-connected domains → Critical ($25K+)
- Config/source map exposure → quick chain to High
- Role/permission bugs in governance contracts → High ($25K+)
- Consumer apps with complex auth flows → High

## Target Selection Weights (derived from data above)

Used by `targets` command to rank candidates:

```
Score = base_payout_score × type_multiplier × freshness_bonus

type_multiplier (from hit rate):
  consumer_app:     1.5  (100% hit rate)
  security_co:      1.4  (100% hit rate)
  infra_naming:     1.3  (100% hit rate)
  defi_hybrid_web:  1.0  (50% hit rate, but high payout)
  defi_vault_sc:    0.4  (33% hit rate, oracle prereqs usually fail)

freshness_bonus:
  launched < 30 days:  1.3
  launched < 90 days:  1.1
  launched > 1 year:   0.8

negative_signals (reduce score):
  prior_c4_sherlock:   × 0.6
  no_web_scope:        × 0.3
  api_known_dead:      × 0.0 (skip entirely)
```
