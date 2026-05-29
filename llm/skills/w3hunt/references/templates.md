# W3Hunt Templates & Schemas

## State.yaml Schema

State file location: `~/PenTest/Hunting/Immunefi/<target>/state.yaml`

```yaml
target:
  name: ""                    # Program name
  slug: ""                    # Program slug (e.g., "stakewise")
  platform: "immunefi"        # immunefi|hackenproof|intigriti
  url: ""                     # Program URL
  started: ""                 # ISO timestamp
  status: "active"            # active|submitted|closed|abandoned
  scope_type: "hybrid"        # hybrid|web_only|sc_only

current_phase: 1              # Integer: 1=triage, 2=recon, 3=web, 4=sc, 5=exploit

gateways:
  1_triage: OPEN
  2_recon: LOCKED
  3_web_assessment: LOCKED
  4_sc_audit: LOCKED
  5_exploit_submit: LOCKED

scope:
  has_web: false
  has_sc: false
  web_targets: []
  sc_repos: []
  sc_addresses: []
  max_payout_web: ""
  max_payout_sc: ""

prerequisites:
  program_live: false
  prior_contest: false
  oracle_permissionless: null
  oracle_swap_onchain: null
  oracle_slippage_derived: null

findings_count: 0
submitted_count: 0

time_tracking:
  phase_1_start: ""
  phase_1_end: ""
  phase_2_start: ""
  phase_2_end: ""
  phase_3_start: ""
  phase_3_end: ""
  phase_4_start: ""
  phase_4_end: ""
  phase_5_start: ""
  phase_5_end: ""

notes: ""                     # Pivot history, decisions, context
```

**Time enforcement:** If elapsed time > 8 hours and `findings_count == 0`, trigger abandon decision. Use `should_abandon()` from state_manager.py.

**Resume (>24h gap):** Re-verify program is live, re-check scope hasn't changed, re-read findings list.

---

## Output Structure

```
~/PenTest/Hunting/Immunefi/<target>/
├── state.yaml             # Phase tracking, time, findings
├── scope.txt              # Program rules, payouts, impacts, targets
├── submissions.yaml       # Submission tracking (created on first submit)
├── subdomains.txt         # Subdomain enumeration results
├── frontend-recon.txt     # Framework, APIs, headers, hosting
├── recon-summary.txt      # Consolidated findings + attack vectors
├── github-repos.txt       # Repository enumeration
├── api-endpoints.txt      # Full API endpoint map
├── findings/              # Individual finding write-ups
│   ├── finding-001.md
│   └── ...
└── poc/                   # PoC scripts for submissions
    ├── poc_001.py
    └── ...
```

---

## Finding Template

Each file in `findings/` follows this format:

```markdown
# Finding-NNN: {Title}

**Severity:** Critical / High / Medium
**Impact Category:** {Exact Immunefi category wording}
**Affected Asset:** {Contract address or URL — MUST be in scope list}
**Chain:** {Ethereum / Arbitrum / Polygon / etc.}
**Phase Discovered:** {2/3/4}
**Status:** draft / validated / submitted / accepted / rejected

## Description
{What the vulnerability is, 2-3 sentences}

## Steps to Reproduce
1. {step}
2. {step}

## PoC
File: `../poc/poc_NNN.py`
Output: {paste actual execution output here}

## Impact
{Quantified: $ amount at risk, users affected, funds drainable}

## Fix Suggestion
{Specific remediation}

## Scope Proof
{How this asset is in scope — address match or call chain}
```
