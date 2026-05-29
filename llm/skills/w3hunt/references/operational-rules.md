# Operational Rules & Pitfalls

> Platform-specific notes (Immunefi rate limits, Cloudflare blocking, HackerOne trust issues, Intigriti reCAPTCHA): See `references/platform-operational-notes.md`

## Scope & Submission Rules

- **Save COMPLETE scope on day 1** — extract ALL assets (SC repos, web apps, docs sites) into `scope.txt`. ENS lesson: missed `contracts-v2` ($10K-$250K) by focusing only on web.
- **ASSET SCOPE IS STRICTLY ENFORCED** — Beefy SC-1 (valid bug, working PoC) rejected because contract wasn't in 2022 asset list. Pre-submission: (1) address in scope? (2) called by in-scope contract? (3) if neither, DO NOT SUBMIT.
- **API endpoints not in scope — reframe via frontend bundle proof** — grep JS bundles for the URL. Use `Origin: https://app.example.io` in PoCs.
- **Map findings to EXACT Immunefi impact categories** — "Profile takeover" won't match. Reframe to their exact wording.
- **Avoid phishing-required framing** — frame as interception (browser storage, cross-protocol reuse), NOT phishing.
- **Check Code4rena/Sherlock BEFORE writing a report** — known issues get rejected.
- **Multi-chain = scope confusion** — contracts on unlisted chains may be out of scope.

## Impact Validation (HARD RULES)

- **NEVER claim impact you haven't proven end-to-end** — prove the FULL chain. Theoretical = rejected.
- **VERIFY EXPLOIT OUTPUT BEFORE WRITING REPORT** — run full chain, confirm output matches claim.
- **Fully exploit EVERY leaked token/key before dismissing** — test all endpoints. Only conclude "no impact" with specific 401/403 evidence.
- **CORS on DeFi APIs — VALIDATE IMPACT** — prove cross-origin access exposes OTHERWISE INACCESSIBLE data. Wallet signatures can't be stolen cross-origin.
- **CORS wildcard on Supabase is NOT a finding** — by design. Only report if service_role key leaked or broken RLS.
- **Verify XSS rendering on React/Next.js** — check for `dangerouslySetInnerHTML` before claiming stored XSS.
- **"Requires external conditions" = #1 oracle bug rejection** — frame as "theft WHEN condition occurs."
- **Code bug ≠ exploitable finding** — trace callers on-chain. No active call path = Informational.

## Target Assessment Heuristics

- **Verify harvest SWAPS on-chain before auditing oracle code** — if harvester just calls `transfer()` to EOA, oracle class is dead.
- **Modern protocols separate harvest from swap** — no on-chain swap = no oracle dependency.
- **Single-asset vaults don't need oracles** — check `getAllAssets()` first.
- **Scope freshness matters** — check `paused()` and `balanceOf()` before investing time.
- **harvest() is often permissionless** — check access control before dismissing MEV findings.
- **DeFi frontends are often well-hardened** — don't assume web is easy.
- **Diamond proxy (EIP-2535)** — call `facetAddresses()` to enumerate all facets.

## High-ROI Techniques

- **SDK repos are the best recon source** — clone FIRST before subdomain scanning.
- **CSP source code audit is highest-ROI first pass** — grep for `script-src`, probe whitelisted domains for 404/abandoned state.
- **GraphQL on DeFi = high ROI** — introspection enabled, mutations often lack auth.
- **EIP-191 signature validation is often incomplete** — test: old timestamp, replay, action binding.
- **Next.js API routes are high-value SSRF targets** — `/api/download-file/`, `/api/proxy/`.
- **Supabase projects leak via auth CNAME** — try anon key from JS chunks, test RLS.
- **SSRF + Cloudflare Access = bypass pattern** — app server requests bypass CF Access.
- **Parallel recon with delegate_task** — 2-3 sub-agents, ~10 min wall-clock.

## Reporting Rules

- **PoC format** — Python only, NEVER curl. Include `Origin` header matching in-scope app URL.
- **Fix suggestion required** — many programs reject without remediation advice.
- **Don't test on mainnet with real funds** — use Foundry fork testing.
- **For SC audits with 5+ source files, use delegate_task** — offload bulk code review to a subagent.
- **Foundry submodule setup for cloned repos** — run `git submodule update --init --recursive` from repo ROOT. Check `remappings.txt`. Use `--skip test` for initial build. Forge at `~/.foundry/bin/forge`.
- **Present ALL recon data before prioritizing** — never cherry-pick "interesting" results. Show complete results grouped by response code first, then highlight priorities.
- **Wallet-based auth** — no cookies to steal, but connected wallet = full fund access via malicious tx.

---

## Script Invocation

All scripts in `~/.hermes/skills/security/w3hunt/scripts/`. Invoke via `execute_code`:

```python
import sys, os
sys.path.insert(0, os.path.expanduser("~/.hermes/skills/security/w3hunt/scripts"))
```

**state_manager.py:**
```python
import state_manager
workdir = os.path.expanduser("~/PenTest/Hunting/Immunefi/<target>")

state_manager.init_state(workdir, "Name", "slug", "immunefi", "hybrid")
state_manager.advance_phase(workdir)
state_manager.pivot(workdir, "web_only", "SC prerequisites fail")
state_manager.abandon(workdir, "6h no High+", next_target="next-slug")
should, reason = state_manager.should_abandon(workdir)
state_manager.track_submission(workdir, "finding-001", "immunefi", report_url="...", severity_claimed="Critical")
state_manager.check_submissions(workdir)
state_manager.update_submission(workdir, "finding-001", status="accepted", payout="$25,000")
```

**phase1_triage.py:**
```python
import phase1_triage
results = phase1_triage.run(workdir, "slug", platform="immunefi")
# returns {"live": bool, "has_web_scope": ..., "has_sc_scope": ...}
```

**phase2_recon.py:**
```python
import phase2_recon
results = phase2_recon.run(workdir, domains=["app.example.io"], org_name="example")
# returns {"subdomains": set, "github_repos": [...], "api_endpoints": [...]}
```

**postmortem.py:**
```python
import postmortem
postmortem.run(workdir, lessons={
    "what_worked": "...", "what_wasted_time": "...",
    "transferable": "yes — ...", "hunt_again": "no — ..."
})
# auto-appends to references/engagement-roi-metrics.md
```

**Combined `start` (init + triage in one shot):**
```python
import state_manager, phase1_triage
slug = "target-slug"
workdir = os.path.expanduser(f"~/PenTest/Hunting/Immunefi/{slug}")
state_manager.init_state(workdir, "Target Name", slug, "immunefi", "hybrid")
results = phase1_triage.run(workdir, slug, "immunefi")
if results["live"]:
    state_manager.advance_phase(workdir)
else:
    state_manager.abandon(workdir, "Program not live")
```
