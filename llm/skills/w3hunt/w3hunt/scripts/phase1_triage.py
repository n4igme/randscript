#!/usr/bin/env python3
"""w3hunt Phase 1: Triage — verify program live, check scope, validate prerequisites."""
import os, re, json
from hermes_tools import terminal

def run(workdir, slug, platform="immunefi"):
    """
    15-minute triage: verify program is live, extract scope, check prerequisites.

    Args:
        workdir: target working directory
        slug: program slug (e.g., 'stakewise' for immunefi.com/bug-bounty/stakewise/)
        platform: immunefi|hackerone|hackenproof|intigriti
    """
    results = {
        "live": False,
        "has_web_scope": None,
        "has_sc_scope": None,
        "slug": slug,
        "platform": platform,
        "url": "",
        "subdomains_found": [],
        "contracts_found": [],
    }

    os.makedirs(workdir, exist_ok=True)

    # Step 1: Verify program is live
    if platform == "immunefi":
        url = f"https://immunefi.com/bug-bounty/{slug}/information/"
        results["url"] = url
        check = terminal(f'curl -sL -o /dev/null -w "%{{http_code}}" "{url}"', timeout=15)
        status_code = check.get("output", "").strip()
        results["live"] = status_code == "200"
        print(f"Program check: {url}")
        print(f"  Status: {status_code} {'✓ LIVE' if results['live'] else '✗ DEAD/MOVED'}")

        if not results["live"]:
            print(f"\\n  ⚠️  Program returned {status_code}. Possible causes:")
            print(f"      - Program paused/removed")
            print(f"      - Slug changed")
            print(f"      - Cloudflare blocking")
            print(f"  Try: browser_navigate to verify manually.")
            return results

    elif platform == "hackerone":
        url = f"https://hackerone.com/{slug}"
        results["url"] = url
        check = terminal(f'curl -sL -o /dev/null -w "%{{http_code}}" "{url}"', timeout=15)
        status_code = check.get("output", "").strip()
        results["live"] = status_code == "200"
        print(f"Program check: {url}")
        print(f"  Status: {status_code} {'✓ LIVE' if results['live'] else '✗ DEAD/MOVED'}")

    elif platform == "hackenproof":
        url = f"https://hackenproof.com/programs/{slug}"
        results["url"] = url
        check = terminal(f'curl -sL -o /dev/null -w "%{{http_code}}" "{url}"', timeout=15)
        status_code = check.get("output", "").strip()
        results["live"] = status_code == "200"
        print(f"Program check: {url}")
        print(f"  Status: {status_code} {'✓ LIVE' if results['live'] else '✗ DEAD/MOVED'}")

    elif platform == "intigriti":
        url = f"https://app.intigriti.com/programs/{slug}"
        results["url"] = url
        # Intigriti requires auth for most pages
        results["live"] = True  # Assume live, verify manually
        print(f"Program: {url}")
        print(f"  Status: assumed live (Intigriti requires auth to verify)")

    # Step 2: Quick domain check (extract main domain from slug for recon prep)
    # Try common patterns
    domain_candidates = []
    if platform == "immunefi":
        # Common: slug matches domain (e.g., stakewise → stakewise.io)
        for tld in [".io", ".com", ".finance", ".xyz", ".org", ".network", ".exchange"]:
            domain_candidates.append(f"{slug}{tld}")

    # Step 3: Check for prior audit contests (C4/Sherlock)
    print(f"\\n  Prior contests check:")
    c4_check = terminal(f'curl -s "https://api.github.com/search/repositories?q={slug}+org:code-423n4" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(\'total_count\',0))"', timeout=10)
    c4_count = c4_check.get("output", "0").strip()
    print(f"    Code4rena repos: {c4_count}")

    sherlock_check = terminal(f'curl -s "https://api.github.com/search/repositories?q={slug}+org:sherlock-audit" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(\'total_count\',0))"', timeout=10)
    sherlock_count = sherlock_check.get("output", "0").strip()
    print(f"    Sherlock repos: {sherlock_count}")

    if int(c4_count or 0) > 0 or int(sherlock_count or 0) > 0:
        print(f"    → Prior contest found. SC bugs likely already reported. Prioritize WEB scope.")

    # Step 4: Generate scope.txt template
    scope_path = os.path.join(workdir, "scope.txt")
    if not os.path.isfile(scope_path):
        scope_template = f"""# Scope — {slug} ({platform})
# URL: {results['url']}
# Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}

## Program Rules
- PoC required: [yes/no]
- Fix suggestion required: [yes/no]
- Primacy: [rules/impact]
- Severity version: [v2.2/v2.3]
- Submission limit: [1/day for new Immunefi accounts]

## Payout Structure
- Critical (SC): $[amount]
- Critical (Web): $[amount]
- High: $[amount]
- Medium: $[amount]

## Web/App Assets (in scope)
[Fill from program scope page — EVERY listed domain/URL]

## Smart Contract Assets (in scope)
[Fill from program scope page — EVERY listed contract address + chain]

## Out of Scope
[Note exclusions]

## Prerequisites Check (SC — 3 oracle conditions)
1. Permissionless trigger: [yes/no/unknown]
2. On-chain oracle swap: [yes/no/unknown]
3. Oracle-derived slippage: [yes/no/unknown]
→ If all 3 FAIL: pivot to web scope on this target.

## Notes
- Prior C4 contests: {c4_count}
- Prior Sherlock contests: {sherlock_count}
"""
        with open(scope_path, "w") as f:
            f.write(scope_template)
        print(f"\\n  Created: {scope_path}")
        print(f"  → Fill in scope details from program page (requires browser).")
    else:
        print(f"\\n  scope.txt already exists — skipping template creation.")

    # Summary
    print(f"\\n{'='*50}")
    print(f"TRIAGE SUMMARY: {slug} ({platform})")
    print(f"  Live: {'YES' if results['live'] else 'NO'}")
    print(f"  Prior contests: C4={c4_count}, Sherlock={sherlock_count}")
    print(f"  Next: Fill scope.txt from program page, then advance to Phase 2.")
    if not results["live"]:
        print(f"  ⚠️  PROGRAM NOT LIVE — skip this target.")

    return results


if __name__ == "__main__":
    pass
