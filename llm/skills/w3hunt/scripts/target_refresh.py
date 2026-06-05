#!/usr/bin/env python3
"""w3hunt target_refresh — fetch and score Immunefi programs for hunting.

Usage:
    python3 target_refresh.py
    python3 target_refresh.py --min-payout 10000
    python3 target_refresh.py --output ~/PenTest/Hunting/Immunefi/targets.md
"""
import argparse
import json
import sys
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError


BOUNTY_DATA_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data"
    "/main/data/immunefi_data.json"
)


def fetch_programs():
    """Fetch Immunefi programs from bounty-targets-data."""
    try:
        req = Request(BOUNTY_DATA_URL, headers={"User-Agent": "w3hunt/1.0"})
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (HTTPError, URLError) as e:
        print(f"✗ Failed to fetch: {e}")
        return None


def score_program(program):
    """Score a program for hunting priority. Higher = better."""
    targets = program.get("targets", {})
    has_web = False
    has_sc = False
    max_payout = 0

    for scope_type, scope_list in targets.items():
        if not isinstance(scope_list, list):
            continue
        for item in scope_list:
            if isinstance(item, dict):
                reward = item.get("maxBounty", 0) or 0
            else:
                reward = 0
            max_payout = max(max_payout, reward)

    # Check scope types from targets keys
    scope_keys = [k.lower() for k in targets.keys()]
    has_web = any("web" in k or "app" in k for k in scope_keys)
    has_sc = any("smart" in k or "contract" in k or "blockchain" in k for k in scope_keys)

    if max_payout == 0:
        # Try top-level reward field
        rewards = program.get("rewards", [])
        if isinstance(rewards, list):
            for r in rewards:
                if isinstance(r, dict):
                    val = r.get("maxBounty", 0) or r.get("max", 0) or 0
                    max_payout = max(max_payout, val)

    # Base score
    score = max_payout / 1000  # normalize

    # Type multiplier
    if has_web and has_sc:
        score *= 1.5  # hybrid = our edge
    elif has_web and not has_sc:
        score *= 1.2
    elif has_sc and not has_web:
        score *= 0.4  # pure SC = not our strength

    return {
        "score": round(score, 1),
        "max_payout": max_payout,
        "has_web": has_web,
        "has_sc": has_sc,
    }


def filter_and_rank(programs, min_payout=10000):
    """Filter and rank programs by score."""
    scored = []
    for prog in programs:
        name = prog.get("name", "Unknown")
        url = prog.get("url", "")
        slug = url.split("/")[-1] if url else ""

        result = score_program(prog)
        if result["max_payout"] < min_payout:
            continue

        scored.append({
            "name": name,
            "slug": slug,
            "url": url,
            "max_payout": result["max_payout"],
            "has_web": result["has_web"],
            "has_sc": result["has_sc"],
            "score": result["score"],
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def write_report(programs, output_path=None):
    """Write ranked target list."""
    now = datetime.now().isoformat()
    lines = []
    lines.append(f"# Immunefi Target Shortlist")
    lines.append(f"")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Programs evaluated:** {len(programs)}")
    lines.append(f"**Refresh when:** >7 days old")
    lines.append(f"")
    lines.append("| # | Program | Max Payout | Web | SC | Score |")
    lines.append("|---|---------|-----------|:---:|:---:|------:|")

    for i, prog in enumerate(programs[:30], 1):
        web = "✓" if prog["has_web"] else "✗"
        sc = "✓" if prog["has_sc"] else "✗"
        payout = f"${prog['max_payout']:,.0f}"
        lines.append(
            f"| {i} | [{prog['name']}]({prog['url']}) | {payout} | {web} | {sc} | {prog['score']} |"
        )

    report = "\n".join(lines) + "\n"

    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
        print(f"✓ Written to: {output_path}")
    else:
        print(report)

    return report


def main():
    parser = argparse.ArgumentParser(description="Refresh w3hunt target list")
    parser.add_argument("--min-payout", type=int, default=10000)
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    print("[*] Fetching Immunefi programs...")
    programs = fetch_programs()
    if not programs:
        sys.exit(1)

    print(f"[*] {len(programs)} programs fetched, filtering...")
    ranked = filter_and_rank(programs, min_payout=args.min_payout)
    print(f"[*] {len(ranked)} programs match criteria")

    write_report(ranked, args.output)


if __name__ == "__main__":
    main()
