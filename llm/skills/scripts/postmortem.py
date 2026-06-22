#!/usr/bin/env python3
"""Postmortem / engagement retrospective for security skills."""
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path


def run_postmortem(workdir: str, skill_name: str = "engagement",
                   payout: float = 0.0, lessons: str = "",
                   patterns: str = "", skill_gaps: str = ""):
    """Collect retrospective data and append to engagement-roi-metrics.md.

    Args:
        workdir: Path to the engagement output directory (containing state.yaml)
        skill_name: Which skill was used (ptest, mtest, etc.)
        payout: Bounty/payout in USD (0 if none)
        lessons: Key lessons learned (one line)
        patterns: Transferable pattern discovered (if any)
        skill_gaps: Skill gaps discovered during engagement
    """
    state_path = os.path.join(workdir, "state.yaml")
    if not os.path.exists(state_path):
        print("No state.yaml found.")
        return

    with open(state_path) as f:
        state = yaml.safe_load(f)

    engagement = state.get("engagement", {})
    started = engagement.get("started", "")
    ended = datetime.now().isoformat()

    elapsed_hours = 0.0
    if started:
        try:
            elapsed_hours = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    current_phase = state.get("current_phase", 1)
    findings_count = state.get("findings_count", 0)
    findings_by_severity = state.get("findings_by_severity", {})

    # Interactive fallback only when running directly from terminal
    if sys.stdin.isatty():
        if payout == 0.0:
            raw = input("Payout (USD) [0 if none]: ").strip()
            payout = float(raw) if raw else 0.0
        if not lessons:
            lessons = input("Key lessons (one line): ").strip()
        if not patterns:
            patterns = input("Transferable pattern (if any): ").strip()
        if not skill_gaps:
            skill_gaps = input("Skill gaps discovered: ").strip()

    entry = {
        "date": ended,
        "skill": skill_name,
        "target": engagement.get("name", "unknown"),
        "elapsed_hours": round(elapsed_hours, 1),
        "findings_total": findings_count,
        "findings_by_severity": findings_by_severity,
        "payout_usd": payout,
        "usd_per_hour": round(payout / elapsed_hours, 2) if elapsed_hours > 0 else 0,
        "phase_found": current_phase,
        "lessons": lessons,
        "patterns": patterns,
        "skill_gaps": skill_gaps,
    }

    metrics_path = Path(__file__).parent.parent / "references" / "engagement-roi-metrics.md"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    with open(metrics_path, "a") as f:
        f.write(f"\n## {engagement.get('name', 'Unknown')} — {ended[:10]}\n")
        f.write(f"- **Elapsed:** {entry['elapsed_hours']}h\n")
        f.write(f"- **Findings:** {entry['findings_total']} total\n")
        if findings_by_severity:
            f.write(f"- **By severity:** {findings_by_severity}\n")
        f.write(f"- **Payout:** ${payout:,.0f}\n")
        f.write(f"- **Rate:** ${entry['usd_per_hour']}/hr\n")
        f.write(f"- **Phase found:** {current_phase}\n")
        if lessons:
            f.write(f"- **Lessons:** {lessons}\n")
        if patterns:
            f.write(f"- **Transferable pattern:** {patterns}\n")
        if skill_gaps:
            f.write(f"- **Skill gaps:** {skill_gaps}\n")

    print(f"Postmortem recorded to {metrics_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run engagement postmortem")
    parser.add_argument("workdir", nargs="?", default=".", help="Engagement output directory")
    parser.add_argument("skill", nargs="?", default="unknown", help="Skill name")
    parser.add_argument("--payout", type=float, default=0.0, help="Payout in USD")
    parser.add_argument("--lessons", default="", help="Key lessons")
    parser.add_argument("--patterns", default="", help="Transferable patterns")
    parser.add_argument("--skill-gaps", default="", help="Skill gaps discovered")
    args = parser.parse_args()

    run_postmortem(args.workdir, args.skill,
                   payout=args.payout, lessons=args.lessons,
                   patterns=args.patterns, skill_gaps=args.skill_gaps)
