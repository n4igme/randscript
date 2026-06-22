#!/usr/bin/env python3
"""w3hunt postmortem — automated ROI data entry from state.yaml + submissions.yaml."""
import os
import yaml
from datetime import datetime


def run(workdir, lessons=None):
    """
    Generate postmortem from engagement data and append to engagement-roi-metrics.md.

    Args:
        workdir: target working directory (e.g., ~/PenTest/Hunting/Immunefi/<target>/)
        lessons: dict with optional keys:
            - what_worked: str
            - what_wasted_time: str
            - transferable: str (yes/no + explanation)
            - skill_gaps: str
            - hunt_again: str (yes/no + why)

    Returns:
        dict with computed metrics
    """
    lessons = lessons or {}

    # Read state.yaml
    state_path = os.path.join(workdir, "state.yaml")
    if not os.path.isfile(state_path):
        print(f"ERROR: No state.yaml found at {workdir}")
        return None

    with open(state_path) as f:
        state = yaml.safe_load(f)

    # Read submissions.yaml (may not exist)
    submissions_path = os.path.join(workdir, "submissions.yaml")
    submissions = []
    if os.path.isfile(submissions_path):
        with open(submissions_path) as f:
            submissions = yaml.safe_load(f) or []

    # Calculate total hours
    target = state.get("target", {})
    started = target.get("started", "")
    total_hours = 0
    if started:
        try:
            start_dt = datetime.fromisoformat(started)
            # Use last phase end time, or now if still active
            last_end = ""
            for i in range(5, 0, -1):
                end = state.get("time_tracking", {}).get(f"phase_{i}_end", "")
                if end:
                    last_end = end
                    break
            if last_end:
                end_dt = datetime.fromisoformat(last_end)
            else:
                end_dt = datetime.now()
            total_hours = round((end_dt - start_dt).total_seconds() / 3600, 1)
        except (ValueError, TypeError):
            pass

    # Determine phase where finding was discovered
    phase_found = "—"
    findings_dir = os.path.join(workdir, "findings")
    if os.path.isdir(findings_dir):
        for fname in sorted(os.listdir(findings_dir)):
            fpath = os.path.join(findings_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath) as f:
                    content = f.read()
                if "**Phase Discovered:**" in content:
                    for line in content.split("\n"):
                        if "**Phase Discovered:**" in line:
                            phase_found = line.split(":**")[1].strip()
                            break
                    break  # Use first finding's phase

    # Calculate time-to-first-finding
    time_to_first = "—"
    if started and state.get("findings_count", 0) > 0:
        # Approximate: use phase_found start time
        try:
            start_dt = datetime.fromisoformat(started)
            phase_num = None
            if "2" in str(phase_found):
                phase_num = 2
            elif "3" in str(phase_found):
                phase_num = 3
            elif "4" in str(phase_found):
                phase_num = 4
            if phase_num:
                phase_start = state.get("time_tracking", {}).get(f"phase_{phase_num}_start", "")
                phase_end = state.get("time_tracking", {}).get(f"phase_{phase_num}_end", "")
                if phase_start:
                    # Midpoint of the phase as estimate
                    ps = datetime.fromisoformat(phase_start)
                    if phase_end:
                        pe = datetime.fromisoformat(phase_end)
                        midpoint = ps + (pe - ps) / 2
                    else:
                        midpoint = ps
                    time_to_first = f"{round((midpoint - start_dt).total_seconds() / 3600, 1)}h"
        except (ValueError, TypeError):
            pass

    # Calculate payout
    total_payout = 0
    outcome = state.get("target", {}).get("status", "unknown")
    if state.get("abandoned"):
        outcome = "abandoned"

    for sub in submissions:
        payout_str = sub.get("payout", "")
        if payout_str:
            # Parse "$25,000" or "25000" style
            try:
                cleaned = payout_str.replace("$", "").replace(",", "").strip()
                total_payout += float(cleaned)
            except (ValueError, TypeError):
                pass
        # Use submission status for outcome if available
        if sub.get("status") in ("accepted", "paid"):
            outcome = sub["status"]
        elif sub.get("status") == "rejected" and outcome not in ("accepted", "paid"):
            outcome = "rejected"
        elif sub.get("status") == "duplicate" and outcome not in ("accepted", "paid", "rejected"):
            outcome = "duplicate"

    if submissions and outcome == "active":
        outcome = "submitted"

    # $/hr calculation
    dollar_per_hour = "—"
    if total_payout > 0 and total_hours > 0:
        dollar_per_hour = f"${round(total_payout / total_hours)}"
    elif outcome in ("abandoned", "rejected"):
        dollar_per_hour = "$0"

    # Determine target type
    scope_type = target.get("scope_type", "unknown")
    slug = target.get("slug", "unknown")
    platform = target.get("platform", "immunefi")
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Format payout string
    payout_display = f"${int(total_payout):,}" if total_payout > 0 else ("pending" if outcome == "submitted" else "$0")

    # Build metrics dict
    metrics = {
        "slug": slug,
        "platform": platform,
        "scope_type": scope_type,
        "hours": total_hours,
        "phase_found": phase_found,
        "outcome": outcome,
        "payout": payout_display,
        "dollar_per_hour": dollar_per_hour,
        "time_to_first": time_to_first,
        "findings_count": state.get("findings_count", 0),
        "submitted_count": state.get("submitted_count", 0),
        "date": date_str,
    }

    # Print summary
    print(f"{'='*50}")
    print(f"POSTMORTEM: {slug} ({platform})")
    print(f"{'='*50}")
    print(f"  Outcome:        {outcome}")
    print(f"  Hours:          {total_hours}h")
    print(f"  Payout:         {payout_display}")
    print(f"  $/hr:           {dollar_per_hour}")
    print(f"  Phase found:    {phase_found}")
    print(f"  Time-to-first:  {time_to_first}")
    print(f"  Findings:       {metrics['findings_count']}")
    print(f"  Submitted:      {metrics['submitted_count']}")

    # Append to engagement-roi-metrics.md
    script_dir = os.path.dirname(os.path.abspath(__file__))
    metrics_path = os.path.join(script_dir, "..", "references", "engagement-roi-metrics.md")
    metrics_path = os.path.normpath(metrics_path)
    if os.path.isfile(metrics_path):
        # Append table row
        table_row = f"| {slug} | {platform} | {scope_type} | {total_hours} | {phase_found} | {outcome} | {payout_display} | {dollar_per_hour} | {date_str} |"

        # Build postmortem entry
        entry = f"\n### {slug} ({date_str})\n"
        entry += f"- **Outcome:** {outcome}\n"
        entry += f"- **Hours:** {total_hours}h | **Payout:** {payout_display} | **$/hr:** {dollar_per_hour}\n"
        entry += f"- **Phase found:** {phase_found} | **Time-to-first:** {time_to_first}\n"

        if lessons.get("what_worked"):
            entry += f"- **What worked:** {lessons['what_worked']}\n"
        if lessons.get("what_wasted_time"):
            entry += f"- **What wasted time:** {lessons['what_wasted_time']}\n"
        if lessons.get("transferable"):
            entry += f"- **Transferable:** {lessons['transferable']}\n"
        if lessons.get("skill_gaps"):
            entry += f"- **Skill gaps:** {lessons['skill_gaps']}\n"
        if lessons.get("hunt_again"):
            entry += f"- **Hunt again:** {lessons['hunt_again']}\n"
        entry += f"- **Skill update:** [pending review]\n"

        with open(metrics_path, "r") as f:
            content = f.read()

        # Insert table row after the header row
        table_marker = "| $/hr | Date |"
        if table_marker in content:
            # Find the line after the table header separator
            lines = content.split("\n")
            insert_idx = None
            for i, line in enumerate(lines):
                if "$/hr" in line and "Date" in line:
                    # Next line is separator (|---|...), insert after that
                    insert_idx = i + 2
                    break
            if insert_idx:
                lines.insert(insert_idx, table_row)
                content = "\n".join(lines)

        # Append detailed entry at the end
        content += f"\n{entry}"

        with open(metrics_path, "w") as f:
            f.write(content)

        print(f"\n  ✓ Appended to: {metrics_path}")
    else:
        print(f"\n  ⚠ Metrics file not found: {metrics_path}")
        print(f"    Table row: {table_row}")

    return metrics


if __name__ == "__main__":
    pass
