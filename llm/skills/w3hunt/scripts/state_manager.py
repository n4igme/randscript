#!/usr/bin/env python3
"""w3hunt state manager — lifecycle operations for hunting sessions."""
import os
import yaml
from datetime import datetime

PHASES = {1: "triage", 2: "recon", 3: "web-assessment", 4: "sc-audit", 5: "exploit-submit"}

GATEWAYS = {
    1: "1_triage",
    2: "2_recon",
    3: "3_web_assessment",
    4: "4_sc_audit",
    5: "5_exploit_submit",
}


def read_state(workdir):
    """Read state.yaml from workdir. Returns dict or None."""
    path = os.path.join(workdir, "state.yaml")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def save_state(workdir, state):
    """Write state dict to state.yaml."""
    path = os.path.join(workdir, "state.yaml")
    with open(path, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def mark_submitted(workdir, finding_id, report_url=""):
    """Update a finding file's status to submitted."""
    finding_path = os.path.join(workdir, "findings", f"{finding_id}.md")
    if not os.path.isfile(finding_path):
        print(f"Finding file not found: {finding_path}")
        return
    with open(finding_path) as f:
        content = f.read()
    content = content.replace("**Status:** draft", "**Status:** submitted")
    content = content.replace("**Status:** validated", "**Status:** submitted")
    with open(finding_path, "w") as f:
        f.write(content)


def _finding_is_high_plus(workdir, finding_id):
    """Check if a finding is High or Critical severity."""
    finding_path = os.path.join(workdir, "findings", f"{finding_id}.md")
    if not os.path.isfile(finding_path):
        return False
    with open(finding_path) as f:
        content = f.read()
    return "**Severity:** Critical" in content or "**Severity:** High" in content


def init_state(workdir, name, slug, platform="immunefi", scope_type="hybrid", url=""):
    """Initialize state.yaml for a new target. Called by `start` command."""
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(os.path.join(workdir, "findings"), exist_ok=True)
    os.makedirs(os.path.join(workdir, "poc"), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "target": {
            "name": name,
            "slug": slug,
            "platform": platform,
            "url": url,
            "started": now,
            "status": "active",
            "scope_type": scope_type,
        },
        "current_phase": 1,
        "gateways": {
            "1_triage": "OPEN",
            "2_recon": "LOCKED",
            "3_web_assessment": "LOCKED",
            "4_sc_audit": "LOCKED",
            "5_exploit_submit": "LOCKED",
        },
        "scope": {
            "has_web": False,
            "has_sc": False,
            "web_targets": [],
            "sc_repos": [],
            "sc_addresses": [],
            "max_payout_web": "",
            "max_payout_sc": "",
        },
        "prerequisites": {
            "program_live": False,
            "prior_contest": False,
            "oracle_permissionless": None,
            "oracle_swap_onchain": None,
            "oracle_slippage_derived": None,
        },
        "findings_count": 0,
        "submitted_count": 0,
        "time_tracking": {
            "phase_1_start": now,
            "phase_1_end": "",
            "phase_2_start": "",
            "phase_2_end": "",
            "phase_3_start": "",
            "phase_3_end": "",
            "phase_4_start": "",
            "phase_4_end": "",
            "phase_5_start": "",
            "phase_5_end": "",
        },
        "notes": "",
    }
    save_state(workdir, state)
    print(f"Initialized: {name} ({platform})")
    print(f"  Workdir: {workdir}")
    print(f"  Phase 1 (Triage) → OPEN")
    return state


def advance_phase(workdir, justification=""):
    """Advance to next phase. Called by `next` command.
    Returns new state or None if at final phase."""
    state = read_state(workdir)
    if not state:
        print("No session found.")
        return None

    current = state["current_phase"]
    if current >= 5:
        print("Already at final phase (5: exploit-submit).")
        return state

    now = datetime.now().isoformat()
    current_key = GATEWAYS[current]
    next_phase = current + 1
    next_key = GATEWAYS[next_phase]

    # Close current phase
    state["gateways"][current_key] = "PASSED"
    state["time_tracking"][f"phase_{current}_end"] = now

    # Open next phase
    state["current_phase"] = next_phase
    state["gateways"][next_key] = "OPEN"
    state["time_tracking"][f"phase_{next_phase}_start"] = now

    if justification:
        state["notes"] = state.get("notes", "") + f"\nPhase {current}→{next_phase} override: {justification} ({now})"

    save_state(workdir, state)
    print(f"Advanced: Phase {current} ({PHASES[current]}) → Phase {next_phase} ({PHASES[next_phase]})")
    return state



def abandon(workdir, reason, next_target=""):
    """Abandon current target — codifies the 'hour 6, no High+' rule.
    Records reason, marks session as abandoned, suggests next target."""
    state = read_state(workdir)
    if not state:
        print("No session found.")
        return

    now = datetime.now().isoformat()
    phase = state["current_phase"]

    # Calculate total elapsed
    started = state["target"]["started"]
    elapsed_hours = 0
    if started:
        try:
            start_dt = datetime.fromisoformat(started)
            elapsed_hours = (datetime.now() - start_dt).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    state["abandoned"] = {
        "at": now,
        "phase": phase,
        "reason": reason,
        "elapsed_hours": round(elapsed_hours, 1),
        "next_target": next_target,
    }

    # Close current phase timing
    state["time_tracking"][f"phase_{phase}_end"] = now

    # Mark all remaining gates as ABANDONED
    for key in state["gateways"]:
        if state["gateways"][key] in ("OPEN", "LOCKED"):
            state["gateways"][key] = "ABANDONED"

    save_state(workdir, state)

    print(f"Session ABANDONED: {state['target']['name']}")
    print(f"  Reason: {reason}")
    print(f"  Phase reached: {phase} ({PHASES.get(phase, '?')})")
    print(f"  Total time: {elapsed_hours:.1f}h")
    print(f"  Findings: {state['findings_count']} | Submitted: {state['submitted_count']}")
    if next_target:
        print(f"  Next target: {next_target}")
    return state


def pivot(workdir, new_scope_type, reason):
    """Pivot within same target (e.g., SC prerequisites fail → web scope).
    Changes scope_type and resets to Phase 2 (recon) for the new scope."""
    state = read_state(workdir)
    if not state:
        print("No session found.")
        return

    old_scope = state["target"]["scope_type"]
    state["target"]["scope_type"] = new_scope_type

    now = datetime.now().isoformat()
    state["notes"] = state.get("notes", "") + f"\\nPivot {old_scope}→{new_scope_type}: {reason} ({now})"

    # If pivoting from SC to web, mark SC phase as N/A
    if new_scope_type == "web_only" and old_scope in ("hybrid", "sc_only"):
        for key in state["gateways"]:
            if key.startswith("4_"):
                state["gateways"][key] = "N/A"
                break

    # Reset to phase 2 (recon) for the new scope
    state["current_phase"] = 2
    state["time_tracking"]["phase_2_start"] = now
    state["time_tracking"]["phase_2_end"] = ""
    for key in state["gateways"]:
        if key.startswith("2_"):
            state["gateways"][key] = "OPEN"
            break

    save_state(workdir, state)
    print(f"Pivoted: {old_scope} → {new_scope_type}")
    print(f"  Reason: {reason}")
    print(f"  Reset to Phase 2 (Recon) for new scope.")
    return state


def should_abandon(workdir):
    """Check if abandon heuristics are triggered. Returns (should_abandon, reason)."""
    state = read_state(workdir)
    if not state:
        return (False, "")

    started = state["target"]["started"]
    if not started:
        return (False, "")

    try:
        start_dt = datetime.fromisoformat(started)
        elapsed_hours = (datetime.now() - start_dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return (False, "")

    findings = state["findings_count"]
    has_high = any(
        _finding_is_high_plus(workdir, f"finding-{i:03d}")
        for i in range(1, findings + 1)
    ) if findings > 0 else False

    if elapsed_hours >= 8:
        return (True, f"Hard budget exceeded ({elapsed_hours:.1f}h). Submit what you have or move on.")
    if elapsed_hours >= 6 and not has_high:
        return (True, f"6+ hours ({elapsed_hours:.1f}h), no High+ finding. Pivot to next target.")

    return (False, "")


def track_submission(workdir, finding_id, platform, report_url="", report_id="",
                     severity_claimed="", bounty_expected=""):
    """Track a submission with platform-specific metadata.
    Updates both the finding file and a central submissions.yaml."""
    state = read_state(workdir)
    if not state:
        return

    now = datetime.now().isoformat()

    # Update finding file
    mark_submitted(workdir, finding_id, report_url)

    # Update/create submissions.yaml
    submissions_path = os.path.join(workdir, "submissions.yaml")
    submissions = []
    if os.path.isfile(submissions_path):
        with open(submissions_path) as f:
            submissions = yaml.safe_load(f) or []

    entry = {
        "finding_id": finding_id,
        "platform": platform,
        "report_url": report_url,
        "report_id": report_id,
        "severity_claimed": severity_claimed,
        "bounty_expected": bounty_expected,
        "submitted_at": now,
        "status": "submitted",
        "last_checked": now,
        "resolution": "",
        "payout": "",
    }
    submissions.append(entry)

    with open(submissions_path, "w") as f:
        yaml.dump(submissions, f, default_flow_style=False)

    print(f"Submission tracked: {finding_id} on {platform}")
    print(f"  URL: {report_url or 'N/A'}")
    print(f"  Severity: {severity_claimed} | Expected: {bounty_expected}")
    print(f"  Saved to: submissions.yaml")


def check_submissions(workdir):
    """Display all tracked submissions and their status."""
    submissions_path = os.path.join(workdir, "submissions.yaml")
    if not os.path.isfile(submissions_path):
        print("No submissions.yaml found.")
        return []

    with open(submissions_path) as f:
        submissions = yaml.safe_load(f) or []

    if not submissions:
        print("No submissions tracked.")
        return []

    print(f"Submissions ({len(submissions)}):")
    for s in submissions:
        status_icon = {"submitted": "📤", "triaging": "🔍", "accepted": "✅",
                       "rejected": "❌", "duplicate": "🔁", "paid": "💰"}.get(s["status"], "?")
        print(f"  {status_icon} {s['finding_id']} [{s['severity_claimed']}] → {s['platform']}")
        print(f"     Status: {s['status']} | URL: {s.get('report_url', 'N/A')}")
        if s.get("resolution"):
            print(f"     Resolution: {s['resolution']}")
        if s.get("payout"):
            print(f"     Payout: {s['payout']}")
    return submissions


def update_submission(workdir, finding_id, status="", resolution="", payout=""):
    """Update a tracked submission's status."""
    submissions_path = os.path.join(workdir, "submissions.yaml")
    if not os.path.isfile(submissions_path):
        print("No submissions.yaml found.")
        return

    with open(submissions_path) as f:
        submissions = yaml.safe_load(f) or []

    updated = False
    for s in submissions:
        if s["finding_id"] == finding_id:
            if status:
                s["status"] = status
            if resolution:
                s["resolution"] = resolution
            if payout:
                s["payout"] = payout
            s["last_checked"] = datetime.now().isoformat()
            updated = True
            break

    if not updated:
        print(f"Finding {finding_id} not found in submissions.")
        return

    with open(submissions_path, "w") as f:
        yaml.dump(submissions, f, default_flow_style=False)

    print(f"Updated {finding_id}: status={status or '(unchanged)'}, resolution={resolution or '(unchanged)'}, payout={payout or '(unchanged)'}")
