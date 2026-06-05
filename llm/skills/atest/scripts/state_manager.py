#!/usr/bin/env python3
"""atest state manager — lifecycle operations for API pentest engagements."""
import os
import yaml
from datetime import datetime

PHASES = {1: "recon", 2: "authn-authz", 3: "injection-logic", 4: "reporting"}

GATEWAYS = {
    1: "1_recon",
    2: "2_authn_authz",
    3: "3_injection_logic",
    4: "4_reporting",
}


def _state_path(workdir):
    return os.path.join(workdir, "atest-output", "state.yaml")


def read_state(workdir):
    """Read state.yaml. Returns dict or None."""
    path = _state_path(workdir)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def save_state(workdir, state):
    """Write state dict to state.yaml."""
    path = _state_path(workdir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def init_state(workdir, name, api_type="rest", auth_mechanism="jwt",
               base_urls=None, has_graphql=False, has_grpc=False,
               write_ops_allowed=True, rate_limit_known=""):
    """Initialize engagement. Called by `start` command."""
    base_urls = base_urls or []
    outdir = os.path.join(workdir, "atest-output")
    for subdir in ("phase1-recon", "phase2-authz", "phase3-injection", "report"):
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": name,
            "started": now,
            "api_type": api_type,
            "auth_mechanism": auth_mechanism,
        },
        "gateways": {
            "1_recon": "OPEN",
            "2_authn_authz": "LOCKED",
            "3_injection_logic": "LOCKED",
            "4_reporting": "LOCKED",
        },
        "findings_count": 0,
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "current_phase": 1,
        "config": {
            "base_urls": base_urls,
            "has_graphql": has_graphql,
            "has_grpc": has_grpc,
            "write_ops_allowed": write_ops_allowed,
            "rate_limit_known": rate_limit_known,
        },
        "time_tracking": {
            "phase_1_start": now,
            "phase_1_end": "",
            "phase_2_start": "",
            "phase_2_end": "",
            "phase_3_start": "",
            "phase_3_end": "",
            "phase_4_start": "",
            "phase_4_end": "",
        },
        "notes": "",
    }
    save_state(workdir, state)

    # Create scope.md template
    scope_path = os.path.join(outdir, "scope.md")
    if not os.path.isfile(scope_path):
        with open(scope_path, "w") as f:
            f.write(f"# Scope — {name}\n\n")
            f.write(f"- API Type: {api_type}\n")
            f.write(f"- Auth: {auth_mechanism}\n")
            f.write(f"- Base URLs: {', '.join(base_urls) or 'TBD'}\n")
            f.write(f"- GraphQL: {has_graphql}\n")
            f.write(f"- gRPC: {has_grpc}\n")
            f.write(f"- Write ops allowed: {write_ops_allowed}\n\n")
            f.write("## Endpoints\n\n[Fill during Phase 1]\n\n")
            f.write("## Auth Flow\n\n[Document token lifecycle]\n")

    # Create findings log
    findings_path = os.path.join(outdir, "findings-log.md")
    if not os.path.isfile(findings_path):
        with open(findings_path, "w") as f:
            f.write(f"# Findings Log — {name}\n\n")
            f.write("| ID | Title | Severity | Category | Endpoint | Status |\n")
            f.write("|---|---|---|---|---|---|\n")

    print(f"Initialized: {name}")
    print(f"  Workdir: {outdir}")
    print(f"  API type: {api_type} | Auth: {auth_mechanism}")
    print(f"  Phase 1 (Recon) → OPEN")
    return state


def advance_phase(workdir, justification=""):
    """Advance to next phase. Returns new state or None."""
    state = read_state(workdir)
    if not state:
        print("No engagement found.")
        return None

    current = state["current_phase"]
    if current >= 4:
        print("Already at final phase (4: reporting).")
        return state

    now = datetime.now().isoformat()
    current_key = GATEWAYS[current]
    next_phase = current + 1
    next_key = GATEWAYS[next_phase]

    state["gateways"][current_key] = "PASSED"
    state["time_tracking"][f"phase_{current}_end"] = now
    state["current_phase"] = next_phase
    state["gateways"][next_key] = "OPEN"
    state["time_tracking"][f"phase_{next_phase}_start"] = now

    if justification:
        state["notes"] = state.get("notes", "") + f"\nPhase {current}→{next_phase} override: {justification} ({now})"

    save_state(workdir, state)
    print(f"Advanced: Phase {current} ({PHASES[current]}) → Phase {next_phase} ({PHASES[next_phase]})")
    return state


def status(workdir):
    """Print current engagement status."""
    state = read_state(workdir)
    if not state:
        print("No engagement found. Use `start` to begin.")
        return None

    current = state["current_phase"]
    name = state["engagement"]["name"]
    started = state["engagement"]["started"]

    elapsed = 0
    if started:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    findings = state["findings_count"]
    should, reason = should_abandon(workdir)

    print(f"─── atest status ───────────────────────────────")
    print(f"Target:   {name} ({state['engagement']['api_type']})")
    print(f"Phase:    {current} ({PHASES[current]}) — {state['gateways'][GATEWAYS[current]]}")
    print(f"Elapsed:  {elapsed:.1f}h")
    print(f"Findings: {findings}")
    print(f"Abandon:  {'YES — ' + reason if should else 'no'}")
    print(f"─────────────────────────────────────────────────")
    return state


def should_abandon(workdir, budget_hours=4):
    """Check abandon heuristics. Returns (should_abandon, reason)."""
    state = read_state(workdir)
    if not state:
        return (False, "")

    started = state["engagement"]["started"]
    if not started:
        return (False, "")

    try:
        elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
    except (ValueError, TypeError):
        return (False, "")

    findings = state["findings_count"]
    threshold = budget_hours * 0.75

    if elapsed >= budget_hours:
        return (True, f"Budget exceeded ({elapsed:.1f}h / {budget_hours}h). Wrap up and report.")
    if elapsed >= threshold and findings == 0:
        return (True, f"75% budget spent ({elapsed:.1f}h), zero findings. Consider reporting as hardened.")

    return (False, "")


def abandon(workdir, reason):
    """Abandon engagement."""
    state = read_state(workdir)
    if not state:
        print("No engagement found.")
        return

    now = datetime.now().isoformat()
    phase = state["current_phase"]
    state["time_tracking"][f"phase_{phase}_end"] = now

    for key in state["gateways"]:
        if state["gateways"][key] in ("OPEN", "LOCKED"):
            state["gateways"][key] = "ABANDONED"

    state["notes"] = state.get("notes", "") + f"\nAbandoned: {reason} ({now})"
    save_state(workdir, state)

    started = state["engagement"]["started"]
    elapsed = 0
    if started:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    print(f"ABANDONED: {state['engagement']['name']}")
    print(f"  Reason: {reason}")
    print(f"  Phase: {phase} ({PHASES[phase]})")
    print(f"  Elapsed: {elapsed:.1f}h | Findings: {state['findings_count']}")


def add_finding(workdir, finding_id, title, severity, category, endpoint):
    """Register a finding in state and findings-log.md."""
    state = read_state(workdir)
    if not state:
        print("No engagement found.")
        return

    state["findings_count"] += 1
    sev_key = severity.lower()
    if "findings_by_severity" not in state:
        state["findings_by_severity"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if sev_key in state["findings_by_severity"]:
        state["findings_by_severity"][sev_key] += 1
    save_state(workdir, state)

    # Append to findings log
    outdir = os.path.join(workdir, "atest-output")
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "a") as f:
        f.write(f"| {finding_id} | {title} | {severity} | {category} | {endpoint} | draft |\n")

    print(f"Finding added: [{finding_id}] {title} ({severity})")


if __name__ == "__main__":
    pass
