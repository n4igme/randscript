#!/usr/bin/env python3
"""adtest state manager — lifecycle operations for AD pentest engagements."""
import os
import yaml
from datetime import datetime

PHASES = {
    1: "recon-enum",
    2: "cred-harvest",
    3: "kerberos",
    4: "relay-delegation",
    5: "privesc-lateral",
    6: "reporting",
}

GATEWAYS = {
    1: "1_recon_enum",
    2: "2_cred_harvest",
    3: "3_kerberos",
    4: "4_relay_delegation",
    5: "5_privesc_lateral",
    6: "6_reporting",
}


def _state_path(workdir: str) -> str:
    return os.path.join(workdir, "adtest-output", "state.yaml")


def read_state(workdir: str) -> dict | None:
    """Read state.yaml. Returns dict or None."""
    path = _state_path(workdir)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def save_state(workdir: str, state: dict) -> None:
    """Write state dict to state.yaml."""
    path = _state_path(workdir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(state, f, default_flow_style=False, sort_keys=False)


def init_state(workdir: str, name: str, domain: str = "",
               dc_ip: str = "", access_level: str = "domain-user",
               scope_type: str = "full") -> dict:
    """Initialize engagement. Called by `start` command."""
    outdir = os.path.join(workdir, "adtest-output")
    for subdir in ("phase1-recon", "phase2-creds", "phase3-kerberos",
                   "phase4-relay", "phase5-privesc", "report", "bloodhound"):
        os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

    now = datetime.now().isoformat()
    state = {
        "engagement": {
            "name": name,
            "started": now,
            "domain": domain,
            "dc_ip": dc_ip,
            "access_level": access_level,
            "scope_type": scope_type,
        },
        "gateways": {
            "1_recon_enum": "OPEN",
            "2_cred_harvest": "LOCKED",
            "3_kerberos": "LOCKED",
            "4_relay_delegation": "LOCKED",
            "5_privesc_lateral": "LOCKED",
            "6_reporting": "LOCKED",
        },
        "findings_count": 0,
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "credentials_count": 0,
        "current_phase": 1,
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
            "phase_6_start": "",
            "phase_6_end": "",
        },
        "notes": "",
    }
    save_state(workdir, state)

    scope_path = os.path.join(outdir, "scope.md")
    if not os.path.isfile(scope_path):
        with open(scope_path, "w") as f:
            f.write(f"# Scope — {name}\n\n")
            f.write(f"- Domain: {domain or 'TBD'}\n")
            f.write(f"- DC IP: {dc_ip or 'TBD'}\n")
            f.write(f"- Access Level: {access_level}\n")
            f.write(f"- Scope Type: {scope_type}\n\n")
            f.write("## Domain Trusts\n\n[Fill during Phase 1]\n\n")
            f.write("## Key Targets\n\n[Document high-value targets]\n")

    findings_path = os.path.join(outdir, "findings-log.md")
    if not os.path.isfile(findings_path):
        with open(findings_path, "w") as f:
            f.write(f"# Findings Log — {name}\n\n")
            f.write("| ID | Title | Severity | Category | Endpoint | Status |\n")
            f.write("|---|---|---|---|---|---|\n")

    cred_path = os.path.join(outdir, "credential-inventory.md")
    if not os.path.isfile(cred_path):
        with open(cred_path, "w") as f:
            f.write(f"# Credential Inventory — {name}\n\n")
            f.write("| # | Type | Username | Source | Timestamp |\n")
            f.write("|---|---|---|---|---|\n")

    print(f"Initialized: {name}")
    print(f"  Workdir: {outdir}")
    print(f"  Domain: {domain} | DC: {dc_ip} | Access: {access_level} | Scope: {scope_type}")
    print(f"  Phase 1 (Recon & Enum) → OPEN")
    return state


def advance_phase(workdir: str, justification: str = "") -> dict | None:
    """Advance to next phase. Returns new state or None."""
    state = read_state(workdir)
    if not state:
        print("No engagement found.")
        return None

    current = state["current_phase"]
    if current >= 6:
        print("Already at final phase (6: reporting).")
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


def status(workdir: str) -> dict | None:
    """Print current engagement status."""
    state = read_state(workdir)
    if not state:
        print("No engagement found. Use `start` to begin.")
        return None

    current = state["current_phase"]
    name = state["engagement"]["name"]
    started = state["engagement"]["started"]

    elapsed = 0.0
    if started:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    findings = state["findings_count"]
    creds = state["credentials_count"]
    should, reason = should_abandon(workdir)

    print(f"─── adtest status ──────────────────────────────")
    print(f"Target:   {name} ({state['engagement']['domain']})")
    print(f"Phase:    {current} ({PHASES[current]}) — {state['gateways'][GATEWAYS[current]]}")
    print(f"Elapsed:  {elapsed:.1f}h")
    print(f"Findings: {findings}")
    print(f"Creds:    {creds}")
    print(f"Abandon:  {'YES — ' + reason if should else 'no'}")
    print(f"─────────────────────────────────────────────────")
    return state


def should_abandon(workdir: str, budget_hours: int = 8) -> tuple[bool, str]:
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

    creds = state["credentials_count"]
    findings = state["findings_count"]
    threshold = budget_hours * 0.75

    if elapsed >= budget_hours:
        return (True, f"Budget exceeded ({elapsed:.1f}h / {budget_hours}h). Wrap up and report.")

    if elapsed >= threshold and creds == 0:
        return (True, f"75% budget spent ({elapsed:.1f}h), zero creds. Pivot to Responder/MITM.")

    if elapsed >= threshold and findings > 0:
        outdir = os.path.join(workdir, "adtest-output", "phase5-privesc")
        attack_path = os.path.join(outdir, "attack-path.md")
        has_da_path = False
        if os.path.isfile(attack_path):
            with open(attack_path) as f:
                has_da_path = "domain admin" in f.read().lower()
        if not has_da_path:
            return (True, f"75% budget spent ({elapsed:.1f}h), no DA path found. Report partial results.")

    return (False, "")


def abandon(workdir: str, reason: str) -> None:
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
    elapsed = 0.0
    if started:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
        except (ValueError, TypeError):
            pass

    print(f"ABANDONED: {state['engagement']['name']}")
    print(f"  Reason: {reason}")
    print(f"  Phase: {phase} ({PHASES[phase]})")
    print(f"  Elapsed: {elapsed:.1f}h | Findings: {state['findings_count']} | Creds: {state['credentials_count']}")


def add_finding(workdir: str, finding_id: str, title: str,
                severity: str, category: str, endpoint: str) -> None:
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

    outdir = os.path.join(workdir, "adtest-output")
    log_path = os.path.join(outdir, "findings-log.md")
    with open(log_path, "a") as f:
        f.write(f"| {finding_id} | {title} | {severity} | {category} | {endpoint} | draft |\n")

    print(f"Finding added: [{finding_id}] {title} ({severity})")


def add_credential(workdir: str, cred_type: str, username: str,
                   source: str) -> None:
    """Track a credential in state and credential-inventory.md."""
    state = read_state(workdir)
    if not state:
        print("No engagement found.")
        return

    state["credentials_count"] += 1
    save_state(workdir, state)

    outdir = os.path.join(workdir, "adtest-output")
    cred_path = os.path.join(outdir, "credential-inventory.md")
    now = datetime.now().isoformat()
    with open(cred_path, "a") as f:
        f.write(f"| {state['credentials_count']} | {cred_type} | {username} | {source} | {now} |\n")

    print(f"Credential added: #{state['credentials_count']} {username} ({cred_type} via {source})")


if __name__ == "__main__":
    pass
