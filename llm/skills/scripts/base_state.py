#!/usr/bin/env python3
"""Base state manager — shared lifecycle for security skill engagements."""
import os
import yaml
from datetime import datetime


class SkillConfig:
    """Override these in each skill's config module."""
    NAME = "base"
    OUTPUT_DIR = "output"
    PHASES = {1: "phase1", 2: "phase2", 3: "phase3", 4: "phase4"}
    GATEWAYS = {1: "1_phase1", 2: "2_phase2", 3: "3_phase3", 4: "4_phase4"}
    SUBDIRS = ["phase1", "phase2", "phase3", "report"]
    INIT_FILES = ["scope.md", "findings-log.md"]
    EXTRA_INIT_FILES = {}  # phase -> [files]
    BUDGET_HOURS = 8


class BaseStateManager:
    def __init__(self, config: SkillConfig = None):
        self.config = config or SkillConfig()

    def _state_path(self, workdir: str) -> str:
        return os.path.join(workdir, self.config.OUTPUT_DIR, "state.yaml")

    def read_state(self, workdir: str) -> dict:
        path = self._state_path(workdir)
        if not os.path.isfile(path):
            return None
        with open(path) as f:
            state = yaml.safe_load(f)
        if state and not self._validate_state(state):
            print(f"WARNING: state.yaml has schema issues (see above)")
        return state

    def _validate_state(self, state: dict) -> bool:
        """Quick schema check — returns True if valid, prints warnings if not."""
        valid = True
        if not isinstance(state, dict):
            print("  SCHEMA: root is not a dict")
            return False
        if 'engagement' not in state:
            print("  SCHEMA: missing 'engagement' key")
            valid = False
        elif not isinstance(state['engagement'], dict):
            print("  SCHEMA: 'engagement' is not a dict")
            valid = False
        if 'gateways' not in state:
            print("  SCHEMA: missing 'gateways' key")
            valid = False
        if 'findings_count' not in state:
            print("  SCHEMA: missing 'findings_count' key")
            valid = False
        if 'current_phase' not in state:
            print("  SCHEMA: missing 'current_phase' — advance_phase() will fail")
            valid = False
        return valid

    def save_state(self, workdir: str, state: dict) -> None:
        path = self._state_path(workdir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(state, f, default_flow_style=False, sort_keys=False)

    def init_state(self, workdir: str, name: str, **kwargs) -> dict:
        outdir = os.path.join(workdir, self.config.OUTPUT_DIR)
        for subdir in self.config.SUBDIRS:
            os.makedirs(os.path.join(outdir, subdir), exist_ok=True)

        now = datetime.now().isoformat()
        engagement = {
            "name": name,
            "started": now,
        }
        engagement.update(kwargs)

        gateways = {}
        for num in self.config.GATEWAYS:
            gateways[self.config.GATEWAYS[num]] = "PASSED" if num == 1 else "LOCKED"

        time_tracking = {}
        for num in self.config.PHASES:
            time_tracking[f"phase_{num}_start"] = now if num == 1 else ""
            time_tracking[f"phase_{num}_end"] = ""

        state = {
            "engagement": engagement,
            "gateways": gateways,
            "findings_count": 0,
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "current_phase": 1,
            "time_tracking": time_tracking,
            "notes": "",
        }
        self.save_state(workdir, state)

        # Create scope.md
        scope_path = os.path.join(outdir, "scope.md")
        if not os.path.isfile(scope_path):
            with open(scope_path, "w") as f:
                f.write(f"# Scope — {name}\n\n")
                for k, v in kwargs.items():
                    f.write(f"- {k.replace('_', ' ').title()}: {v or 'TBD'}\n")
                f.write("\n[Fill during Phase 1]\n")

        # Create findings log
        findings_path = os.path.join(outdir, "findings-log.md")
        if not os.path.isfile(findings_path):
            with open(findings_path, "w") as f:
                f.write(f"# Findings Log — {name}\n\n")
                f.write("| ID | Title | Severity | Category | Target | Status |\n")
                f.write("|---|---|---|---|---|---|\n")

        print(f"Initialized: {name}")
        print(f"  Workdir: {outdir}")
        return state

    def advance_phase(self, workdir: str, justification: str = "") -> dict:
        state = self.read_state(workdir)
        if not state:
            print("No engagement found.")
            return None

        current = state["current_phase"]
        max_phase = max(self.config.PHASES.keys())
        if current >= max_phase:
            print(f"Already at final phase ({max_phase}: {self.config.PHASES[max_phase]}).")
            return state

        now = datetime.now().isoformat()
        current_key = self.config.GATEWAYS[current]
        next_phase = current + 1
        next_key = self.config.GATEWAYS[next_phase]

        state["gateways"][current_key] = "PASSED"
        state["time_tracking"][f"phase_{current}_end"] = now
        state["current_phase"] = next_phase
        state["gateways"][next_key] = "OPEN"
        state["time_tracking"][f"phase_{next_phase}_start"] = now

        if justification:
            state["notes"] = state.get("notes", "") + f"\nPhase {current}->{next_phase} override: {justification} ({now})"

        self.save_state(workdir, state)
        print(f"Advanced: Phase {current} ({self.config.PHASES[current]}) -> Phase {next_phase} ({self.config.PHASES[next_phase]})")
        return state

    def status(self, workdir: str) -> dict:
        state = self.read_state(workdir)
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
        should, reason = self.should_abandon(workdir)

        print(f"--- {self.config.NAME} status ---")
        print(f"Target:   {name}")
        print(f"Phase:    {current} ({self.config.PHASES.get(current, '?')}) — {state['gateways'].get(self.config.GATEWAYS.get(current), '?')}")
        print(f"Elapsed:  {elapsed:.1f}h")
        print(f"Findings: {findings}")
        print(f"Abandon:  {'YES — ' + reason if should else 'no'}")
        print("-" * 45)
        return state

    def should_abandon(self, workdir: str, budget_hours: int = None) -> tuple:
        budget = budget_hours or self.config.BUDGET_HOURS
        state = self.read_state(workdir)
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
        threshold = budget * 0.75

        if elapsed >= budget:
            return (True, f"Budget exceeded ({elapsed:.1f}h / {budget}h). Wrap up and report.")
        if elapsed >= threshold and findings == 0:
            return (True, f"75% budget spent ({elapsed:.1f}h), zero findings. Consider reporting as hardened.")

        return (False, "")

    def abandon(self, workdir: str, reason: str) -> None:
        state = self.read_state(workdir)
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
        self.save_state(workdir, state)

        started = state["engagement"]["started"]
        elapsed = 0.0
        if started:
            try:
                elapsed = (datetime.now() - datetime.fromisoformat(started)).total_seconds() / 3600
            except (ValueError, TypeError):
                pass

        print(f"ABANDONED: {state['engagement']['name']}")
        print(f"  Reason: {reason}")
        print(f"  Phase: {phase} ({self.config.PHASES.get(phase, '?')})")
        print(f"  Elapsed: {elapsed:.1f}h | Findings: {state['findings_count']}")

    def add_finding(self, workdir: str, finding_id: str, title: str,
                    severity: str, category: str, target: str) -> None:
        state = self.read_state(workdir)
        if not state:
            print("No engagement found.")
            return

        # Validate severity
        valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
        if severity.lower() not in valid_severities:
            print(f"WARNING: severity '{severity}' not in {valid_severities}")

        state["findings_count"] += 1
        sev_key = severity.lower()
        if "findings_by_severity" not in state:
            state["findings_by_severity"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if sev_key in state["findings_by_severity"]:
            state["findings_by_severity"][sev_key] += 1
        self.save_state(workdir, state)

        outdir = os.path.join(workdir, self.config.OUTPUT_DIR)
        log_path = os.path.join(outdir, "findings-log.md")
        with open(log_path, "a") as f:
            f.write(f"| {finding_id} | {title} | {severity} | {category} | {target} | draft |\n")

        print(f"Finding added: [{finding_id}] {title} ({severity})")

    def mark_na(self, workdir: str, phase: int, reason: str) -> None:
        """Mark a phase as N/A with justification."""
        state = self.read_state(workdir)
        if not state:
            return
        gateway = self.config.GATEWAYS.get(phase)
        if gateway:
            state["gateways"][gateway] = "N/A"
            state["notes"] = state.get("notes", "") + f"\nPhase {phase} N/A: {reason}"
            self.save_state(workdir, state)
            print(f"Phase {phase} marked N/A: {reason}")
