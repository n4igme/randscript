#!/usr/bin/env python3
"""Base gate checker — shared phase gate validation."""
from __future__ import annotations

import os
import yaml


class BaseGateChecker:
    def __init__(self, output_dir: str, phase_gates: dict):
        self.output_dir = output_dir
        self.phase_gates = phase_gates

    def check_gate(self, workdir: str, phase: int | None = None) -> dict:
        output_dir = os.path.join(workdir, self.output_dir)
        state_path = os.path.join(output_dir, "state.yaml")

        if not os.path.exists(state_path):
            return {"passed": False, "phase": 0, "met": [], "unmet": ["state.yaml not found"], "warnings": []}

        with open(state_path) as f:
            state = yaml.safe_load(f)

        if phase is None:
            phase = state.get("current_phase", 1)

        gate = self.phase_gates.get(phase)
        if not gate:
            return {"passed": False, "phase": phase, "met": [], "unmet": [f"Unknown phase {phase}"], "warnings": []}

        phase_dir = os.path.join(output_dir, gate["dir"])
        met, unmet, warnings = [], [], []

        if not os.path.isdir(phase_dir):
            unmet.append(f"Directory missing: {gate['dir']}/")
            return {"passed": False, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}

        met.append(f"Directory exists: {gate['dir']}/")

        for req_file in gate.get("required_files", []):
            fpath = os.path.join(phase_dir, req_file)
            if not os.path.exists(fpath):
                unmet.append(f"Missing: {gate['dir']}/{req_file}")
            elif os.path.getsize(fpath) < 20:
                unmet.append(f"Empty: {gate['dir']}/{req_file}")
            else:
                met.append(f"Exists: {gate['dir']}/{req_file}")

        min_req = gate.get("min_items", 0)
        if min_req > 0:
            items = [f for f in os.listdir(phase_dir) if not f.startswith(".")]
            if len(items) >= min_req:
                met.append(f"Output files: {len(items)} (min: {min_req})")
            else:
                unmet.append(f"Only {len(items)} output files (min: {min_req})")

        # Skill-specific checks
        for check_name, check_fn in gate.get("checks", {}).items():
            result = check_fn(output_dir, state, phase_dir)
            if result.startswith("MET:"):
                met.append(result[4:])
            elif result.startswith("UNMET:"):
                unmet.append(result[6:])
            elif result.startswith("WARN:"):
                warnings.append(result[5:])

        findings_count = state.get("findings_count", 0)
        if phase >= 3 and findings_count == 0:
            warnings.append("Zero findings at Phase 3+ — check abandon heuristics")

        passed = len(unmet) == 0
        return {"passed": passed, "phase": phase, "name": gate["name"], "met": met, "unmet": unmet, "warnings": warnings}


def print_gate_status(result: dict) -> bool:
    icon = "PASS" if result["passed"] else "FAIL"
    print(f"\n[{icon}] Phase {result['phase']} ({result.get('name', '')}) Gate Check")
    print("=" * 50)
    if result["met"]:
        for m in result["met"]:
            print(f"  + {m}")
    if result["unmet"]:
        print("  Blocking:")
        for u in result["unmet"]:
            print(f"  - {u}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  ! {w}")
    return result["passed"]
