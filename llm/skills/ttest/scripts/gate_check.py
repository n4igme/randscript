#!/usr/bin/env python3
"""Thin wrapper over base_gate for ttest."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from base_gate import BaseGateChecker, print_gate_status
from config import SKILL_CONFIG

checker = BaseGateChecker(
    output_dir=SKILL_CONFIG["OUTPUT_DIR"],
    phase_gates={
        1: {"name": f"Phase 1: {list(SKILL_CONFIG['PHASES'].values())[0]}", "dir": SKILL_CONFIG['SUBDIRS'][0], "required_files": []},
        2: {"name": f"Phase 2: {list(SKILL_CONFIG['PHASES'].values())[1]}", "dir": SKILL_CONFIG['SUBDIRS'][1], "required_files": []},
        3: {"name": f"Phase 3: {list(SKILL_CONFIG['PHASES'].values())[2]}", "dir": SKILL_CONFIG['SUBDIRS'][2], "required_files": []},
        4: {"name": f"Phase 4: {list(SKILL_CONFIG['PHASES'].values())[3]}", "dir": SKILL_CONFIG['SUBDIRS'][3], "required_files": []},
    },
)
phases = SKILL_CONFIG["PHASES"]
subs = SKILL_CONFIG["SUBDIRS"]
for i, (num, name) in enumerate(phases.items(), 1):
    if i >= 5:
        break
checker.phase_gates[num] = {"name": f"Phase {num}: {name}", "dir": subs[i-1], "required_files": []}

def check_gate(workdir, phase=None):
    return checker.check_gate(workdir, phase)

def print_gate_status(result):
    return print_gate_status(result)
