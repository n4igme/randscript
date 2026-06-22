#!/usr/bin/env python3
"""Tests for base_state.py and base_gate.py — run with: pytest scripts/test_base.py"""
from __future__ import annotations

import os
import sys
import yaml
import pytest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))
from base_state import BaseStateManager, SkillConfig
from base_gate import BaseGateChecker


@pytest.fixture
def workdir():
    """Create a temp working directory, clean up after."""
    td = tempfile.mkdtemp(prefix="security_test_")
    yield td
    shutil.rmtree(td, ignore_errors=True)


@pytest.fixture
def mgr():
    """Default state manager with test config."""
    class TestConfig:
        NAME = "test"
        OUTPUT_DIR = "test-output"
        PHASES = {1: "recon", 2: "exploit", 3: "report"}
        GATEWAYS = {1: "1_recon", 2: "2_exploit", 3: "3_report"}
        SUBDIRS = ["phase1-recon", "phase2-exploit", "report"]
        BUDGET_HOURS = 4
        INIT_FILES = ["scope.md", "findings-log.md"]
        EXTRA_INIT_FILES = {}

    return BaseStateManager(TestConfig())


class TestBaseStateManager:

    def test_init_creates_dirs(self, mgr, workdir):
        state = mgr.init_state(workdir, "Target Corp")
        outdir = os.path.join(workdir, "test-output")
        assert os.path.isdir(outdir)
        assert os.path.isdir(os.path.join(outdir, "phase1-recon"))
        assert os.path.isdir(os.path.join(outdir, "phase2-exploit"))
        assert os.path.isdir(os.path.join(outdir, "report"))

    def test_init_creates_state_yaml(self, mgr, workdir):
        state = mgr.init_state(workdir, "Target Corp")
        state_path = os.path.join(workdir, "test-output", "state.yaml")
        assert os.path.isfile(state_path)

    def test_init_state_structure(self, mgr, workdir):
        state = mgr.init_state(workdir, "Target Corp")
        assert state["engagement"]["name"] == "Target Corp"
        assert state["current_phase"] == 1
        assert state["findings_count"] == 0
        assert state["gateways"]["1_recon"] == "PASSED"
        assert state["gateways"]["2_exploit"] == "LOCKED"
        assert state["gateways"]["3_report"] == "LOCKED"

    def test_read_state_no_file(self, mgr, workdir):
        assert mgr.read_state(workdir) is None

    def test_read_state_after_init(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        state = mgr.read_state(workdir)
        assert state is not None
        assert state["engagement"]["name"] == "Test"

    def test_advance_phase(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        state = mgr.advance_phase(workdir)
        assert state["current_phase"] == 2
        assert state["gateways"]["1_recon"] == "PASSED"
        assert state["gateways"]["2_exploit"] == "OPEN"

    def test_advance_phase_at_max(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        mgr.advance_phase(workdir)  # 1→2
        mgr.advance_phase(workdir)  # 2→3
        state = mgr.advance_phase(workdir)  # 3→ should stay
        assert state["current_phase"] == 3

    def test_add_finding(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        mgr.add_finding(workdir, "F-001", "XSS", "High", "web", "target.com")
        state = mgr.read_state(workdir)
        assert state["findings_count"] == 1
        assert state["findings_by_severity"]["high"] == 1

    def test_add_finding_invalid_severity_warns(self, mgr, workdir, capsys):
        mgr.init_state(workdir, "Test")
        mgr.add_finding(workdir, "F-001", "Test", "BOGUS", "cat", "t")
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_should_abandon_under_budget(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        should, reason = mgr.should_abandon(workdir)
        assert should is False

    def test_abandon(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        mgr.abandon(workdir, "Client revoked")
        state = mgr.read_state(workdir)
        assert "ABANDONED" in str(state["gateways"].values())

    def test_mark_na(self, mgr, workdir):
        mgr.init_state(workdir, "Test")
        mgr.mark_na(workdir, 3, "No containers in scope")
        state = mgr.read_state(workdir)
        assert state["gateways"]["3_report"] == "N/A"

    def test_schema_validation_warns_missing_keys(self, mgr, workdir, capsys):
        """State with missing keys should print warnings."""
        outdir = os.path.join(workdir, "test-output")
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "state.yaml"), "w") as f:
            yaml.dump({"engagement": {"name": "test"}}, f)
        state = mgr.read_state(workdir)
        captured = capsys.readouterr()
        assert "SCHEMA" in captured.out
        assert state is not None


class TestBaseGateChecker:

    @pytest.fixture
    def checker(self):
        return BaseGateChecker(
            output_dir="test-output",
            phase_gates={
                1: {"name": "Phase 1: Recon", "dir": "phase1-recon", "required_files": ["scope.md"]},
                2: {"name": "Phase 2: Exploit", "dir": "phase2-exploit", "required_files": []},
            },
        )

    def test_no_state_file(self, checker, workdir):
        result = checker.check_gate(workdir, phase=1)
        assert result["passed"] is False
        assert "state.yaml not found" in result["unmet"][0]

    def test_missing_phase_dir(self, checker, workdir):
        outdir = os.path.join(workdir, "test-output")
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "state.yaml"), "w") as f:
            yaml.dump({"current_phase": 1, "findings_count": 0}, f)
        result = checker.check_gate(workdir, phase=1)
        assert result["passed"] is False
        assert "Directory missing" in result["unmet"][0]

    def test_missing_required_file(self, checker, workdir):
        outdir = os.path.join(workdir, "test-output")
        phase_dir = os.path.join(outdir, "phase1-recon")
        os.makedirs(phase_dir, exist_ok=True)
        with open(os.path.join(outdir, "state.yaml"), "w") as f:
            yaml.dump({"current_phase": 1, "findings_count": 0}, f)
        result = checker.check_gate(workdir, phase=1)
        assert result["passed"] is False
        assert any("scope.md" in u for u in result["unmet"])

    def test_passes_with_required_file(self, checker, workdir):
        outdir = os.path.join(workdir, "test-output")
        phase_dir = os.path.join(outdir, "phase1-recon")
        os.makedirs(phase_dir, exist_ok=True)
        with open(os.path.join(outdir, "state.yaml"), "w") as f:
            yaml.dump({"current_phase": 1, "findings_count": 0}, f)
        with open(os.path.join(phase_dir, "scope.md"), "w") as f:
            f.write("# Scope\nTarget: example.com\n")
        result = checker.check_gate(workdir, phase=1)
        assert result["passed"] is True

    def test_zero_findings_warning_at_phase3(self, checker, workdir):
        outdir = os.path.join(workdir, "test-output")
        phase_dir = os.path.join(outdir, "phase2-exploit")
        os.makedirs(phase_dir, exist_ok=True)
        with open(os.path.join(outdir, "state.yaml"), "w") as f:
            yaml.dump({"current_phase": 3, "findings_count": 0}, f)
        result = checker.check_gate(workdir, phase=3)
        # Phase 3 doesn't exist in this checker, should fail
        assert result["passed"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
