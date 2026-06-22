#!/usr/bin/env python3
"""Thin wrapper over base_state for opsec."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from base_state import BaseStateManager
from config import SKILL_CONFIG

class Config:
    NAME = SKILL_CONFIG["NAME"]
    OUTPUT_DIR = SKILL_CONFIG["OUTPUT_DIR"]
    PHASES = SKILL_CONFIG["PHASES"]
    GATEWAYS = SKILL_CONFIG["GATEWAYS"]
    SUBDIRS = SKILL_CONFIG["SUBDIRS"]
    BUDGET_HOURS = SKILL_CONFIG["BUDGET_HOURS"]

mgr = BaseStateManager(Config())

def _state_path(workdir): return mgr._state_path(workdir)
def read_state(workdir): return mgr.read_state(workdir)
def save_state(workdir, state): mgr.save_state(workdir, state)
def init_state(workdir, name, **kwargs): return mgr.init_state(workdir, name, **kwargs)
def advance_phase(workdir, justification=""): return mgr.advance_phase(workdir, justification)
def status(workdir): return mgr.status(workdir)
def should_abandon(workdir, budget_hours=None): return mgr.should_abandon(workdir, budget_hours)
def abandon(workdir, reason): mgr.abandon(workdir, reason)
def add_finding(workdir, finding_id, title, severity, category, target): mgr.add_finding(workdir, finding_id, title, severity, category, target)
