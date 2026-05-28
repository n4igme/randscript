#!/usr/bin/env python3
"""Phase 8: Reporting setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json, re

WORKDIR = "./ptest-output"

# 1. Read findings-log.md and validate completeness
findings = []
validation_errors = []
try:
    findings_data = read_file(f"{WORKDIR}/findings-log.md")
    content = findings_data["content"]

    # Split into individual findings
    finding_blocks = re.split(r'(?=## \[FINDING-)', content)
    for block in finding_blocks:
        if not block.strip() or "## [FINDING-" not in block:
            continue

        # Extract finding ID and title
        id_match = re.search(r'## \[FINDING-(\d+)\]\s*(.*)', block)
        if not id_match:
            continue

        fid = id_match.group(1)
        title = id_match.group(2).strip()
        errors = []

        # Check required fields
        if "**Severity:**" not in block:
            errors.append("missing Severity")
        if "**CVSS 3.1:**" not in block:
            errors.append("missing CVSS score")
        elif "**CVSS 3.1:** " in block:
            cvss_match = re.search(r'\*\*CVSS 3\.1:\*\*\s*(\S+)', block)
            if cvss_match and cvss_match.group(1) in ("", "TBD", "N/A"):
                errors.append("CVSS score not calculated")
        if "**Affected Asset:**" not in block:
            errors.append("missing Affected Asset")
        if "**Environment:**" not in block:
            errors.append("missing Environment tag")
        if "**Verification Status:**" not in block:
            errors.append("missing Verification Status")
        elif "Unverified" in block:
            errors.append("finding is Unverified — move to Potential Issues appendix")
        if "### Steps to Reproduce" not in block:
            errors.append("missing Steps to Reproduce")
        if "### Evidence" not in block:
            errors.append("missing Evidence section")
        if "### Impact" not in block:
            errors.append("missing Impact section")
        if "### Remediation" not in block:
            errors.append("missing Remediation section")

        # Extract severity for summary
        sev_match = re.search(r'\*\*Severity:\*\*\s*(Critical|High|Medium|Low|Info)', block)
        severity = sev_match.group(1) if sev_match else "Unknown"

        findings.append({
            "id": f"FINDING-{fid}",
            "title": title,
            "severity": severity,
            "errors": errors,
            "complete": len(errors) == 0,
        })

        if errors:
            validation_errors.append(f"FINDING-{fid} ({title}): {', '.join(errors)}")
except Exception as e:
    validation_errors.append(f"Could not read findings-log.md: {str(e)}")

# Create report directory
terminal(f"mkdir -p {WORKDIR}/report")

# Write validation report
if validation_errors:
    validation_md = "# Findings Validation Report\n\n"
    validation_md += f"**Total findings:** {len(findings)}\n"
    validation_md += f"**Complete:** {sum(1 for f in findings if f['complete'])}\n"
    validation_md += f"**Incomplete:** {sum(1 for f in findings if not f['complete'])}\n\n"
    validation_md += "## Issues to Fix Before Report\n\n"
    for err in validation_errors:
        validation_md += f"- ⚠️ {err}\n"
    validation_md += "\n## Required Actions\n\n"
    validation_md += "Fix all issues above before writing the final report. "
    validation_md += "Unverified findings should be moved to a 'Potential Issues' appendix.\n"
else:
    validation_md = "# Findings Validation Report\n\n"
    validation_md += f"**Total findings:** {len(findings)}\n"
    validation_md += "**Status:** ✅ All findings complete — ready for report assembly.\n"

write_file(f"{WORKDIR}/report/findings-validation.md", validation_md)

# 2. Generate severity summary table
severity_counts = {
    "Critical": sum(1 for f in findings if f["severity"] == "Critical"),
    "High": sum(1 for f in findings if f["severity"] == "High"),
    "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
    "Low": sum(1 for f in findings if f["severity"] == "Low"),
    "Info": sum(1 for f in findings if f["severity"] == "Info"),
}

summary_table_md = "# Findings Summary\n\n"
summary_table_md += "## Severity Breakdown\n\n"
summary_table_md += "| Severity | Count |\n|----------|-------|\n"
for sev, count in severity_counts.items():
    summary_table_md += f"| {sev} | {count} |\n"
summary_table_md += f"| **Total** | **{len(findings)}** |\n"

summary_table_md += "\n## Findings List\n\n"
summary_table_md += "| # | Finding | Severity | Affected Asset | Environment |\n"
summary_table_md += "|---|---------|----------|----------------|-------------|\n"
for f in findings:
    # Extract asset and environment from the finding block
    asset = ""
    env = ""
    for block in re.split(r'(?=## \[FINDING-)', findings_data["content"]):
        if f["id"] in block:
            asset_match = re.search(r'\*\*Affected Asset:\*\*\s*(.*)', block)
            env_match = re.search(r'\*\*Environment:\*\*\s*(.*)', block)
            if asset_match:
                asset = asset_match.group(1).strip()
            if env_match:
                env = env_match.group(1).strip()
            break
    summary_table_md += f"| {f['id']} | {f['title']} | {f['severity']} | {asset} | {env} |\n"

write_file(f"{WORKDIR}/report/findings-summary.md", summary_table_md)

# 3. Engagement metrics from state.yaml
metrics = {}
try:
    state_data = read_file(f"{WORKDIR}/state.yaml")
    state_content = state_data["content"]

    # Extract time tracking
    phase_times = {}
    for i in range(1, 9):
        start_match = re.search(rf'phase_{i}_start:\s*"?([^"\n]+)"?', state_content)
        end_match = re.search(rf'phase_{i}_end:\s*"?([^"\n]+)"?', state_content)
        if start_match and start_match.group(1).strip():
            phase_times[f"phase_{i}"] = {
                "start": start_match.group(1).strip(),
                "end": end_match.group(1).strip() if end_match and end_match.group(1).strip() else "in progress",
            }

    # Extract findings and escalation counts
    fc_match = re.search(r'findings_count:\s*(\d+)', state_content)
    ec_match = re.search(r'escalations_count:\s*(\d+)', state_content)
    findings_count = int(fc_match.group(1)) if fc_match else len(findings)
    escalations_count = int(ec_match.group(1)) if ec_match else 0

    # Extract engagement name and scope type
    name_match = re.search(r'name:\s*"?([^"\n]+)"?', state_content)
    scope_match = re.search(r'scope_type:\s*"?([^"\n]+)"?', state_content)

    metrics = {
        "engagement_name": name_match.group(1).strip() if name_match else "Unknown",
        "scope_type": scope_match.group(1).strip() if scope_match else "Unknown",
        "findings_count": findings_count,
        "escalations_count": escalations_count,
        "phase_times": phase_times,
    }
except Exception as e:
    metrics = {"error": f"Could not read state.yaml: {str(e)}"}

# Write engagement metrics
metrics_md = "# Engagement Metrics\n\n"
if "error" not in metrics:
    metrics_md += f"**Engagement:** {metrics.get('engagement_name', 'Unknown')}\n"
    metrics_md += f"**Scope Type:** {metrics.get('scope_type', 'Unknown')}\n\n"
    metrics_md += "## Summary\n\n"
    metrics_md += f"| Metric | Value |\n|--------|-------|\n"
    metrics_md += f"| Total findings | {metrics['findings_count']} |\n"
    metrics_md += f"| Critical | {severity_counts['Critical']} |\n"
    metrics_md += f"| High | {severity_counts['High']} |\n"
    metrics_md += f"| Medium | {severity_counts['Medium']} |\n"
    metrics_md += f"| Low | {severity_counts['Low']} |\n"
    metrics_md += f"| Info | {severity_counts['Info']} |\n"
    metrics_md += f"| Escalations | {metrics['escalations_count']} |\n"
    metrics_md += f"| Attack chains | TBD |\n\n"
    metrics_md += "## Phase Time Tracking\n\n"
    metrics_md += "| Phase | Start | End | Duration |\n|-------|-------|-----|----------|\n"
    for phase, times in metrics.get("phase_times", {}).items():
        metrics_md += f"| {phase} | {times['start']} | {times['end']} | — |\n"
else:
    metrics_md += f"⚠️ {metrics['error']}\n"

write_file(f"{WORKDIR}/report/engagement-metrics.md", metrics_md)

# 4. Generate report skeleton from existing files
scope_content = ""
try:
    scope_data = read_file(f"{WORKDIR}/scope.md")
    scope_content = scope_data["content"]
except:
    scope_content = "<!-- scope.md not found — fill manually -->"

attack_path_content = ""
try:
    ap_data = read_file(f"{WORKDIR}/post-exploit/attack-path.md")
    attack_path_content = ap_data["content"]
except:
    attack_path_content = "<!-- attack-path.md not found — fill manually -->"

eng_name = metrics.get("engagement_name", "Unknown") if "error" not in metrics else "Unknown"

report_skeleton = f"""# Penetration Test Report — {eng_name}

**Date:** {metrics.get("phase_times", {}).get("phase_1", {}).get("start", "TBD")} – TBD
**Prepared by:** [Tester Name]
**Classification:** Confidential

---

## 1. Executive Summary

### Engagement Overview
<!-- One sentence: who, what, when, scope -->

### Key Findings

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['Critical']} |
| High | {severity_counts['High']} |
| Medium | {severity_counts['Medium']} |
| Low | {severity_counts['Low']} |
| Info | {severity_counts['Info']} |

### Critical Risk
<!-- 2-3 sentences describing the worst attack chain in business terms. No jargon. -->

### Security Posture Assessment

**Strengths:**
- 

**Weaknesses:**
- 

### Immediate Actions Required
1. 
2. 
3. 

---

## 2. Scope & Methodology

{scope_content}

### Methodology
Structured 8-phase penetration testing framework: Passive Recon → Active Recon → Enumeration → Attack Surface Mapping → Vulnerability Assessment → Exploitation → Post-Exploitation → Reporting.

### Limitations
<!-- Time constraints, scope exclusions, techniques not tested -->

---

## 3. Risk Matrix

| Finding | Severity | CVSS | Exploitability | Blast Radius | Priority |
|---------|----------|------|---------------|-------------|----------|
"""

for f in findings:
    report_skeleton += f"| {f['id']}: {f['title'][:40]} | {f['severity']} | | | | |\n"

report_skeleton += f"""
---

## 4. Findings Summary

<!-- See report/findings-summary.md for auto-generated table -->

---

## 5. Detailed Findings

<!-- Copy each finding from findings-log.md here, grouped by severity -->

"""

for sev in ["Critical", "High", "Medium", "Low", "Info"]:
    sev_findings = [f for f in findings if f["severity"] == sev]
    if sev_findings:
        report_skeleton += f"### {sev} Findings\n\n"
        for f in sev_findings:
            report_skeleton += f"#### {f['id']}: {f['title']}\n<!-- Copy from findings-log.md -->\n\n"

report_skeleton += f"""---

## 6. Attack Narrative & Chains

{attack_path_content}

---

## 7. Remediation Roadmap

### Immediate (1-7 days)
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
| | | | | |

### Short-term (1-4 weeks)
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
| | | | | |

### Medium-term (1-3 months)
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
| | | | | |

### Long-term (3-6 months)
| # | Finding | Fix | Owner | Effort |
|---|---------|-----|-------|--------|
| | | | | |

---

## 8. Positive Findings
<!-- What the client does well — always include -->

- 

---

## 9. Appendices

### A. Engagement Metrics
<!-- See report/engagement-metrics.md -->

### B. Tools Used
<!-- List tools and versions used during the engagement -->

### C. Potential Issues (Unverified)
<!-- Findings that could not be confirmed — for follow-up -->

### D. Techniques Not Tested
<!-- Due to time/scope constraints -->

"""

write_file(f"{WORKDIR}/report/report-draft.md", report_skeleton)

# 5. Pre-delivery checklist
pre_delivery_md = """# Pre-Delivery Checklist

## Accuracy
- [ ] Every finding is reproducible right now (not just when you tested it)
- [ ] CVSS scores are calculated, not guessed (use calculator)
- [ ] Environment tags are correct (prod vs nonprod)
- [ ] No findings based solely on version numbers without verification
- [ ] Attack chains are logically sound (each step actually enables the next)

## Completeness
- [ ] All mandatory techniques from each phase are accounted for
- [ ] Skipped techniques are documented with reasons
- [ ] Scope exclusions are noted
- [ ] Time constraints are documented (what wasn't tested)
- [ ] Positive findings included (what's working well)

## Sensitivity
- [ ] No plaintext production credentials in the report
- [ ] Customer PII redacted in evidence (show structure, not data)
- [ ] Internal IPs/hostnames — check if client wants these redacted
- [ ] Your own test credentials removed
- [ ] Evidence files don't contain more data than needed

## Formatting
- [ ] Consistent severity labels (Critical, not CRITICAL or Crit)
- [ ] Finding IDs sequential and referenced correctly
- [ ] Screenshots are readable (not tiny, not blurry)
- [ ] Code blocks are syntax-highlighted
- [ ] Table of contents matches actual sections
- [ ] Page numbers (if PDF)

## Delivery
- [ ] Report sent via secure channel (encrypted email, secure portal)
- [ ] Receipt confirmed by client
- [ ] Debrief meeting scheduled (if applicable)
- [ ] Retest window communicated (typically 2-4 weeks)
- [ ] Engagement materials archived (see cleanup command)
"""

write_file(f"{WORKDIR}/report/pre-delivery-checklist.md", pre_delivery_md)

# 6. Generate checklist.md
all_valid = len(validation_errors) == 0
checklist_items = [
    ("8.1", "Findings Assembly & Validation", "DONE" if all_valid else f"INCOMPLETE ({len(validation_errors)} errors)"),
    ("8.2", "Severity Summary Table", "DONE"),
    ("8.3", "Attack Chain Integration", "PENDING"),
    ("8.4", "Remediation Prioritization", "PENDING"),
    ("8.5", "Executive Summary Writing", "PENDING"),
    ("8.6", "Technical Review (pre-delivery checklist)", "PENDING"),
    ("8.7", "Report Formatting & Polish", "PENDING"),
    ("8.8", "Delivery & Debrief", "PENDING"),
]

checklist_md = "# Phase 8: Reporting Checklist\n\n| # | Step | Status | Notes |\n|---|------|--------|-------|\n"
for num, step, status in checklist_items:
    checklist_md += f"| {num} | {step} | {status} | |\n"

checklist_md += "\n## Generated Files\n\n"
checklist_md += "- `report/findings-validation.md` — field completeness check\n"
checklist_md += "- `report/findings-summary.md` — severity table + findings list\n"
checklist_md += "- `report/engagement-metrics.md` — time tracking + stats\n"
checklist_md += "- `report/report-draft.md` — assembled report skeleton\n"
checklist_md += "- `report/pre-delivery-checklist.md` — final QA before sending\n"

write_file(f"{WORKDIR}/report/checklist.md", checklist_md)

# 7. Summary
print(json.dumps({
    "total_findings": len(findings),
    "complete": sum(1 for f in findings if f["complete"]),
    "incomplete": sum(1 for f in findings if not f["complete"]),
    "validation_errors": validation_errors[:10],
    "severity_breakdown": severity_counts,
    "engagement_metrics": metrics if "error" not in metrics else metrics["error"],
    "remaining_manual": [
        "8.3: Attack chain integration (narrative writing, diagrams)",
        "8.4: Remediation prioritization (client context needed)",
        "8.5: Executive summary writing (business language)",
        "8.6: Technical review (run pre-delivery checklist)",
        "8.7: Report formatting & polish (proofread, screenshots)",
        "8.8: Delivery & debrief (secure channel, meeting)",
    ],
    "generated_files": [
        "report/findings-validation.md",
        "report/findings-summary.md",
        "report/engagement-metrics.md",
        "report/report-draft.md",
        "report/pre-delivery-checklist.md",
        "report/checklist.md",
    ],
    "next": "Fix validation errors" if validation_errors else "Write executive summary and attack chain narrative",
}, indent=2))
