#!/usr/bin/env python3
"""Phase 4: Attack Surface Mapping setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json, re

WORKDIR = "./ptest-output"

# 1. Read live hosts from Phase 2
hosts = []
host_ips = {}
try:
    hosts_data = read_file(f"{WORKDIR}/recon-active/live-hosts.txt")
    for line in hosts_data["content"].split("\n"):
        if "|" in line:
            parts = line.strip().split("|")
            if len(parts) >= 2:
                hosts.append(parts[0])
                host_ips[parts[0]] = parts[1]
except:
    pass

# 2. Read framework detection from Phase 3
frameworks = {}
try:
    enum_data = read_file(f"{WORKDIR}/enumeration/checklist.md")
    # Frameworks are in the summary, try reading from there
except:
    pass

# 3. Read auth endpoints from Phase 3
auth_endpoints = []
try:
    checklist_data = read_file(f"{WORKDIR}/enumeration/checklist.md")
except:
    pass

# 4. Read actuator/admin hits from Phase 3
actuator_hits = []
try:
    # Try multiple possible locations
    for filename in ["enumeration/summary.md", "enumeration/checklist.md"]:
        try:
            data = read_file(f"{WORKDIR}/{filename}")
            for line in data["content"].split("\n"):
                if "https://" in line and any(code in line for code in ["200", "401", "403"]):
                    actuator_hits.append(line.strip())
        except:
            pass
except:
    pass

# 5. Read GraphQL and WebSocket endpoints from Phase 3
graphql_endpoints = []
websocket_endpoints = []
# These would be in the phase3 summary output — try to find them
try:
    for filename in ["enumeration/summary.md"]:
        data = read_file(f"{WORKDIR}/{filename}")
        content = data["content"]
        if "graphql" in content.lower():
            for line in content.split("\n"):
                if "graphql" in line.lower() and "https://" in line:
                    graphql_endpoints.append(line.strip())
        if "websocket" in content.lower() or "/ws" in content:
            for line in content.split("\n"):
                if ("ws" in line.lower() or "websocket" in line.lower()) and "https://" in line:
                    websocket_endpoints.append(line.strip())
except:
    pass

# 6. Generate asset inventory skeleton
terminal(f"mkdir -p {WORKDIR}/attack-surface")

inventory_md = "# Asset Inventory\n\n"
inventory_md += "| # | Host/URL | IP | Technology | Auth Mechanism | Business Function | Exposure | Priority |\n"
inventory_md += "|---|----------|-----|-----------|----------------|-------------------|----------|----------|\n"
for i, host in enumerate(hosts[:50], 1):
    ip = host_ips.get(host, "")
    tech = ""  # Would come from framework detection
    inventory_md += f"| {i} | {host} | {ip} | {tech} | | | Public | |\n"

write_file(f"{WORKDIR}/attack-surface/asset-inventory.md", inventory_md)

# 7. Generate entry points map from Phase 3 discoveries
entry_points_md = "# Entry Point Map\n\n"
entry_points_md += "## Unauthenticated Entry Points\n\n"
entry_points_md += "| # | URL/Endpoint | Method | Input Type | Notes |\n"
entry_points_md += "|---|-------------|--------|-----------|-------|\n"

ep_count = 0
for hit in actuator_hits:
    ep_count += 1
    entry_points_md += f"| {ep_count} | {hit} | GET | — | Actuator/Admin |\n"

entry_points_md += "\n## GraphQL Endpoints\n\n"
if graphql_endpoints:
    for ep in graphql_endpoints:
        entry_points_md += f"- {ep}\n"
else:
    entry_points_md += "None discovered.\n"

entry_points_md += "\n## WebSocket Endpoints\n\n"
if websocket_endpoints:
    for ep in websocket_endpoints:
        entry_points_md += f"- {ep}\n"
else:
    entry_points_md += "None discovered.\n"

entry_points_md += "\n## Authenticated Entry Points (require valid session)\n\n"
entry_points_md += "| # | URL/Endpoint | Method | Input Type | Auth Required | Notes |\n"
entry_points_md += "|---|-------------|--------|-----------|---------------|-------|\n"
entry_points_md += "| | | | | | |\n"

entry_points_md += "\n## File Upload Points\n\n"
entry_points_md += "| # | URL/Endpoint | Accepted Types | Max Size | Notes |\n"
entry_points_md += "|---|-------------|---------------|----------|-------|\n"
entry_points_md += "| | | | | |\n"

write_file(f"{WORKDIR}/attack-surface/entry-points.md", entry_points_md)

# 8. Generate scoring template
scoring_md = "# Attack Surface Priority Matrix\n\n"
scoring_md += "## Scoring Guide\n\n"
scoring_md += "| Factor | Score 3 (High) | Score 2 (Medium) | Score 1 (Low) |\n"
scoring_md += "|--------|---------------|-----------------|--------------|\n"
scoring_md += "| Auth Status | No auth required | Weak auth (Basic, default) | Strong auth (JWT, MFA, IAP) |\n"
scoring_md += "| Data Sensitivity | PII, credentials, financial | Business logic, configs | Public/reference data |\n"
scoring_md += "| Exposure Level | Internet-facing, no WAF | Internet-facing, behind WAF | Internal IP only |\n"
scoring_md += "| Attack Surface Size | Multiple endpoints, accepts input | Few endpoints, limited input | Single static endpoint |\n"
scoring_md += "| Environment | Production | UAT/Staging | Dev/Mock |\n\n"
scoring_md += "**Priority tiers:** 12-15 = Critical, 8-11 = High, 5-7 = Medium, 3-4 = Low\n\n"
scoring_md += "## Priority Matrix\n\n"
scoring_md += "| # | Asset | Auth | Data | Exposure | Surface | Env | Score | Tier |\n"
scoring_md += "|---|-------|------|------|----------|---------|-----|-------|------|\n"
for i, host in enumerate(hosts[:20], 1):
    scoring_md += f"| {i} | {host} | | | | | | | |\n"

write_file(f"{WORKDIR}/attack-surface/priority-matrix.md", scoring_md)

# 9. Generate checklist
checklist_items = [
    ("1", "Asset Inventory Compiled", "DONE (skeleton generated — fill Technology, Auth, Business Function)"),
    ("2", "Scope Confirmed with User", "PENDING"),
    ("3", "Entry Points Mapped", "DONE (auto-populated from Phase 3 — verify and expand)"),
    ("4", "Attack Surface Scoring", "PENDING (fill priority-matrix.md)"),
    ("5", "Cross-Environment Correlation", "PENDING"),
    ("6", "Dismissed Assets Documented", "PENDING"),
    ("7", "Program Exclusion Cross-Check", "PENDING"),
]

checklist_md = "# Attack Surface Mapping Checklist\n\n| # | Task | Status | Notes |\n|---|------|--------|-------|\n"
for num, task, status in checklist_items:
    checklist_md += f"| {num} | {task} | {status} | |\n"

write_file(f"{WORKDIR}/attack-surface/checklist.md", checklist_md)

# 10. Summary
print(json.dumps({
    "total_hosts": len(hosts),
    "actuator_hits": len(actuator_hits),
    "graphql_endpoints": len(graphql_endpoints),
    "websocket_endpoints": len(websocket_endpoints),
    "generated_files": [
        "attack-surface/asset-inventory.md",
        "attack-surface/entry-points.md",
        "attack-surface/priority-matrix.md",
        "attack-surface/checklist.md",
    ],
    "remaining_manual": [
        "1: Fill Technology, Auth Mechanism, Business Function in asset-inventory.md",
        "2: Confirm scope with user (MANDATORY sign-off before Phase 5)",
        "3: Verify and expand entry points (add auth endpoints, file uploads, input fields)",
        "4: Score each asset in priority-matrix.md (Auth × Data × Exposure × Surface × Env)",
        "5: Cross-environment correlation (same service across dev/stg/prod)",
        "6: Document dismissed assets with reasons and verification evidence",
        "7: Cross-check all vectors against program exclusion list",
    ],
    "next": "Fill asset inventory details, then get user scope confirmation",
}, indent=2))
