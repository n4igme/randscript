#!/usr/bin/env python3
"""Phase 3: Enumeration setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json, os

WORKDIR = "./ptest-output"

# 1. Read live hosts from Phase 2
hosts_data = read_file(f"{WORKDIR}/recon-active/live-hosts.txt")
hosts = [l.split("|")[0].strip() for l in hosts_data["content"].split("\n") if l.strip() and not l.startswith(" ")]

# 2. Check tools
tools = {}
for tool in ["gobuster", "feroxbuster", "ffuf", "nuclei", "curl"]:
    r = terminal(f"which {tool}")
    tools[tool] = r["exit_code"] == 0

# 3. Resolve SecLists path
seclists = ""
for p in ["/usr/share/seclists", "/opt/homebrew/share/seclists", os.path.expanduser("~/SecLists")]:
    r = terminal(f"test -d {p} && echo yes")
    if "yes" in r["output"]:
        seclists = p
        break

# 4. Bulk actuator quick-scan (top 10 hosts, baseline + key paths)
actuator_hits = []
for host in hosts[:10]:
    base = terminal(f'curl -sk -o /dev/null -w "%{{size_download}}" "https://{host}/nonexistent12345xyz" --max-time 5')
    baseline_size = base["output"].strip()
    for path in ["/actuator", "/actuator/env", "/swagger-ui.html", "/api-docs", "/admin"]:
        r = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}|%{{size_download}}" "https://{host}{path}" --max-time 5')
        parts = r["output"].strip().split("|")
        if len(parts) == 2:
            code, size = parts
            if code == "200" and size != baseline_size:
                actuator_hits.append(f"https://{host}{path} [{code}, {size}B]")

# 5. Write results
terminal(f"mkdir -p {WORKDIR}/enumeration")

# 6. Summary
print(json.dumps({
    "live_hosts": len(hosts),
    "tools": tools,
    "seclists_path": seclists,
    "dirbrute_tool": "gobuster" if tools.get("gobuster") else ("feroxbuster" if tools.get("feroxbuster") else "NONE"),
    "actuator_quick_hits": actuator_hits,
    "next": "Run bulk actuator scan on all hosts, then dir brute-force on priority targets"
}, indent=2))
