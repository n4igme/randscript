#!/usr/bin/env python3
"""Phase 2: Active Recon setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json, re

WORKDIR = "./ptest-output"

# 1. Read subdomains from Phase 1
subs_data = read_file(f"{WORKDIR}/recon-passive/subdomains-merged.txt")
subdomains = [l.split("|")[-1].strip() for l in subs_data["content"].split("\n") if l.strip() and not l.startswith(" ")]

# 2. Check tools
tools = {}
for tool in ["nmap", "dnsx", "puredns", "massdns", "ffuf", "dig"]:
    r = terminal(f"which {tool}")
    tools[tool] = r["exit_code"] == 0

# 3. DNS resolution (batch, cap at 200)
live_hosts = []
for sub in subdomains[:200]:
    r = terminal(f"dig +short {sub}", timeout=5)
    if r["exit_code"] == 0 and r["output"].strip():
        ips = [l for l in r["output"].strip().split("\n") if re.match(r'^\d+\.\d+\.\d+\.\d+$', l)]
        if ips:
            live_hosts.append(f"{sub}|{ips[0]}")

# 4. Extract naming patterns for permutation
prefixes = set()
for sub in subdomains:
    parts = sub.split(".")
    if len(parts) > 2:
        prefixes.add(parts[0])

# 5. Write results
terminal(f"mkdir -p {WORKDIR}/recon-active")
write_file(f"{WORKDIR}/recon-active/live-hosts.txt", "\n".join(live_hosts))

# 6. Summary
print(json.dumps({
    "subdomains_input": len(subdomains),
    "live_hosts_resolved": len(live_hosts),
    "tools": tools,
    "naming_prefixes": len(prefixes),
    "top_prefixes": sorted(prefixes)[:20],
    "next": "Run nmap on live hosts, then DNS permutation brute-force"
}, indent=2))
