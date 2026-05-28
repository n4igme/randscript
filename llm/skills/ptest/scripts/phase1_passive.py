#!/usr/bin/env python3
"""Phase 1: Passive Recon setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json

WORKDIR = "./ptest-output"

# 1. Read state and scope
state = read_file(f"{WORKDIR}/state.yaml")
scope = read_file(f"{WORKDIR}/scope.md")
domains = []
for line in scope["content"].split("\n"):
    content = line.split("|", 1)[-1] if "|" in line else ""
    if "." in content and not content.strip().startswith("Target"):
        parts = [p.strip() for p in content.split("|") if p.strip()]
        if parts and "." in parts[0]:
            domains.append(parts[0])

# 2. Check tools
tools = {}
for tool in ["dig", "curl", "whois", "subfinder", "amass"]:
    r = terminal(f"which {tool}")
    tools[tool] = r["exit_code"] == 0

# 3. crt.sh enumeration
all_subs = set()
for domain in domains:
    r = terminal(f'curl -sk "https://crt.sh/?q=%25.{domain}&output=json"', timeout=30)
    if r["exit_code"] == 0 and r["output"].strip().startswith("["):
        try:
            for entry in json.loads(r["output"]):
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        all_subs.add(sub)
        except:
            pass

# 4. subfinder (if available)
if tools.get("subfinder"):
    for domain in domains:
        r = terminal(f"subfinder -d {domain} -silent", timeout=120)
        if r["exit_code"] == 0:
            for line in r["output"].split("\n"):
                if line.strip():
                    all_subs.add(line.strip().lower())

# 5. Env-prefix quick-win
env_patterns = ["dev.", "staging.", "stg.", "sit.", "uat.", "mock.", "sandbox.", "test.", "qa.", "preprod.", "nonprod.", "demo.", "lab."]
env_hits = [s for s in all_subs if any(p in s for p in env_patterns)]
bare_candidates = set()
for sub in env_hits:
    for p in env_patterns:
        if p in sub:
            bare = sub.replace(p, "")
            if bare and bare not in all_subs:
                bare_candidates.add(bare)

# 6. Write results
terminal(f"mkdir -p {WORKDIR}/recon-passive")
write_file(f"{WORKDIR}/recon-passive/subdomains-merged.txt", "\n".join(sorted(all_subs)))
if bare_candidates:
    write_file(f"{WORKDIR}/recon-passive/env-prefix-bare-domains.txt", "\n".join(sorted(bare_candidates)))

# 7. Summary
print(json.dumps({
    "domains": domains,
    "tools": tools,
    "subdomains_found": len(all_subs),
    "env_prefix_hits": len(env_hits),
    "bare_domain_candidates": len(bare_candidates),
    "next": "Complete remaining OSINT techniques manually, then resolve bare-domain candidates"
}, indent=2))
