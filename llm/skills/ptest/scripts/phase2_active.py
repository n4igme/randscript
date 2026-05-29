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

# 3. DNS resolution (batch all subdomains)
live_hosts = []
for sub in subdomains:
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

# 4b. Wildcard detection
wildcard_ips = {}
for sub in subdomains:
    parts = sub.split(".")
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        if root not in wildcard_ips:
            r = terminal(f"dig +short randomnonexistent98765.{root}", timeout=5)
            if r["exit_code"] == 0 and r["output"].strip():
                ip = r["output"].strip().split("\n")[0]
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    wildcard_ips[root] = ip

# 4c. Generate permutation wordlist
service_names = [
    "api", "admin", "auth", "sso", "keycloak", "grafana", "prometheus",
    "alertmanager", "kibana", "elasticsearch", "airflow", "argocd", "vault",
    "consul", "sentry", "jaeger", "jenkins", "gitlab", "harbor", "nexus",
    "sonar", "n8n", "metabase", "superset", "redash", "mlflow", "jupyter",
    "vpn", "bastion", "sftp", "mail", "smtp", "monitoring", "kafka",
    "rabbitmq", "redis", "postgres", "mysql", "mongo", "minio", "backup",
    "gateway", "ingress", "proxy", "lb", "cdn", "waf"
]
env_prefixes = [
    "dev", "stg", "staging", "sit", "uat", "pt", "prod", "lab",
    "test", "sandbox", "demo", "internal", "private"
]

permutations = set()
for env in env_prefixes:
    for svc in service_names:
        permutations.add(f"{env}-{svc}")
        permutations.add(f"{svc}-{env}")
        permutations.add(f"{env}{svc}")
# Add discovered prefixes combined with service names
for prefix in sorted(prefixes)[:30]:
    for svc in service_names:
        permutations.add(f"{prefix}-{svc}")
        permutations.add(f"{svc}-{prefix}")

write_file(f"{WORKDIR}/recon-active/permutation-wordlist.txt", "\n".join(sorted(permutations)))

# 5. Write results
terminal(f"mkdir -p {WORKDIR}/recon-active")
write_file(f"{WORKDIR}/recon-active/live-hosts.txt", "\n".join(live_hosts))

# 5b. DNS Zone Transfer attempt
zone_transfer_results = []
for sub in subdomains:
    # Extract root domain (last 2 parts)
    parts = sub.split(".")
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        break
else:
    root = subdomains[0] if subdomains else ""

if root:
    r = terminal(f"dig +short NS {root}", timeout=10)
    if r["exit_code"] == 0 and r["output"].strip():
        nameservers = [ns.strip().rstrip(".") for ns in r["output"].strip().split("\n") if ns.strip()]
        for ns in nameservers:
            r = terminal(f"dig @{ns} {root} AXFR +noall +answer", timeout=15)
            if r["exit_code"] == 0 and r["output"].strip():
                zone_transfer_results.append(f"=== AXFR from {ns} ===\n{r['output']}")

if zone_transfer_results:
    write_file(f"{WORKDIR}/recon-active/zone-transfer.txt", "\n\n".join(zone_transfer_results))

# 6. Generate checklist.md
checklist_items = [
    ("0a", "Pattern-Based Permutation Brute-Force (MANDATORY)", "PENDING"),
    ("0b", "DNS-Level Subdomain Brute-Force — dnsx/puredns/massdns (MANDATORY)", "PENDING"),
    ("0c", "Reverse DNS on Known IP Ranges", "PENDING"),
    ("0d", "Virtual Host Enumeration", "PENDING"),
    ("0e", "DNS Zone Transfer Attempt", "PENDING"),
    ("0f", "Merge & Deduplicate Expanded Subdomains", "PENDING"),
    ("1", "Port Scanning — nmap (MANDATORY)", "PENDING"),
    ("2", "Service Detection & Banner Grabbing", "PENDING"),
    ("3", "OS Fingerprinting", "PENDING"),
    ("4", "Network Topology Mapping", "PENDING"),
]

checklist_md = "# Active Recon Checklist\n\n| # | Technique | Status | Notes |\n|---|-----------|--------|-------|\n"
for num, technique, status in checklist_items:
    checklist_md += f"| {num} | {technique} | {status} | |\n"

write_file(f"{WORKDIR}/recon-active/checklist.md", checklist_md)

# 7. Summary
print(json.dumps({
    "subdomains_input": len(subdomains),
    "live_hosts_resolved": len(live_hosts),
    "tools": tools,
    "naming_prefixes": len(prefixes),
    "top_prefixes": sorted(prefixes)[:20],
    "wildcard_detected": wildcard_ips if wildcard_ips else None,
    "permutation_wordlist_size": len(permutations),
    "zone_transfer": "SUCCESS" if zone_transfer_results else "failed (expected)",
    "remaining_manual": [
        "0a: Pattern permutation brute-force (use generated wordlist with ffuf/dnsx)",
        "0b: DNS-level brute-force (dnsx/puredns/massdns)",
        "0c: Reverse DNS on known IP ranges",
        "0d: Virtual host enumeration (Host header brute-force)",
        "0f: Merge & deduplicate all expanded subdomains",
        "1: Port scanning — nmap on all live hosts (MANDATORY)",
        "2: Service detection & banner grabbing",
        "3: OS fingerprinting",
        "4: Network topology mapping",
    ],
    "next": "Run nmap on live hosts, then DNS permutation brute-force with generated wordlist"
}, indent=2))
