#!/usr/bin/env python3
"""Phase 1: Passive Recon — run via execute_code."""
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
for tool in ["dig", "curl", "whois", "subfinder", "amass", "theHarvester"]:
    r = terminal(f"which {tool}")
    tools[tool] = r["exit_code"] == 0

terminal(f"mkdir -p {WORKDIR}/recon-passive")

# 3. WHOIS + DNS records
dns_records = []
for domain in domains:
    # WHOIS
    r = terminal(f"whois {domain} | head -40", timeout=10)
    if r["exit_code"] == 0:
        dns_records.append(f"=== WHOIS {domain} ===\n{r['output']}")
    # DNS: A, MX, TXT, NS
    for rtype in ["A", "MX", "TXT", "NS"]:
        r = terminal(f"dig +short {domain} {rtype}", timeout=5)
        if r["exit_code"] == 0 and r["output"].strip():
            dns_records.append(f"{domain} {rtype}: {r['output'].strip()}")
    # DMARC
    r = terminal(f"dig +short _dmarc.{domain} TXT", timeout=5)
    if r["exit_code"] == 0 and r["output"].strip():
        dns_records.append(f"_dmarc.{domain}: {r['output'].strip()}")

if dns_records:
    write_file(f"{WORKDIR}/recon-passive/dns-records.txt", "\n\n".join(dns_records))

# 3b. SPF include: extraction (third-party services)
spf_includes = []
for record in dns_records:
    if "v=spf1" in record:
        for part in record.split():
            if part.startswith("include:"):
                spf_includes.append(part.replace("include:", ""))
            elif part.startswith("ip4:") or part.startswith("ip6:"):
                spf_includes.append(part)

if spf_includes:
    write_file(f"{WORKDIR}/recon-passive/spf-third-parties.txt", "\n".join(spf_includes))

# 4. Subdomain enumeration (crt.sh + subfinder)
all_subs = set()
for domain in domains:
    # crt.sh
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
    # subfinder
    if tools.get("subfinder"):
        r = terminal(f"subfinder -d {domain} -silent", timeout=120)
        if r["exit_code"] == 0:
            for line in r["output"].split("\n"):
                if line.strip():
                    all_subs.add(line.strip().lower())
    # amass (passive only)
    if tools.get("amass"):
        r = terminal(f"amass enum -passive -d {domain} -timeout 2", timeout=180)
        if r["exit_code"] == 0:
            for line in r["output"].split("\n"):
                line = line.strip().lower()
                if line and "." in line and " " not in line:
                    all_subs.add(line)

# 5. Wayback Machine (URLs for each domain)
wayback_urls = []
for domain in domains:
    r = terminal(f'curl -sk "https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=200"', timeout=20)
    if r["exit_code"] == 0 and r["output"].strip():
        wayback_urls.extend(r["output"].strip().split("\n")[:100])

if wayback_urls:
    write_file(f"{WORKDIR}/recon-passive/wayback-urls.txt", "\n".join(wayback_urls))

# 6. Shodan InternetDB (first 10 resolved IPs)
shodan_results = []
resolved_ips = set()
for sub in sorted(all_subs)[:30]:
    r = terminal(f"dig +short {sub}", timeout=3)
    if r["exit_code"] == 0 and r["output"].strip():
        ip = r["output"].strip().split("\n")[0]
        if ip not in resolved_ips and not ip.startswith("10.") and not ip.startswith("172.") and not ip.startswith("192.168."):
            resolved_ips.add(ip)

for ip in list(resolved_ips)[:10]:
    r = terminal(f'curl -sk "https://internetdb.shodan.io/{ip}"', timeout=5)
    if r["exit_code"] == 0 and r["output"].strip().startswith("{"):
        shodan_results.append(f"{ip}: {r['output'].strip()}")

if shodan_results:
    write_file(f"{WORKDIR}/recon-passive/shodan-internetdb.txt", "\n".join(shodan_results))

# 7. Env-prefix quick-win
env_patterns = ["dev.", "staging.", "stg.", "sit.", "uat.", "mock.", "sandbox.", "test.", "qa.", "preprod.", "nonprod.", "demo.", "lab."]
env_hits = [s for s in all_subs if any(p in s for p in env_patterns)]
bare_candidates = set()
for sub in env_hits:
    for p in env_patterns:
        if p in sub:
            bare = sub.replace(p, "")
            if bare and bare not in all_subs:
                bare_candidates.add(bare)

# 8. Write results
write_file(f"{WORKDIR}/recon-passive/subdomains-merged.txt", "\n".join(sorted(all_subs)))
if bare_candidates:
    write_file(f"{WORKDIR}/recon-passive/env-prefix-bare-domains.txt", "\n".join(sorted(bare_candidates)))

# 9. Generate checklist.md with statuses
checklist_items = [
    ("0", "Request Asset Inventory (internal engagements)", "PENDING"),
    ("0b", "Knowledge Base / Support Site Scraping", "PENDING"),
    ("1a", "WHOIS + DNS Records", "DONE" if dns_records else "FAILED (no records collected)"),
    ("1b", "Shodan InternetDB", "DONE" if shodan_results else "DONE (0 results)"),
    ("1c", "Wayback Machine", "DONE" if wayback_urls else "DONE (0 URLs)"),
    ("1d", "GitHub/GitLab Code Search", "PENDING"),
    ("1e", "DNS Record Intelligence (SPF/DMARC/DKIM)", "DONE" if dns_records else "PENDING"),
    ("1f", "Google Dorks", "PENDING"),
    ("1g", "Job Posting Intelligence", "PENDING"),
    ("2", "Subdomain Enumeration (crt.sh + subfinder)", "DONE" if all_subs else "FAILED (0 subdomains)"),
    ("3", "Technology Fingerprinting", "PENDING"),
    ("4", "Email & Username Discovery", "PENDING"),
    ("5", "Network Mapping (ASN/BGP)", "PENDING"),
    ("6", "Asset Validation (DNS + HTTP probe)", "PENDING"),
    ("7", "Binary/Source Intelligence", "PENDING"),
    ("—", "Env-Prefix Quick-Win Check", "DONE" if env_hits else "DONE (0 env-prefix hits)"),
]

checklist_md = "# Passive Recon Checklist\n\n| # | Technique | Status | Notes |\n|---|-----------|--------|-------|\n"
for num, technique, status in checklist_items:
    checklist_md += f"| {num} | {technique} | {status} | |\n"

write_file(f"{WORKDIR}/recon-passive/checklist.md", checklist_md)

# 10. Summary
print(json.dumps({
    "domains": domains,
    "tools": tools,
    "subdomains_found": len(all_subs),
    "dns_records_collected": len(dns_records),
    "wayback_urls": len(wayback_urls),
    "shodan_ips_queried": len(shodan_results),
    "unique_ips": len(resolved_ips),
    "env_prefix_hits": len(env_hits),
    "bare_domain_candidates": len(bare_candidates),
    "remaining_manual": [
        "0: Request asset inventory (internal engagements)",
        "0b: Knowledge base scraping",
        "1d: GitHub/GitLab code search",
        "1f: Google dorks",
        "1g: Job posting intelligence (tech stack from LinkedIn)",
        "3: Technology fingerprinting (response headers)",
        "4: Email/username discovery",
        "5: Network mapping (ASN/BGP lookup)",
        "6: Asset validation (HTTP probe on all subs)",
        "7: Binary/source intelligence",
    ],
    "next": "Run HTTP probe on subdomains, then complete manual OSINT techniques"
}, indent=2))
