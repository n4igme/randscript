#!/usr/bin/env python3
"""Phase 5: Vulnerability Assessment setup — run via execute_code."""
from hermes_tools import terminal, read_file, write_file
import json, re

WORKDIR = "./ptest-output"

# 1. Read live hosts from Phase 2/4
hosts = []
try:
    hosts_data = read_file(f"{WORKDIR}/recon-active/live-hosts.txt")
    for line in hosts_data["content"].split("\n"):
        if "|" in line:
            hosts.append(line.strip().split("|")[0])
except:
    pass

# 2. Read priority targets from Phase 4
priority_targets = []
try:
    matrix_data = read_file(f"{WORKDIR}/attack-surface/priority-matrix.md")
    for line in matrix_data["content"].split("\n"):
        if "Critical" in line or "High" in line:
            # Extract host from table row
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2 and "." in parts[1]:
                priority_targets.append(parts[1])
except:
    pass

# 3. Check tools
tools = {}
for tool in ["nuclei", "nikto", "testssl.sh", "testssl", "searchsploit", "curl"]:
    r = terminal(f"which {tool}")
    tools[tool] = r["exit_code"] == 0

# Normalize testssl (binary name varies)
tools["testssl"] = tools.get("testssl.sh", False) or tools.get("testssl", False)

# 4. CDN/WAF detection on live hosts (top 20)
cdn_hosts = []
direct_hosts = []
for host in hosts[:20]:
    r = terminal(f'curl -sk -D - -o /dev/null "https://{host}/" --max-time 5', timeout=10)
    if r["exit_code"] == 0:
        output_lower = r["output"].lower()
        if any(sig in output_lower for sig in ["cf-ray", "cloudflare", "cloudfront", "x-amz-cf", "akamai", "x-cdn"]):
            cdn_hosts.append(host)
        else:
            direct_hosts.append(host)

# 5. CORS reflection test on auth/data endpoints
cors_findings = []
# Read entry points from Phase 4
test_endpoints = []
try:
    ep_data = read_file(f"{WORKDIR}/attack-surface/entry-points.md")
    for line in ep_data["content"].split("\n"):
        url_match = re.search(r'(https://[^\s|]+)', line)
        if url_match:
            test_endpoints.append(url_match.group(1))
except:
    pass

# Also test root of each host
for host in hosts[:15]:
    if f"https://{host}" not in test_endpoints:
        test_endpoints.append(f"https://{host}")

for endpoint in test_endpoints[:30]:
    r = terminal(f'curl -sk -H "Origin: https://evil.com" -D - -o /dev/null "{endpoint}" --max-time 5')
    if r["exit_code"] == 0:
        output_lower = r["output"].lower()
        if "access-control-allow-origin: https://evil.com" in output_lower:
            creds = "with-credentials" if "access-control-allow-credentials: true" in output_lower else "no-credentials"
            cors_findings.append(f"{endpoint} [reflects evil.com, {creds}]")
        elif "access-control-allow-origin: null" in output_lower:
            cors_findings.append(f"{endpoint} [reflects null origin]")

# 6. SSL/TLS quick check on priority targets (if testssl available)
ssl_issues = []
if tools["testssl"] and priority_targets:
    testssl_bin = "testssl.sh" if tools.get("testssl.sh") else "testssl"
    for host in priority_targets[:3]:
        r = terminal(f'{testssl_bin} --fast --quiet "https://{host}" 2>/dev/null | grep -iE "VULNERABLE|NOT ok|WEAK"', timeout=60)
        if r["exit_code"] == 0 and r["output"].strip():
            ssl_issues.append(f"{host}: {r['output'].strip()[:200]}")

# 7. Write results
terminal(f"mkdir -p {WORKDIR}/vuln-assessment")

if cors_findings:
    write_file(f"{WORKDIR}/vuln-assessment/cors-results.txt", "\n".join(cors_findings))

if ssl_issues:
    write_file(f"{WORKDIR}/vuln-assessment/ssl-quick-results.txt", "\n".join(ssl_issues))

# Write CDN classification
cdn_md = "# CDN/WAF Classification\n\n"
cdn_md += "## CDN-Fronted Hosts (skip nuclei, use manual checks)\n\n"
for h in cdn_hosts:
    cdn_md += f"- {h}\n"
cdn_md += f"\n## Direct Hosts (nuclei/nikto viable)\n\n"
for h in direct_hosts:
    cdn_md += f"- {h}\n"
cdn_md += f"\n## Not Checked ({len(hosts) - len(cdn_hosts) - len(direct_hosts)} remaining)\n"

write_file(f"{WORKDIR}/vuln-assessment/cdn-classification.md", cdn_md)

# 8. Generate checklist
checklist_items = [
    ("5A", "Threat Modeling (attack trees)", "PENDING"),
    ("1", "Nuclei Scan (MANDATORY)", "PENDING" if direct_hosts else "BLOCKED (all hosts CDN-fronted)"),
    ("2", "CORS Origin Reflection Testing (MANDATORY)", "DONE" if cors_findings else "DONE (0 reflections found)"),
    ("3", "OAuth/OIDC redirect_uri Validation (MANDATORY)", "PENDING"),
    ("4", "Nikto Scan", "PENDING" if tools.get("nikto") else "SKIPPED (nikto not installed)"),
    ("5", "SSL/TLS Assessment", "DONE" if ssl_issues else ("DONE (no issues)" if tools["testssl"] else "SKIPPED (testssl not installed)")),
    ("6", "CVE Mapping", "PENDING"),
    ("7", "Manual Verification of Findings", "PENDING"),
    ("8", "Prioritized Vector List", "PENDING"),
]

checklist_md = "# Vulnerability Assessment Checklist\n\n| # | Technique | Status | Notes |\n|---|-----------|--------|-------|\n"
for num, technique, status in checklist_items:
    checklist_md += f"| {num} | {technique} | {status} | |\n"

write_file(f"{WORKDIR}/vuln-assessment/checklist.md", checklist_md)

# 9. Generate nuclei command suggestions
nuclei_cmds = []
if tools.get("nuclei") and direct_hosts:
    direct_file = f"{WORKDIR}/vuln-assessment/direct-hosts.txt"
    write_file(direct_file, "\n".join([f"https://{h}" for h in direct_hosts]))
    nuclei_cmds = [
        f"nuclei -l {direct_file} -severity info,low,medium,high,critical -o {WORKDIR}/vuln-assessment/nuclei-full.txt",
        f"nuclei -l {direct_file} -t cves/ -o {WORKDIR}/vuln-assessment/nuclei-cves.txt",
        f"nuclei -l {direct_file} -t exposures/ -t misconfiguration/ -o {WORKDIR}/vuln-assessment/nuclei-misconfig.txt",
    ]

# 10. Summary
print(json.dumps({
    "total_hosts": len(hosts),
    "priority_targets": priority_targets[:10],
    "tools": tools,
    "cdn_classification": {
        "cdn_fronted": len(cdn_hosts),
        "direct": len(direct_hosts),
        "not_checked": len(hosts) - len(cdn_hosts) - len(direct_hosts),
    },
    "cors_findings": cors_findings,
    "ssl_issues": ssl_issues,
    "nuclei_commands": nuclei_cmds,
    "remaining_manual": [
        "5A: Threat modeling — build attack trees for priority targets",
        "1: Run nuclei on direct hosts (commands generated in summary)",
        "3: OAuth/OIDC redirect_uri validation on all auth endpoints",
        "4: Nikto scan on direct hosts (if available)",
        "6: CVE mapping — searchsploit for each identified technology/version",
        "7: Manual verification of all scanner findings (eliminate false positives)",
        "8: Build prioritized vector list for Phase 6 (vectors-prioritized.md)",
    ],
    "next": "Run nuclei on direct hosts, then build threat models for priority targets",
}, indent=2))
