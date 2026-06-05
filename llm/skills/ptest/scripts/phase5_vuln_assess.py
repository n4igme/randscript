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

# 6b. JWT Weakness Detection (on auth endpoints from Phase 3)
jwt_findings = []
auth_eps = []
try:
    auth_data = read_file(f"{WORKDIR}/enumeration/checklist.md")
    # Also try to get auth endpoints from phase3 output
    auth_ep_data = read_file(f"{WORKDIR}/enumeration/auth-endpoints.txt")
    auth_eps = [l.strip().split(" ")[0] for l in auth_ep_data["content"].split("\n") if l.strip()]
except:
    pass

# Test JWT none algorithm on any endpoint that returns a JWT
for endpoint in test_endpoints[:15]:
    r = terminal(f'curl -sk -D - --max-time 5 "{endpoint}"', timeout=10)
    resp = r.get("output", "")
    # Look for JWTs in response headers/body
    import re as re5
    jwt_matches = re5.findall(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', resp)
    if jwt_matches:
        jwt = jwt_matches[0]
        # Decode header to check algorithm
        import base64
        try:
            header_b64 = jwt.split(".")[0] + "=="
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            alg = header.get("alg", "unknown")
            jwt_findings.append(f"{endpoint} → JWT found (alg={alg})")
            # Flag weak algorithms
            if alg in ("HS256", "HS384", "HS512"):
                jwt_findings.append(f"  ⚠️ HMAC-based — test key confusion (RS→HS) and weak secret brute")
            elif alg == "none":
                jwt_findings.append(f"  🔴 NONE ALGORITHM — immediate bypass")
        except:
            jwt_findings.append(f"{endpoint} → JWT found (decode failed)")

# 6c. Open Redirect Validation (from auth endpoints)
redirect_findings = []
redirect_params = ["redirect", "redirect_uri", "return", "returnTo", "next", "url", "continue", "dest", "destination", "redir", "return_url", "callback"]
for host in hosts[:10]:
    for param in redirect_params:
        test_url = f"https://{host}/login?{param}=https://evil.attacker.com"
        r = terminal(f'curl -sk -o /dev/null -D /tmp/redir_headers.txt -w "%{{http_code}}|%{{redirect_url}}" --max-time 5 "{test_url}"', timeout=10)
        parts = r.get("output", "").split("|")
        code = parts[0] if parts else ""
        redir_target = parts[1] if len(parts) > 1 else ""
        if code in ("301", "302", "303", "307") and "evil.attacker.com" in redir_target:
            redirect_findings.append(f"https://{host}/login?{param}= → OPEN REDIRECT to attacker domain")
            break  # One hit per host is enough
        # Also test path-based bypass
        test_url2 = f"https://{host}/login?{param}=//evil.attacker.com"
        r2 = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}|%{{redirect_url}}" --max-time 5 "{test_url2}"', timeout=10)
        parts2 = r2.get("output", "").split("|")
        if len(parts2) > 1 and "evil" in parts2[1]:
            redirect_findings.append(f"https://{host}/login?{param}=//evil → OPEN REDIRECT (protocol-relative)")
            break

# 6d. Header Injection / CRLF Check
crlf_findings = []
for host in hosts[:10]:
    payloads = [
        ("%0d%0aInjected-Header:%20true", "Injected-Header"),
        ("%0aSet-Cookie:%20hacked=1", "Set-Cookie"),
    ]
    for payload, sig in payloads:
        r = terminal(f'curl -sk -D - -o /dev/null --max-time 5 "https://{host}/?param=test{payload}"', timeout=10)
        if sig.lower() in r.get("output", "").lower() and "test" in r.get("output", "").lower():
            crlf_findings.append(f"https://{host}/?param= → CRLF injection ({sig} reflected in response headers)")
            break

# 6e. Race Condition Signal Detection (identify state-changing endpoints)
race_candidates = []
# Look for endpoints that modify state (transfer, redeem, apply, vote, like, follow, checkout)
state_change_keywords = ["transfer", "redeem", "coupon", "apply", "vote", "like", "follow",
                         "checkout", "purchase", "withdraw", "send", "claim", "activate"]
try:
    js_eps_data = read_file(f"{WORKDIR}/enumeration/js-endpoints.txt")
    all_endpoints = js_eps_data["content"].split("\n")
except:
    all_endpoints = []

for ep in all_endpoints + test_endpoints:
    ep_lower = ep.lower()
    for keyword in state_change_keywords:
        if keyword in ep_lower:
            race_candidates.append(f"{ep} → state-changing ({keyword}) — TEST FOR RACE CONDITION")
            break

# 7. Write results
terminal(f"mkdir -p {WORKDIR}/vuln-assessment")

if cors_findings:
    write_file(f"{WORKDIR}/vuln-assessment/cors-results.txt", "\n".join(cors_findings))

if ssl_issues:
    write_file(f"{WORKDIR}/vuln-assessment/ssl-quick-results.txt", "\n".join(ssl_issues))

if jwt_findings:
    write_file(f"{WORKDIR}/vuln-assessment/jwt-findings.txt", "\n".join(jwt_findings))

if redirect_findings:
    write_file(f"{WORKDIR}/vuln-assessment/open-redirect.txt", "\n".join(redirect_findings))

if crlf_findings:
    write_file(f"{WORKDIR}/vuln-assessment/crlf-injection.txt", "\n".join(crlf_findings))

if race_candidates:
    write_file(f"{WORKDIR}/vuln-assessment/race-condition-candidates.txt", "\n".join(race_candidates))

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
    ("6", "JWT Weakness Detection", "DONE" if jwt_findings else "DONE (0 JWTs found)"),
    ("7", "Open Redirect Validation", "DONE" if redirect_findings else "DONE (0 redirects found)"),
    ("8", "CRLF / Header Injection", "DONE" if crlf_findings else "DONE (0 CRLF found)"),
    ("9", "Race Condition Candidates", "DONE" if race_candidates else "DONE (0 state-changing endpoints)"),
    ("10", "CVE Mapping", "PENDING"),
    ("11", "Manual Verification of Findings", "PENDING"),
    ("12", "Prioritized Vector List", "PENDING"),
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
    "jwt_findings": jwt_findings,
    "redirect_findings": redirect_findings,
    "crlf_findings": crlf_findings,
    "race_condition_candidates": race_candidates[:10],
    "nuclei_commands": nuclei_cmds,
    "remaining_manual": [
        "5A: Threat modeling — build attack trees for priority targets",
        "1: Run nuclei on direct hosts (commands generated in summary)",
        "3: OAuth/OIDC redirect_uri validation on all auth endpoints",
        "10: CVE mapping — searchsploit for each identified technology/version",
        "11: Manual verification of all scanner findings (eliminate false positives)",
        "12: Build prioritized vector list for Phase 6 (vectors-prioritized.md)",
    ],
    "next": "Run nuclei on direct hosts, then build threat models for priority targets",
}, indent=2))
