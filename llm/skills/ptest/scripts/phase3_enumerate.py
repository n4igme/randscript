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

# 4. Bulk actuator quick-scan (all hosts, baseline + key paths)
actuator_hits = []
actuator_paths = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/mappings", "/actuator/configprops", "/actuator/heapdump",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/admin", "/console", "/management", "/_profiler", "/debug",
    "/metrics", "/prometheus", "/actuator/prometheus",
    "/env", "/info", "/health", "/jolokia", "/trace"
]
for host in hosts:
    base = terminal(f'curl -sk -o /dev/null -w "%{{size_download}}" "https://{host}/nonexistent12345xyz" --max-time 5')
    baseline_size = base["output"].strip()
    for path in actuator_paths:
        r = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}|%{{size_download}}" "https://{host}{path}" --max-time 5')
        parts = r["output"].strip().split("|")
        if len(parts) == 2:
            code, size = parts
            if code in ("200", "401", "403") and size != baseline_size and size != "0":
                actuator_hits.append(f"https://{host}{path} [{code}, {size}B]")

# 4b. Framework detection (fingerprint each live host)
frameworks_detected = {}
fw_signatures = {
    "Next.js": "__NEXT_DATA__",
    "Laravel": "laravel_session",
    "Django": "csrftoken",
    "WordPress": "wp-content",
    "Rails": "X-Request-Id",
    "Spring Boot": "X-Application-Context",
    "ASP.NET": "X-AspNet-Version",
}
for host in hosts[:20]:
    r = terminal(f'curl -sk -D - "https://{host}/" --max-time 5', timeout=10)
    if r["exit_code"] == 0 and r["output"]:
        for fw, sig in fw_signatures.items():
            if sig.lower() in r["output"].lower():
                frameworks_detected.setdefault(fw, []).append(host)
                break

# 4c. Authentication endpoint mapping
auth_endpoints = []
auth_paths = ["/login", "/signin", "/auth", "/admin/login", "/api/auth", "/oauth", "/sso",
              "/api/login", "/accounts/login", "/user/login", "/.well-known/openid-configuration"]
for host in hosts[:20]:
    for path in auth_paths:
        r = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}" "https://{host}{path}" --max-time 3')
        code = r["output"].strip()
        if code not in ("000", "404", ""):
            auth_endpoints.append(f"https://{host}{path} [{code}]")

# 4d. GraphQL endpoint discovery
graphql_endpoints = []
gql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/v1/graphql", "/query", "/gql"]
for host in hosts[:20]:
    for path in gql_paths:
        r = terminal(f'curl -sk -X POST "https://{host}{path}" -H "Content-Type: application/json" -d \'{{\"query\":\"{{__typename}}\"}}\' -o /dev/null -w "%{{http_code}}" --max-time 3')
        code = r["output"].strip()
        if code not in ("000", "404", "405", ""):
            graphql_endpoints.append(f"https://{host}{path} [{code}]")

# 4e. WebSocket endpoint discovery
websocket_endpoints = []
ws_paths = ["/ws", "/websocket", "/socket", "/socket.io", "/hub", "/signalr", "/cable", "/live"]
for host in hosts[:20]:
    for path in ws_paths:
        r = terminal(f'curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://{host}{path}" -o /dev/null -w "%{{http_code}}" --max-time 3')
        code = r["output"].strip()
        if code in ("101", "400"):
            websocket_endpoints.append(f"https://{host}{path} [{code}]")

# 4f. JS Bundle Analysis (secrets, endpoints, routes)
import re as re_mod
js_secrets = []
js_endpoints = []
SECRET_PATTERNS = [
    ("AWS Key", r"AKIA[0-9A-Z]{16}"),
    ("Google API", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Stripe", r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}"),
    ("Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Generic Secret", r"""(?:secret|password|api_key|apikey|token)["':\s]*["'][^"']{8,64}["']"""),
]
for host in hosts[:10]:
    # Fetch HTML, extract script URLs
    r = terminal(f'curl -sk --max-time 10 "https://{host}/"', timeout=15)
    html = r.get("output", "")
    scripts = re_mod.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
    for script_url in scripts[:10]:
        if script_url.startswith("//"):
            script_url = "https:" + script_url
        elif script_url.startswith("/"):
            script_url = f"https://{host}{script_url}"
        elif not script_url.startswith("http"):
            script_url = f"https://{host}/{script_url}"
        # Skip third-party CDNs
        if any(x in script_url for x in ["google", "facebook", "hotjar", "gtag", "clarity", "cdn.jsdelivr"]):
            continue
        jr = terminal(f'curl -sk --max-time 10 "{script_url}"', timeout=15)
        js_content = jr.get("output", "")
        if not js_content:
            continue
        # Secrets
        for name, pattern in SECRET_PATTERNS:
            for match in re_mod.finditer(pattern, js_content):
                js_secrets.append(f"[{name}] {match.group(0)[:80]} (in {script_url.split('/')[-1][:40]})")
        # API endpoints
        for ep in re_mod.findall(r'["\'](/api/[a-zA-Z0-9_/\-{}:.]+)["\']', js_content):
            js_endpoints.append(f"https://{host}{ep}")
        for ep in re_mod.findall(r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)["\']', js_content):
            js_endpoints.append(f"https://{host}{ep}")
        # Internal/admin paths
        for ep in re_mod.findall(r'["\'](/(?:admin|internal|debug|graphql|webhook|ws)[a-zA-Z0-9_/\-:.]*)["\']', js_content):
            js_endpoints.append(f"https://{host}{ep}")
        # Source map check
        if "sourceMappingURL" in js_content:
            map_url = re_mod.search(r'sourceMappingURL=(\S+)', js_content)
            if map_url:
                js_secrets.append(f"[SOURCE MAP] {script_url}.map available")

js_endpoints = list(set(js_endpoints))

# 4g. CSP Stale Domain Check (subdomain takeover via CSP whitelisted domains)
csp_stale = []
for host in hosts[:10]:
    r = terminal(f'curl -sk -D - -o /dev/null "https://{host}/" --max-time 5', timeout=10)
    headers = r.get("output", "")
    csp_match = re_mod.search(r'content-security-policy[^:]*:\s*([^\r\n]+)', headers, re_mod.IGNORECASE)
    if csp_match:
        csp = csp_match.group(1)
        # Extract domains from CSP
        csp_domains = re_mod.findall(r'https?://([a-zA-Z0-9._-]+)', csp)
        for domain in set(csp_domains):
            if domain == host or "googleapis" in domain or "gstatic" in domain:
                continue
            # DNS check — NXDOMAIN = potentially registrable = CSP bypass
            dr = terminal(f'dig +short "{domain}" 2>/dev/null', timeout=5)
            if dr["exit_code"] == 0 and not dr["output"].strip():
                csp_stale.append(f"{host} CSP allows {domain} → NXDOMAIN (potential takeover for XSS)")

# 4h. Subdomain Takeover Check (dangling CNAMEs)
takeover_candidates = []
try:
    subs_data = read_file(f"{WORKDIR}/recon-passive/subdomains.txt")
    subdomains = [s.strip() for s in subs_data["content"].split("\n") if s.strip()]
except:
    subdomains = []

takeover_sigs = {
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "no-such-app",
    "ghost.io": "Site not found",
    "github.io": "There isn't a GitHub Pages",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "pantheon.io": "404 error unknown site",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "azurewebsites.net": "404 Web Site not found",
}
for sub in subdomains[:50]:
    r = terminal(f'dig +short CNAME "{sub}" 2>/dev/null', timeout=5)
    cname = r.get("output", "").strip().rstrip(".")
    if cname:
        for service, sig in takeover_sigs.items():
            if service in cname:
                # Verify the CNAME target is dead
                vr = terminal(f'curl -sk --max-time 5 "https://{sub}" 2>/dev/null', timeout=10)
                if sig.lower() in vr.get("output", "").lower():
                    takeover_candidates.append(f"{sub} → CNAME {cname} [{service} TAKEOVER POSSIBLE]")
                break

# 5. Write results
terminal(f"mkdir -p {WORKDIR}/enumeration")

# Write JS analysis results
if js_secrets:
    write_file(f"{WORKDIR}/enumeration/js-secrets.txt", "\n".join(js_secrets))
if js_endpoints:
    write_file(f"{WORKDIR}/enumeration/js-endpoints.txt", "\n".join(js_endpoints))
if csp_stale:
    write_file(f"{WORKDIR}/enumeration/csp-stale-domains.txt", "\n".join(csp_stale))
if takeover_candidates:
    write_file(f"{WORKDIR}/enumeration/subdomain-takeover.txt", "\n".join(takeover_candidates))

# 6. Generate checklist.md
checklist_items = [
    ("1", "Directory & File Brute-Force (MANDATORY)", "PENDING"),
    ("2", "API Endpoint Discovery (MANDATORY)", "PENDING"),
    ("3", "Parameter Discovery", "PENDING"),
    ("4", "Virtual Host Enumeration", "PENDING"),
    ("5", "CMS-Specific Enumeration", "PENDING"),
    ("6", "JavaScript Analysis", "DONE" if (js_secrets or js_endpoints) else "DONE (0 secrets/endpoints)"),
    ("7", "Authentication Endpoint Mapping", "DONE" if auth_endpoints else "DONE (0 auth endpoints found)"),
    ("8", "Framework Detection & Targeted Enumeration", "DONE" if frameworks_detected else "DONE (no frameworks identified)"),
    ("9", "GraphQL Endpoint Discovery", "DONE" if graphql_endpoints else "DONE (0 GraphQL endpoints found)"),
    ("10", "WebSocket Endpoint Discovery", "DONE" if websocket_endpoints else "DONE (0 WebSocket endpoints found)"),
    ("11", "Deserialization Sink Identification", "PENDING"),
    ("12", "Bulk Actuator/Admin Scan (MANDATORY)", "DONE" if actuator_hits else "DONE (0 hits on top 10)"),
    ("13", "Cloud Misconfiguration Checks", "PENDING"),
    ("14", "CSP Stale Domain Check", "DONE" if csp_stale else "DONE (0 stale CSP domains)"),
    ("15", "Subdomain Takeover Check", "DONE" if takeover_candidates else "DONE (0 takeover candidates)"),
]

checklist_md = "# Enumeration Checklist\n\n| # | Technique | Status | Notes |\n|---|-----------|--------|-------|\n"
for num, technique, status in checklist_items:
    checklist_md += f"| {num} | {technique} | {status} | |\n"

write_file(f"{WORKDIR}/enumeration/checklist.md", checklist_md)

# 7. Summary
print(json.dumps({
    "live_hosts": len(hosts),
    "tools": tools,
    "seclists_path": seclists,
    "dirbrute_tool": "gobuster" if tools.get("gobuster") else ("feroxbuster" if tools.get("feroxbuster") else "NONE"),
    "actuator_quick_hits": actuator_hits,
    "frameworks_detected": frameworks_detected,
    "auth_endpoints": auth_endpoints,
    "graphql_endpoints": graphql_endpoints,
    "websocket_endpoints": websocket_endpoints,
    "js_secrets_found": len(js_secrets),
    "js_secrets_samples": js_secrets[:5],
    "js_endpoints_found": len(js_endpoints),
    "js_endpoints_samples": js_endpoints[:10],
    "csp_stale_domains": csp_stale,
    "subdomain_takeover_candidates": takeover_candidates,
    "remaining_manual": [
        "1: Directory & file brute-force (MANDATORY — use gobuster/feroxbuster)",
        "2: API endpoint discovery (MANDATORY — use ffuf)",
        "3: Parameter discovery (arjun/ffuf)",
        "4: Virtual host enumeration",
        "5: CMS-specific enumeration (if CMS detected)",
        "11: Deserialization sink identification",
        "13: Cloud misconfiguration checks (buckets, monitoring, registries)",
    ],
    "next": "Run bulk actuator scan on all hosts, then dir brute-force on priority targets"
}, indent=2))
