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

# 5. Write results
terminal(f"mkdir -p {WORKDIR}/enumeration")

# 6. Generate checklist.md
checklist_items = [
    ("1", "Directory & File Brute-Force (MANDATORY)", "PENDING"),
    ("2", "API Endpoint Discovery (MANDATORY)", "PENDING"),
    ("3", "Parameter Discovery", "PENDING"),
    ("4", "Virtual Host Enumeration", "PENDING"),
    ("5", "CMS-Specific Enumeration", "PENDING"),
    ("6", "JavaScript Analysis", "PENDING"),
    ("7", "Authentication Endpoint Mapping", "DONE" if auth_endpoints else "DONE (0 auth endpoints found)"),
    ("8", "Framework Detection & Targeted Enumeration", "DONE" if frameworks_detected else "DONE (no frameworks identified)"),
    ("9", "GraphQL Endpoint Discovery", "DONE" if graphql_endpoints else "DONE (0 GraphQL endpoints found)"),
    ("10", "WebSocket Endpoint Discovery", "DONE" if websocket_endpoints else "DONE (0 WebSocket endpoints found)"),
    ("11", "Deserialization Sink Identification", "PENDING"),
    ("12", "Bulk Actuator/Admin Scan (MANDATORY)", "DONE" if actuator_hits else "DONE (0 hits on top 10)"),
    ("13", "Cloud Misconfiguration Checks", "PENDING"),
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
    "remaining_manual": [
        "1: Directory & file brute-force (MANDATORY — use gobuster/feroxbuster)",
        "2: API endpoint discovery (MANDATORY — use ffuf)",
        "3: Parameter discovery (arjun/ffuf)",
        "4: Virtual host enumeration",
        "5: CMS-specific enumeration (if CMS detected)",
        "6: JavaScript analysis (linkfinder, source maps, secrets)",
        "7: Authentication endpoint mapping",
        "8: Framework detection & targeted enumeration",
        "9: GraphQL endpoint discovery",
        "10: WebSocket endpoint discovery",
        "11: Deserialization sink identification",
        "12: Bulk actuator/admin scan on ALL hosts (expand beyond top 10)",
        "13: Cloud misconfiguration checks (buckets, monitoring, registries)",
    ],
    "next": "Run bulk actuator scan on all hosts, then dir brute-force on priority targets"
}, indent=2))
