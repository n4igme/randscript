# Execute Code Integration

## Overview

Use `execute_code` (Python with `hermes_tools`) to batch mechanical operations that would otherwise consume 20-50 sequential tool calls. The agent still makes decisions — scripts handle data collection.

## Two Tiers

### Tier 1: Phase Setup Scripts

**Purpose:** Initialize phase structure, generate checklists, run quick automated discovery.
**When:** Called ONCE when entering a phase.
**Pattern:** Reads state from previous phase → runs lightweight automation → prints structured summary.

**How to call:** Inline the logic in `execute_code` using `hermes_tools`. Code blocks for each phase are below.

#### Phase 1 Setup (Passive Recon)

```python
from hermes_tools import terminal, read_file, write_file
import json

WORKDIR = "./ptest-output"  # adjust per engagement

# 1. Read state
state = read_file(f"{WORKDIR}/state.yaml")
# Parse scope domains from scope.md
scope = read_file(f"{WORKDIR}/scope.md")
domains = []
for line in scope["content"].split("\n"):
    content = line.split("|",1)[-1] if "|" in line else ""
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
                for sub in entry.get("name_value","").split("\\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        all_subs.add(sub)
        except: pass

# 4. subfinder (if available)
if tools.get("subfinder"):
    for domain in domains:
        r = terminal(f"subfinder -d {domain} -silent", timeout=120)
        if r["exit_code"] == 0:
            for line in r["output"].split("\\n"):
                if line.strip():
                    all_subs.add(line.strip().lower())

# 5. Env-prefix quick-win
env_patterns = ["dev.","staging.","stg.","sit.","uat.","mock.","sandbox.","test.","qa.","preprod.","nonprod.","demo.","lab."]
env_hits = [s for s in all_subs if any(p in s for p in env_patterns)]
bare_candidates = set()
for sub in env_hits:
    for p in env_patterns:
        if p in sub:
            bare = sub.replace(p, "")
            if bare and bare not in all_subs:
                bare_candidates.add(bare)

# 6. Write results
write_file(f"{WORKDIR}/recon-passive/subdomains-merged.txt", "\\n".join(sorted(all_subs)))
if bare_candidates:
    write_file(f"{WORKDIR}/recon-passive/env-prefix-bare-domains.txt", "\\n".join(sorted(bare_candidates)))

# 7. Summary
print(json.dumps({
    "domains": domains,
    "tools": tools,
    "subdomains_found": len(all_subs),
    "env_prefix_hits": len(env_hits),
    "bare_domain_candidates": len(bare_candidates),
}, indent=2))
```

#### Phase 2 Setup (Active Recon)

```python
from hermes_tools import terminal, read_file, write_file
import json, re

WORKDIR = "./ptest-output"  # adjust per engagement

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
write_file(f"{WORKDIR}/recon-active/live-hosts.txt", "\n".join(live_hosts))

# 6. Summary
print(json.dumps({
    "subdomains_input": len(subdomains),
    "live_hosts_resolved": len(live_hosts),
    "tools": tools,
    "naming_prefixes": len(prefixes),
    "top_prefixes": sorted(prefixes)[:20],
}, indent=2))
```

#### Phase 3 Setup (Enumeration)

```python
from hermes_tools import terminal, read_file, write_file
import json, os

WORKDIR = "./ptest-output"  # adjust per engagement

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

# 4. Bulk actuator quick-scan (top 10 hosts, baseline + 3 paths)
actuator_hits = []
for host in hosts[:10]:
    # Baseline for SPA detection
    base = terminal(f'curl -sk -o /dev/null -w "%{{size_download}}" "https://{host}/nonexistent12345xyz" --max-time 5')
    baseline_size = base["output"].strip()
    for path in ["/actuator", "/swagger-ui.html", "/api-docs"]:
        r = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}|%{{size_download}}" "https://{host}{path}" --max-time 5')
        parts = r["output"].strip().split("|")
        if len(parts) == 2:
            code, size = parts
            if code == "200" and size != baseline_size:
                actuator_hits.append(f"{host}{path} [{code}]")

# 5. Summary
print(json.dumps({
    "live_hosts": len(hosts),
    "tools": tools,
    "seclists_path": seclists,
    "actuator_quick_hits": actuator_hits,
    "dirbrute_tool": "gobuster" if tools.get("gobuster") else ("feroxbuster" if tools.get("feroxbuster") else "NONE"),
}, indent=2))
```

#### Phase 6 Setup (Exploitation)

```python
from hermes_tools import terminal, read_file, write_file
import json

WORKDIR = "./ptest-output"  # adjust per engagement

# 1. Read prioritized vectors from Phase 5
try:
    vectors_data = read_file(f"{WORKDIR}/vuln-assessment/vectors-prioritized.md")
    vectors_content = vectors_data["content"]
except:
    vectors_content = "(not found — create manually)"

# 2. Check for credential inventory
try:
    creds_data = read_file(f"{WORKDIR}/credential-inventory.md")
    has_creds = True
except:
    has_creds = False

# 3. Read unauth endpoints from Phase 3 (for method testing)
try:
    enum_data = read_file(f"{WORKDIR}/enumeration/actuator-hits.md")
    unauth_endpoints = [l for l in enum_data["content"].split("\n") if "200" in l]
except:
    unauth_endpoints = []

# 4. Create exploit tracking structure
terminal(f"mkdir -p {WORKDIR}/exploit/poc {WORKDIR}/exploit/evidence")

# 5. Summary
print(json.dumps({
    "prioritized_vectors": "found" if "(not found" not in vectors_content else "MISSING",
    "credential_inventory": has_creds,
    "unauth_endpoints_for_method_test": len(unauth_endpoints),
    "unauth_samples": unauth_endpoints[:5],
    "next_action": "6.1 Credential Validation" if has_creds else "6.2 Authentication Bypass",
}, indent=2))
```

#### Phase 7 Setup (Post-Exploitation)

```python
from hermes_tools import terminal, read_file, write_file
import json

WORKDIR = "./ptest-output"  # adjust per engagement

# 1. Read findings from Phase 6
try:
    findings = read_file(f"{WORKDIR}/findings-log.md")
    finding_count = findings["content"].count("## [FINDING-")
except:
    finding_count = 0

# 2. Determine access type from Phase 6 results
try:
    exploit_data = read_file(f"{WORKDIR}/exploit/checklist.md")
    content = exploit_data["content"]
    has_shell = "RCE" in content or "shell" in content.lower()
    has_api = "JWT" in content or "token" in content or "authenticated" in content.lower()
    has_data = "data" in content.lower() or "records" in content.lower()
except:
    has_shell = False
    has_api = False
    has_data = False

# 3. Classify access type
if has_shell:
    access_type = "Shell"
    playbook = "A"
elif has_api:
    access_type = "API"
    playbook = "B"
elif has_data:
    access_type = "Data"
    playbook = "C"
else:
    access_type = "None"
    playbook = "Skip to Phase 8"

# 4. Create post-exploit structure
terminal(f"mkdir -p {WORKDIR}/post-exploit/evidence")

# 5. Summary
print(json.dumps({
    "findings_from_phase6": finding_count,
    "access_type": access_type,
    "playbook": playbook,
    "next_action": f"Follow Playbook {playbook} in phase7-post-exploitation-framework.md",
}, indent=2))
```

### Tier 2: Batch Execution Scripts

**Purpose:** Handle high-volume operations mid-phase. Takes target list, runs N operations, returns structured JSON.
**When:** Called during phase execution when the agent hits a bulk operation.
**Pattern:** Input (target list + params) → parallel/batch execution → structured JSON output → agent reasons on summary.

**Build on-demand.** These don't exist yet — create them when the pain point surfaces.

| Script | Phase | What It Batches | Build When |
|--------|-------|-----------------|------------|
| Bulk HTTP Probe | 1-3 | HTTP probe all subdomains | 50+ subs to validate |
| Bulk Actuator Scan | 3 | Actuator/admin on all hosts with SPA filtering | 30+ live hosts |
| HTTP Method Testing | 6 | POST/PUT/PATCH/DELETE on all unauth endpoints | 10+ unauth endpoints |
| Credential Validation | 6 | Test creds across all environments | 5+ credentials found |
| DNS Expansion | 2 | Pattern permutation + batch resolution | Naming patterns detected |
| CORS Testing | 5 | Origin reflection on all auth endpoints | 10+ auth endpoints |

#### Tier 2 Example: HTTP Method Testing (Phase 6)

```python
from hermes_tools import terminal
import json

# Input: list of unauthenticated GET endpoints
ENDPOINTS = [
    "https://target.com/api/v1/users",
    "https://target.com/api/v1/config",
    "https://target.com/master/v1/general",
    # ... populate from Phase 3 results
]

results = {"critical": [], "safe": [], "ambiguous": [], "errors": []}

for endpoint in ENDPOINTS:
    for method in ["POST", "PUT", "PATCH", "DELETE"]:
        r = terminal(
            f'curl -sk -X {method} -w "|%{{http_code}}" "{endpoint}" '
            f'-H "Content-Type: application/json" -d \'{{"name":"pentest-probe","code":"PT"}}\' --max-time 8',
            timeout=10
        )
        output = r["output"].strip()
        code = output.split("|")[-1] if "|" in output else "000"

        if code in ["200", "201"]:
            results["critical"].append({"endpoint": endpoint, "method": method, "code": code})
        elif code in ["401", "403", "405"]:
            results["safe"].append(f"{method} {endpoint} [{code}]")
        elif code == "500":
            results["ambiguous"].append({"endpoint": endpoint, "method": method})
        elif code == "000":
            results["errors"].append(endpoint)
            break  # host unreachable, skip remaining methods

print(json.dumps({
    "total_endpoints": len(ENDPOINTS),
    "critical_writes": results["critical"],
    "ambiguous_500s": results["ambiguous"][:10],
    "safe_count": len(results["safe"]),
    "errors": len(results["errors"]),
}, indent=2))
```

#### Tier 2 Example: Bulk Actuator Scan (Phase 3)

```python
from hermes_tools import terminal, read_file
import json

# Input: live hosts from Phase 2
hosts_data = read_file("./ptest-output/recon-active/live-hosts.txt")
hosts = [l.split("|")[0].strip() for l in hosts_data["content"].split("\n") if l.strip() and not l.startswith(" ")]

PATHS = ["/actuator", "/actuator/env", "/actuator/heapdump", "/swagger-ui.html", "/v3/api-docs", "/admin", "/graphql"]

results = {"hits": [], "spa_filtered": 0, "hosts_scanned": 0}

for host in hosts[:50]:  # cap at 50 (hermes_tools limit awareness)
    results["hosts_scanned"] += 1
    # Baseline for SPA detection
    base = terminal(f'curl -sk -o /dev/null -w "%{{size_download}}" "https://{host}/nonexistent12345xyz" --max-time 5')
    baseline = base["output"].strip()

    for path in PATHS:
        r = terminal(f'curl -sk -o /dev/null -w "%{{http_code}}|%{{size_download}}" "https://{host}{path}" --max-time 5')
        parts = r["output"].strip().split("|")
        if len(parts) == 2:
            code, size = parts
            if code == "200" and size != baseline:
                results["hits"].append(f"https://{host}{path} [{code}, {size}B]")
            elif code == "200" and size == baseline:
                results["spa_filtered"] += 1

print(json.dumps(results, indent=2))
```

---

## Integration Flow

```
Agent enters Phase N
  │
  ├── Load phase reference file (skill_view)
  │
  ├── execute_code: Tier 1 setup script
  │   └── Returns: checklist, host count, tool status, suggested commands
  │
  ├── Agent reviews summary, picks first technique
  │
  ├── [If bulk operation needed] execute_code: Tier 2 batch script
  │   └── Returns: structured JSON results
  │
  ├── Agent reasons on results, writes findings
  │
  └── Agent continues with manual techniques
```

## Key Rules

1. **Always print structured JSON** at the end — agent parses it for decisions
2. **Cap at 50 tool calls** per `execute_code` block (hermes_tools limit)
3. **For 50+ targets**, split into batches across multiple `execute_code` calls
4. **Include error counts** so agent knows if retries are needed
5. **Use `shell_quote()`** when interpolating user-provided values into commands
6. **Use `try/except`** around file reads — files may not exist yet in early phases

## When to Use execute_code vs Sequential Calls

| Situation | Use |
|-----------|-----|
| 1-3 targets, simple checks | Direct tool calls (curl via terminal) |
| 4-10 targets, same operation | execute_code with a loop |
| 10+ targets, same operation | execute_code with Tier 2 pattern |
| Decision-heavy work (is this a finding?) | Agent reasoning, not script |
| Parsing large output (nmap XML, nuclei JSON) | execute_code to filter/summarize |

## Build Trigger

When you're mid-engagement and find yourself writing the same curl loop for the 3rd time, or the context is filling up with repetitive probe results — that's the signal to use execute_code. Copy the relevant Tier 2 example above, adjust the ENDPOINTS/hosts list, and run it.
