# Module Development Patterns (Proven via DVWA Engagement)

## Critical: Sibling Params Pattern

When testing a parameter for injection, ALL other form parameters must be included in the request. Without them, many apps silently ignore the request (form doesn't execute).

### Problem
```python
# WRONG — DVWA exec requires 'submit' alongside 'ip'
resp = await client.get(url, params={param: payload})
# Returns empty form — the injection never runs
```

### Solution
```python
# Build sibling params — submit buttons get their name as value
base_params = {}
for p in endpoint.params:
    if p == param:
        continue
    if p.lower() in ("submit", "btn", "button", "go", "send"):
        base_params[p] = p  # submit buttons echo their name
    else:
        base_params[p] = "1"  # other params get safe defaults

params = {**base_params, param: payload}
resp = await client.get(url, params=params)
```

## POST Fallback

Many forms use POST not GET. Modules MUST try both methods:
```python
# Try GET first
resp = await client.get(url, params=params)
if marker not in resp.text:
    # Fallback to POST form data
    resp = await client.post(url, data=params)
```

DVWA command execution only works via POST. Without POST fallback, CMDi goes undetected.

## LFI: Include Absolute Paths

Always test absolute paths BEFORE traversal variants:
```python
LFI_PAYLOADS = [
    "/etc/passwd",              # absolute first
    "../../../../etc/passwd",   # then traversal
    "....//....//etc/passwd",   # double encoding
    ...
]
```

Many apps (DVWA fi/low) accept absolute paths directly without needing traversal.

## Crawler Budget Patterns

### Time budget (prevent hangs)
```python
CRAWL_BUDGET = 15.0  # max seconds
crawl_start = asyncio.get_event_loop().time()
while crawl_queue:
    if asyncio.get_event_loop().time() - crawl_start > CRAWL_BUDGET:
        break
```

### Skip library JS (prevent multi-MB downloads)
```python
SKIP_JS = {"jquery", "swagger", "lodash", "react", "angular", "vue", "bootstrap"}
basename = js_url.split("/")[-1].lower()
if any(lib in basename for lib in SKIP_JS):
    continue
if len(resp.text) > 500_000:
    continue
```

### Cache crawled responses (don't re-fetch)
```python
page_bodies: dict[str, str] = {}
# Store during crawl
page_bodies[url] = body
# Reuse for JS/CSP extraction later (no second HTTP call)
```

## DVWA Validation Setup

DVWA requires explicit DB setup before login works:
```python
# 1. Setup DB (without this, login always fails)
await client.get(f'{base}/setup.php')
await client.post(f'{base}/setup.php', data={'create_db': 'Create / Reset Database'})

# 2. Login
await client.get(f'{base}/login.php')
await client.post(f'{base}/login.php',
    data={'username':'admin','password':'password','Login':'Login'})

# 3. Force security=low via cookie
cookies['security'] = 'low'
```

## Nmap Grepable Output Parsing

The regex for parsing nmap `-oG -` output must use DOUBLE slash between service and version:

```python
# WRONG — captures empty version
re.finditer(r'(\d+)/open/tcp//([^/]*)/([^/,]*)', line)

# CORRECT — nmap uses // before version field
re.finditer(r'(\d+)/open/tcp//([^/]*)//([^/,]*)', line)
```

Example nmap grepable line:
```
Host: 10.10.10.1 ()  Ports: 22/open/tcp//ssh//OpenSSH 7.2p2/, 80/open/tcp//http//Apache httpd 2.4.49/
```

## CLI Format

The CLI uses subcommands. Correct invocation:
```bash
python main.py scan <target> [OPTIONS]
# NOT: python main.py <target>
# NOT: python main.py scan <target> <url>  (url is not a second arg)
```

## stdlib Shadow Pitfall

A `queue/` directory in the project shadows Python's built-in `queue` module, breaking `anyio`/`httpx`. Rename to `scan_queue/` and update imports.
