# Wayback Machine & Alternative OSINT for Dorking

When search engines block automated dorking (Google/Bing/DuckDuckGo CAPTCHA), use these alternatives:

## Wayback Machine CDX API (no auth, no block)
```python
import httpx

# Get all archived URLs for a domain
r = httpx.get('http://web.archive.org/cdx/search/cdx', params={
    'url': '*.target.com/*',
    'output': 'text',
    'fl': 'original,statuscode,mimetype',
    'collapse': 'urlkey',
    'limit': '500',
    'filter': '!mimetype:image/.*',
})

# Search specific subdomain
r = httpx.get('http://web.archive.org/cdx/search/cdx', params={
    'url': 'api.target.com/*',
    'output': 'text',
    'fl': 'original,statuscode',
    'collapse': 'urlkey',
    'limit': '50',
})
```

Key lesson: Wayback reveals historical paths that may still be accessible (e.g., `/partner-webview/` on api.jago.com was archived as 200 and still works today bypassing the 401 on root).

## Shodan InternetDB (free, no auth)
```
GET https://internetdb.shodan.io/{IP}
```
Returns ports, hostnames, CVEs, CPEs. No rate limit for reasonable use.

## Common Crawl Index
```python
r = httpx.get('http://index.commoncrawl.org/CC-MAIN-2025-51-index', params={
    'url': '*.target.com',
    'output': 'json',
    'limit': '50',
})
```

## Pitfalls
- Wayback `matchType=domain` with wildcard may return 0 results — use `url=*.domain.com/*` instead
- GCP Global LBs show hundreds of "open" ports on Shodan — these are SYN-ACK traps (accept TCP on any port but send no data). Verify with banner grab before reporting.
- Search engine alternatives (Searx instances) also rate-limit or block; Wayback CDX is the most reliable fallback.

## Phase Classification Reminder
- Wayback/Shodan/Common Crawl queries = Phase 1 (passive, querying third-party DBs)
- HTTP probing, port scanning, fingerprinting = Phase 2 (active, touching the target)
- Don't mix them — port scanning is NOT passive recon
