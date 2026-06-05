# Nginx Case-Sensitivity Bypass

## Discovery (LINE WORKS, June 2026)

When nginx uses location-based rules to block specific paths (e.g., `/wp-json/wp/v2/users`), the rules are often case-sensitive on Linux servers while the backend application handles routes case-insensitively.

## Pattern

```
/wp-json/wp/v2/users   → 403 (nginx blocks, exact case match)
/wp-json/wp/v2/Users   → 401 (bypasses nginx, reaches WordPress)
/wp-json/wp/v2/USERS   → 401 (bypasses nginx, reaches WordPress)
```

## Affected Paths (WordPress + nginx)

| Blocked Path | Bypass | Backend Response |
|---|---|---|
| `/wp-json/wp/v2/users` | `/wp-json/wp/v2/Users` | 401 (WP auth required) |
| `/wp-json/wp/v2/media` | `/wp-json/wp/v2/Media` | 401 (WP auth required) |
| `/wp-json/wp/v2/plugins` | `/wp-json/wp/v2/Plugins` | 401 |
| `/wp-json/wp/v2/posts` | `/wp-json/wp/v2/Posts` | 401 |
| `/wp-json/wp/v2/pages` | `/wp-json/wp/v2/Pages` | 401 |
| `/wp-json/wp/v2/comments` | `/wp-json/wp/v2/Comments` | 401 |
| `/wp-json/wp/v2/themes` | `/wp-json/wp/v2/Themes` | 401 |
| `/wp-json/wp/v2/settings` | `/wp-json/wp/v2/Settings` | 401 |
| `/wp-json/wp/v2/templates` | `/wp-json/wp/v2/Templates` | 401 |
| `/xmlrpc.php` | `/XMLRPC.php` | 404 (file not found — Linux FS is case-sensitive) |
| `/wp-cron.php` | `/WP-CRON.php` | 404 (same — real files don't bypass) |
| `/wp-content/debug.log` | `/wp-content/Debug.log` | 404 (file not found) |

**Note:** The bypass works for ALL WP REST routes (any `/wp-json/` namespace endpoint) because they all go through the rewrite engine. Confirmed on LINE WORKS: Users, Posts, Pages, Comments, Categories, Tags, Search, Block-types, Templates, Menus, Taxonomies, Types, Statuses, Media, Plugins, Themes, Settings all bypass via capitalization.

## Key Insight

- **REST API routes** bypass successfully because WordPress routes are case-insensitive (handled by rewrite engine via index.php)
- **Direct file paths** (.php, .log) do NOT bypass because Linux filesystem IS case-sensitive
- The bypass is useful for: REST API endpoints, wp-json namespaces, any rewrite-based route

## Exploitation Chain

Standalone: Low impact (endpoints still require WP authentication)

Combined with XSS:
1. DOM XSS fires in admin's browser (e.g., CVE-2022-29455)
2. XSS reads `wpApiSettings.nonce` from the page
3. XSS fetches `/wp-json/wp/v2/Users` (bypasses nginx 403)
4. With admin's nonce + cookies → full user data exfiltrated
5. Also works for `/wp-json/wp/v2/Media` → all uploaded files

## Detection

```python
import httpx

def check_nginx_case_bypass(base_url, blocked_paths):
    client = httpx.Client(verify=False, timeout=10)
    bypasses = []
    for path in blocked_paths:
        r_lower = client.get(f"{base_url}{path}")
        # Try capitalizing first letter of last segment
        parts = path.rsplit('/', 1)
        if len(parts) == 2:
            bypass_path = f"{parts[0]}/{parts[1].capitalize()}"
            r_cap = client.get(f"{base_url}{bypass_path}")
            if r_lower.status_code == 403 and r_cap.status_code != 403:
                bypasses.append((path, bypass_path, r_cap.status_code))
    client.close()
    return bypasses
```

## When to Test

- WordPress behind nginx with custom security rules (403 on sensitive endpoints)
- Any application where nginx blocks paths but backend handles routing case-insensitively
- Common with: WordPress, Laravel, Django, Spring Boot behind nginx reverse proxy
- **CDN/alternate origins:** If target has a CDN mirror (pstatic, Akamai, CloudFront), test same blocked paths on CDN domain — CDN may not replicate nginx location blocks at all, eliminating the need for case bypass entirely

## CDN Bypass Variant (LINE WORKS, June 2026)

When a CDN serves the same WordPress content on a different hostname:
- `line-works.pstatic.net/wp-json/wp/v2/Users` → 401 (no case bypass needed — CDN lacks nginx rules)
- `line-works.pstatic.net/wp-json/wp/v2/users` → 403 (some rules still applied, inconsistently)
- `line-works.pstatic.net/wp-config-sample.php` → 500 (PHP executes on CDN, unlike static-only expectation)

**Lesson:** CDN configs often lag behind origin security rules. Test BOTH the case bypass AND the alternate hostname independently.
