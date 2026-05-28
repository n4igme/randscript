# Parallel HTTP Probing for Asset Validation

When validating 100+ subdomains in Phase 1 (Asset Validation), sequential `curl` probes are too slow (3-4s timeout × N hosts). This reference documents the working pattern discovered during the bfi.co.id engagement.

## Working Pattern: Per-File Background Jobs

Write a bash script and execute it via `bash script.sh` in terminal:

```bash
#!/bin/bash
cd /path/to/ptest-output/recon-passive
TMPDIR=$(mktemp -d)
i=0

while IFS='|' read -r sub ip; do
  i=$((i+1))
  {
    status=$(curl -sI --max-time 4 -o /dev/null -w "%{http_code}" "https://$sub" 2>/dev/null)
    if [ "$status" != "000" ] && [ -n "$status" ]; then
      echo "$sub|https|$status|$ip" > "$TMPDIR/live_$i.txt"
    else
      status=$(curl -sI --max-time 4 -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
      if [ "$status" != "000" ] && [ -n "$status" ]; then
        echo "$sub|http|$status|$ip" > "$TMPDIR/live_$i.txt"
      else
        echo "$sub|$ip" > "$TMPDIR/dead_$i.txt"
      fi
    fi
  } &
  # Limit concurrency
  if [ $((i % 25)) -eq 0 ]; then wait; fi
done < resolving-subs.txt

wait
cat "$TMPDIR"/live_*.txt > live-subs.txt 2>/dev/null || touch live-subs.txt
cat "$TMPDIR"/dead_*.txt > no-http-subs.txt 2>/dev/null || touch no-http-subs.txt
rm -rf "$TMPDIR"
echo "LIVE: $(wc -l < live-subs.txt)"
echo "NO_HTTP: $(wc -l < no-http-subs.txt)"
echo "DONE"
```

## Pitfalls (Failed Approaches)

1. **Do NOT use `>> file` with background jobs** — race conditions cause empty/corrupted output. Multiple processes writing to the same file simultaneously lose data.

2. **Do NOT use `xargs -P -I {} sh -c '...'` with grep/variable expansion inside** — the `{}` substitution breaks when hostnames contain special characters, and grep inside the subshell can't reliably read the parent's files.

3. **Do NOT use `execute_code` sandbox for network probing** — `terminal()` calls inside the Python sandbox are slow, and the sandbox has a 300s hard timeout. 270 hosts × sequential terminal calls = guaranteed timeout.

4. **Do NOT use inline `&` backgrounding in Hermes terminal** — the terminal tool rejects commands with `&` backgrounding. You must write the script to a file first, then run it with `bash script.sh`.

## Correct Approach

- Each background job writes to its **own unique temp file** (`$TMPDIR/live_$i.txt`)
- After all jobs complete (`wait`), merge with `cat $TMPDIR/live_*.txt`
- 25 concurrent probes is a good balance for 200-500 hosts (finishes in ~60s)
- Use `write_file` to create the script, then `terminal("bash /path/to/probe.sh", timeout=180)`

## Input Format

The script expects `resolving-subs.txt` with format:
```
subdomain.example.com|IP_ADDRESS
```

## Output Format

`live-subs.txt`:
```
subdomain.example.com|https|200|IP_ADDRESS
```

`no-http-subs.txt`:
```
subdomain.example.com|IP_ADDRESS
```

## Performance

- 270 hosts with 25 concurrency: ~50-70 seconds
- 500 hosts with 30 concurrency: ~90-120 seconds
- 1100 hosts with 60 concurrency (Python): ~90 seconds
- 3000 hosts with 80 concurrency (Python): ~180 seconds
- Adjust `--max-time` (curl timeout) based on target geography. 4s works for most; increase to 6s for high-latency targets.

## Alternative: Python ThreadPoolExecutor (for 500+ hosts)

For large-scale probing (1000+ hosts), the Python approach is more reliable than bash backgrounding — better error handling, progress reporting, and output capture:

```python
import subprocess, concurrent.futures

with open('public-subdomains.txt') as f:
    subs = [l.strip() for l in f if l.strip()]

def probe(host):
    for scheme in ['https', 'http']:
        try:
            r = subprocess.run(
                ['curl', '-s', '-o', '/dev/null',
                 '-w', '%{http_code}|%{size_download}|%{content_type}',
                 '--max-time', '7', '-k', f'{scheme}://{host}'],
                capture_output=True, text=True, timeout=10)
            parts = r.stdout.split('|')
            code = parts[0] if parts else '000'
            size = parts[1] if len(parts) > 1 else '0'
            ctype = parts[2] if len(parts) > 2 else ''
            if code and code != '000':
                return f'{code} {scheme}://{host} [{size}b] [{ctype}]'
        except:
            pass
    return None

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
    futures = {ex.submit(probe, h): h for h in subs}
    done = 0
    for future in concurrent.futures.as_completed(futures):
        done += 1
        if done % 200 == 0:
            print(f'  Progress: {done}/{len(subs)}')
        result = future.result()
        if result:
            results.append(result)

results.sort()
with open('live-hosts.txt', 'w') as f:
    f.write('\n'.join(results))
```

### When to use Python vs Bash
- **Bash script**: <500 hosts, simple alive/dead check, no progress needed
- **Python ThreadPoolExecutor**: 500+ hosts, need status codes + response size + content-type, want progress reporting

### Pitfall: httpx on this system
The `httpx` binary at `/opt/homebrew/bin/httpx` is **Python httpx CLI** (not ProjectDiscovery httpx). It does NOT support `--status-code`, `--tech-detect`, `--threads`, or pipe-from-stdin subdomain probing. Use `dnsx` for DNS resolution and the Python/bash probing patterns above for HTTP.
