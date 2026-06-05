#!/bin/bash
# Parallel HTTP probe for subdomain validation
# Input: resolving-subs.txt (format: subdomain|ip per line)
# Output: live-subs.txt, no-http-subs.txt
# Usage: bash http-probe-parallel.sh [input_file] [concurrency]

INPUT="${1:-resolving-subs.txt}"
CONCURRENCY="${2:-25}"
TMPDIR_PROBE=$(mktemp -d)
i=0

while IFS='|' read -r sub ip; do
  i=$((i+1))
  {
    status=$(curl -sI --max-time 4 -o /dev/null -w "%{http_code}" "https://$sub" 2>/dev/null)
    if [ "$status" != "000" ] && [ -n "$status" ]; then
      echo "$sub|https|$status|$ip" > "$TMPDIR_PROBE/live_$i.txt"
    else
      status=$(curl -sI --max-time 4 -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
      if [ "$status" != "000" ] && [ -n "$status" ]; then
        echo "$sub|http|$status|$ip" > "$TMPDIR_PROBE/live_$i.txt"
      else
        echo "$sub|$ip" > "$TMPDIR_PROBE/dead_$i.txt"
      fi
    fi
  } &

  # Limit concurrency
  if [ $((i % CONCURRENCY)) -eq 0 ]; then
    wait
  fi
done < "$INPUT"

wait

# Merge results
cat "$TMPDIR_PROBE"/live_*.txt > live-subs.txt 2>/dev/null || touch live-subs.txt
cat "$TMPDIR_PROBE"/dead_*.txt > no-http-subs.txt 2>/dev/null || touch no-http-subs.txt
rm -rf "$TMPDIR_PROBE"

echo "LIVE: $(wc -l < live-subs.txt)"
echo "NO_HTTP: $(wc -l < no-http-subs.txt)"
echo "DONE"
