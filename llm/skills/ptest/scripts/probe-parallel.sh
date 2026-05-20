#!/bin/bash
# Parallel HTTP probe for subdomain validation
# Input: resolving-subs.txt (format: subdomain|ip per line)
# Output: live-subs.txt, no-http-subs.txt
# Usage: bash probe-parallel.sh [input_file] [output_dir]
#
# This script avoids the >> race condition by writing each result
# to an individual temp file, then merging after all jobs complete.

INPUT="${1:-resolving-subs.txt}"
OUTDIR="${2:-.}"
CONCURRENCY="${3:-25}"
TIMEOUT="${4:-4}"

TMPDIR=$(mktemp -d)
i=0

echo "Probing $(wc -l < "$INPUT") subdomains (concurrency: $CONCURRENCY, timeout: ${TIMEOUT}s)..."

while IFS='|' read -r sub ip; do
  i=$((i+1))
  {
    status=$(curl -sI --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "https://$sub" 2>/dev/null)
    if [ "$status" != "000" ] && [ -n "$status" ]; then
      echo "$sub|https|$status|$ip" > "$TMPDIR/live_$i.txt"
    else
      status=$(curl -sI --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
      if [ "$status" != "000" ] && [ -n "$status" ]; then
        echo "$sub|http|$status|$ip" > "$TMPDIR/live_$i.txt"
      else
        echo "$sub|$ip" > "$TMPDIR/dead_$i.txt"
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
cat "$TMPDIR"/live_*.txt > "$OUTDIR/live-subs.txt" 2>/dev/null || touch "$OUTDIR/live-subs.txt"
cat "$TMPDIR"/dead_*.txt > "$OUTDIR/no-http-subs.txt" 2>/dev/null || touch "$OUTDIR/no-http-subs.txt"
rm -rf "$TMPDIR"

echo "LIVE: $(wc -l < "$OUTDIR/live-subs.txt")"
echo "NO_HTTP: $(wc -l < "$OUTDIR/no-http-subs.txt")"
echo "DONE"
