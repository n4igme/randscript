#!/bin/bash
# bulk-actuator-scan.sh
# Mandatory Phase 3 technique: scan ALL live subdomains for exposed actuator/admin endpoints
# Usage: bash bulk-actuator-scan.sh [input-file] [output-file]
#
# Input: file with subdomains (one per line, or pipe-separated sub|ip format)
# Output: list of exposed endpoints with HTTP status codes

INPUT="${1:-live-subs.txt}"
OUTPUT="${2:-actuator-scan-results.txt}"

if [ ! -f "$INPUT" ]; then
  echo "Error: Input file '$INPUT' not found"
  echo "Usage: bash bulk-actuator-scan.sh <live-subs-file> [output-file]"
  exit 1
fi

TOTAL=$(wc -l < "$INPUT" | tr -d ' ')
COUNT=0
FOUND=0

echo "[*] Bulk Actuator/Admin Scan"
echo "[*] Input: ${INPUT} (${TOTAL} hosts)"
echo "[*] Output: ${OUTPUT}"
echo ""

> "$OUTPUT"

PATHS="/actuator /actuator/health /actuator/env /actuator/heapdump /swagger-ui.html /v3/api-docs /camunda/app/welcome/"

while IFS='|' read -r sub rest; do
  # Strip whitespace
  sub=$(echo "$sub" | tr -d ' ')
  [ -z "$sub" ] && continue
  
  COUNT=$((COUNT + 1))
  [ $((COUNT % 25)) -eq 0 ] && echo "[*] Progress: ${COUNT}/${TOTAL} hosts checked (${FOUND} found)"
  
  for path in /actuator /actuator/health /actuator/env /actuator/heapdump /swagger-ui.html /v3/api-docs; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}${path}" --max-time 8 -k 2>/dev/null)
    if [ "$code" = "200" ]; then
      echo "[200] https://${sub}${path}" | tee -a "$OUTPUT"
      FOUND=$((FOUND + 1))
      # If /actuator returns 200, skip /actuator/health (redundant)
      [ "$path" = "/actuator" ] && break
    fi
  done
done < "$INPUT"

echo ""
echo "[*] Scan complete."
echo "[*] Hosts checked: ${COUNT}"
echo "[*] Exposed endpoints found: ${FOUND}"
echo "[*] Results saved to: ${OUTPUT}"

if [ "$FOUND" -gt 0 ]; then
  echo ""
  echo "[!] FINDINGS:"
  cat "$OUTPUT"
fi
