# Redsocks Transparent Proxy for Flutter Apps

## When to Use

- Flutter apps ignore system proxy settings
- macOS Burp can't handle DNAT (no SO_ORIGINAL_DST)
- Need transparent HTTPS interception without app cooperation

## Architecture

```
App → iptables REDIRECT → redsocks (device:12345)
                              ↓ reads original dest (SO_ORIGINAL_DST)
                              ↓ CONNECT host:port → Burp (host:PORT)
                           Burp decrypts + logs traffic
```

## Cross-Compile redsocks for ARM64

```bash
# Prerequisites: Android NDK
NDK=~/Library/Android/sdk/ndk/27.0.12077973
CC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android28-clang

# Build libevent (dependency)
curl -sL https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz | tar xz
cd libevent-2.1.12-stable
./configure --host=aarch64-linux-android CC="$CC" --disable-shared --enable-static --disable-openssl --disable-samples --prefix=$PWD/../libevent-install
make -j4 && make install

# Build redsocks
cd .. && git clone https://github.com/darkk/redsocks.git && cd redsocks

# Fix pipe2 issue (not in older Android API)
sed -i '' 's/pipe2(&pump->request.read, O_NONBLOCK)/pipe(\&pump->request.read)/' redsocks.c

# Add version symbol
echo 'const char* redsocks_version = "redsocks/0.5-custom";' > version.c

# Compile (dynamic linking - static has TLS alignment issues on ARM64 Bionic)
$CC -I../libevent-install/include -DUSE_IPTABLES -D_GNU_SOURCE \
  -o redsocks \
  base.c base64.c debug.c dnstc.c dnsu2t.c http-auth.c http-connect.c \
  http-relay.c log.c main.c md5.c parser.c redsocks.c redudp.c \
  socks4.c socks5.c utils.c version.c \
  -L../libevent-install/lib -l:libevent.a -l:libevent_core.a
```

**Build pitfalls:**
- `pipe2` not declared: use API level 28+ or patch to use `pipe()`
- `redsocks_version` undefined: create `version.c` with the symbol
- Static linking TLS alignment error on ARM64 Bionic: use dynamic linking instead (`-l:libevent.a` without `-static`)

## Install on Device

```bash
adb push redsocks /data/local/tmp/redsocks
adb shell su -c 'chmod 755 /data/local/tmp/redsocks'
```

## Config File

**CRITICAL: Verify Burp's actual port FIRST:**
```bash
# On host machine — find Burp's proxy listener port
lsof -i -P | grep java | grep LISTEN
# PITFALL: Multiple Java apps (JADX-GUI, Ghidra, Burp) all show as "java" in lsof.
# Verify PID matches Burp: ps aux | grep -i burp
# Common confusion: JADX-GUI MCP server (port 9876) or JADX random port mistaken for Burp.
# Look for the port that matches Burp's Proxy > Settings > Proxy Listeners config.
```

```bash
cat > /tmp/redsocks.conf << 'EOF'
base {
    log_debug = off;
    log_info = on;
    log = "file:/data/local/tmp/redsocks.log";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = BURP_HOST_IP;
    port = BURP_PORT;
    type = http-connect;
    login = "";
    password = "";
}
EOF
adb push /tmp/redsocks.conf /data/local/tmp/redsocks.conf
```

## Toggle ON/OFF

### ON
```bash
adb shell su -c '/data/local/tmp/redsocks -c /data/local/tmp/redsocks.conf'
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner UID --dport 443 -j REDIRECT --to-port 12345'
```

### OFF
```bash
adb shell su -c 'killall redsocks'
adb shell su -c 'iptables -t nat -F OUTPUT'
```

### Status
```bash
adb shell su -c 'ps -A | grep redsocks'
adb shell su -c 'iptables -t nat -L OUTPUT -nv'
adb shell su -c 'tail -20 /data/local/tmp/redsocks.log'
```

## Burp Listener Requirements

For redsocks `type = http-connect`:
- **Support invisible proxying: OFF** (redsocks sends explicit CONNECT)
- **Force use of TLS: OFF** (CONNECT is plain HTTP)
- **Bind to: All interfaces** (device connects over network)
- **Intercept: OFF** (or CONNECT requests get stuck)

## Burp Upstream Proxy with redsocks (PITFALL)

When using Burp upstream proxy to route traffic through a parsing proxy (e.g., Flask on localhost:5556):

**PROBLEM:** redsocks resolves the hostname on-device and sends `CONNECT <IP>:<port>` (e.g., `CONNECT 172.64.148.24:443`). Burp upstream proxy rules match by **hostname** (e.g., `api.jago.com`). Since the CONNECT uses an IP, the rule NEVER matches.

**FIX:** Set upstream proxy destination host to `*` (wildcard) to catch all traffic. The parsing proxy can then forward to the real API by reading SNI/Host header.

**Verification:** After setting upstream proxy, check your parsing proxy log. If total requests stays at 0 while redsocks log shows "accepted" — the upstream rule isn't matching.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `HTTP Proxy error: HTTP/1.1 400 Bad Request` | Burp has invisible proxy ON | Uncheck "Support invisible proxying" |
| `shutdown: bufferevent_disable(client, EV_READ)` | Burp has Force TLS ON | Uncheck "Force use of TLS" |
| Connections accepted, no errors, no Burp traffic | App rejects Burp cert (SSL pinning) | Need Frida SSL bypass + system cert |
| Connections accepted, SSL hooks fire, still no Burp traffic | Burp intercept ON (CONNECT stuck in queue) or listener misconfiguration | Turn intercept OFF, verify listener settings match below |
| SSL hooks fire (onEnter logs) but 0 HTTP History entries | Burp processes CONNECT but drops inner TLS — check Event Log | Burp → Dashboard → Event Log for TLS errors; try fresh listener on different port |
| `Error binding to address` | redsocks already running | `killall redsocks` first |
| Wrong port | Ghidra/other tool took Burp's port | Check `lsof -i :PORT -P` and update config |
| `HTTP/1.1 405 METHOD NOT ALLOWED` from upstream | Upstream points to Flask (can't handle CONNECT) | Remove upstream proxy, use Burp extension instead |
| Burp upstream proxy rule doesn't match traffic | redsocks sends CONNECT with IP, not hostname | Don't use upstream proxy with redsocks — use passive analyzer pattern |

## CRITICAL LIMITATION: Flutter + redsocks + Burp = No HTTP History

**This combination is fundamentally broken for logging Flutter traffic in Burp.**

**Root cause**: redsocks sends `CONNECT <IP>:443` (not `CONNECT hostname:443`). Flutter's BoringSSL does NOT send SNI when the connection target is an IP address. Burp therefore cannot determine the hostname, cannot generate a per-host certificate, and logs ZERO requests in HTTP History.

**Symptoms**: 27+ ESTABLISHED connections on Burp port, redsocks log shows dozens of `accepted` entries, SSL bypass hooks fire (onEnter logs), but Burp Proxy History stays completely empty.

**Attempted fixes that DON'T work** (all tested, all failed):
- Invisible proxy mode ON
- Disable HTTP/2 negotiation in Burp
- Hostname resolution entries (Project Settings → Hostname Resolution: api.jago.com→IP)
- Scope + SSL pass-through configuration changes
- Fresh listener on different port
- Any combination of the above

**Why Flutter specifically breaks**: Native Android apps using OkHttp/HttpURLConnection typically include SNI even when connecting by IP (because the URL was hostname-based). Flutter's BoringSSL, when it receives a pre-resolved IP from the Dart runtime, omits SNI entirely.

**When to detect (SAVE TIME)**: If after setting up redsocks→Burp you see connections in redsocks log + SSL bypass hooks firing + ZERO Burp history entries — stop troubleshooting Burp immediately. Switch to alternative capture.

**Correct alternatives**:
1. **Frida Dart-layer HTTP dumper** — hook Dart `_SecureSocket`, `HttpClient`, or Dio interceptor to dump plaintext. Best when SSL bypass already works.
2. **HTTP Toolkit** — handles IP-based connections better than Burp
3. **mitmproxy transparent mode** — can infer hostname from cert CN/SAN
4. **Frida native IO hooks** — hook `read()`/`write()` on SSL socket FDs after SSL bypass nullifies encryption verification

See `references/passive-traffic-analyzer.md` for the Frida dumper implementation.

## Magisk CA Installation

Standard `mount -o remount,rw /system` FAILS on Magisk-rooted devices (overlay FS, /system not in /proc/mounts).

**Working approaches**:
1. **MagiskTrustUserCerts module**: Install CA as user cert (Settings), module auto-promotes
2. **Manual module**: `mkdir -p /data/adb/modules/customcerts/system/etc/security/cacerts/ && cp <hash>.0 there`
3. **For Frida-based capture**: CA install unnecessary — hooking at Dart layer captures plaintext before TLS

## Notes

- Get app UID: `adb shell pm list packages -U | grep PACKAGE`
- Only targets specified UID — other apps unaffected
- Still need SSL bypass (Frida or system cert) for app to accept Burp's cert
- redsocks sends CONNECT with IP address (not hostname) — Burp resolves via SNI in the subsequent TLS handshake
- For Flutter apps: **skip redsocks entirely**, use Frida Dart-layer dumper from the start
