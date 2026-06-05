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

## Notes

- Get app UID: `adb shell pm list packages -U | grep PACKAGE`
- Only targets specified UID — other apps unaffected
- Still need SSL bypass (Frida or system cert) for app to accept Burp's cert
- redsocks sends CONNECT with IP address (not hostname) — Burp resolves via SNI in the subsequent TLS handshake
