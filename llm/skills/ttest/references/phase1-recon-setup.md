# Phase 1: Recon & Setup

## Gate: App type identified, proxy intercepting, tools ready

## Steps

### 1.1 App Type Identification
```bash
# Windows: check file type
file app.exe                    # PE32/PE32+ → native or .NET
strings app.exe | grep -i "electron\|node\|chromium"  # Electron
strings app.exe | grep -i "mscoree\|mscorlib\|System\."  # .NET

# Check for .NET
python3 -c "
import pefile
pe = pefile.PE('app.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if b'mscoree' in entry.dll: print('.NET detected')
"

# Check for Java
ls *.jar 2>/dev/null && echo "Java JAR"
ls lib/*.jar 2>/dev/null && echo "Java with libs"
file app.jar  # "Java archive data"

# Electron detection
ls resources/app.asar 2>/dev/null && echo "Electron (asar)"
ls resources/app/ 2>/dev/null && echo "Electron (unpacked)"
```

### 1.2 Proxy Setup by App Type

**.NET apps:**
```
# Option 1: System proxy (Settings → Network → Proxy)
# Option 2: app.config / appsettings.json proxy settings
# Option 3: Fiddler (hooks .NET automatically)
# Option 4: Proxifier (process-level routing)
```

**Java apps:**
```bash
# JVM proxy flags (add to launch script)
-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080
-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080

# Trust Burp CA for Java
keytool -import -alias burp -keystore $JAVA_HOME/lib/security/cacerts \
  -file burp-ca.der -storepass changeit -noprompt
```

**Electron apps:**
```bash
# Launch with proxy flag
./app --proxy-server="http://127.0.0.1:8080"
# Or set env: HTTPS_PROXY=http://127.0.0.1:8080

# Ignore cert errors (for Burp CA)
./app --ignore-certificate-errors --proxy-server="http://127.0.0.1:8080"
```

**Native apps (non-HTTP aware):**
```
# Proxifier: route specific process through Burp
# Rule: app.exe → 127.0.0.1:8080 (HTTPS)
# For raw TCP: use Proxifier SOCKS mode → Burp SOCKS proxy

# Alternative: echo/socat TCP relay
socat TCP-LISTEN:4444,fork TCP:real-server:4444
# Then Wireshark on lo interface
```

### 1.3 Non-HTTP Protocol Identification
```bash
# Wireshark capture during app usage
# Filter: ip.addr == <server_ip> && !http

# Common non-HTTP protocols in thick clients:
# - Custom TCP (binary framing)
# - gRPC (HTTP/2 + protobuf)
# - AMQP / RabbitMQ
# - MQTT (IoT apps)
# - WebSocket (wss://)
# - Named pipes (Windows IPC)
# - .NET Remoting / WCF (SOAP/binary)
```

### 1.4 Tool Checklist

| App Type | Required | Optional |
|----------|----------|----------|
| .NET | dnSpy/ILSpy, Burp/Fiddler, Process Monitor | dotPeek, de4dot (deobfuscation) |
| Java | JADX/JD-GUI, Burp, jarsigner | Recaf, Bytecode Viewer |
| Electron | npx asar, Burp, Chrome DevTools | electron-debug |
| Native | Ghidra/IDA, x64dbg, Wireshark, Proxifier | API Monitor, Rohitab |
| All | Process Monitor (Sysinternals), Wireshark | Regshot, DLL Export Viewer |

### 1.5 Output Directory
```
./ttest-output/
├── state.yaml
├── scope.md
├── phase1-recon/
│   ├── app-type.md
│   └── proxy-config.md
├── phase2-traffic/
├── phase3-local/
├── phase4-logic/
└── report/
```
