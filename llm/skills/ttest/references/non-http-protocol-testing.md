# Non-HTTP Protocol Testing

When thick clients use custom TCP/UDP protocols instead of HTTP.

## Identification

```bash
# Wireshark capture during app operation
# Filter: ip.addr == <server_ip> && !http && !dns
# Look for: consistent port, binary framing, repeated magic bytes

# Netstat to find connections
netstat -an | grep <app_pid>    # Windows
lsof -i -P -n | grep <app>    # macOS/Linux
```

## Common Non-HTTP Protocols in Thick Clients

| Protocol | Port | Detection | Tool |
|----------|------|-----------|------|
| Custom TCP (binary) | Varies | Binary frames, magic bytes | Wireshark + Python |
| gRPC | 50051 (default) | HTTP/2 + application/grpc | grpcurl, grpcui |
| AMQP / RabbitMQ | 5672 | AMQP 0-9-1 header | pika (Python) |
| MQTT | 1883/8883 | CONNECT/PUBLISH packets | mosquitto_sub/pub |
| .NET Remoting | Varies | .NET binary formatter | Custom deserializer |
| WCF (SOAP/binary) | Varies | SOAP envelope or binary formatter | SoapUI, WCF tools |
| Named Pipes | N/A (local) | `\\.\pipe\<name>` | PowerShell, pipelist |
| MSSQL TDS | 1433 | TDS protocol header | impacket-mssqlclient |
| Oracle TNS | 1521 | TNS header | odat |

## Interception Strategies

### Strategy 1: TCP Relay (man-in-the-middle)
```bash
# socat relay — see cleartext traffic
socat -v TCP-LISTEN:4444,fork TCP:<real_server>:4444

# mitmproxy for TCP (raw mode)
mitmdump --mode raw@4444 --set upstream=<real_server>:4444
```

### Strategy 2: Wireshark + Replay
```bash
# Capture → analyze → replay modified
tshark -i lo -f "port 4444" -w capture.pcap
# Extract payload, modify, replay with ncat:
cat modified_payload.bin | ncat <server> 4444
```

### Strategy 3: Python Socket Proxy
```python
import socket, threading

def relay(src, dst, label):
    while True:
        data = src.recv(4096)
        if not data: break
        print(f"[{label}] {len(data)} bytes: {data[:50].hex()}")
        dst.send(data)

server = socket.socket()
server.bind(("0.0.0.0", 4444))
server.listen(1)
client_sock, _ = server.accept()
remote = socket.socket()
remote.connect(("real_server", 4444))

threading.Thread(target=relay, args=(client_sock, remote, "C→S")).start()
threading.Thread(target=relay, args=(remote, client_sock, "S→C")).start()
```

### Strategy 4: Frida Network Hooks (intercept at app level)
```javascript
// Hook send/recv to see data before encryption
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter: function(args) {
        console.log("[send] " + args[2].toInt32() + " bytes");
        console.log(hexdump(args[1], {length: Math.min(args[2].toInt32(), 128)}));
    }
});
```

## Testing Methodology

1. **Map message types** — correlate app actions with captured packets
2. **Identify framing** — length-prefix? delimiter? fixed-size? magic bytes?
3. **Find auth tokens** — session IDs, API keys in binary stream
4. **Replay attacks** — send captured messages from another session
5. **Modify fields** — change user IDs, amounts, permissions in binary
6. **Fuzzing** — mutate fields (boofuzz, custom Python scripts)

## gRPC Testing (most common non-HTTP in modern apps)

```bash
# Server reflection (enumerate services)
grpcurl -plaintext <host>:50051 list
grpcurl -plaintext <host>:50051 describe <service>

# Call method
grpcurl -plaintext -d '{"id": 1}' <host>:50051 app.UserService/GetUser

# Test auth (no token)
grpcurl -plaintext <host>:50051 app.AdminService/ListUsers

# BOLA via gRPC
grpcurl -plaintext -H "authorization: Bearer <user_a_token>" \
  -d '{"user_id": "USER_B_ID"}' <host>:50051 app.UserService/GetProfile
```

## Pitfalls

- Binary protocols often have length fields — wrong length = connection drop
- Encryption (TLS) on custom ports: use Frida to hook pre-encryption
- Stateful protocols: messages depend on prior handshake — can't just replay one message
- Endianness matters: x86 = little-endian, network protocols often = big-endian
- gRPC with TLS: use `-insecure` flag or provide CA cert to grpcurl
