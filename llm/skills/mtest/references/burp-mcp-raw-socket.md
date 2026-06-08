# Burp MCP Raw Socket Access

When Hermes MCP client reports "MCP server 'burpsuite' is not connected", talk directly via raw sockets.

## Protocol

1. GET `/` with `Accept: text/event-stream` → SSE stream returns `data: ?sessionId=<uuid>`
2. POST `/?sessionId=<uuid>` with JSON-RPC body → returns `202 Accepted`
3. Response arrives on the SSE stream as `event: message\ndata: {jsonrpc response}`

## Python Template

```python
import socket, json, time

HOST = '127.0.0.1'
PORT = 9876  # Burp MCP SSE port

def burp_mcp_call(tool_name, arguments):
    # Open SSE connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.settimeout(15)
    s.sendall(b'GET / HTTP/1.1\r\nHost: localhost:9876\r\nAccept: text/event-stream\r\n\r\n')
    buf = b''
    while b'sessionId=' not in buf:
        buf += s.recv(4096)
    sid = buf.split(b'sessionId=')[1].split(b'\r\n')[0].split(b'\n')[0].decode()

    # POST tool call
    payload = json.dumps({
        'jsonrpc': '2.0', 'id': 1,
        'method': 'tools/call',
        'params': {'name': tool_name, 'arguments': arguments}
    }).encode()
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((HOST, PORT))
    s2.sendall(f'POST /?sessionId={sid} HTTP/1.1\r\nHost: localhost:9876\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n'.encode() + payload)
    s2.recv(4096)
    s2.close()

    # Read SSE response
    time.sleep(4)
    data = b''
    try:
        while True:
            data += s.recv(65536)
    except socket.timeout:
        pass
    s.close()
    return data.decode('utf-8', errors='replace')
```

## Common Tools

- `output_project_options` / `output_user_options` — dump config
- `set_project_options` / `set_user_options` — apply config changes
  - JSON arg key: `{'json': json.dumps({...})}`
  - Project: top-level key `project_options`
  - User: top-level key `user_options`
- `get_proxy_http_history` — `{'count': N, 'offset': M}`
- `get_proxy_http_history_regex` — `{'count': N, 'offset': M, 'regex': 'pattern'}`

## Fix Upstream Proxy Example

```python
config = json.dumps({
    'user_options': {
        'connections': {
            'upstream_proxy': {'servers': []}
        }
    }
})
burp_mcp_call('set_user_options', {'json': config})
```

## Gotchas

- Response is chunked transfer encoding — raw bytes include hex chunk sizes
- Each call needs a FRESH session (new GET / connection)
- `set_user_options` accepts config but may require key structure: `user_options.connections.upstream_proxy`
- `set_project_options` uses `project_options.connections.*`
- Response parsing: find `data:` line after SSE event, parse JSON from there
