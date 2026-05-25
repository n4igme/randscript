# Burp Suite MCP Integration

## Setup
Config in `~/.hermes/config.yaml`:
```yaml
mcp_servers:
  burpsuite:
    command: java
    args:
    - -jar
    - /path/to/mcp-burp.jar
    - --sse-url
    - http://127.0.0.1:9876
    timeout: 120
```

The Burp extension (from BApp Store) must be loaded and running — it serves SSE on port 9876.

## Verify Connection
```bash
hermes mcp test burpsuite   # Shows 24 tools if working
lsof -i :9876               # Check if SSE server is listening
```

## Key Tools

### get_proxy_http_history
**Required params:** `count` (int), `offset` (int)
```json
{"name": "get_proxy_http_history", "arguments": {"count": 50, "offset": 0}}
```

### get_proxy_http_history_regex
**Required params:** `regex` (string), `count` (int), `offset` (int)
```json
{"name": "get_proxy_http_history_regex", "arguments": {"regex": "api.target.com", "count": 100, "offset": 0}}
```

### send_http1_request
Send requests directly through Burp.

### Other useful tools
- `create_repeater_tab` — send request to Repeater
- `send_to_intruder` — send to Intruder
- `get_scanner_issues` — get scanner findings
- `generate_collaborator_payload` — OOB testing
- `get_collaborator_interactions` — check OOB hits

## Response Format
Responses contain `content[0].text` with newline-separated JSON objects:
```json
{"request": "GET /path HTTP/1.1\r\n...", "response": "HTTP/1.1 200 OK\r\n...", "notes": ""}
```

Each entry is separated by `\n\n`. Parse with:
```python
entries = text.strip().split('\n\n')
for entry in entries:
    obj = json.loads(entry)
    req = obj['request']   # Full HTTP request
    resp = obj['response'] # Full HTTP response
```

## Programmatic Access (when MCP tools aren't loaded in session)
```python
import subprocess, json, time, select

proc = subprocess.Popen(
    ['java', '-jar', '/path/to/mcp-burp.jar', '--sse-url', 'http://127.0.0.1:9876'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
)

def send_msg(msg):
    proc.stdin.write(json.dumps(msg).encode() + b"\n")
    proc.stdin.flush()

# Initialize
send_msg({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}})
# Read response...
send_msg({"jsonrpc":"2.0","method":"notifications/initialized"})
time.sleep(1)

# Call tool
send_msg({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_proxy_http_history_regex","arguments":{"regex":"target.com","count":50,"offset":0}}})
```

## Pitfalls
- `get_proxy_http_history` WITHOUT count/offset returns error: "Fields [count, offset] are required"
- Response JSON may contain binary data (protobuf responses) that breaks json.loads — use try/except per entry
- Large responses with special chars may need regex extraction rather than JSON parsing
- Bearer tokens can be extracted with: `re.findall(r'Bearer (eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', raw)`
- The SSE endpoint (`/`) returns `event: endpoint\ndata: ?sessionId=<uuid>` — curl with `--max-time` to verify it's alive
