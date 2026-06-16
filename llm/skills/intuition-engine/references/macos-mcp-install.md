# macOS MCP Server Installation

## Problem
macOS ships with Python 3.9.6 (Apple). MCP servers (arxiv, cve-mcp-server, semantic-scholar-mcp, wikipedia-mcp) require Python 3.11 or 3.12. `pip install` fails with "No matching distribution found."

## Solution: uv tool install
`uv tool install` creates isolated venvs with the correct Python version automatically.

```bash
# Python 3.11 servers
uv tool install arxiv-mcp-server --python 3.11
uv tool install semantic-scholar-mcp --python 3.11
uv tool install wikipedia-mcp --python 3.11

# Python 3.12 servers (cve-mcp-server specifically requires 3.12)
uv tool install cve-mcp-server --python 3.12
```

## Config: Use Full Paths
Hermes spawns MCP servers in its own env — `~/.local/bin` may not be in PATH.
Always use absolute paths in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  cve_intel:
    command: /Users/USERNAME/.local/bin/cve-mcp-server
    args: []
    timeout: 120
  arxiv:
    command: /Users/USERNAME/.local/bin/arxiv-mcp-server
    args: []
    timeout: 120
```

## Reload Without Restart
In active session: `/mcp reload` or ask hermes to reload MCP servers.

## Maintenance
```bash
uv tool upgrade arxiv-mcp-server
uv tool upgrade cve-mcp-server
uv tool upgrade semantic-scholar-mcp
uv tool upgrade wikipedia-mcp
```

## Pitfalls
- Don't use `pip install --break-system-packages` on macOS — version mismatch
- Don't use bare command names in config — use full `/Users/X/.local/bin/Y` paths
- cve-mcp-server needs 3.12, not 3.11 (fails with version error otherwise)
- npm MCP servers (exa, tavily) need `brew install node` first
- Pre-cache npm packages: `npx --yes exa-mcp-server --help` (slow first run)
