# Script Recovery from Session DB

When scripts are lost (accidental overwrite, bad sync), they can be recovered from `~/.hermes/state.db` if they were originally written in the main session (not delegate_task subagents).

## Technique

```python
import sqlite3, json, os, re

db_path = os.path.expanduser("~/.hermes/state.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Find messages that wrote scripts via execute_code
cur.execute("""
    SELECT id, tool_calls FROM messages 
    WHERE session_id = '<SESSION_ID>'
    AND role = 'assistant'
    AND tool_calls IS NOT NULL
    AND tool_calls LIKE '%execute_code%'
    AND tool_calls LIKE '%<skill>/scripts%'
    ORDER BY id
""")

for msg_id, tc_json in cur.fetchall():
    tool_calls = json.loads(tc_json)
    for tc in tool_calls:
        func = tc.get("function", {})
        if func.get("name") != "execute_code":
            continue
        code = json.loads(func.get("arguments", "{}")).get("code", "")
        
        # Extract triple-quoted script content
        matches = re.finditer(r"(\w+)\s*=\s*'''(.*?)'''", code, re.DOTALL)
        for m in matches:
            var_name = m.group(1)
            content = m.group(2)
            # Write content directly — escape sequences are preserved correctly
            # Do NOT apply .replace('\\n', '\n') — that breaks f-string escapes
```

## Key Lessons

1. **Write content as-is** — the triple-quote extraction preserves escape sequences correctly. Applying `.replace('\\n', '\n')` breaks f-strings that contain `\n` escape sequences.

2. **delegate_task subagent writes are NOT recoverable** — only the summary is stored in the main session DB, not the individual tool calls the subagent made. Scripts created by subagents are gone if no filesystem backup exists.

3. **Syntax errors after extraction** — common issues:
   - Regex patterns with quotes inside single-quoted raw strings → rewrite as double-quoted r-strings
   - f-strings containing `\n` → these are correct as `\\n` in the extracted content, don't touch them
   - Nested triple-quotes (PoC templates) → rewrite using string concatenation or list join

4. **Finding the right session** — use `session_search(query="state_manager.py security")` to find sessions that created scripts, then query state.db directly with the session_id.

5. **Backup strategy** — always sync Hermes→randscript/myherms BEFORE making changes. The myherms repo and randscript repo are mirrors, not sources.

## Limitations

- Scripts created inside `delegate_task` subagents cannot be recovered from DB
- The curator backup (`.curator_backups/`) only runs weekly — may not have latest
- Time Machine not available on this system
- No git tracking in `~/.hermes/skills/security/`
