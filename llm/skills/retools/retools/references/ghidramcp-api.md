# GhidraMCP HTTP API Reference

All endpoints run on http://127.0.0.1:8080/ when the plugin is enabled in CodeBrowser.

## Key Gotcha

Most endpoints read parameters from the **POST request body** (raw text), NOT query parameters.

## Endpoints

### Read-only (GET)

| Endpoint | Description |
|----------|-------------|
| `/methods` | List all function names |
| `/classes` | List all class/namespace names |
| `/segments` | List memory segments (name: start - end) |
| `/imports` | List imported symbols |
| `/exports` | List exported symbols |
| `/namespaces` | List namespaces |
| `/data` | List defined data |
| `/strings` | List defined strings |
| `/get_current_address` | Get cursor address in CodeBrowser |
| `/get_current_function` | Get function at cursor |
| `/list_functions` | List functions (alternative to /methods) |

### Decompile/Disassemble (POST body = parameter)

| Endpoint | Body content | Description |
|----------|-------------|-------------|
| `/decompile` | function name (e.g. `FUN_001f8db4`) | Decompile by name |
| `/decompile_function` | address (e.g. `0x001f8db4`) | Decompile by address |
| `/disassemble_function` | address | Disassemble by address |
| `/get_function_by_address` | address | Get function info at address |
### Search (GET with query params)

| Endpoint | Query params | Description |
|----------|-------------|-------------|
| `/searchFunctions?query=...&offset=0&limit=100` | query, offset, limit | Search functions by name substring |

### Cross-references (GET with query params)

| Endpoint | Query param | Description |
|----------|-------------|-------------|
| `/xrefs_to?address=0x...` | address | Get cross-references TO address |
| `/xrefs_from?address=0x...` | address | Get cross-references FROM address |
| `/function_xrefs?name=...` | function name | Get xrefs for a function |

### Rename/Modify (POST body = newline-separated params)

| Endpoint | Body format | Description |
|----------|-------------|-------------|
| `/renameFunction` | `oldName\nnewName` | Rename function |
| `/renameData` | `oldName\nnewName` | Rename data label |
| `/renameVariable` | `functionName\noldVarName\nnewVarName` | Rename local variable |
| `/rename_function_by_address` | `address\nnewName` | Rename function at address |
| `/set_decompiler_comment` | `address\ncomment` | Set decompiler comment |
| `/set_disassembly_comment` | `address\ncomment` | Set disassembly comment |
| `/set_function_prototype` | `address\nprototype` | Set function signature |
| `/set_local_variable_type` | `functionAddress\nvarName\nnewType` | Change variable type |

## Usage Examples

```bash
# List all functions
curl -s http://127.0.0.1:8080/methods

# Decompile by name
curl -s -X POST -d "FUN_001f8db4" http://127.0.0.1:8080/decompile

# Decompile by address
curl -s -X POST -d "0x001f8db4" http://127.0.0.1:8080/decompile_function

# Get xrefs to an address (GET with query param)
curl -s "http://127.0.0.1:8080/xrefs_to?address=0x001f8db4"

# Rename a function
curl -s -X POST -d "FUN_001f8db4
myDestructor" http://127.0.0.1:8080/renameFunction

# Search functions (GET with query param)
curl -s "http://127.0.0.1:8080/searchFunctions?query=init"

# List all functions with addresses (more complete than /methods)
curl -s http://127.0.0.1:8080/list_functions
```
