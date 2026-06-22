# Redundancy Elimination Log

## API Pipeline Merge (2026-06-20)

### Problem
`pipeline/api.py` duplicated logic from hunt modules:
- BOLA test = same as `modules/api.py::_test_bola()` = same as `modules/idor.py`
- Verb tampering = same as `modules/api.py::_test_verb_tampering()` = same as `signals._expand_idor()`
- Path brute = same as `pipeline/discover.py::_brute_paths()`

### Resolution
- Deleted `pipeline/api.py` entirely
- Removed `ScanType.API`
- Merged OpenAPI spec discovery into `pipeline/discover.py` (probes OPENAPI_PATHS, parses spec → endpoints)
- `modules/idor.py` now skips API-prefixed URLs to avoid overlap with `modules/api.py` (APIModule)
- Orchestrator no longer routes to API pipeline

### Module Responsibility Split (Final)

| Concern | Owner | Trigger |
|---------|-------|---------|
| BOLA (API endpoints) | modules/api.py | Endpoints with /api/, /v1/, /v2/, /graphql |
| IDOR (non-API paths) | modules/idor.py | Endpoints with numeric IDs NOT in API prefixes |
| Write-method escalation | signals._expand_idor | Only after confirmed IDOR finding |
| Verb tampering (auth bypass) | modules/api.py | 401/403 on API endpoints |
| OpenAPI discovery | pipeline/discover.py | Probes spec paths during discover phase |
| Mass assignment | modules/api.py | POST/PUT/PATCH API endpoints |
| Rate limiting | modules/api.py | First 3 API endpoints |

### Rule
When adding new test logic, check if `modules/` already covers it before putting it in a pipeline file.
Pipeline files handle orchestration + discovery. Vulnerability testing belongs in modules.
