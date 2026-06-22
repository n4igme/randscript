# Attack Recipes — atest

## BOLA/IDOR Patterns

| Vector | Payload | Expected |
|--------|---------|----------|
| Swap user ID in path | `GET /api/users/{other_id}/profile` | 200 with other user's data |
| Swap resource ID | `GET /api/orders/{other_order_id}` | 200 with other order |
| Numeric ID increment | `id=1001` → `id=1002` | Access to adjacent resource |
| UUID prediction | Collect UUIDs, check sequential patterns | Predictable allocation |

## Auth Bypass Patterns

| Vector | Technique | Notes |
|--------|-----------|-------|
| Missing auth on endpoint | Remove Authorization header | Compare 401 vs 200 |
| JWT none algorithm | `{"alg":"none"}` | Check if server validates |
| Token reuse after logout | Save token, logout, replay | Session invalidation check |
| Role parameter injection | Add `role=admin` to registration | Mass assignment |

## Injection Patterns

| Vector | Payload | Target |
|--------|---------|--------|
| SQLi in filters | `?sort=name;DROP--` | Order/filter params |
| NoSQL injection | `{"$gt":""}` in JSON body | MongoDB queries |
| SSRF via URL param | `url=http://169.254.169.254/` | Webhook/callback URLs |
| Template injection | `{{7*7}}` in user input | Server-rendered fields |

## Rate Limit Bypass

| Technique | Implementation |
|-----------|---------------|
| Header rotation | X-Forwarded-For, X-Real-IP, X-Original-URL |
| Case variation | `/API/Users` vs `/api/users` |
| Path padding | `/api/users/./` or `//api//users` |
| Unicode normalization | `%C0%AF` as path separator |

[Expand with engagement-specific recipes as discovered]
