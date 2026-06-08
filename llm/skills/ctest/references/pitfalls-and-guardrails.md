## Pitfalls

- AWS metadata v2 (IMDSv2) requires PUT with token header — simple GET to 169.254.169.254 won't work
- K8s service account tokens in pods ≠ cluster-admin — check RBAC before assuming full access
- Container escape via /var/run/docker.sock only works if socket is mounted (check `ls -la /var/run/`)
- Terraform state files contain secrets in plaintext — check S3 buckets for .tfstate before moving on
- GCP metadata requires `Metadata-Flavor: Google` header — missing it returns 403
- Azure IMDS requires `Metadata: true` header — curl without it looks like the endpoint doesn't exist
- EKS/GKE managed clusters patch fast — kernel exploits rarely work, focus on misconfig/RBAC instead


---

## Guardrails

- **Authorization First** — cloud pentesting without explicit written authorization is illegal. Confirm scope covers specific accounts/projects.
- **Production Safety** — never modify production resources without explicit approval. Read-only enumeration by default. Document any write operations needed for PoC.
- **Credential Handling** — discovered credentials go in findings, not in your shell history. Use environment variables, clear after use.
- **Blast Radius** — before running automated tools (ScoutSuite, Pacu), confirm they won't trigger alerts or rate limits that disrupt production.
- **Region Awareness** — test ALL regions, not just the primary. Resources hidden in unused regions are a common finding.
- **No Persistence** — document persistence techniques but do NOT deploy backdoors without explicit authorization.
- **Evidence Preservation** — screenshot/log everything before remediation discussions. Cloud resources can be deleted quickly.
- **Alibaba Cloud metadata** — uses `100.100.100.200` (NOT 169.254.169.254). Requires no special headers (unlike GCP/Azure). RAM security credentials at `/latest/meta-data/ram/security-credentials/`.
- **Alibaba OSS buckets** — format `{name}.{region}.aliyuncs.com`. Common regions: oss-ap-southeast-1, oss-cn-hangzhou, oss-cn-shanghai. POST to OSS returns XML `MethodNotAllowed` with `webapp-origin.marmot-cloud.com` HostId (confirms static bucket). Always test via CNAME too — different ACLs possible.
- **Ant Group/Alipay infrastructure** — Spanner (internal LB), Tengine (CDN edge), ESA (edge security). `x-fc-request-id` = Function Compute, `x-oss-request-id` = OSS. See ptest `references/intel-alibaba-cloud-infrastructure.md` for full fingerprinting guide.
- **Geo-blocking** — SEA companies (Grab, Gojek, Tokopedia, OVO) commonly geo-restrict API gateways. All endpoints return 502 from outside the region. If you hit consistent 502s across all API paths, test from a regional VPN before concluding the service is down. Static assets (CDN, S3 via CNAME) often remain accessible globally even when APIs are blocked.
- **Cost Awareness** — cloud pentesting can accidentally generate costs (ScoutSuite scanning all regions, large S3 sync, spinning up compute for PoC). If using client credentials, monitor billing. Prefer `--dry-run` flags and `--max-keys`/`--limit` on enumeration. Never run crypto mining PoCs on client accounts.
- **S3 ListBucket via CNAME** — some buckets allow ListBucket only through their CNAME (e.g., `subdomain.target.com` → bucket) but deny direct `bucket.s3.amazonaws.com` access. Always test both paths. A 200 on listing doesn't mean GetObject works — test read/write separately.
- **Multi-target sessions** — when compacted context contains multiple targets (e.g., WinTicket + LINE WORKS), ONLY work on the target the user's latest message refers to. Do NOT pull tasks from compacted context unless explicitly re-requested. Respond to post-compaction messages only.
- **cloud_enum on macOS** — the pip-installed `cloud_enum` may fail with "Cannot access mutations file" because it looks for `fuzz.txt` relative to the binary, not the package. Fix: find the package dir (`pip3 show cloud_enum | grep Location`) and run from there, or symlink the enum_tools directory. If cloud_enum fails, use manual GCS bucket brute-force: `curl -sk "https://storage.googleapis.com/BUCKET" -o /dev/null -w "%{http_code}"` (404=doesn't exist, 403=exists+ACL'd, 401=exists+needs auth). Test keywords: {company}, {project}-prd/stg/dev, {product}-backup/logs/data.
- **macOS port 5000** — AirPlay Receiver occupies port 5000. Use 5001+ for Flask/web tools. Or disable AirPlay in System Settings > General > AirDrop & Handoff.
- **Firebase API key referer restriction** — Firebase Identity Toolkit returns 403 "Requests from referer <empty> are blocked" without Referer header. Always add `-H "Referer: https://target.domain/"` to all identitytoolkit.googleapis.com calls.
- **Firebase brute-force threshold** — `signInWithPassword` returns `INVALID_PASSWORD` for ~5 attempts, then switches to `TOO_MANY_ATTEMPTS_TRY_LATER` (lockout). The different error messages (`INVALID_PASSWORD` vs `EMAIL_NOT_FOUND`) confirm email existence even without `createAuthUri`. Document both the enumeration leak AND the lockout threshold in findings.
- **Firebase account self-deletion** — `accounts:delete` with any valid idToken deletes that account permanently. Test this on your OWN test account only. If the app has no server-side account deletion flow, this bypasses business logic (e.g., outstanding balances, cooldown periods).
- **CDN path traversal → origin disclosure** — Fastly/Varnish/CloudFront may not normalize `%2e%2e` (URL-encoded `..`). When CDN can't resolve the traversed path, it often generates a 302 redirect to the internal origin hostname, leaking backend infrastructure. Test: `curl -D- "https://cdn-target.com/v1/any/%2e%2e/test"` — if Location header reveals a different domain (e.g., `api-origin.target.internal`), you've found the origin. Follow-up: DNS enumerate the leaked domain for admin panels, staging, internal services. Chain: if the redirect is to a domain you control or can influence → open redirect. This pattern is common on GCP (Google Frontend + Fastly) and AWS (CloudFront + ALB).
- **Client-side config leaks (window.__CONFIG__, __NEXT_DATA__)** — SSR apps often expose keys in HTML: Sentry DSN, Datadog client tokens, Braze SDK keys, payment public keys, OAuth client IDs. These are almost always CLIENT-SIDE-ONLY. Test each with ONE REST API call — if "Invalid API key" → move on immediately. Real value: discovering internal API URLs (CMS_SERVER_API_URL), GCP project numbers (from Dynamic Links 403 errors), and feature flags. Don't burn time trying to exploit SDK-only tokens server-side.
- **Datadog RUM client tokens (pub* prefix)** — accept event injection via POST to browser-intake-datadoghq.com (HTTP 202). Impact is monitoring pollution only — Low/Informational. Not a standalone report for most programs.
- **Firebase email-change is NOT standalone ATO** — `accounts:update` with `{email:"new@x.com"}` requires the victim's idToken. This is post-auth escalation needing XSS or localStorage theft FIRST. Programs reject without the token-theft prerequisite proved. Don't waste time building "ATO chains" that start with "attacker has victim's token" — that's not a finding, it's a prerequisite.
- **GCP project number extraction** — `POST firebasedynamiclinks.googleapis.com/v1/shortLinks?key=<API_KEY>` returns 403 with `metadata.consumer: "projects/NNNNN"` leaking the numeric project ID. Also check Firebase App ID format: `1:PROJECT_NUMBER:web:HEX`. Use the number to enumerate other GCP services, test IAM, check for staging buckets (`staging.<project>.appspot.com`).
- **Firebase provider conflicts** — if an account exists with `password` provider, `signInWithEmailLink` to the same email will FAIL or conflict silently. When testing emailLink flows, use fresh emails never registered via password on that Firebase project.

