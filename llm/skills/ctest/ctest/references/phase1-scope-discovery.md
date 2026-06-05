## Phase 1: Scope & Discovery

### Gate: cloud provider confirmed, account/project enumerated, external attack surface mapped

**First: run proven patterns (10 min) — see `references/proven-patterns.md`**
7 high-hit-rate checks before systematic discovery. If any hits (leaked keys, public storage with secrets) → pivot immediately to Phase 2 with found credentials.

**Prioritization by scope type:**
- **External:** Credential Discovery (#5) first → then Service Discovery (#3) → then External Attack Surface (#4). You need creds or public resources before anything else matters.
- **Authenticated:** Account/Project Enumeration (#2) first → then Service Discovery (#3). You already have access, map what's reachable.
- **Internal:** All techniques in parallel — you have visibility, be systematic.

**Techniques:**

1. **Provider Identification:**
   ```bash
   # DNS indicators
   dig +short CNAME target.com  # *.amazonaws.com, *.googleusercontent.com, *.azurewebsites.net
   # IP range lookup
   whois <IP> | grep -i "amazon\|google\|microsoft"
   # HTTP headers
   curl -sI https://target.com | grep -i "x-amz\|x-goog\|x-ms\|server"
   ```

2. **Account/Project Enumeration:**
   - AWS: account ID from S3 bucket policies, STS error messages, CloudFront distributions
   - GCP: project ID from APIs, Firebase configs, GCS bucket names
   - Azure: tenant ID from `.well-known/openid-configuration`, subscription from error messages

3. **Service Discovery:**
   ```bash
   # Multi-cloud resource enumeration (S3, Azure Blobs, GCS in one pass)
   # https://github.com/initstring/cloud_enum
   cloud_enum -k <keyword> -k <company> -k <product> --disable-gcp  # or --disable-aws, --disable-azure
   # Discovers: open buckets, Azure apps, GCP projects, storage containers

   # S3/GCS/Blob enumeration (manual)
   aws s3 ls s3://<bucket> --no-sign-request
   gsutil ls gs://<bucket>

   # PITFALL: Some buckets have different ACLs via CNAME vs direct S3 URL
   # e.g., assets.target.com (CNAME → bucket.s3.amazonaws.com) may allow ListBucket
   # but s3://bucket directly returns AccessDenied. Always test BOTH paths.
   curl -s 'https://assets.target.com/'  # via CNAME
   aws s3 ls s3://bucket-name --no-sign-request  # direct

   # Cloud metadata from SSRF (if web app in scope)
   curl http://169.254.169.254/latest/meta-data/
   curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
   curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   ```

4. **External Attack Surface:**
   - Exposed storage buckets (public read/write)
   - Exposed databases (RDS/CloudSQL/CosmosDB with public endpoints)
   - Exposed management interfaces (console, API gateways)
   - Serverless function URLs (Lambda URLs, Cloud Functions, Azure Functions)
   - Container registries (ECR, GCR, ACR with public access)

5. **Credential Discovery:**
   - GitHub/GitLab code search for access keys
   - `.env` files, terraform state files, CI/CD configs
   - JS bundles with embedded cloud credentials
   - Docker images with baked-in secrets
   - **GitHub OSINT for leaked session tokens** (see `references/github-credential-osint.md`)

**Reference:** `references/aws-attack-paths.md`, `references/gcp-attack-paths.md`, `references/azure-attack-paths.md`

**Cross-reference:** ptest `references/cloud-infrastructure-enumeration.md` for passive enumeration techniques.

**Cross-skill triggers from ctest:**
- Web app found on cloud infra → invoke `ptest` for web pentest
- API gateway discovered → invoke `atest` for API-specific testing
- Container with mobile backend → invoke `mtest` if app in scope
- SSRF to internal services → feed endpoints back to `ptest`/`atest`
- Geo-blocked cloud services → see ptest `references/geo-restriction-bypass.md`

**Cross-skill triggers INTO ctest (reverse):**
- SSRF found in ptest/atest → run ctest Phase 1 metadata checks (169.254.169.254) + Phase 3 compute exploitation
- Cloud credentials leaked via web app (config.js, .env, source maps) → run ctest Phase 2 IAM analysis with found creds
- S3/GCS URLs in API responses → run ctest Phase 3 storage enumeration on those buckets
- Docker registry URL found in mtest/ptest → run ctest Phase 4 registry access checks

---
