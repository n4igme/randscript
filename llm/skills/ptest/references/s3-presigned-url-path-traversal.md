# S3 Presigned URL Path Traversal

## Trigger
- Application generates S3 presigned URLs based on user-supplied filename/path
- Download endpoints like `/download?file=`, `/s3download?image_name=`
- Presigned URL visible in 302 Location header

## Detection
1. Observe the redirect Location header on a download endpoint
2. Note the S3 bucket name, region, key prefix, and access key ID
3. The key in the URL reveals the path structure (e.g., `upload/filename.pdf`)

## Exploitation

### Step 1: List Bucket Contents
Inject `../` to escape the key prefix and request the bucket root:
```
GET /s3download?image_name=../ HTTP/1.1
```
This generates a presigned URL to `https://bucket.s3.amazonaws.com/` (no key).
Following the redirect returns ListBucketResult XML with all objects.

### Step 2: Download Arbitrary Objects
Once you know object keys from the listing, request them:
```
GET /s3download?image_name=profile_avatar/secret.txt HTTP/1.1
```
(if prefix is `upload/`, the object key becomes `upload/profile_avatar/secret.txt`)

For objects outside the normal prefix:
```
GET /s3download?image_name=../credentials.json HTTP/1.1
```

## Key Observations (SecOps mock exam, June 2026)
- The app prepends `upload/` to the image_name value
- `../` escapes to bucket root — presigned URL with empty key = ListBucket
- Presigned URL leaks: Access Key ID (AKIA...), region, algorithm
- The Access Key alone is not enough to use AWS CLI (need secret key)
- But the app's presigned URL generator gives authenticated access to any key

## Impact
- Full bucket enumeration (all objects visible)
- Download of any object regardless of intended access controls
- AWS Access Key ID disclosure
- Potential secrets/credentials in bucket objects

## Remediation Detection
- Input validation strips `../` → try URL encoding (`%2e%2e%2f`), double encoding, `..\/`
- Allowlist-based file selection → no traversal possible
- IAM policy scoped to prefix → ListBucket may fail but GetObject on specific keys may still work
