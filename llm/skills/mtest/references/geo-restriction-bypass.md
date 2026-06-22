# Geo-Restriction Bypass — mtest

## When to Apply

- App restricts features by country/region
- App shows different content based on IP geolocation
- App enforces regional compliance rules client-side

## Techniques

### 1. GPS Spoofing

```bash
# Android (via adb)
adb shell appops set <package> android:mock_location allow

# Frida hook for Location APIs
Java.perform(function() {
    var Location = Java.use("android.location.Location");
    Location.getLatitude.implementation = function() { return 1.3521; }; // Singapore
    Location.getLongitude.implementation = function() { return 103.8198; };
});
```

### 2. VPN/Proxy

- Route traffic through target region
- Check if app validates exit node consistency
- Some apps detect VPN via DNS leak or WebRTC

### 3. Client-Side Bypass

- Patch smali: find geo-check methods, force return true
- Hook with Frida: intercept restriction check, return allowed
- Modify SharedPreferences: set `country_code` directly

### 4. API-Level Bypass

- Remove geo headers: `X-Country-Code`, `CF-IPCountry`
- Modify `Accept-Language` and `locale` parameters
- Test API directly without geo-restriction headers

## Verification

- [ ] Confirm restricted feature accessible after bypass
- [ ] Check if bypass persists across app restart
- [ ] Verify server-side vs client-side enforcement
- [ ] Document which layer enforces the restriction

## Severity Guidance

- Client-side only enforcement: Medium (if accessing paid/restricted content)
- Server accepts any geo header without validation: Medium
- Bypasses compliance requirement (e.g., gambling restriction): High
- No actual restriction on API (client cosmetic only): Info/Low
